package discover

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/registry"
	"github.com/adamgyulavari/upkeeper-cli/agent/versions"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// ImageUpdate is one newer version (or digest) found for a running service.
type ImageUpdate struct {
	Project, Service string
	Image            string // as written
	FromTag, ToTag   string
	Change           versions.Change // Patch | Minor | Major; Same for a new digest
	NewDigest        bool
	FromDigest       string
	ToDigest         string
	// FirstSeen is when this agent first saw the target (digest, or tag
	// if the digest is unknown). Zero if the registry client doesn't track it.
	FirstSeen time.Time
	// FamilyChange is set when ToTag moves something bundled in the image
	// (the version in the tag suffix) by a major version: "pg 16 → 17".
	FamilyChange string
}

// SeenTracker is implemented by registry clients that remember when they
// first saw a digest or tag (registry.Client does).
type SeenTracker interface {
	FirstSeen(key string) time.Time
}

// Registry is the subset of registry.Client discovery needs.
type Registry interface {
	Tags(ctx context.Context, ref registry.Ref) ([]string, error)
	Digest(ctx context.Context, ref registry.Ref, tag string) (string, error)
	Skipped() map[string]error
}

// Images looks for newer tags and new digests on floating tags (A-06).
// Pinned services are skipped: they're reported, never looked up.
func Images(ctx context.Context, reg Registry, projects []protocol.Project, facts collect.DockerFacts, errs *collect.Errs) []ImageUpdate {
	var out []ImageUpdate
	reported := map[string]bool{}
	note := func(key string, err error) {
		if err == nil || errors.Is(err, registry.ErrUnavailable) || reported[key] {
			return // unavailable registries get one line below
		}
		reported[key] = true
		errs.Add("image "+key, err)
	}
	for _, p := range projects {
		for _, s := range p.Services {
			f := facts.Services[p.Name+"/"+s.Name]
			if s.Pinned || f.Coolify || f.RefErr != nil || f.Ref.Repo == "" {
				continue
			}
			if s.Digest == "" {
				continue // built locally or never pulled: no registry to ask
			}
			ref := f.Ref
			base := ImageUpdate{Project: p.Name, Service: s.Name, Image: s.Image, FromTag: ref.Tag, FromDigest: s.Digest}

			cur, semver := versions.ParseTag(ref.Tag)
			if semver && (cur.Prerelease() || (len(cur.Nums) == 1 && cur.Nums[0] >= 1000)) {
				semver = false // rc builds and date/build-number tags: digest only
			}
			if semver {
				tags, err := reg.Tags(ctx, ref)
				note(ref.Familiar(), err)
				if err == nil {
					minor, major := NewerTags(cur, tags)
					for _, t := range []string{minor, major} {
						if t == "" {
							continue
						}
						nt, _ := versions.ParseTag(t)
						u := base
						u.ToTag, u.Change = t, versions.Diff(cur, nt)
						out = append(out, u)
					}
					if t := NewerFamily(cur, tags); t != "" {
						nt, _ := versions.ParseTag(t)
						u := base
						u.ToTag, u.Change, u.FamilyChange = t, versions.Major, versions.FamilyChange(cur, nt)
						out = append(out, u)
					}
				}
			}
			if !semver || !cur.Precise() {
				// floating tag (latest, release, 16, 1.2): did it move?
				dg, err := reg.Digest(ctx, ref, ref.Tag)
				note(ref.Familiar()+":"+ref.Tag, err)
				if err == nil && dg != "" && dg != s.Digest {
					u := base
					u.ToTag, u.NewDigest, u.ToDigest = ref.Tag, true, dg
					out = append(out, u)
				}
			}
		}
	}
	// Resolve the digest every version update would run, so a run pulls
	// exactly what was planned, and note when each target was first seen.
	seen, _ := reg.(SeenTracker)
	for i := range out {
		u := &out[i]
		f := facts.Services[u.Project+"/"+u.Service]
		if !u.NewDigest && u.ToDigest == "" {
			if dg, err := reg.Digest(ctx, f.Ref, u.ToTag); err == nil {
				u.ToDigest = dg
			}
		}
		if seen != nil {
			key := f.Ref.Name() + ":" + u.ToTag
			if u.ToDigest != "" {
				key = f.Ref.Name() + "@" + u.ToDigest
			}
			u.FirstSeen = seen.FirstSeen(key)
		}
	}
	skipped := reg.Skipped()
	names := make([]string, 0, len(skipped))
	for n := range skipped {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		errs.Add("registry "+n, fmt.Errorf("skipped image checks: %v", skipped[n]))
	}
	return out
}

// NewerFamily returns the newest tag of the same kind whose suffix moves an
// embedded version up by a major (0.7.2-pg16 → 0.7.4-pg17), or "". These
// are never offered as an ordinary update of the current line.
func NewerFamily(cur versions.Tag, tags []string) string {
	var best versions.Tag
	for _, s := range tags {
		t, ok := versions.ParseTag(s)
		if !ok || t.Prerelease() || !cur.SameKind(t) || t.Family == cur.Family || !versions.FamilyNewer(cur, t) {
			continue
		}
		if best.Raw == "" || familyLess(best, t) {
			best = t
		}
	}
	return best.Raw
}

func familyLess(a, b versions.Tag) bool {
	for i := range a.Embedded {
		if i < len(b.Embedded) && a.Embedded[i].Major != b.Embedded[i].Major {
			return a.Embedded[i].Major < b.Embedded[i].Major
		}
	}
	return versions.Compare(a, b) < 0
}

// NewerTags returns the newest compatible tag within the same major
// (minor/patch) and the newest one with a higher major, if any.
func NewerTags(cur versions.Tag, tags []string) (sameMajor, nextMajor string) {
	var bestMinor, bestMajor versions.Tag
	for _, s := range tags {
		t, ok := versions.ParseTag(s)
		if !ok || t.Prerelease() || !cur.Compatible(t) || versions.Compare(t, cur) <= 0 {
			continue
		}
		if versions.Diff(cur, t) == versions.Major {
			if bestMajor.Raw == "" || versions.Compare(t, bestMajor) > 0 {
				bestMajor = t
			}
		} else if bestMinor.Raw == "" || versions.Compare(t, bestMinor) > 0 {
			bestMinor = t
		}
	}
	return bestMinor.Raw, bestMajor.Raw
}
