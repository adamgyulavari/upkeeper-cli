// Package discover finds available updates without changing anything:
// Docker Engine and Compose versions from apt metadata, and image tags and
// digests from registries.
package discover

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/host"
	"github.com/adamgyulavari/upkeeper-cli/agent/registry"
	"github.com/adamgyulavari/upkeeper-cli/agent/versions"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// DockerRepoBase is Docker's apt repository.
const DockerRepoBase = "https://download.docker.com/linux"

// SupportedMajors is how many Docker Engine major versions upstream keeps
// patching (the newest and the one before). Older majors count as out of support.
const SupportedMajors = 2

// MinSupportedMajorFallback is used when we can't see upstream's newest version.
const MinSupportedMajorFallback = 28

// DockerVersions is what discovery learned about Docker packages.
type DockerVersions struct {
	Engine          []string // upstream versions available to this server's family
	Compose         []string // upstream versions of the Compose plugin package
	UpstreamLatest  string   // newest docker-ce in Docker's repo (for support status)
	ComposeLatest   string   // newest Compose plugin available in the family
	EngineLatest    string
	EngineLatestFix string // newest patch in the running minor
}

// AptMeta fetches Docker's apt Packages index (cached 6 h) and falls back to
// the server's own apt lists via `apt-cache madison`.
type AptMeta struct {
	HTTP  *http.Client
	Cache *registry.Cache
	Base  string // DockerRepoBase unless testing
	Env   collect.Env
}

// DockerRepoPackages returns package → upstream versions from Docker's repo
// for this distro, codename and arch.
func (m AptMeta) DockerRepoPackages(ctx context.Context, osID, codename, arch string) (map[string][]string, error) {
	if osID == "" || codename == "" || arch == "" {
		return nil, fmt.Errorf("unknown OS release; can't look up Docker's repository")
	}
	url := fmt.Sprintf("%s/%s/dists/%s/stable/binary-%s/Packages.gz", m.base(), osID, codename, arch)
	wanted := []string{"docker-ce", "docker-compose-plugin", "containerd.io"}
	out := map[string][]string{}
	cached := true
	for _, p := range wanted {
		v, ok := m.Cache.GetList("apt " + url + " " + p)
		if !ok {
			cached = false
			break
		}
		out[p] = v
	}
	if cached {
		return out, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	zr, err := gzip.NewReader(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	all := ParsePackagesIndex(zr)
	out = map[string][]string{}
	for _, p := range wanted {
		out[p] = all[p]
		m.Cache.PutList("apt "+url+" "+p, all[p])
	}
	return out, nil
}

func (m AptMeta) base() string {
	if m.Base != "" {
		return m.Base
	}
	return DockerRepoBase
}

func (m AptMeta) http() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// ParsePackagesIndex reads a Debian Packages file into package → versions.
func ParsePackagesIndex(r io.Reader) map[string][]string {
	out := map[string][]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	pkg := ""
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			pkg = ""
		case strings.HasPrefix(line, "Package: "):
			pkg = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		case strings.HasPrefix(line, "Version: ") && pkg != "":
			out[pkg] = append(out[pkg], strings.TrimSpace(strings.TrimPrefix(line, "Version: ")))
		}
	}
	return out
}

// Madison returns package → versions known to the local apt lists.
func (m AptMeta) Madison(ctx context.Context, pkgs ...string) (map[string][]string, error) {
	args := append(append([]string{}, host.AptNoCache...), "madison")
	out, err := m.Env.Run.Run(ctx, "apt-cache", append(args, pkgs...)...)
	res := ParseMadison(out)
	if err != nil && len(res) == 0 {
		return nil, err
	}
	return res, nil
}

// ParseMadison parses `apt-cache madison` lines: "pkg | version | source".
func ParseMadison(out []byte) map[string][]string {
	res := map[string][]string{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, "|")
		if len(f) < 3 {
			continue
		}
		pkg, ver := strings.TrimSpace(f[0]), strings.TrimSpace(f[1])
		if pkg != "" && ver != "" && !containsStr(res[pkg], ver) {
			res[pkg] = append(res[pkg], ver)
		}
	}
	return res
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// Docker fills LatestPatch, LatestVersion and EngineEOL (A-06). Docker is
// upgraded within the family the server already uses, so docker.io servers
// see distro versions; support status always comes from upstream.
func Docker(ctx context.Context, m AptMeta, sys protocol.System, d *protocol.Docker, facts collect.DockerFacts, errs *collect.Errs) DockerVersions {
	var dv DockerVersions
	if !d.Installed {
		return dv
	}
	current := d.EngineVersion
	if current == "" && facts.EngineDpkg != "" {
		current = versions.UpstreamDebian(facts.EngineDpkg)
	}

	upstream, upErr := m.DockerRepoPackages(ctx, sys.OSID, sys.OSCodename, sys.Arch)
	var local map[string][]string
	localPkgs := []string{"docker-ce", "docker-compose-plugin"}
	if d.Family == "docker.io" {
		localPkgs = []string{"docker.io", "docker-compose-v2"}
	}
	if d.Family == "docker.io" || upErr != nil {
		var err error
		local, err = m.Madison(ctx, localPkgs...)
		if err != nil && d.Family == "docker.io" {
			errs.Add("docker versions", err)
		}
	}
	if upErr != nil {
		errs.Add("docker versions", fmt.Errorf("Docker's apt repository: %w", upErr))
	}

	switch d.Family {
	case "docker-ce":
		src := upstream
		if upErr != nil {
			src = local
		}
		dv.Engine = upstreamAll(src["docker-ce"])
		dv.Compose = upstreamAll(src["docker-compose-plugin"])
	case "docker.io":
		dv.Engine = upstreamAll(local["docker.io"])
		dv.Compose = upstreamAll(local["docker-compose-v2"])
	}
	if upErr == nil {
		dv.UpstreamLatest = newest(upstreamAll(upstream["docker-ce"]))
	}

	cur, ok := versions.ParseVersion(current)
	if ok {
		dv.EngineLatestFix = newestWhere(dv.Engine, func(t versions.Tag) bool {
			return versions.SameMinor(t, cur) && versions.Compare(t, cur) > 0
		})
		dv.EngineLatest = newestWhere(dv.Engine, func(t versions.Tag) bool { return versions.Compare(t, cur) > 0 })
		d.LatestPatch = dv.EngineLatestFix
		d.LatestVersion = dv.EngineLatest

		minMajor := MinSupportedMajorFallback
		if up, ok := versions.ParseVersion(dv.UpstreamLatest); ok {
			minMajor = up.Nums[0] - (SupportedMajors - 1)
		}
		d.EngineEOL = cur.Nums[0] < minMajor
	}
	if cv, ok := versions.ParseVersion(d.ComposeVersion); ok {
		dv.ComposeLatest = newestWhere(dv.Compose, func(t versions.Tag) bool { return versions.Compare(t, cv) > 0 })
	}
	return dv
}

func upstreamAll(debs []string) []string {
	out := make([]string, 0, len(debs))
	for _, v := range debs {
		u := versions.UpstreamDebian(v)
		if !containsStr(out, u) {
			out = append(out, u)
		}
	}
	return out
}

func newest(vs []string) string {
	return newestWhere(vs, func(versions.Tag) bool { return true })
}

func newestWhere(vs []string, keep func(versions.Tag) bool) string {
	var best versions.Tag
	found := false
	for _, v := range vs {
		t, ok := versions.ParseVersion(v)
		if !ok || t.Prerelease() || !keep(t) {
			continue
		}
		if !found || versions.Compare(t, best) > 0 {
			best, found = t, true
		}
	}
	if !found {
		return ""
	}
	return strings.TrimPrefix(best.Raw, "v")
}
