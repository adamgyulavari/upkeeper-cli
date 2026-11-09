package registry

import (
	"fmt"
	"strings"
)

// Ref is a normalized image reference.
type Ref struct {
	Registry string // docker.io, ghcr.io, quay.io …
	Repo     string // library/nginx, immich-app/immich-server
	Tag      string // "" when only a digest is given
	Digest   string // sha256:… when pinned
}

// ParseRef normalizes an image reference the way the Docker CLI does:
// "nginx" → docker.io/library/nginx:latest.
func ParseRef(s string) (Ref, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Ref{}, fmt.Errorf("empty image reference")
	}
	var r Ref
	if i := strings.Index(s, "@"); i >= 0 {
		r.Digest = s[i+1:]
		s = s[:i]
	}
	// A tag is after the last ':' that comes after the last '/'.
	if i := strings.LastIndex(s, ":"); i > strings.LastIndex(s, "/") {
		r.Tag = s[i+1:]
		s = s[:i]
	}
	first, rest, hasSlash := strings.Cut(s, "/")
	if hasSlash && (strings.ContainsAny(first, ".:") || first == "localhost") {
		r.Registry = first
		r.Repo = rest
	} else {
		r.Registry = "docker.io"
		r.Repo = s
	}
	if r.Registry == "index.docker.io" || r.Registry == "registry-1.docker.io" {
		r.Registry = "docker.io"
	}
	if r.Registry == "docker.io" && !strings.Contains(r.Repo, "/") {
		r.Repo = "library/" + r.Repo
	}
	if r.Repo == "" || strings.ToLower(r.Repo) != r.Repo {
		return Ref{}, fmt.Errorf("invalid image reference %q", s)
	}
	if r.Tag == "" && r.Digest == "" {
		r.Tag = "latest"
	}
	return r, nil
}

// Name is registry/repo, the form RepoDigests use for non-Hub images.
func (r Ref) Name() string { return r.Registry + "/" + r.Repo }

// Familiar is the short form Docker prints ("nginx", "ghcr.io/x/y").
func (r Ref) Familiar() string {
	if r.Registry == "docker.io" {
		return strings.TrimPrefix(r.Repo, "library/")
	}
	return r.Name()
}

// SameRepo reports whether a RepoDigests entry ("nginx@sha256:…") names this repo.
func (r Ref) SameRepo(repoDigest string) bool {
	name, _, _ := strings.Cut(repoDigest, "@")
	o, err := ParseRef(name)
	return err == nil && o.Registry == r.Registry && o.Repo == r.Repo
}
