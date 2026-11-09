package registry_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/fakes"
	"github.com/adamgyulavari/upkeeper-cli/agent/registry"
)

func TestParseRef(t *testing.T) {
	tests := []struct {
		in   string
		want registry.Ref
	}{
		{"nginx", registry.Ref{Registry: "docker.io", Repo: "library/nginx", Tag: "latest"}},
		{"nginx:1.27", registry.Ref{Registry: "docker.io", Repo: "library/nginx", Tag: "1.27"}},
		{"docker.io/redis:6.2-alpine", registry.Ref{Registry: "docker.io", Repo: "library/redis", Tag: "6.2-alpine"}},
		{"portainer/portainer-ce:latest", registry.Ref{Registry: "docker.io", Repo: "portainer/portainer-ce", Tag: "latest"}},
		{"ghcr.io/immich-app/immich-server:v1.119.0", registry.Ref{Registry: "ghcr.io", Repo: "immich-app/immich-server", Tag: "v1.119.0"}},
		{"quay.io/prometheus/node-exporter:v1.8.2", registry.Ref{Registry: "quay.io", Repo: "prometheus/node-exporter", Tag: "v1.8.2"}},
		{"localhost:5000/app", registry.Ref{Registry: "localhost:5000", Repo: "app", Tag: "latest"}},
		{"registry-1.docker.io/library/postgres:16", registry.Ref{Registry: "docker.io", Repo: "library/postgres", Tag: "16"}},
		{"tensorchord/pgvecto-rs:pg14-v0.2.0@sha256:90724186f0a3517cf6914295b5ab410db9ce23190a2d9d0b9dd6463e3fa298f0",
			registry.Ref{Registry: "docker.io", Repo: "tensorchord/pgvecto-rs", Tag: "pg14-v0.2.0", Digest: "sha256:90724186f0a3517cf6914295b5ab410db9ce23190a2d9d0b9dd6463e3fa298f0"}},
		{"redis@sha256:abc", registry.Ref{Registry: "docker.io", Repo: "library/redis", Digest: "sha256:abc"}},
	}
	for _, tt := range tests {
		got, err := registry.ParseRef(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("ParseRef(%q) = %+v, %v; want %+v", tt.in, got, err, tt.want)
		}
	}
	for _, bad := range []string{"", "Nginx:latest"} {
		if _, err := registry.ParseRef(bad); err == nil {
			t.Errorf("ParseRef(%q) should fail", bad)
		}
	}
	r, _ := registry.ParseRef("nginx:1.27")
	if !r.SameRepo("nginx@sha256:1") || !r.SameRepo("docker.io/library/nginx@sha256:1") || r.SameRepo("ghcr.io/nginx@sha256:1") {
		t.Error("SameRepo")
	}
	if r.Familiar() != "nginx" {
		t.Errorf("Familiar = %s", r.Familiar())
	}
}

func TestParseChallenge(t *testing.T) {
	scheme, p := registry.ParseChallenge(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"`)
	want := map[string]string{"realm": "https://auth.docker.io/token", "service": "registry.docker.io", "scope": "repository:library/nginx:pull"}
	if scheme != "Bearer" || !reflect.DeepEqual(p, want) {
		t.Errorf("got %s %v", scheme, p)
	}
	scheme, p = registry.ParseChallenge(`Basic realm="Registry Realm"`)
	if scheme != "Basic" || p["realm"] != "Registry Realm" {
		t.Errorf("got %s %v", scheme, p)
	}
}

func newClient(reg *fakes.Registry, cache *registry.Cache) *registry.Client {
	c := registry.New(cache, "upkeeper-test")
	c.MinInterval = time.Millisecond
	c.Endpoint = func(string) string { return reg.Srv.URL }
	return c
}

func TestTagsAndDigestWithTokenFlow(t *testing.T) {
	// The same anonymous token dance for each of Docker Hub, ghcr.io and quay.io.
	for _, name := range []string{"docker.io", "ghcr.io", "quay.io"} {
		t.Run(name, func(t *testing.T) {
			repo := map[string]string{"docker.io": "library/traefik", "ghcr.io": "immich-app/immich-server", "quay.io": "prometheus/node-exporter"}[name]
			reg := fakes.NewRegistry(map[string]fakes.Repo{repo: {
				Tags:    []string{"v2.11.2", "v2.11.14", "v3.2.1", "latest", "v3.3.0-rc1"},
				Digests: map[string]string{"latest": "sha256:new"},
			}})
			defer reg.Srv.Close()
			c := newClient(reg, registry.OpenCache("", nil))
			ref := registry.Ref{Registry: name, Repo: repo, Tag: "latest"}
			tags, err := c.Tags(context.Background(), ref)
			if err != nil {
				t.Fatal(err)
			}
			sort.Strings(tags)
			if len(tags) != 5 {
				t.Errorf("paginated tags: %v", tags)
			}
			dg, err := c.Digest(context.Background(), ref, "latest")
			if err != nil || dg != "sha256:new" {
				t.Errorf("digest %q %v", dg, err)
			}
			// 1 challenge + 1 token + 3 pages + 1 HEAD; the token is reused.
			if n := reg.Count(); n != 6 {
				t.Errorf("requests = %d: %v", n, reg.Requests)
			}
		})
	}
}

func TestDigestFallsBackToGET(t *testing.T) {
	reg := fakes.NewRegistry(map[string]fakes.Repo{"library/nginx": {Digests: map[string]string{"latest": "sha256:ignored"}}})
	reg.NoHeadDigest = true
	defer reg.Srv.Close()
	c := newClient(reg, nil)
	dg, err := c.Digest(context.Background(), registry.Ref{Registry: "docker.io", Repo: "library/nginx"}, "latest")
	sum := sha256.Sum256([]byte(`{"schemaVersion":2}`))
	if want := "sha256:" + hex.EncodeToString(sum[:]); err != nil || dg != want {
		t.Errorf("digest %q %v", dg, err)
	}
}

func TestCacheTTLAndPersistence(t *testing.T) {
	reg := fakes.NewRegistry(map[string]fakes.Repo{"library/redis": {Tags: []string{"7.4"}}})
	defer reg.Srv.Close()
	dir := t.TempDir()
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	ref := registry.Ref{Registry: "docker.io", Repo: "library/redis", Tag: "7.4"}

	c := newClient(reg, registry.OpenCache(dir, clock))
	if _, err := c.Tags(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if err := c.Cache.Save(); err != nil {
		t.Fatal(err)
	}
	first := reg.Count()

	// A new process within 6 h reads the file and asks nothing.
	now = now.Add(5 * time.Hour)
	c2 := newClient(reg, registry.OpenCache(dir, clock))
	if _, err := c2.Tags(context.Background(), ref); err != nil || reg.Count() != first {
		t.Errorf("cached lookup hit the registry: %d → %d (%v)", first, reg.Count(), err)
	}
	// After 6 h it asks again.
	now = now.Add(2 * time.Hour)
	c3 := newClient(reg, registry.OpenCache(dir, clock))
	if _, err := c3.Tags(context.Background(), ref); err != nil || reg.Count() == first {
		t.Errorf("expired entry not refreshed")
	}
}

func TestRateLimitBacksOff(t *testing.T) {
	reg := fakes.NewRegistry(map[string]fakes.Repo{"library/a": {Tags: []string{"1"}}, "library/b": {Tags: []string{"1"}}})
	defer reg.Srv.Close()
	reg.RateLimit.Store(true)
	dir := t.TempDir()
	c := newClient(reg, registry.OpenCache(dir, nil))
	_, err := c.Tags(context.Background(), registry.Ref{Registry: "docker.io", Repo: "library/a"})
	if !errors.Is(err, registry.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	n := reg.Count()
	_, err = c.Tags(context.Background(), registry.Ref{Registry: "docker.io", Repo: "library/b"})
	if !errors.Is(err, registry.ErrUnavailable) || reg.Count() != n {
		t.Errorf("second lookup should not hit a rate-limited registry: %v", err)
	}
	if len(c.Skipped()) != 1 {
		t.Errorf("skipped: %v", c.Skipped())
	}
	// The back-off survives a restart (it's in the cache file).
	if err := c.Cache.Save(); err != nil {
		t.Fatal(err)
	}
	reg.RateLimit.Store(false)
	c2 := newClient(reg, registry.OpenCache(dir, nil))
	if _, err := c2.Tags(context.Background(), registry.Ref{Registry: "docker.io", Repo: "library/b"}); !errors.Is(err, registry.ErrUnavailable) || reg.Count() != n {
		t.Errorf("back-off not persisted: %v", err)
	}
}

func TestOffline(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	c := registry.New(nil, "t")
	c.Endpoint = func(string) string { return "http://" + addr }
	for i := 0; i < 3; i++ {
		_, err := c.Tags(context.Background(), registry.Ref{Registry: "ghcr.io", Repo: "x/y"})
		if !errors.Is(err, registry.ErrUnavailable) {
			t.Fatalf("want ErrUnavailable, got %v", err)
		}
	}
	if len(c.Skipped()) != 1 {
		t.Errorf("one skipped registry expected: %v", c.Skipped())
	}
}

func TestMinInterval(t *testing.T) {
	reg := fakes.NewRegistry(map[string]fakes.Repo{"library/a": {Tags: []string{"1", "2", "3", "4", "5", "6"}}})
	defer reg.Srv.Close()
	c := newClient(reg, nil)
	c.MinInterval = 40 * time.Millisecond
	start := time.Now()
	if _, err := c.Tags(context.Background(), registry.Ref{Registry: "docker.io", Repo: "library/a"}); err != nil {
		t.Fatal(err)
	}
	// 1 challenge + 1 token + 3 pages to one host = 5 requests → ≥ 4 gaps.
	if el := time.Since(start); el < 4*40*time.Millisecond {
		t.Errorf("requests not spaced: %s for %d requests", el, reg.Count())
	}
}

func TestPrivateImage(t *testing.T) {
	reg := fakes.NewRegistry(map[string]fakes.Repo{})
	defer reg.Srv.Close()
	c := newClient(reg, nil)
	_, err := c.Tags(context.Background(), registry.Ref{Registry: "ghcr.io", Repo: "acme/private"})
	if err == nil || errors.Is(err, registry.ErrUnavailable) {
		t.Errorf("a missing repo is a per-image error, not a skipped registry: %v", err)
	}
}
