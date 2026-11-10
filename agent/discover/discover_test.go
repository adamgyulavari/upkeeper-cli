package discover_test

import (
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/discover"
	"github.com/adamgyulavari/upkeeper-cli/agent/fakes"
	"github.com/adamgyulavari/upkeeper-cli/agent/host"
	"github.com/adamgyulavari/upkeeper-cli/agent/registry"
	"github.com/adamgyulavari/upkeeper-cli/agent/versions"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// dockerRepo serves testdata Packages as Docker's apt repo for ubuntu/noble/amd64.
func dockerRepo(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	b, err := os.ReadFile("testdata/docker-noble-amd64-Packages")
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/ubuntu/dists/noble/stable/binary-amd64/Packages.gz" {
			http.NotFound(w, r)
			return
		}
		zw := gzip.NewWriter(w)
		zw.Write(b)
		zw.Close()
	}))
}

func TestParsePackagesIndex(t *testing.T) {
	f, err := os.Open("testdata/docker-noble-amd64-Packages")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got := discover.ParsePackagesIndex(f)
	if len(got["docker-ce"]) != 6 || len(got["docker-compose-plugin"]) != 3 || len(got["containerd.io"]) != 2 {
		t.Errorf("got %v", got)
	}
}

func TestParseMadison(t *testing.T) {
	out := ` docker.io | 27.5.1-0ubuntu3~24.04.2 | http://archive.ubuntu.com/ubuntu noble-updates/universe amd64 Packages
 docker.io | 27.5.1-0ubuntu3~24.04.2 | http://security.ubuntu.com/ubuntu noble-security/universe amd64 Packages
 docker.io | 24.0.7-0ubuntu4 | http://archive.ubuntu.com/ubuntu noble/universe amd64 Packages
docker-compose-v2 | 2.27.1+ds1-0ubuntu1~24.04.1 | http://archive.ubuntu.com/ubuntu noble-updates/universe amd64 Packages
`
	got := discover.ParseMadison([]byte(out))
	want := map[string][]string{
		"docker.io":         {"27.5.1-0ubuntu3~24.04.2", "24.0.7-0ubuntu4"},
		"docker-compose-v2": {"2.27.1+ds1-0ubuntu1~24.04.1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
}

var noble = protocol.System{OSID: "ubuntu", OSVersion: "24.04", OSCodename: "noble", Arch: "amd64"}

func TestDockerVersions(t *testing.T) {
	var hits atomic.Int32
	repo := dockerRepo(t, &hits)
	defer repo.Close()
	madisonKey := func(pkgs ...string) string {
		return host.Key("apt-cache", append(append(append([]string{}, host.AptNoCache...), "madison"), pkgs...)...)
	}

	tests := []struct {
		name     string
		sys      protocol.System
		docker   protocol.Docker
		facts    collect.DockerFacts
		madison  map[string]string
		repoBase string
		want     protocol.Docker
		errs     int
	}{
		{
			name:   "docker-ce behind on patch and minor",
			sys:    noble,
			docker: protocol.Docker{Installed: true, Family: "docker-ce", EngineVersion: "28.3.1", ComposeVersion: "2.29.1"},
			want: protocol.Docker{Installed: true, Family: "docker-ce", EngineVersion: "28.3.1", ComposeVersion: "2.29.1",
				LatestPatch: "28.3.3", LatestVersion: "29.1.2"},
		},
		{
			name:   "docker-ce out of support (two majors behind)",
			sys:    noble,
			docker: protocol.Docker{Installed: true, Family: "docker-ce", EngineVersion: "27.5.1"},
			want: protocol.Docker{Installed: true, Family: "docker-ce", EngineVersion: "27.5.1",
				LatestVersion: "29.1.2", EngineEOL: true},
		},
		{
			name:   "docker-ce up to date; rc not offered",
			sys:    noble,
			docker: protocol.Docker{Installed: true, Family: "docker-ce", EngineVersion: "29.1.2", ComposeVersion: "2.31.0"},
			want:   protocol.Docker{Installed: true, Family: "docker-ce", EngineVersion: "29.1.2", ComposeVersion: "2.31.0"},
		},
		{
			name:    "docker.io stays in its family; support status from upstream",
			sys:     noble,
			docker:  protocol.Docker{Installed: true, Family: "docker.io", EngineVersion: "24.0.7", ComposeVersion: "2.27.1"},
			madison: map[string]string{"docker.io docker-compose-v2": " docker.io | 27.5.1-0ubuntu3~24.04.2 | http://archive.ubuntu.com/ubuntu noble-updates/universe amd64 Packages\n docker.io | 24.0.7-0ubuntu4 | http://archive.ubuntu.com/ubuntu noble/universe amd64 Packages\n"},
			want: protocol.Docker{Installed: true, Family: "docker.io", EngineVersion: "24.0.7", ComposeVersion: "2.27.1",
				LatestVersion: "27.5.1", EngineEOL: true},
		},
		{
			name:     "Docker's repo unreachable: fall back to local apt lists",
			sys:      noble,
			repoBase: "http://127.0.0.1:1",
			docker:   protocol.Docker{Installed: true, Family: "docker-ce", EngineVersion: "28.3.1"},
			madison:  map[string]string{"docker-ce docker-compose-plugin": " docker-ce | 5:28.3.2-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable amd64 Packages\n"},
			want:     protocol.Docker{Installed: true, Family: "docker-ce", EngineVersion: "28.3.1", LatestPatch: "28.3.2", LatestVersion: "28.3.2"},
			errs:     1,
		},
		{
			name:   "not installed: nothing looked up",
			sys:    noble,
			docker: protocol.Docker{},
			want:   protocol.Docker{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &host.FakeRunner{Out: map[string]string{}}
			for pk, out := range tt.madison {
				r.Out[madisonKey(strings.Fields(pk)...)] = out
			}
			base := repo.URL
			if tt.repoBase != "" {
				base = tt.repoBase
			}
			m := discover.AptMeta{Cache: registry.OpenCache("", nil), Base: base, Env: collect.Env{Run: r}}
			var errs collect.Errs
			d := tt.docker
			discover.Docker(context.Background(), m, tt.sys, &d, tt.facts, &errs)
			if d != tt.want {
				t.Errorf("\n got %+v\nwant %+v", d, tt.want)
			}
			if len(errs) != tt.errs {
				t.Errorf("errs = %v", errs)
			}
		})
	}

	// The Packages index is cached: a second lookup doesn't download it again.
	hits.Store(0)
	cache := registry.OpenCache("", nil)
	m := discover.AptMeta{Cache: cache, Base: repo.URL}
	for i := 0; i < 3; i++ {
		d := protocol.Docker{Installed: true, Family: "docker-ce", EngineVersion: "28.3.1"}
		var errs collect.Errs
		discover.Docker(context.Background(), m, noble, &d, collect.DockerFacts{}, &errs)
	}
	if hits.Load() != 1 {
		t.Errorf("Packages.gz fetched %d times", hits.Load())
	}
}

func TestNewerTags(t *testing.T) {
	tags := []string{"v2.11.2", "v2.11.14", "v2.10.7", "v3.2.1", "v3.3.0-rc1", "2.11.15", "latest", "v3.2", "v3"}
	tests := []struct {
		cur          string
		minor, major string
	}{
		{"v2.11.2", "v2.11.14", "v3.2.1"},
		{"v3.2.1", "", ""},
		{"v3.2", "", ""},
		{"v2", "", "v3"},
	}
	for _, tt := range tests {
		cur, _ := versions.ParseTag(tt.cur)
		minor, major := discover.NewerTags(cur, tags)
		if minor != tt.minor || major != tt.major {
			t.Errorf("%s: got %q %q, want %q %q", tt.cur, minor, major, tt.minor, tt.major)
		}
	}
	cur, _ := versions.ParseTag("16.4-alpine3.20")
	if minor, major := discover.NewerTags(cur, []string{"16.6-alpine3.21", "17.2-alpine3.21", "16.6-bookworm", "16.6"}); minor != "16.6-alpine3.21" || major != "17.2-alpine3.21" {
		t.Errorf("variants: %q %q", minor, major)
	}
	pg, _ := versions.ParseTag("0.7.2-pg16")
	tags = []string{"0.7.4-pg16", "0.7.4-pg17", "0.8.0-pg15", "0.7.9-pg18-rc1"}
	if minor, major := discover.NewerTags(pg, tags); minor != "0.7.4-pg16" || major != "" {
		t.Errorf("pg16 line: %q %q", minor, major)
	}
	if f := discover.NewerFamily(pg, tags); f != "0.7.4-pg17" {
		t.Errorf("newer family: %q", f)
	}
}

type fakeReg struct {
	tags    map[string][]string
	digests map[string]string
	err     error
	calls   []string
}

func (f *fakeReg) Tags(_ context.Context, r registry.Ref) ([]string, error) {
	f.calls = append(f.calls, "tags "+r.Name())
	if f.err != nil {
		return nil, f.err
	}
	return f.tags[r.Name()], nil
}

func (f *fakeReg) Digest(_ context.Context, r registry.Ref, tag string) (string, error) {
	f.calls = append(f.calls, "digest "+r.Name()+":"+tag)
	if f.err != nil {
		return "", f.err
	}
	return f.digests[r.Name()+":"+tag], nil
}

func (f *fakeReg) Skipped() map[string]error {
	if f.err != nil {
		return map[string]error{"ghcr.io": errors.New("offline")}
	}
	return nil
}

func svc(name, image, digest string, pinned bool) (protocol.Service, collect.ServiceFacts) {
	ref, err := registry.ParseRef(image)
	return protocol.Service{Name: name, Image: image, Digest: digest, Pinned: pinned}, collect.ServiceFacts{Ref: ref, RefErr: err}
}

func TestImages(t *testing.T) {
	facts := collect.DockerFacts{Services: map[string]collect.ServiceFacts{}}
	var services []protocol.Service
	for _, s := range []struct {
		name, image, digest string
		pinned              bool
	}{
		{"traefik", "traefik:v2.11.2", "sha256:t1", false},
		{"redis", "redis:6.2-alpine", "sha256:r-old", false},
		{"portainer", "portainer/portainer-ce:latest", "sha256:p-same", false},
		{"db", "tensorchord/pgvecto-rs:pg14-v0.2.0@sha256:9072", "sha256:9072", true},
		{"app", "shop-app", "", false},
		{"rc", "ghcr.io/x/y:2.0.0-rc1", "sha256:rc", false},
	} {
		sv, f := svc(s.name, s.image, s.digest, s.pinned)
		services = append(services, sv)
		facts.Services["p/"+s.name] = f
	}
	projects := []protocol.Project{{Name: "p", Services: services}}
	reg := &fakeReg{
		tags: map[string][]string{
			"docker.io/library/traefik": {"v2.11.2", "v2.11.14", "v3.2.1"},
			"docker.io/library/redis":   {"6.2-alpine", "7.4-alpine", "6.2"},
		},
		digests: map[string]string{
			"docker.io/library/redis:6.2-alpine":      "sha256:r-new",
			"docker.io/portainer/portainer-ce:latest": "sha256:p-same",
			"ghcr.io/x/y:2.0.0-rc1":                   "sha256:rc2",
		},
	}
	var errs collect.Errs
	got := discover.Images(context.Background(), reg, projects, facts, &errs)
	type short struct {
		svc, to string
		change  versions.Change
		digest  bool
	}
	var gs []short
	for _, u := range got {
		gs = append(gs, short{u.Service, u.ToTag, u.Change, u.NewDigest})
	}
	want := []short{
		{"traefik", "v2.11.14", versions.Patch, false},
		{"traefik", "v3.2.1", versions.Major, false},
		{"redis", "7.4-alpine", versions.Major, false},
		{"redis", "6.2-alpine", versions.Same, true},
		{"rc", "2.0.0-rc1", versions.Same, true},
	}
	if !reflect.DeepEqual(gs, want) {
		t.Errorf("\n got %+v\nwant %+v", gs, want)
	}
	for _, c := range reg.calls {
		if strings.Contains(c, "pgvecto") || strings.Contains(c, "shop-app") {
			t.Errorf("pinned or local images must not be looked up: %s", c)
		}
	}
	if len(errs) != 0 {
		t.Errorf("errs %v", errs)
	}

	// Offline: one line per registry, no crash, no updates.
	reg = &fakeReg{err: registry.ErrUnavailable}
	errs = nil
	if got := discover.Images(context.Background(), reg, projects, facts, &errs); len(got) != 0 {
		t.Errorf("offline updates: %v", got)
	}
	if len(errs) != 1 || !strings.HasPrefix(errs[0], "registry ghcr.io") {
		t.Errorf("offline errs %v", errs)
	}
}

func TestImagesAgainstFakeRegistry(t *testing.T) {
	// End to end through the real client and the fake registry's token flow.
	reg := fakes.NewRegistry(map[string]fakes.Repo{
		"immich-app/immich-server": {Tags: []string{"v1.119.0", "v1.120.2", "v1.121.0-rc1", "v2.0.1", "release"}},
	})
	defer reg.Srv.Close()
	c := registry.New(nil, "t")
	c.MinInterval = time.Millisecond
	c.Endpoint = func(string) string { return reg.Srv.URL }
	sv, f := svc("immich-server", "ghcr.io/immich-app/immich-server:v1.119.0", "sha256:i", false)
	var errs collect.Errs
	got := discover.Images(context.Background(), c, []protocol.Project{{Name: "immich", Services: []protocol.Service{sv}}},
		collect.DockerFacts{Services: map[string]collect.ServiceFacts{"immich/immich-server": f}}, &errs)
	if len(got) != 2 || got[0].ToTag != "v1.120.2" || got[1].ToTag != "v2.0.1" || len(errs) != 0 {
		t.Errorf("got %+v errs %v", got, errs)
	}
}
