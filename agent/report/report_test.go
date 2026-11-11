package report_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/cloudclient"
	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/discover"
	"github.com/adamgyulavari/upkeeper-cli/agent/fakes"
	"github.com/adamgyulavari/upkeeper-cli/agent/host"
	"github.com/adamgyulavari/upkeeper-cli/agent/registry"
	"github.com/adamgyulavari/upkeeper-cli/agent/report"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

const fx = "../collect/testdata/ubuntu2404"

func dockerRepo(t *testing.T) *httptest.Server {
	b, err := os.ReadFile("../discover/testdata/docker-noble-amd64-Packages")
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zw := gzip.NewWriter(w)
		zw.Write(b)
		zw.Close()
	}))
}

func digest(t *testing.T, key string) string {
	var m map[string]string
	b, _ := os.ReadFile("../collect/testdata/digests.json")
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m[key]
}

func ubuntuCollector(t *testing.T) (*report.Collector, func()) {
	t.Helper()
	docker := fakes.DockerAPI(fx + "/docker")
	repo := dockerRepo(t)
	reg := fakes.NewRegistry(map[string]fakes.Repo{
		"library/traefik":          {Tags: []string{"v2.11.2", "v2.11.14", "v3.2.1"}},
		"library/redis":            {Tags: []string{"6.2-alpine", "7.4-alpine"}, Digests: map[string]string{"6.2-alpine": "sha256:" + strings.Repeat("e", 64)}},
		"portainer/portainer-ce":   {Digests: map[string]string{"latest": digest(t, "portainer")}},
		"immich-app/immich-server": {Tags: []string{"v1.119.0", "v1.120.2", "v2.0.1"}},
		"example/backup":           {Tags: []string{"1.4.2", "1.4.3"}},
	})
	reg.PageSize = 100
	cache := registry.OpenCache(t.TempDir(), nil)
	rc := registry.New(cache, "test")
	rc.MinInterval = time.Millisecond
	rc.Endpoint = func(string) string { return reg.Srv.URL }

	env := collect.Env{
		FS: fakes.FS{RootFS: host.RootFS{Root: fx}, Disks: map[string][2]uint64{
			"/": {76800, 41200}, "/boot": {1952, 1850}, "/boot/efi": {104, 6}, "/srv/photos": {512000, 300000},
		}},
		Run:  fakes.FixtureRunner(fx, collect.DpkgPatterns),
		Arch: "amd64",
	}
	c := &report.Collector{
		Env:          env,
		Docker:       fakes.DockerClient(docker),
		Registry:     rc,
		AptMeta:      discover.AptMeta{Cache: cache, Base: repo.URL, Env: env},
		Cache:        cache,
		AgentVersion: "test",
		Now:          func() time.Time { return time.Date(2026, 11, 8, 3, 0, 0, 0, time.UTC) },
	}
	return c, func() { docker.Close(); repo.Close(); reg.Srv.Close() }
}

func TestCollectUbuntuEndToEnd(t *testing.T) {
	c, done := ubuntuCollector(t)
	defer done()
	r := c.Collect(context.Background())

	if len(r.Errors) != 0 {
		t.Errorf("errors: %v", r.Errors)
	}
	if r.ProtocolVersion != protocol.Version || r.AgentVersion != "test" || r.System.OSID != "ubuntu" {
		t.Errorf("header: %+v", r)
	}
	if r.Docker.LatestPatch != "28.3.3" || r.Docker.LatestVersion != "29.1.2" || r.Docker.EngineEOL {
		t.Errorf("docker: %+v", r.Docker)
	}

	got := map[string]protocol.Decision{}
	for _, it := range r.Items {
		got[string(it.Layer)+" "+it.Subject+" "+it.To] = it.Decision
		if it.Layer == protocol.LayerImage && strings.Count(it.Subject, "/") != 1 {
			t.Errorf("image subject must be project/service: %q", it.Subject)
		}
	}
	want := map[string]protocol.Decision{
		"os libssl3t64 3.0.13-0ubuntu3.5":     protocol.Auto,
		"os mysql-server-8.0 ":                protocol.Never,
		"kernel kernel 6.8.0-50-generic":      protocol.Auto,
		"docker docker-ce 28.3.3":             protocol.Auto,
		"docker docker-ce 29.1.2":             protocol.Flagged,
		"docker containerd.io 1.7.24-1":       protocol.Auto,
		"docker docker-compose-plugin 2.31.0": protocol.Auto,
		"image immich/immich-server v1.120.2": protocol.Flagged, // minor, writes data on the host
		"image immich/immich-server v2.0.1":   protocol.Flagged,
		"image immich/database ":              protocol.Never,
		"image immich/redis 7.4-alpine":       protocol.Flagged,
		"image proxy/traefik v2.11.14":        protocol.Auto,
		"image proxy/traefik v3.2.1":          protocol.Flagged,
		"image proxy/whoami ":                 protocol.Never,
		"image jobs/backup 1.4.3":             protocol.Flagged,
	}
	for k, d := range want {
		if got[k] != d {
			t.Errorf("%s: got %q want %q", k, got[k], d)
		}
	}
	// redis 6.2-alpine moved to a new digest: one auto item with a digest "To".
	foundRedisDigest := false
	for _, it := range r.Items {
		if it.Subject == "immich/redis" && it.Decision == protocol.Auto && strings.HasPrefix(it.To, "6.2-alpine@eeee") {
			foundRedisDigest = true
		}
		// portainer's digest didn't move: no item.
		if it.Subject == "(standalone)/portainer" {
			t.Errorf("unexpected portainer item %+v", it)
		}
	}
	if !foundRedisDigest {
		t.Errorf("redis new digest missing:\n%+v", r.Items)
	}
	if r.Packages.SecurityUpdates != 10 || r.Packages.OtherUpdates != 5 {
		t.Errorf("packages %+v", r.Packages)
	}

	risks := map[string]bool{}
	for _, rk := range r.Risks {
		risks[rk.Code+" "+rk.Subject] = true
	}
	for _, k := range []string{
		"reboot_pending kernel", "failed_units certbot.service, nginx.service", "disk_low /boot",
		"unattended_upgrades_conflict unattended-upgrades", "no_restart_policy (standalone)/portainer",
		"no_restart_policy jobs/backup", "floating_tag (standalone)/portainer",
	} {
		if !risks[k] {
			t.Errorf("missing risk %q in %+v", k, r.Risks)
		}
	}

	// The ports were probed (nothing listens in the test, so closed).
	for _, p := range r.Projects {
		for _, s := range p.Services {
			for _, port := range s.Ports {
				if port.TCPOpen && port.HostPort < 1024 {
					t.Logf("note: %d open on this machine", port.HostPort)
				}
			}
		}
	}

	// Round trip through JSON as the cloud will read it.
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back protocol.Report
	if err := json.Unmarshal(b, &back); err != nil || len(back.Items) != len(r.Items) {
		t.Errorf("round trip: %v", err)
	}
}

func TestCollectSendsToCloud(t *testing.T) {
	c, done := ubuntuCollector(t)
	defer done()
	cloud := fakes.NewCloud()
	defer cloud.Srv.Close()
	cl := &cloudclient.Client{Base: cloud.Srv.URL}
	resp, err := cl.Enroll(context.Background(), protocol.EnrollRequest{EnrollToken: cloud.EnrollToken, Hostname: "web-1"})
	if err != nil {
		t.Fatal(err)
	}
	cl.Token = resp.AgentToken
	if _, err := cl.Report(context.Background(), c.Collect(context.Background())); err != nil {
		t.Fatal(err)
	}
	if cloud.ReportCount() != 1 || len(cloud.Reports[0].Items) == 0 {
		t.Errorf("cloud got %+v", cloud.Reports)
	}
}

func TestCollectOfflineAndBrokenNeverFails(t *testing.T) {
	// Nil FS makes the system collector panic; the report still comes back.
	c := &report.Collector{
		Env:          collect.Env{Run: &host.FakeRunner{}},
		AgentVersion: "test",
		Offline:      true,
	}
	r := c.Collect(context.Background())
	if r.ProtocolVersion != protocol.Version || r.Items == nil || r.Risks == nil || r.Projects == nil {
		t.Errorf("report shape: %+v", r)
	}
	crashed := false
	for _, e := range r.Errors {
		if strings.Contains(e, "collector crashed") {
			crashed = true
		}
	}
	if !crashed {
		t.Errorf("errors: %v", r.Errors)
	}
}

func TestCollectRegistriesOffline(t *testing.T) {
	c, done := ubuntuCollector(t)
	defer done()
	rc := registry.New(nil, "t")
	rc.Endpoint = func(string) string { return "http://127.0.0.1:1" }
	c.Registry = rc
	r := c.Collect(context.Background())
	var regErrs []string
	for _, e := range r.Errors {
		if strings.HasPrefix(e, "registry ") {
			regErrs = append(regErrs, e)
		}
	}
	// docker.io and ghcr.io, one line each, however many images use them.
	if len(regErrs) != 2 {
		t.Errorf("registry errors: %v", r.Errors)
	}
}
