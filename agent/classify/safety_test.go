package classify

import (
	"strings"
	"testing"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/discover"
	"github.com/adamgyulavari/upkeeper-cli/agent/versions"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

func TestDistroOrigin(t *testing.T) {
	noble := protocol.System{OSID: "ubuntu", OSCodename: "noble"}
	bookworm := protocol.System{OSID: "debian", OSCodename: "bookworm"}
	for _, tt := range []struct {
		sys    protocol.System
		origin string
		ok     bool
	}{
		{noble, "Ubuntu:24.04/noble-security", true},
		{noble, "Ubuntu:24.04/noble-updates", true},
		{noble, "Ubuntu:24.04/noble", true},
		{noble, "Ubuntu:24.04/noble-proposed", false},
		{noble, "Ubuntu:24.04/noble-backports", false},
		{noble, "LP-PPA-ondrej-php:24.04/noble", false},
		{noble, "Docker CE:noble/noble", false},
		{noble, "Debian:12.8/stable", false},
		{noble, "Ubuntu:22.04/jammy-updates", false},
		{bookworm, "Debian:12.8/stable", true},
		{bookworm, "Debian-Security:12/stable-security", true},
		{bookworm, "Debian:12/bookworm-updates", true},
		{bookworm, "nodesource:nodistro/nodistro", false},
		{bookworm, "garbage", false},
	} {
		if got := DistroOrigin(tt.sys, tt.origin); got != tt.ok {
			t.Errorf("%s %s: %v, want %v", tt.sys.OSCodename, tt.origin, got, tt.ok)
		}
	}
}

func TestThirdPartyAptIsFlagged(t *testing.T) {
	in := base()
	in.Apt = apt(
		collect.AptUpgrade{Package: "nodejs", From: "20.18.0-1nodesource1", To: "20.18.1-1nodesource1", Origins: []string{"nodesource:nodistro/nodistro"}},
		collect.AptUpgrade{Package: "php8.3", From: "8.3.12-1", To: "8.3.13-1", Origins: []string{"LP-PPA-ondrej-php:26.04/resolute"}},
		collect.AptUpgrade{Package: "curl", From: "8.5.0-2ubuntu10.4", To: "8.5.0-2ubuntu10.5", Security: true},
		collect.AptUpgrade{Package: "linux-image-6.8.0-50-generic", To: "6.8.0-50.51", Origins: []string{"Other:x/y"}},
	)
	items := Items(in)
	got := map[string]protocol.Item{}
	for _, it := range items {
		got[it.Subject] = it
	}
	for _, s := range []string{"nodejs", "php8.3", "kernel"} {
		if got[s].Decision != protocol.Flagged || !strings.Contains(got[s].Reason, "package source outside Ubuntu") {
			t.Errorf("%s: %+v", s, got[s])
		}
	}
	if got["curl"].Decision != protocol.Auto {
		t.Errorf("distro security update: %+v", got["curl"])
	}
	checkVoice(t, items)
}

func TestStatefulImages(t *testing.T) {
	tests := []struct {
		name   string
		image  string
		mounts []string
		up     discover.ImageUpdate
		want   protocol.Decision
		reason string
	}{
		{"postgres minor", "postgres:16.4", nil, discover.ImageUpdate{FromTag: "16.4", ToTag: "16.6", Change: versions.Minor}, protocol.Flagged, "keeps data (postgres)"},
		{"redis minor", "redis:7.2.5", nil, discover.ImageUpdate{FromTag: "7.2.5", ToTag: "7.4.1", Change: versions.Minor}, protocol.Flagged, "minor release of a service that keeps data"},
		{"redis patch", "redis:7.2.5", nil, discover.ImageUpdate{FromTag: "7.2.5", ToTag: "7.2.6", Change: versions.Patch}, protocol.Auto, ""},
		{"valkey latest digest", "valkey/valkey:latest", nil, discover.ImageUpdate{FromTag: "latest", ToTag: "latest", NewDigest: true, FromDigest: "sha256:aaaa", ToDigest: "sha256:bbbb"}, protocol.Flagged, "Pin a version tag"},
		{"redis 7.4 digest", "redis:7.4", nil, discover.ImageUpdate{FromTag: "7.4", ToTag: "7.4", NewDigest: true, FromDigest: "sha256:aaaa", ToDigest: "sha256:bbbb"}, protocol.Auto, ""},
		{"postgres 16 digest", "postgres:16", nil, discover.ImageUpdate{FromTag: "16", ToTag: "16", NewDigest: true, FromDigest: "sha256:aaaa", ToDigest: "sha256:bbbb"}, protocol.Auto, ""},
		{"app with db data path", "example/app:1.2.0", []string{"/var/lib/mysql"}, discover.ImageUpdate{FromTag: "1.2.0", ToTag: "1.3.0", Change: versions.Minor}, protocol.Flagged, "data in /var/lib/mysql"},
		{"plain app minor", "example/app:1.2.0", []string{"/config"}, discover.ImageUpdate{FromTag: "1.2.0", ToTag: "1.3.0", Change: versions.Minor}, protocol.Auto, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := withService(base(), tt.image, nil, "", tt.up)
			f := in.DockerFacts.Services["p/s"]
			f.MountDests = tt.mounts
			in.DockerFacts.Services["p/s"] = f
			items := Items(in)
			if len(items) != 1 || items[0].Decision != tt.want || !strings.Contains(items[0].Reason, tt.reason) {
				t.Fatalf("%s", dump(items))
			}
			checkVoice(t, items)
		})
	}
}

func TestImageSetComposeLabels(t *testing.T) {
	in := withService(base(), "evil/tool:1.0.0", nil, "", discover.ImageUpdate{FromTag: "1.0.0", ToTag: "1.0.1", Change: versions.Patch})
	f := in.DockerFacts.Services["p/s"]
	f.ImageComposeLabels = []string{"com.docker.compose.project.working_dir"}
	in.DockerFacts.Services["p/s"] = f
	items := Items(in)
	if items[0].Decision != protocol.Flagged || !strings.Contains(items[0].Reason, "sets Docker Compose labels itself") {
		t.Fatalf("%s", dump(items))
	}
	risks := Risks(in)
	found := false
	for _, r := range risks {
		if r.Code == "image_compose_labels" {
			found = true
		}
	}
	if !found {
		t.Errorf("no image_compose_labels risk: %+v", risks)
	}
}

func TestMinReleaseAge(t *testing.T) {
	now := time.Date(2026, 11, 10, 3, 0, 0, 0, time.UTC)
	s := Settings{MinReleaseAge: DefaultMinReleaseAge, Now: func() time.Time { return now }}
	in := withService(base(), "traefik:v2.11.2", nil, "", discover.ImageUpdate{FromTag: "v2.11.2", ToTag: "v2.11.14", Change: versions.Patch, FirstSeen: now.Add(-30 * time.Hour)})
	in.Settings = s
	items := Items(in)
	if items[0].Decision != protocol.Auto || items[0].Reason != "Released 1 day ago; waits until it's 3 days old, so a bad release has time to be noticed and pulled." {
		t.Fatalf("%s", dump(items))
	}
	u := in.Images[0]
	if young, _ := s.TooNew(u); !young {
		t.Error("30 h old should be too new")
	}
	u.FirstSeen = now.Add(-73 * time.Hour)
	if young, _ := s.TooNew(u); young {
		t.Error("73 h old is old enough")
	}
	u.FirstSeen = time.Time{}
	if young, _ := s.TooNew(u); !young {
		t.Error("unknown first-seen counts as new")
	}
	checkVoice(t, items)
}
