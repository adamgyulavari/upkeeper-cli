package classify

import (
	"strings"
	"testing"

	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/discover"
	"github.com/adamgyulavari/upkeeper-cli/agent/registry"
	"github.com/adamgyulavari/upkeeper-cli/agent/versions"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

var ubuntu = protocol.System{OSID: "ubuntu", OSVersion: "26.04", OSCodename: "resolute", Supported: true, KernelRunning: "6.8.0-49-generic"}

func base() Input {
	return Input{
		System:      ubuntu,
		Packages:    protocol.Packages{Held: []string{}},
		DockerFacts: collect.DockerFacts{Services: map[string]collect.ServiceFacts{}, EnginePackage: "docker-ce", ComposePackage: "docker-compose-plugin"},
	}
}

func withDocker(in Input, engine, patch, latest string) Input {
	in.Docker = protocol.Docker{Installed: true, Family: "docker-ce", EngineVersion: engine, ComposeVersion: "2.29.1", LatestPatch: patch, LatestVersion: latest}
	return in
}

// withService adds project p, service s with the image and its update.
func withService(in Input, image string, mounts []string, policy string, ups ...discover.ImageUpdate) Input {
	ref, err := registry.ParseRef(image)
	s := protocol.Service{Name: "s", Image: image, HostPathMounts: mounts, RestartPolicy: "unless-stopped",
		Pinned: ref.Digest != "" || policy == "pin"}
	in.Projects = append(in.Projects, protocol.Project{Name: "p", Services: []protocol.Service{s}})
	in.DockerFacts.Services["p/s"] = collect.ServiceFacts{Ref: ref, RefErr: err, Policy: policy}
	for _, u := range ups {
		u.Project, u.Service = "p", "s"
		in.Images = append(in.Images, u)
	}
	return in
}

// apt builds a simulation; packages without origins come from the
// distribution's own archive (Ubuntu resolute, or Debian stable).
func apt(pkgs ...collect.AptUpgrade) collect.AptSim {
	for i := range pkgs {
		if pkgs[i].Origins == nil {
			suite := "Ubuntu:26.04/resolute-updates"
			if pkgs[i].Security {
				suite = "Ubuntu:26.04/resolute-security"
			}
			if strings.HasSuffix(pkgs[i].Package, "-amd64") || strings.Contains(pkgs[i].To, "deb") {
				suite = "Debian:13/stable"
			}
			pkgs[i].Origins = []string{suite}
		}
	}
	return collect.AptSim{Upgrades: pkgs}
}

type want struct {
	layer    protocol.Layer
	subject  string
	to       string // optional
	decision protocol.Decision
	reason   string // substring
	security bool
}

// TestScopeRows covers every row of docs/mvp-scope.md §5.
func TestScopeRows(t *testing.T) {
	tests := []struct {
		row  string
		in   func() Input
		want []want
	}{
		{
			row: "OS security update → auto",
			in: func() Input {
				in := base()
				in.Apt = apt(collect.AptUpgrade{Package: "openssl", From: "3.0.13-0ubuntu3.4", To: "3.0.13-0ubuntu3.5", Security: true})
				return in
			},
			want: []want{{protocol.LayerOS, "openssl", "3.0.13-0ubuntu3.5", protocol.Auto, "Security update within Ubuntu 26.04", true}},
		},
		{
			row: "regular update within the same release → auto",
			in: func() Input {
				in := base()
				in.Apt = apt(collect.AptUpgrade{Package: "tzdata", From: "2024a-3ubuntu1.1", To: "2024b-0ubuntu0.24.04"})
				return in
			},
			want: []want{{protocol.LayerOS, "tzdata", "", protocol.Auto, "Regular update", false}},
		},
		{
			row: "kernel install + reboot → auto with L3",
			in: func() Input {
				in := base()
				in.Apt = apt(
					collect.AptUpgrade{Package: "linux-image-6.8.0-50-generic", To: "6.8.0-50.51", Security: true},
					collect.AptUpgrade{Package: "linux-modules-6.8.0-50-generic", To: "6.8.0-50.51", Security: true},
					collect.AptUpgrade{Package: "linux-image-generic", From: "6.8.0-49.49", To: "6.8.0-50.50", Security: true},
				)
				return in
			},
			want: []want{{protocol.LayerKernel, "kernel", "6.8.0-50-generic", protocol.Auto, "used from the next reboot", true}},
		},
		{
			row: "kernel reboot set to supervised per server → flagged",
			in: func() Input {
				in := base()
				in.Settings.SupervisedReboots = true
				in.Apt = apt(collect.AptUpgrade{Package: "linux-image-6.8.0-50-generic", To: "6.8.0-50.51"})
				return in
			},
			want: []want{{protocol.LayerKernel, "kernel", "", protocol.Flagged, "supervised run", false}},
		},
		{
			row:  "Docker Engine patch release → auto with L2",
			in:   func() Input { return withDocker(base(), "28.3.1", "28.3.2", "28.3.2") },
			want: []want{{protocol.LayerDocker, "docker-ce", "28.3.2", protocol.Auto, "doesn't update Docker Engine yet", false}},
		},
		{
			row:  "Docker Engine minor → flagged",
			in:   func() Input { return withDocker(base(), "28.3.1", "", "28.5.2") },
			want: []want{{protocol.LayerDocker, "docker-ce", "28.5.2", protocol.Flagged, "minor upgrade", false}},
		},
		{
			row: "Docker Engine major (28 → 29) → flagged; patch still auto",
			in:  func() Input { return withDocker(base(), "28.3.1", "28.3.3", "29.1.2") },
			want: []want{
				{protocol.LayerDocker, "docker-ce", "29.1.2", protocol.Flagged, "major upgrade", false},
				{protocol.LayerDocker, "docker-ce", "28.3.3", protocol.Auto, "Patch release within Docker 28.3", false},
			},
		},
		{
			row: "Compose plugin major → flagged",
			in: func() Input {
				in := withDocker(base(), "29.1.2", "", "")
				in.DockerVers.ComposeLatest = "5.0.1"
				return in
			},
			want: []want{{protocol.LayerDocker, "docker-compose-plugin", "5.0.1", protocol.Flagged, "Compose 2 → 5 is a major upgrade", false}},
		},
		{
			row: "Compose plugin minor → auto",
			in: func() Input {
				in := withDocker(base(), "29.1.2", "", "")
				in.DockerVers.ComposeLatest = "2.31.0"
				return in
			},
			want: []want{{protocol.LayerDocker, "docker-compose-plugin", "2.31.0", protocol.Auto, "Minor update within Compose 2", false}},
		},
		{
			row: "image patch/minor → auto with L1",
			in: func() Input {
				return withService(base(), "traefik:v2.11.2", nil, "",
					discover.ImageUpdate{FromTag: "v2.11.2", ToTag: "v2.11.14", Change: versions.Patch})
			},
			want: []want{{protocol.LayerImage, "p/s", "v2.11.14", protocol.Auto, "previous image is put back", false}},
		},
		{
			row: "new digest on the same floating tag → auto with L1",
			in: func() Input {
				return withService(base(), "portainer/portainer-ce:latest", nil, "",
					discover.ImageUpdate{FromTag: "latest", ToTag: "latest", NewDigest: true, FromDigest: "sha256:aaaaaaaaaaaaaaaa", ToDigest: "sha256:bbbbbbbbbbbbbbbb"})
			},
			want: []want{{protocol.LayerImage, "p/s", "latest@bbbbbbbbbbbb", protocol.Auto, "same tag (latest)", false}},
		},
		{
			row: "image major version → flagged",
			in: func() Input {
				return withService(base(), "traefik:v2.11.2", nil, "",
					discover.ImageUpdate{FromTag: "v2.11.2", ToTag: "v3.2.1", Change: versions.Major})
			},
			want: []want{{protocol.LayerImage, "p/s", "v3.2.1", protocol.Flagged, "major version", false}},
		},
		{
			row: "image 0.x minor counts as major → flagged",
			in: func() Input {
				return withService(base(), "ghcr.io/x/y:0.105.1", nil, "",
					discover.ImageUpdate{FromTag: "0.105.1", ToTag: "0.106.0", Change: versions.Major})
			},
			want: []want{{protocol.LayerImage, "p/s", "0.106.0", protocol.Flagged, "Below version 1.0", false}},
		},
		{
			row: "release notes mark breaking → flagged (even a patch)",
			in: func() Input {
				in := withService(base(), "traefik:v2.11.2", nil, "",
					discover.ImageUpdate{FromTag: "v2.11.2", ToTag: "v2.11.14", Change: versions.Patch})
				in.Notes = map[string]ReleaseNote{NoteKey(protocol.LayerImage, "p/s", "v2.11.14"): {Breaking: true}}
				return in
			},
			want: []want{{protocol.LayerImage, "p/s", "v2.11.14", protocol.Flagged, "breaking changes", false}},
		},
		{
			row: "release notes ask for manual steps → flagged (Docker patch)",
			in: func() Input {
				in := withDocker(base(), "28.3.1", "28.3.2", "28.3.2")
				in.Notes = map[string]ReleaseNote{NoteKey(protocol.LayerDocker, "docker-ce", "28.3.2"): {ManualSteps: true}}
				return in
			},
			want: []want{{protocol.LayerDocker, "docker-ce", "28.3.2", protocol.Flagged, "manual steps", false}},
		},
		{
			row: "release notes mention a DB/storage migration → flagged",
			in: func() Input {
				in := withService(base(), "ghcr.io/immich-app/immich-server:v1.119.0", nil, "",
					discover.ImageUpdate{FromTag: "v1.119.0", ToTag: "v1.120.0", Change: versions.Minor})
				in.Notes = map[string]ReleaseNote{NoteKey(protocol.LayerImage, "p/s", "v1.120.0"): {Migration: true}}
				return in
			},
			want: []want{{protocol.LayerImage, "p/s", "v1.120.0", protocol.Flagged, "migration, which can't be undone", false}},
		},
		{
			row: "data on a host path and the new version mentions migrations → flagged (L1 can't undo)",
			in: func() Input {
				in := withService(base(), "ghcr.io/immich-app/immich-server:v1.119.0", []string{"/srv/photos/library"}, "",
					discover.ImageUpdate{FromTag: "v1.119.0", ToTag: "v1.120.0", Change: versions.Minor})
				in.Notes = map[string]ReleaseNote{NoteKey(protocol.LayerImage, "p/s", "v1.120.0"): {Migration: true}}
				return in
			},
			want: []want{{protocol.LayerImage, "p/s", "v1.120.0", protocol.Flagged, "keeps data on the host (/srv/photos/library)", false}},
		},
		{
			row: "pinned digest → never",
			in: func() Input {
				return withService(base(), "tensorchord/pgvecto-rs:pg14-v0.2.0@sha256:90724186f0a3517cf6914295b5ab410db9ce23190a2d9d0b9dd6463e3fa298f0", nil, "")
			},
			want: []want{{protocol.LayerImage, "p/s", "", protocol.Never, "Pinned to a digest", false}},
		},
		{
			row: "label upkeeper.policy=pin → never, even with an update found",
			in: func() Input {
				return withService(base(), "traefik/whoami:v1.10", nil, "pin",
					discover.ImageUpdate{FromTag: "v1.10", ToTag: "v1.11", Change: versions.Minor})
			},
			want: []want{{protocol.LayerImage, "p/s", "", protocol.Never, "upkeeper.policy=pin", false}},
		},
		{
			row: "label upkeeper.policy=supervised → flagged",
			in: func() Input {
				return withService(base(), "ghcr.io/example/backup:1.4.2", nil, "supervised",
					discover.ImageUpdate{FromTag: "1.4.2", ToTag: "1.4.3", Change: versions.Patch})
			},
			want: []want{{protocol.LayerImage, "p/s", "1.4.3", protocol.Flagged, "upkeeper.policy=supervised", false}},
		},
		{
			row: "package held with apt-mark hold → never",
			in: func() Input {
				in := base()
				in.Packages.Held = []string{"mysql-server-8.0"}
				return in
			},
			want: []want{{protocol.LayerOS, "mysql-server-8.0", "", protocol.Never, "apt-mark unhold mysql-server-8.0", false}},
		},
		{
			row: "held kernel → never",
			in: func() Input {
				in := base()
				in.Packages.Held = []string{"linux-image-generic"}
				return in
			},
			want: []want{{protocol.LayerKernel, "kernel", "", protocol.Never, "held with apt-mark hold (linux-image-generic)", false}},
		},
		{
			row: "held Docker → never",
			in: func() Input {
				in := withDocker(base(), "28.3.1", "28.3.2", "29.1.2")
				in.Packages.Held = []string{"docker-ce", "docker-ce-cli"}
				return in
			},
			want: []want{
				{protocol.LayerDocker, "docker-ce", "28.3.2", protocol.Never, "held with apt-mark hold", false},
				{protocol.LayerDocker, "docker-ce", "29.1.2", protocol.Never, "held with apt-mark hold", false},
			},
		},
		{
			row: "kernel on a DKMS/ZFS host → never (reported)",
			in: func() Input {
				in := base()
				in.SystemFacts.DKMSModules = []string{"zfs"}
				in.SystemFacts.ZFS = true
				in.Apt = apt(collect.AptUpgrade{Package: "linux-image-6.1.0-28-amd64", To: "6.1.119-1", Security: true})
				return in
			},
			want: []want{{protocol.LayerKernel, "kernel", "6.1.0-28-amd64", protocol.Never, "DKMS (zfs)", true}},
		},
		{
			row: "distro release upgrade → report only",
			in: func() Input {
				in := base()
				in.System.OSVersion = "22.04"
				return in
			},
			want: []want{{protocol.LayerOS, "release upgrade", "26.04", protocol.Never, "doesn't do release upgrades", false}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.row, func(t *testing.T) {
			items := Items(tt.in())
			if len(items) != len(tt.want) {
				t.Fatalf("got %d items, want %d:\n%s", len(items), len(tt.want), dump(items))
			}
			for i, w := range tt.want {
				it := items[i]
				if it.Layer != w.layer || it.Subject != w.subject || it.Decision != w.decision || it.Security != w.security ||
					(w.to != "" && it.To != w.to) || !strings.Contains(it.Reason, w.reason) {
					t.Errorf("item %d\n got %+v\nwant %+v", i, it, w)
				}
			}
			checkVoice(t, items)
		})
	}
}

func TestDebianSameABIKernelAndDockerAptRebuild(t *testing.T) {
	in := base()
	in.System = protocol.System{OSID: "debian", OSVersion: "13", KernelRunning: "6.12.0-1-amd64"}
	in.Apt = apt(
		collect.AptUpgrade{Package: "linux-image-6.12.0-1-amd64", From: "6.12.6-1", To: "6.12.9-1", Security: true},
		collect.AptUpgrade{Package: "docker.io", From: "26.1.5+dfsg1-9", To: "26.1.5+dfsg1-9+deb13u1", Security: true},
		collect.AptUpgrade{Package: "containerd", From: "1.7.24~ds1-6", To: "1.7.24~ds1-6+deb13u1"},
	)
	in.Docker = protocol.Docker{Installed: true, Family: "docker.io", EngineVersion: "26.1.5"}
	in.DockerFacts.EnginePackage = "docker.io"
	items := Items(in)
	if len(items) != 3 {
		t.Fatalf("%s", dump(items))
	}
	if items[0].Subject != "kernel" || items[0].To != "6.12.0-1-amd64 (6.12.9-1)" || items[0].Decision != protocol.Auto {
		t.Errorf("kernel: %+v", items[0])
	}
	if items[2].Subject != "containerd" || items[2].Decision != protocol.Auto {
		t.Errorf("containerd: %+v", items[2])
	}
	if items[1].Subject != "docker.io" || items[1].Decision != protocol.Auto || !items[1].Security || !strings.Contains(items[1].Reason, "same Docker version") {
		t.Errorf("docker.io rebuild: %+v", items[1])
	}
	checkVoice(t, items)
}

func TestOrdering(t *testing.T) {
	in := withDocker(base(), "28.3.1", "28.3.3", "29.1.2")
	in.Apt = apt(
		collect.AptUpgrade{Package: "zlib1g", From: "1", To: "2"},
		collect.AptUpgrade{Package: "openssl", From: "1", To: "2", Security: true},
		collect.AptUpgrade{Package: "docker-ce", From: "5:28.3.1-1", To: "5:28.3.3-1"}, // folded into the engine item
	)
	items := Items(in)
	var got []string
	for _, it := range items {
		got = append(got, string(it.Layer)+":"+it.Subject+":"+string(it.Decision))
	}
	want := "os:openssl:auto os:zlib1g:auto docker:docker-ce:flagged docker:docker-ce:auto"
	if strings.Join(got, " ") != want {
		t.Errorf("order:\n got %s\nwant %s", strings.Join(got, " "), want)
	}
}

func TestRisks(t *testing.T) {
	in := base()
	in.System = protocol.System{
		OSID: "ubuntu", OSVersion: "20.04", Supported: false,
		KernelRunning: "5.4.0-200-generic", KernelInstalled: "5.4.0-202-generic", RebootRequired: true,
		FailedUnits:        []string{"certbot.service"},
		UnattendedUpgrades: true,
		Disks: []protocol.Disk{
			{Mount: "/", SizeMB: 20000, UsedMB: 19700},     // 300 MB free → problem
			{Mount: "/boot", SizeMB: 1952, UsedMB: 1800},   // 152 MB → warning
			{Mount: "/boot/efi", SizeMB: 100, UsedMB: 99},  // ignored
			{Mount: "/srv", SizeMB: 100000, UsedMB: 92000}, // 8 % → warning
			{Mount: "/opt/tiny", SizeMB: 48, UsedMB: 31},   // small but 35 % free → fine
		},
	}
	in.Docker = protocol.Docker{Installed: true, Family: "docker.io", EngineVersion: "20.10.24", ComposeV1: true, EngineEOL: true}
	in.DockerVers.UpstreamLatest = "29.1.2"
	in = withService(in, "portainer/portainer-ce:latest", nil, "")
	in.Projects[0].Services[0].RestartPolicy = "no"

	risks := Risks(in)
	got := map[string]protocol.Risk{}
	for _, r := range risks {
		got[r.Code+" "+r.Subject] = r
	}
	wantRisks := map[string]protocol.Severity{
		"os_unsupported Ubuntu 20.04":  protocol.Problem,
		"reboot_pending kernel":        protocol.Warning,
		"failed_units certbot.service": protocol.Warning,
		"disk_low /":                   protocol.Problem,
		"disk_low /boot":               protocol.Warning,
		"disk_low /srv":                protocol.Warning,
		"unattended_upgrades_conflict unattended-upgrades": protocol.Info,
		"compose_v1 docker-compose":                        protocol.Problem,
		"docker_eol docker.io":                             protocol.Problem,
		"no_restart_policy p/s":                            protocol.Warning,
		"floating_tag p/s":                                 protocol.Info,
	}
	for k, sev := range wantRisks {
		r, ok := got[k]
		if !ok {
			t.Errorf("missing risk %q", k)
			continue
		}
		if r.Severity != sev {
			t.Errorf("%s: severity %s want %s", k, r.Severity, sev)
		}
	}
	if len(risks) != len(wantRisks) {
		t.Errorf("got %d risks, want %d: %+v", len(risks), len(wantRisks), risks)
	}
	if !strings.Contains(got["docker_eol docker.io"].Message, "newest is 29.1.2") ||
		!strings.Contains(got["reboot_pending kernel"].Message, "5.4.0-202-generic is installed") {
		t.Errorf("messages: %+v", risks)
	}
	if risks[0].Severity != protocol.Problem || risks[len(risks)-1].Severity != protocol.Info {
		t.Errorf("risks not sorted by severity")
	}
	for _, r := range risks {
		if r.Message == "" || strings.Contains(r.Message, "!") {
			t.Errorf("voice: %q", r.Message)
		}
	}

	// u-u allowed to upgrade Docker: a problem, not just a note.
	in.SystemFacts.UUDockerOrigin = true
	for _, r := range Risks(in) {
		if r.Code == RiskUUConflict && r.Severity != protocol.Problem {
			t.Errorf("uu docker origin should be a problem: %+v", r)
		}
	}
	// A healthy, supported server has no risks.
	clean := base()
	clean.System.Disks = []protocol.Disk{{Mount: "/", SizeMB: 80000, UsedMB: 20000}}
	if rs := Risks(clean); len(rs) != 0 {
		t.Errorf("clean server risks: %+v", rs)
	}
}

// checkVoice applies docs/positioning.md: plain, calm, no exclamation marks,
// no claims we can't make.
func checkVoice(t *testing.T, items []protocol.Item) {
	t.Helper()
	banned := []string{"!", "full rollback", "zero downtime", "never breaks", "AI-powered", "guarantee"}
	for _, it := range items {
		if it.Reason == "" {
			t.Errorf("%s: empty reason", it.Subject)
		}
		for _, b := range banned {
			if strings.Contains(strings.ToLower(it.Reason), strings.ToLower(b)) {
				t.Errorf("%s: reason contains %q: %s", it.Subject, b, it.Reason)
			}
		}
		if !strings.HasSuffix(it.Reason, ".") {
			t.Errorf("%s: reason should be a full sentence: %s", it.Subject, it.Reason)
		}
	}
}

func dump(items []protocol.Item) string {
	var b strings.Builder
	for _, it := range items {
		b.WriteString("  " + string(it.Layer) + " " + it.Subject + " " + it.From + "→" + it.To + " " + string(it.Decision) + ": " + it.Reason + "\n")
	}
	return b.String()
}
