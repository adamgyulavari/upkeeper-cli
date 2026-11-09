package collect_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/dockerapi"
	"github.com/adamgyulavari/upkeeper-cli/agent/fakes"
	"github.com/adamgyulavari/upkeeper-cli/agent/host"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

type fixture struct {
	dir   string
	disks map[string][2]uint64
}

var fixtures = map[string]fixture{
	"ubuntu2404": {dir: "testdata/ubuntu2404", disks: map[string][2]uint64{
		"/": {76800, 41200}, "/boot": {1952, 1850}, "/boot/efi": {104, 6}, "/srv/photos": {512000, 300000},
	}},
	"debian12": {dir: "testdata/debian12", disks: map[string][2]uint64{
		"/": {19456, 18900}, "/boot/efi": {124, 12}, "/tank": {3800000, 1200000}, "/var/lib/docker": {102400, 20000},
	}},
}

func env(t *testing.T, name string) (collect.Env, *host.FakeRunner) {
	t.Helper()
	fx := fixtures[name]
	r := fakes.FixtureRunner(fx.dir, collect.DpkgPatterns)
	return collect.Env{FS: fakes.FS{RootFS: host.RootFS{Root: fx.dir}, Disks: fx.disks}, Run: r, Arch: "amd64"}, r
}

func dpkg(t *testing.T, e collect.Env) map[string]collect.DpkgPkg {
	t.Helper()
	p, err := collect.QueryDpkg(context.Background(), e, collect.DpkgPatterns...)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSystem(t *testing.T) {
	tests := []struct {
		name string
		want protocol.System
		dkms []string
		zfs  bool
	}{
		{
			name: "ubuntu2404",
			want: protocol.System{
				OSID: "ubuntu", OSVersion: "24.04", OSCodename: "noble", Supported: true, Arch: "amd64",
				KernelRunning: "6.8.0-49-generic", KernelInstalled: "6.8.0-49-generic", RebootRequired: true,
				UptimeSeconds: 1209876, MemTotalMB: 7940,
				Disks: []protocol.Disk{
					{Mount: "/", SizeMB: 76800, UsedMB: 41200},
					{Mount: "/boot", SizeMB: 1952, UsedMB: 1850},
					{Mount: "/boot/efi", SizeMB: 104, UsedMB: 6},
					{Mount: "/srv/photos", SizeMB: 512000, UsedMB: 300000},
				},
				FailedUnits:        []string{"certbot.service", "nginx.service"},
				UnattendedUpgrades: true,
			},
		},
		{
			name: "debian12",
			want: protocol.System{
				OSID: "debian", OSVersion: "12", OSCodename: "bookworm", Supported: true, Arch: "amd64",
				KernelRunning: "6.1.0-27-amd64", KernelInstalled: "6.1.0-27-amd64", RebootRequired: false,
				UptimeSeconds: 86400, MemTotalMB: 1967,
				Disks: []protocol.Disk{
					{Mount: "/", SizeMB: 19456, UsedMB: 18900},
					{Mount: "/boot/efi", SizeMB: 124, UsedMB: 12},
					{Mount: "/tank", SizeMB: 3800000, UsedMB: 1200000},
					{Mount: "/var/lib/docker", SizeMB: 102400, UsedMB: 20000},
				},
				FailedUnits:        []string{},
				UnattendedUpgrades: false,
			},
			dkms: []string{"zfs"},
			zfs:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, _ := env(t, tt.name)
			var errs collect.Errs
			got, facts := collect.System(context.Background(), e, dpkg(t, e), &errs)
			if len(errs) > 0 {
				t.Errorf("errors: %v", errs)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("System mismatch\n got %+v\nwant %+v", got, tt.want)
			}
			if !reflect.DeepEqual(facts.DKMSModules, tt.dkms) || facts.ZFS != tt.zfs {
				t.Errorf("dkms=%v zfs=%v, want %v %v", facts.DKMSModules, facts.ZFS, tt.dkms, tt.zfs)
			}
			if facts.MachineID == "" || facts.Hostname == "" {
				t.Errorf("machine id / hostname missing: %+v", facts)
			}
		})
	}
}

func TestSystemDebianKernelNewerThanRunning(t *testing.T) {
	// Debian has no /run/reboot-required for kernels: an installed kernel
	// newer than the running one is the signal.
	e, r := env(t, "debian12")
	k := host.Key("dpkg-query", append([]string{"-W", host.DpkgQueryFormat}, collect.DpkgPatterns...)...)
	r.Out[k] += "linux-image-6.1.0-28-amd64\t6.1.119-1\tinstalled\n"
	var errs collect.Errs
	s, _ := collect.System(context.Background(), e, dpkg(t, e), &errs)
	if s.KernelInstalled != "6.1.0-28-amd64" || !s.RebootRequired {
		t.Errorf("got installed=%q reboot=%v", s.KernelInstalled, s.RebootRequired)
	}
}

func TestSystemFallbacksAndErrors(t *testing.T) {
	// No dpkg, no systemd, no /proc: the kernel comes from /boot, and every
	// failure becomes an error line instead of a crash.
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "boot"), 0o755))
	for _, f := range []string{"vmlinuz-6.8.0-45-generic", "vmlinuz-6.8.0-100-generic", "vmlinuz-6.8.0-9-generic"} {
		must(t, os.WriteFile(filepath.Join(root, "boot", f), nil, 0o644))
	}
	e := collect.Env{FS: fakes.FS{RootFS: host.RootFS{Root: root}}, Run: &host.FakeRunner{}, Arch: "arm64"}
	var errs collect.Errs
	s, _ := collect.System(context.Background(), e, nil, &errs)
	if s.KernelInstalled != "6.8.0-100-generic" {
		t.Errorf("newest kernel from /boot = %q", s.KernelInstalled)
	}
	for _, area := range []string{"os-release", "kernel", "uptime", "memory", "disks", "systemd"} {
		found := false
		for _, e := range errs {
			if strings.HasPrefix(e, area+":") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected an error for %s, got %v", area, errs)
		}
	}
	if s.Supported || s.Arch != "arm64" {
		t.Errorf("unexpected %+v", s)
	}
}

func TestUnsupportedOS(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "etc"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=ubuntu\nVERSION_ID=\"20.04\"\nVERSION_CODENAME=focal\n"), 0o644))
	e := collect.Env{FS: fakes.FS{RootFS: host.RootFS{Root: root}}, Run: &host.FakeRunner{}}
	var errs collect.Errs
	s, _ := collect.System(context.Background(), e, nil, &errs)
	if s.Supported || s.OSVersion != "20.04" || s.OSCodename != "focal" {
		t.Errorf("got %+v", s)
	}
}

func TestUnattendedUpgradesDockerOrigin(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc/apt/apt.conf.d")
	must(t, os.MkdirAll(dir, 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "20auto-upgrades"), []byte(`APT::Periodic::Unattended-Upgrade "1";`), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "50unattended-upgrades"), []byte("Unattended-Upgrade::Allowed-Origins {\n\t\"Docker:${distro_codename}\";\n};\n"), 0o644))
	// A later file switches it off again: apt reads files in order, last wins.
	pk := map[string]collect.DpkgPkg{"unattended-upgrades": {Name: "unattended-upgrades", Version: "2.9", Status: "installed"}}
	e := collect.Env{FS: fakes.FS{RootFS: host.RootFS{Root: root}}, Run: &host.FakeRunner{}}
	var errs collect.Errs
	s, f := collect.System(context.Background(), e, pk, &errs)
	if !s.UnattendedUpgrades || !f.UUDockerOrigin {
		t.Errorf("enabled=%v docker=%v", s.UnattendedUpgrades, f.UUDockerOrigin)
	}
	must(t, os.WriteFile(filepath.Join(dir, "99disable"), []byte(`APT::Periodic::Unattended-Upgrade "0";`), 0o644))
	s, f = collect.System(context.Background(), e, pk, &errs)
	if s.UnattendedUpgrades || f.UUDockerOrigin {
		t.Errorf("after disable: enabled=%v docker=%v", s.UnattendedUpgrades, f.UUDockerOrigin)
	}
}

func TestParseAptSim(t *testing.T) {
	tests := []struct {
		file            string
		upgrades, isNew int
		security, other int
		kept            []string
		sample          collect.AptUpgrade
	}{
		{
			file: "testdata/ubuntu2404/apt-get-s-upgrade.txt", upgrades: 20, isNew: 5, security: 10, other: 5,
			kept: []string{"python3-distupgrade", "ubuntu-release-upgrader-core"},
			sample: collect.AptUpgrade{Package: "libssl3t64", From: "3.0.13-0ubuntu3.4", To: "3.0.13-0ubuntu3.5",
				Origins: []string{"Ubuntu:24.04/noble-updates", "Ubuntu:24.04/noble-security"}, Security: true},
		},
		{
			file: "testdata/debian12/apt-get-s-upgrade.txt", upgrades: 8, isNew: 1, security: 4, other: 3,
			kept: []string{"zfs-dkms", "zfsutils-linux"},
			sample: collect.AptUpgrade{Package: "libc6", From: "2.36-9+deb12u8", To: "2.36-9+deb12u9",
				Origins: []string{"Debian:12.8/stable"}},
		},
	}
	for _, tt := range tests {
		t.Run(filepath.Base(filepath.Dir(tt.file)), func(t *testing.T) {
			b, err := os.ReadFile(tt.file)
			must(t, err)
			sim := collect.ParseAptSim(b)
			if len(sim.Upgrades) != tt.upgrades {
				t.Errorf("upgrades=%d want %d", len(sim.Upgrades), tt.upgrades)
			}
			var isNew, sec, other int
			for _, u := range sim.Upgrades {
				switch {
				case u.From == "":
					isNew++
				case u.Security:
					sec++
				default:
					other++
				}
				if u.Package == tt.sample.Package && !reflect.DeepEqual(u, tt.sample) {
					t.Errorf("sample\n got %+v\nwant %+v", u, tt.sample)
				}
			}
			if isNew != tt.isNew || sec != tt.security || other != tt.other {
				t.Errorf("new=%d sec=%d other=%d", isNew, sec, other)
			}
			if !reflect.DeepEqual(sim.KeptBack, tt.kept) {
				t.Errorf("kept=%v", sim.KeptBack)
			}
		})
	}
}

func TestPackages(t *testing.T) {
	tests := []struct {
		name          string
		security      int
		other         int
		held          []string
		wantLastApt   bool
		wantErrPrefix string
	}{
		{name: "ubuntu2404", security: 10, other: 5, held: []string{"mysql-server-8.0"}, wantLastApt: true},
		{name: "debian12", security: 4, other: 3, held: []string{}, wantLastApt: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, r := env(t, tt.name)
			stamp := time.Date(2026, 10, 30, 6, 25, 0, 0, time.UTC)
			lists, _ := filepath.Glob(filepath.Join(fixtures[tt.name].dir, "var/lib/apt/lists/*"))
			for _, l := range lists {
				must(t, os.Chtimes(l, stamp, stamp))
			}
			var errs collect.Errs
			p, _ := collect.Packages(context.Background(), e, &errs)
			if len(errs) > 0 {
				t.Errorf("errors: %v", errs)
			}
			if p.SecurityUpdates != tt.security || p.OtherUpdates != tt.other || !reflect.DeepEqual(p.Held, tt.held) {
				t.Errorf("got %+v", p)
			}
			if tt.wantLastApt && (p.LastAptUpdate == nil || p.LastAptUpdate.Before(stamp)) {
				t.Errorf("last apt update = %v", p.LastAptUpdate)
			}
			for _, cmd := range r.Seen {
				if strings.HasPrefix(cmd, "apt-get") && !strings.Contains(cmd, " -s ") {
					t.Errorf("apt-get called without -s: %s", cmd)
				}
			}
		})
	}
}

func TestPackagesAptMissing(t *testing.T) {
	e := collect.Env{FS: fakes.FS{RootFS: host.RootFS{Root: t.TempDir()}}, Run: &host.FakeRunner{}}
	var errs collect.Errs
	p, _ := collect.Packages(context.Background(), e, &errs)
	if len(errs) != 2 || p.LastAptUpdate != nil || p.Held == nil {
		t.Errorf("errs=%v p=%+v", errs, p)
	}
}

func TestParseFailedUnits(t *testing.T) {
	out := "● certbot.service loaded failed failed Certbot\nsnapd.seeded.service loaded failed failed Wait until snapd is fully seeded\n\n"
	got := collect.ParseFailedUnits([]byte(out))
	want := []string{"certbot.service", "snapd.seeded.service"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
	if got := collect.ParseFailedUnits(nil); got == nil || len(got) != 0 {
		t.Errorf("empty should be [] not nil")
	}
}

func TestDocker(t *testing.T) {
	ctx := context.Background()
	t.Run("ubuntu2404 docker-ce", func(t *testing.T) {
		e, _ := env(t, "ubuntu2404")
		srv := fakes.DockerAPI("testdata/ubuntu2404/docker")
		defer srv.Close()
		var errs collect.Errs
		d, projects, facts := collect.Docker(ctx, e, fakes.DockerClient(srv), dpkg(t, e), &errs)
		if len(errs) > 0 {
			t.Errorf("errors: %v", errs)
		}
		want := protocol.Docker{Installed: true, Family: "docker-ce", EngineVersion: "28.3.1", ComposeVersion: "2.29.1"}
		if d != want {
			t.Errorf("docker\n got %+v\nwant %+v", d, want)
		}
		names := []string{}
		for _, p := range projects {
			names = append(names, p.Name)
		}
		if !reflect.DeepEqual(names, []string{"(standalone)", "immich", "jobs", "proxy", "shop"}) {
			t.Errorf("projects %v", names)
		}
		svc := find(t, projects, "immich", "immich-server")
		wantSvc := protocol.Service{
			Name: "immich-server", Image: "ghcr.io/immich-app/immich-server:v1.119.0",
			Digest: readDigest(t, "immich"), State: "running", Health: "healthy", RestartPolicy: "always",
			Ports:          []protocol.Port{{HostPort: 2283, Proto: "tcp"}},
			HostPathMounts: []string{"/srv/photos/library"},
		}
		if !reflect.DeepEqual(svc, wantSvc) {
			t.Errorf("immich-server\n got %+v\nwant %+v", svc, wantSvc)
		}
		if db := find(t, projects, "immich", "database"); !db.Pinned || !strings.HasPrefix(db.Digest, "sha256:9072") {
			t.Errorf("database should be digest-pinned: %+v", db)
		}
		if w := find(t, projects, "proxy", "whoami"); !w.Pinned {
			t.Errorf("whoami has upkeeper.policy=pin: %+v", w)
		}
		tr := find(t, projects, "proxy", "traefik")
		if len(tr.Ports) != 3 || !reflect.DeepEqual(tr.HostPathMounts, []string{"/opt/proxy/acme"}) {
			t.Errorf("traefik ports/mounts: %+v", tr)
		}
		pt := find(t, projects, "(standalone)", "portainer")
		if pt.RestartPolicy != "no" || !reflect.DeepEqual(pt.HostPathMounts, []string{"/var/lib/docker/volumes/portainer_data/_data"}) {
			t.Errorf("portainer: %+v", pt)
		}
		app := find(t, projects, "shop", "app")
		if app.Digest != "" || app.RestartCount != 17 || app.State != "restarting" || !facts.Services["shop/app"].OOMKilled {
			t.Errorf("shop/app: %+v", app)
		}
		if facts.Services["jobs/backup"].Policy != "supervised" {
			t.Errorf("backup policy: %+v", facts.Services["jobs/backup"])
		}
		if facts.Services["immich/redis"].Ref.Tag != "6.2-alpine" {
			t.Errorf("redis ref: %+v", facts.Services["immich/redis"].Ref)
		}
	})

	t.Run("debian12 docker.io and compose v1", func(t *testing.T) {
		e, _ := env(t, "debian12")
		srv := fakes.DockerAPI("testdata/debian12/docker")
		defer srv.Close()
		var errs collect.Errs
		d, projects, _ := collect.Docker(ctx, e, fakes.DockerClient(srv), dpkg(t, e), &errs)
		want := protocol.Docker{Installed: true, Family: "docker.io", EngineVersion: "20.10.24+dfsg1", ComposeV1: true}
		if d != want || len(errs) > 0 {
			t.Errorf("docker\n got %+v\nwant %+v (errs %v)", d, want, errs)
		}
		ha := find(t, projects, "ha", "homeassistant")
		if !reflect.DeepEqual(ha.HostPathMounts, []string{"/tank/data/ha"}) || ha.Ports == nil {
			t.Errorf("ha: %+v", ha)
		}
	})

	t.Run("socket down", func(t *testing.T) {
		e, _ := env(t, "ubuntu2404")
		api := dockerapi.NewUnix(filepath.Join(t.TempDir(), "nope.sock"))
		var errs collect.Errs
		d, projects, _ := collect.Docker(ctx, e, api, dpkg(t, e), &errs)
		if !d.Installed || d.EngineVersion != "28.3.1" || len(projects) != 0 {
			t.Errorf("got %+v %v", d, projects)
		}
		if len(errs) != 1 || !strings.Contains(errs[0], "no answer on /var/run/docker.sock") {
			t.Errorf("errs %v", errs)
		}
	})

	t.Run("no docker at all", func(t *testing.T) {
		e := collect.Env{FS: fakes.FS{RootFS: host.RootFS{Root: t.TempDir()}}, Run: &host.FakeRunner{}}
		api := dockerapi.NewUnix(filepath.Join(t.TempDir(), "nope.sock"))
		var errs collect.Errs
		d, _, _ := collect.Docker(ctx, e, api, nil, &errs)
		if d.Installed || d.Family != "" {
			t.Errorf("got %+v", d)
		}
	})
}

func TestComposeV1Detection(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"python script", "#!/usr/bin/python3\n# EASY-INSTALL-ENTRY-SCRIPT: 'docker-compose==1.29.2'\n", true},
		{"pyinstaller binary", "\x7fELF....payload...MEI\x0c\x0b\x0a\x0b\x0e", true},
		{"v2 shim script", "#!/bin/sh\nexec docker compose \"$@\"\n", false},
		{"v2 go binary", "\x7fELF....Go build ID: github.com/docker/compose/v2", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			must(t, os.MkdirAll(filepath.Join(root, "usr/local/bin"), 0o755))
			must(t, os.WriteFile(filepath.Join(root, "usr/local/bin/docker-compose"), []byte(tt.content), 0o755))
			e := collect.Env{FS: fakes.FS{RootFS: host.RootFS{Root: root}}, Run: &host.FakeRunner{}}
			var errs collect.Errs
			d, _, _ := collect.Docker(context.Background(), e, dockerapi.NewUnix(filepath.Join(root, "x.sock")), nil, &errs)
			if d.ComposeV1 != tt.want {
				t.Errorf("ComposeV1=%v want %v", d.ComposeV1, tt.want)
			}
		})
	}
}

func TestComposePluginVersionFromBinary(t *testing.T) {
	// A Compose plugin installed by hand (no package) is asked for its version.
	root := t.TempDir()
	p := "/usr/local/lib/docker/cli-plugins/docker-compose"
	must(t, os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755))
	must(t, os.WriteFile(filepath.Join(root, p), []byte("bin"), 0o755))
	r := &host.FakeRunner{Out: map[string]string{host.Key(p, "version", "--short"): "v2.30.3\n"}}
	e := collect.Env{FS: fakes.FS{RootFS: host.RootFS{Root: root}}, Run: r}
	var errs collect.Errs
	d, _, _ := collect.Docker(context.Background(), e, dockerapi.NewUnix(filepath.Join(root, "x.sock")), nil, &errs)
	if d.ComposeVersion != "2.30.3" {
		t.Errorf("compose=%q errs=%v", d.ComposeVersion, errs)
	}
}

func TestProbe(t *testing.T) {
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound) // must not be followed
	}))
	defer httpSrv.Close()
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer okSrv.Close()

	// A TCP service that doesn't speak HTTP (like Postgres or SSH).
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer raw.Close()
	go func() {
		for {
			c, err := raw.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			c.Close()
		}
	}()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	closedAddr := closed.Addr().String()
	closed.Close()

	p := collect.Prober{Timeout: 500 * time.Millisecond}
	tests := []struct {
		name   string
		addr   string
		open   bool
		status int
	}{
		{"redirect not followed", httpSrv.Listener.Addr().String(), true, 302},
		{"plain 200", okSrv.Listener.Addr().String(), true, 200},
		{"not http", raw.Addr().String(), true, 0},
		{"closed", closedAddr, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			open, status := p.Probe(context.Background(), tt.addr)
			if open != tt.open || status != tt.status {
				t.Errorf("got open=%v status=%d", open, status)
			}
		})
	}

	// ProbeAll fills ports in place and skips UDP.
	_, portStr, _ := net.SplitHostPort(okSrv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	projects := []protocol.Project{{Name: "p", Services: []protocol.Service{{Name: "s", Ports: []protocol.Port{{HostPort: port, Proto: "tcp"}, {HostPort: port, Proto: "udp"}}}}}}
	p.ProbeAll(context.Background(), projects, collect.DockerFacts{})
	got := projects[0].Services[0].Ports
	if !got[0].TCPOpen || got[0].HTTPStatus != 200 || got[1].TCPOpen {
		t.Errorf("ProbeAll: %+v", got)
	}
}

func TestProbeTarget(t *testing.T) {
	for in, want := range map[string]string{"": "127.0.0.1:80", "0.0.0.0": "127.0.0.1:80", "::": "127.0.0.1:80", "10.0.0.5": "10.0.0.5:80", "::1": "[::1]:80"} {
		if got := collect.ProbeTarget(in, 80); got != want {
			t.Errorf("ProbeTarget(%q)=%q want %q", in, got, want)
		}
	}
}

func TestQueryDpkgPartial(t *testing.T) {
	// dpkg-query exits 1 when some names are unknown but still prints the rest.
	k := host.Key("dpkg-query", "-W", host.DpkgQueryFormat, "docker-ce", "nope")
	r := &host.FakeRunner{
		Out:  map[string]string{k: "docker-ce\t5:28.3.1-1~ubuntu.24.04~noble\tinstalled\n"},
		Errs: map[string]error{k: errors.New("dpkg-query: exit status 1: dpkg-query: no packages found matching nope")},
	}
	got, err := collect.QueryDpkg(context.Background(), collect.Env{Run: r}, "docker-ce", "nope")
	if err != nil || !got["docker-ce"].Installed() {
		t.Errorf("got %v %v", got, err)
	}
}

func find(t *testing.T, ps []protocol.Project, project, service string) protocol.Service {
	t.Helper()
	for _, p := range ps {
		if p.Name != project {
			continue
		}
		for _, s := range p.Services {
			if s.Name == service {
				return s
			}
		}
	}
	t.Fatalf("%s/%s not found", project, service)
	return protocol.Service{}
}

func readDigest(t *testing.T, key string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/digests.json")
	must(t, err)
	s := string(b)
	i := strings.Index(s, `"`+key+`": "`)
	if i < 0 {
		t.Fatalf("digest %s missing", key)
	}
	s = s[i+len(key)+5:]
	return s[:strings.Index(s, `"`)]
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
