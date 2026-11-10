package host

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestAllowed(t *testing.T) {
	tests := []struct {
		name string
		args []string
		ok   bool
	}{
		{"apt-get", AptSimulateUpgrade, true},
		{"apt-get", []string{"upgrade", "-y"}, false},
		{"apt-get", []string{"-s", "upgrade"}, false}, // must disable the on-disk cache too
		{"apt-get", []string{"update"}, true},
		{"apt-get", []string{"update", "-o", "APT::Update::Post-Invoke=rm"}, false},
		{"apt-get", []string{"install", "-y", "docker-ce"}, false},
		{"apt-get", AptInstallArgs([]PkgVersion{{"openssl", "3.0.13-0ubuntu3.5"}, {"vim", "2:9.1.0016-1ubuntu7.4"}}), true},
		{"apt-get", AptSimInstallArgs([]PkgVersion{{"openssl", "3.0.13-0ubuntu3.5"}}), true},
		{"apt-get", AptInstallArgs(nil), false},
		{"apt-get", AptInstallArgs([]PkgVersion{{"docker-ce", "5:28.3.2-1"}}), false},
		{"apt-get", AptInstallArgs([]PkgVersion{{"containerd.io", "1.7.24-1"}}), false},
		{"apt-get", AptInstallArgs([]PkgVersion{{"docker-ce-rootless-extras", "5:28.3.2-1"}}), false},
		{"apt-get", AptInstallArgs([]PkgVersion{{"openssl", ""}}), false},
		{"apt-get", AptInstallArgs([]PkgVersion{{"-oDpkg::Pre-Invoke=x", "1"}}), false},
		{"apt-get", AptInstallArgs([]PkgVersion{{"openssl", "1;reboot"}}), false},
		{"apt-get", append(AptInstallArgs([]PkgVersion{{"openssl", "1"}}), "--allow-downgrades"), false},
		{"apt-get", AptInstallArgs([]PkgVersion{{"openssh-server", "1:9.6p1-3ubuntu13.99-"}}), false},
		{"apt-get", AptInstallArgs([]PkgVersion{{"foo-", "1"}}), false},
		{"apt-get", AptInstallArgs([]PkgVersion{{"foo+", "1"}}), false},
		{"apt-get", AptInstallArgs([]PkgVersion{{"foo", "1.0+"}}), false},
		{"apt-get", AptInstallArgs([]PkgVersion{{"libstdc++6", "14.2.0-4ubuntu2~24.04"}}), true},
		{"apt-get", AptInstallArgs([]PkgVersion{{"vim", "2:9.1.0016-1ubuntu7.4"}, {"a", "1"}}), true},
		{"apt-get", []string{"-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "install", "--only-upgrade", "openssl"}, false},
		{"apt-get", []string{"-y", "install", "--only-upgrade", "openssl=1"}, false},
		{"apt-get", []string{"-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "install", "openssl=1"}, false},
		{"apt-mark", []string{"showhold"}, true},
		{"apt-mark", []string{"hold", "docker-ce"}, false},
		{"apt-cache", append(slices.Clone(AptNoCache), "madison", "docker-ce", "docker-compose-plugin"), true},
		{"apt-cache", append(slices.Clone(AptNoCache), "madison", "docker-ce;reboot"), false},
		{"apt-cache", []string{"madison", "docker-ce"}, false},
		{"dpkg-query", []string{"-W", DpkgQueryFormat, "linux-image-[0-9]*", "docker.io"}, true},
		{"dpkg-query", []string{"-W", DpkgQueryFormat, "$(rm -rf /)"}, false},
		{"dpkg-query", []string{"-W", "-f=${Package}"}, false},
		{"dpkg", []string{"--configure", "-a"}, false},
		{"systemctl", SystemctlFailed, true},
		{"systemctl", []string{"restart", "docker"}, false},
		{"docker", []string{"pull", "nginx"}, false},
		{"docker", ComposeUp{ProjectDir: "/opt/app", Project: "app", Files: []string{"/opt/app/compose.yml", "/opt/app/compose.override.upkeeper.yml"}, Services: []string{"web"}}.Args(), true},
		{"docker", ComposeUp{ProjectDir: "/opt/my app", Project: "app", Files: []string{"/opt/my app/compose.yml"}, Services: []string{"web", "worker_1"}}.Args(), true},
		{"docker", []string{"compose", "--project-directory", "/opt/app", "-p", "app", "-f", "/opt/app/compose.yml", "--env-file", "/etc/shadow", "up", "-d", "--no-deps", "--no-build", "--force-recreate", "--pull", "never", "web"}, false},
		{"docker", ComposeUp{ProjectDir: "opt/app", Project: "app", Files: []string{"/opt/app/compose.yml"}, Services: []string{"web"}}.Args(), false},
		{"docker", ComposeUp{ProjectDir: "/opt/app/../../etc", Project: "app", Files: []string{"/opt/app/compose.yml"}, Services: []string{"web"}}.Args(), false},
		{"docker", ComposeUp{ProjectDir: "/opt/app", Project: "App", Files: []string{"/opt/app/compose.yml"}, Services: []string{"web"}}.Args(), false},
		{"docker", ComposeUp{ProjectDir: "/opt/app", Project: "app", Files: []string{"-f"}, Services: []string{"web"}}.Args(), false},
		{"docker", ComposeUp{ProjectDir: "/opt/app", Project: "app", Files: []string{"/opt/app/compose.yml"}, Services: []string{"--build"}}.Args(), false},
		{"docker", ComposeUp{ProjectDir: "/opt/app", Project: "app", Files: []string{"/opt/app/compose.yml"}}.Args(), false},
		{"docker", ComposeUp{ProjectDir: "/opt/app", Project: "app", Files: []string{"/opt/app/compose.yml\nx"}, Services: []string{"web"}}.Args(), false},
		{"docker", []string{"compose", "--project-directory", "/opt/app", "-p", "app", "-f", "/opt/app/compose.yml", "up", "-d", "web"}, false},
		{"docker", []string{"compose", "--project-directory", "/opt/app", "-p", "app", "-f", "/opt/app/compose.yml", "down"}, false},
		{"docker", []string{"compose", "--project-directory", "/opt/app", "-p", "app", "-f", "/opt/app/compose.yml", "up", "-d", "--no-deps", "--no-build", "--force-recreate", "--pull", "always", "web"}, false},
		{"/usr/libexec/docker/cli-plugins/docker-compose", []string{"version", "--short"}, true},
		{"/usr/libexec/docker/cli-plugins/docker-compose", []string{"up", "-d"}, false},
		{"/tmp/docker-compose", []string{"version", "--short"}, false},
		{"sh", []string{"-c", "true"}, false},
		{"reboot", nil, false},
	}
	for _, tt := range tests {
		err := Allowed(tt.name, tt.args)
		if (err == nil) != tt.ok {
			t.Errorf("Allowed(%s %v) = %v, want ok=%v", tt.name, tt.args, err, tt.ok)
		}
		if err != nil && !errors.Is(err, ErrNotAllowed) {
			t.Errorf("error should wrap ErrNotAllowed: %v", err)
		}
	}
}

func TestParseComposeUpRoundTrip(t *testing.T) {
	c := ComposeUp{ProjectDir: "/srv/a", Project: "a", Files: []string{"/srv/a/docker-compose.yml"}, Services: []string{"redis"}}
	got, ok := ParseComposeUp(c.Args())
	if !ok || !slices.Equal(got.Args(), c.Args()) {
		t.Fatalf("round trip: %+v %v", got, ok)
	}
}

func TestDockerFamily(t *testing.T) {
	for _, p := range []string{"docker-ce", "docker-ce-cli", "docker.io", "containerd.io", "containerd", "runc", "docker-compose-plugin", "docker-buildx-plugin", "docker-compose-v2", "moby-engine"} {
		if !IsDockerFamily(p) {
			t.Errorf("%s should be Docker family", p)
		}
	}
	for _, p := range []string{"openssl", "linux-image-generic", "dockerfile-mode"} {
		if IsDockerFamily(p) {
			t.Errorf("%s isn't Docker family", p)
		}
	}
}

func TestExecRunnerEnv(t *testing.T) {
	for _, want := range []string{"DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l", "LC_ALL=C"} {
		if !slices.Contains(Env, want) {
			t.Errorf("Env lacks %s", want)
		}
	}
}

func TestLockedHelper(t *testing.T) {
	if os.Getenv("UPKEEPER_LOCK_HELPER") == "" {
		t.Skip("helper process")
	}
	f, err := os.OpenFile(os.Getenv("UPKEEPER_LOCK_HELPER"), os.O_RDWR, 0)
	if err != nil {
		os.Exit(2)
	}
	lk := syscall.Flock_t{Type: syscall.F_WRLCK}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lk); err != nil {
		os.Exit(3)
	}
	os.Stdout.WriteString("locked\n")
	time.Sleep(10 * time.Second)
	os.Exit(0)
}

func TestLocked(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, locked, err := Locked([]string{filepath.Join(dir, "missing"), lock}); locked || err != nil {
		t.Fatalf("unlocked file reported locked: %v %v", locked, err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockedHelper$")
	cmd.Env = append(os.Environ(), "UPKEEPER_LOCK_HELPER="+lock)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	buf := make([]byte, 7)
	if _, err := io.ReadFull(out, buf); err != nil || string(buf) != "locked\n" {
		t.Fatalf("helper didn't lock: %q %v", buf, err)
	}
	p, locked, err := Locked([]string{lock})
	if !locked || err != nil || p != lock {
		t.Fatalf("held lock not seen: %s %v %v", p, locked, err)
	}
}

func TestExecRunnerRefuses(t *testing.T) {
	_, err := ExecRunner{}.Run(context.Background(), "apt-get", "install", "-y", "curl")
	if !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("want ErrNotAllowed, got %v", err)
	}
}

func TestRootFS(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "boot"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "boot", "vmlinuz-1"), []byte("k"), 0o644)
	fs := RootFS{Root: root}
	got, err := fs.Glob("/boot/vmlinuz-*")
	if err != nil || !slices.Equal(got, []string{"/boot/vmlinuz-1"}) {
		t.Errorf("Glob = %v, %v", got, err)
	}
	// ".." can't escape the root.
	if _, err := fs.ReadFile("/../../../../etc/hostname"); err == nil {
		if b, _ := fs.ReadFile("/etc/hostname"); b != nil {
			t.Error("path escaped root")
		}
	}
	if total, _, err := fs.Statfs("/"); err != nil || total == 0 {
		t.Errorf("Statfs: %d %v", total, err)
	}
}

// TestWriteActionsOnlyInRun scans the agent's source. From M1 the agent can
// change the system, but only from agent/run, only through the allowlisted
// runner and the Engine API calls in agent/run/docker.go. Everything else
// stays read-only, as in M0.
func TestWriteActionsOnlyInRun(t *testing.T) {
	type rule struct {
		re      *regexp.Regexp
		allowed []string // files or directories (ending in /) relative to the repo root
		why     string
	}
	rules := []rule{
		{regexp.MustCompile(`exec\.Command`), []string{"agent/host/runner.go"}, "commands go through the allowlisted runner"},
		{regexp.MustCompile(`syscall\.(Exec|ForkExec|Reboot|Kill|Mount|Unlink|Rmdir|Sethostname|Settimeofday)`), nil, "no direct syscalls that change the system"},
		{regexp.MustCompile(`os\.(WriteFile|Create|CreateTemp|Remove|RemoveAll|Rename|Chmod|Chown|Symlink|Link|Truncate|MkdirAll|Mkdir|OpenFile)\(|\.Chmod\(`),
			[]string{"agent/config/config.go", "agent/registry/cache.go", "agent/policy/", "agent/run/", "agent/jobs/", "agent/statefile/"},
			"writes only to the agent's own files and, in agent/run, the override file"},
		{regexp.MustCompile(`http\.Method(Post|Put|Delete|Patch)|"(POST|PUT|DELETE|PATCH)"`), []string{"agent/cloudclient/client.go", "agent/run/docker.go"}, "only the cloud client and the run engine's Docker calls post"},
		{regexp.MustCompile(`host\.(AptUpdate|AptInstallArgs|ComposeUp)\b`), []string{"agent/run/"}, "write commands are built only in agent/run"},
		{regexp.MustCompile(`images/create|"/tag"|/containers/[^"]*/(start|stop|kill|restart|update)|"(DELETE|delete)"`), []string{"agent/run/docker.go"}, "Engine API writes only in agent/run/docker.go"},
	}
	allowed := func(list []string, rel string) bool {
		for _, a := range list {
			if a == rel || (strings.HasSuffix(a, "/") && strings.HasPrefix(rel, a)) {
				return true
			}
		}
		return false
	}
	root := filepath.Join("..", "..")
	for _, dir := range []string{"agent", "cmd/upkeeper"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == "testdata" || d.Name() == "fakes") {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, r := range rules {
				if r.re.Match(b) && !allowed(r.allowed, rel) {
					t.Errorf("%s matches %q: %s", rel, r.re, r.why)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestFakesNotImported keeps test doubles out of the binary.
func TestFakesNotImported(t *testing.T) {
	root := filepath.Join("..", "..")
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.Contains(path, "/fakes/") {
			return nil
		}
		b, _ := os.ReadFile(path)
		if strings.Contains(string(b), "agent/fakes\"") {
			t.Errorf("%s imports agent/fakes", path)
		}
		return nil
	})
}
