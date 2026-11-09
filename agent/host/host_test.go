package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
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
		{"apt-get", []string{"update"}, false},
		{"apt-get", []string{"install", "-y", "docker-ce"}, false},
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

// TestNoWriteActions scans the agent's source: M0 must contain no action that
// changes the system (scope M0: "zero write actions exist in the binary").
func TestNoWriteActions(t *testing.T) {
	type rule struct {
		re      *regexp.Regexp
		allowed []string // files (relative to repo root) where this is fine
		why     string
	}
	rules := []rule{
		{regexp.MustCompile(`exec\.Command`), []string{"agent/host/runner.go"}, "commands go through the allowlisted runner"},
		{regexp.MustCompile(`syscall\.(Exec|ForkExec|Reboot|Kill|Mount|Unlink|Rmdir)`), nil, "no direct syscalls that change the system"},
		{regexp.MustCompile(`os\.(WriteFile|Create|CreateTemp|Remove|RemoveAll|Rename|Chmod|Chown|Symlink|Link|Truncate|MkdirAll|Mkdir)\(|\.Chmod\(`),
			[]string{"agent/config/config.go", "agent/registry/cache.go"}, "writes only to /etc/upkeeper and the cache dir"},
		{regexp.MustCompile(`http\.Method(Post|Put|Delete|Patch)|"(POST|PUT|DELETE|PATCH)"`), []string{"agent/cloudclient/client.go"}, "only the cloud client posts"},
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
				if r.re.Match(b) && !slices.Contains(r.allowed, rel) {
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
