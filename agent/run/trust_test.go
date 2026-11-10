package run

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func project(t *testing.T) (PathChecker, ProjectInfo, string) {
	root := t.TempDir()
	dir := filepath.Join(root, "opt", "app")
	os.MkdirAll(dir, 0o755)
	os.Chmod(filepath.Join(root, "opt"), 0o755)
	os.WriteFile(filepath.Join(dir, "compose.yml"), []byte("services: {}\n"), 0o644)
	pc := PathChecker{OwnerUID: os.Getuid(), Root: root}
	return pc, ProjectInfo{Name: "app", WorkDir: dir, ConfigFiles: []string{filepath.Join(dir, "compose.yml")}}, root
}

func TestCheckProjectAcceptsAPlainProject(t *testing.T) {
	pc, pi, _ := project(t)
	if err := pc.CheckProject(&pi, nil); err != nil {
		t.Fatal(err)
	}
	if err := pc.Recheck(pi, nil); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(pi.ConfigFiles[0], []byte("services: {web: {privileged: true}}\n"), 0o644)
	if err := pc.Recheck(pi, nil); err == nil || !strings.Contains(err.Error(), "changed during the run") {
		t.Errorf("content change not seen: %v", err)
	}
}

func TestCheckProjectRefusesHostilePaths(t *testing.T) {
	tests := map[string]func(t *testing.T, pc *PathChecker, pi *ProjectInfo, root string) (mounts []string){
		"symlinked compose file": func(t *testing.T, pc *PathChecker, pi *ProjectInfo, root string) []string {
			evil := filepath.Join(root, "evil.yml")
			os.WriteFile(evil, []byte("x"), 0o644)
			os.Remove(pi.ConfigFiles[0])
			os.Symlink(evil, pi.ConfigFiles[0])
			return nil
		},
		"world-writable dir": func(t *testing.T, pc *PathChecker, pi *ProjectInfo, root string) []string {
			os.Chmod(pi.WorkDir, 0o777)
			return nil
		},
		"group-writable file": func(t *testing.T, pc *PathChecker, pi *ProjectInfo, root string) []string {
			os.Chmod(pi.ConfigFiles[0], 0o664)
			return nil
		},
		"inside a container's mount": func(t *testing.T, pc *PathChecker, pi *ProjectInfo, root string) []string {
			return []string{pi.WorkDir}
		},
		"below a mounted parent": func(t *testing.T, pc *PathChecker, pi *ProjectInfo, root string) []string {
			return []string{filepath.Dir(pi.WorkDir)}
		},
		"docker volume dir": func(t *testing.T, pc *PathChecker, pi *ProjectInfo, root string) []string {
			pi.WorkDir = "/var/lib/docker/volumes/tool_data/_data"
			pi.ConfigFiles = []string{pi.WorkDir + "/compose.yml"}
			return nil
		},
		"relative path": func(t *testing.T, pc *PathChecker, pi *ProjectInfo, root string) []string {
			pi.ConfigFiles = []string{"compose.yml"}
			return nil
		},
		"image sets compose labels": func(t *testing.T, pc *PathChecker, pi *ProjectInfo, root string) []string {
			pi.ImageLabels, pi.ImageLabelsFrom = []string{"com.docker.compose.project.working_dir"}, "web"
			return nil
		},
		"containers disagree": func(t *testing.T, pc *PathChecker, pi *ProjectInfo, root string) []string {
			pi.Inconsistent = "its containers disagree about the project's directory or compose files"
			return nil
		},
		"custom env file": func(t *testing.T, pc *PathChecker, pi *ProjectInfo, root string) []string {
			pi.EnvFileLabel = "/etc/shadow"
			return nil
		},
		"writable .env": func(t *testing.T, pc *PathChecker, pi *ProjectInfo, root string) []string {
			os.WriteFile(filepath.Join(pi.WorkDir, ".env"), []byte("X=1"), 0o666)
			os.Chmod(filepath.Join(pi.WorkDir, ".env"), 0o666)
			return nil
		},
		"other owner": func(t *testing.T, pc *PathChecker, pi *ProjectInfo, root string) []string {
			pc.OwnerUID = os.Getuid() + 1
			return nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			pc, pi, root := project(t)
			mounts := mutate(t, &pc, &pi, root)
			if err := pc.CheckProject(&pi, mounts); err == nil {
				t.Errorf("accepted")
			}
		})
	}
}

func TestOverrideFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, OverrideName)
	if o, ok, err := ReadOverride(p); ok || err != nil || len(o) != 0 {
		t.Fatalf("missing: %v %v %v", o, ok, err)
	}
	o := Override{"redis": "redis:7.4.2@sha256:2222", "web": "ghcr.io/x/web:1.2.3@sha256:abcd"}
	if err := WriteOverride(p, o); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.HasPrefix(string(b), "# Written by upkeeper.sh.") || !strings.Contains(string(b), "  redis:\n    image: \"redis:7.4.2@sha256:2222\"\n") {
		t.Errorf("content:\n%s", b)
	}
	got, ok, err := ReadOverride(p)
	if !ok || err != nil || got["web"] != o["web"] || len(got) != 2 {
		t.Fatalf("read back: %v %v %v", got, ok, err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", st.Mode())
	}
	// Hand edits are refused.
	os.WriteFile(p, append(b, []byte("  web:\n    privileged: true\n")...), 0o644)
	if _, _, err := ReadOverride(p); err != ErrHandEdited {
		t.Errorf("hand edit: %v", err)
	}
	// Refuses to render anything but an image reference.
	if err := WriteOverride(p, Override{"web": "x\n    privileged: true"}); err == nil {
		t.Error("rendered a hostile image value")
	}
	// A symlink in place of the override is never followed.
	target := filepath.Join(dir, "cron")
	os.WriteFile(target, []byte("keep"), 0o644)
	os.Remove(p)
	os.Symlink(target, p)
	if err := WriteOverride(p, o); err == nil {
		t.Error("wrote through a symlink")
	}
	if _, _, err := ReadOverride(p); err == nil {
		t.Error("read through a symlink")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Error("symlink target changed")
	}
	// Empty override removes the file.
	os.Remove(p)
	WriteOverride(p, o)
	if err := WriteOverride(p, Override{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Error("empty override not removed")
	}
}
