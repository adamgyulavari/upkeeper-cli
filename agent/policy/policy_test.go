package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

func store(t *testing.T) Store {
	d := t.TempDir()
	os.Chmod(d, 0o755)
	uid := os.Getuid()
	return Store{Path: filepath.Join(d, "etc", "policy.yaml"), StateDir: filepath.Join(d, "state"), OwnerUID: &uid}
}

func TestDefaultIsObserve(t *testing.T) {
	s := store(t)
	if m, err := s.Mode(); m != protocol.ModeObserve || err != nil {
		t.Fatalf("missing file: %v %v", m, err)
	}
}

func TestSetAndLoad(t *testing.T) {
	s := store(t)
	for _, m := range []protocol.Mode{protocol.ModeAuto, protocol.ModeDryRun, protocol.ModeObserve} {
		if err := s.SetMode(m); err != nil {
			t.Fatal(err)
		}
		if got, err := s.Mode(); got != m || err != nil {
			t.Errorf("set %s, got %s %v", m, got, err)
		}
	}
	b, _ := os.ReadFile(s.Path)
	if !strings.HasPrefix(string(b), "# upkeeper.sh local policy") {
		t.Errorf("no header: %s", b)
	}
	if err := s.SetMode("yolo"); err == nil {
		t.Error("bad mode accepted")
	}
}

func TestBrokenFileMeansObserve(t *testing.T) {
	s := store(t)
	for _, content := range []string{
		"mode: auto\nmode: auto\n",
		"mode: always\n",
		"mode: auto\nallow_reboots: yes\n",
		"just text\n",
	} {
		os.MkdirAll(filepath.Dir(s.Path), 0o700)
		os.WriteFile(s.Path, []byte(content), 0o600)
		os.Chmod(s.Path, 0o600)
		if m, err := s.Mode(); m != protocol.ModeObserve || err == nil {
			t.Errorf("%q: got %s %v, want observe with an error", content, m, err)
		}
	}
	os.WriteFile(s.Path, []byte("# comment\nmode: \"dry-run\"  # quoted\n"), 0o600)
	if m, err := s.Mode(); m != protocol.ModeDryRun || err != nil {
		t.Errorf("quoted: %s %v", m, err)
	}
}

func TestFreeze(t *testing.T) {
	s := store(t)
	if s.Frozen().Frozen {
		t.Fatal("frozen by default")
	}
	if err := s.FreezeNow("redis didn't come back.", "job_1"); err != nil {
		t.Fatal(err)
	}
	f := s.Frozen()
	if !f.Frozen || f.Reason != "redis didn't come back." || f.JobID != "job_1" || f.At.IsZero() {
		t.Errorf("freeze: %+v", f)
	}
	if p := s.Report(); !p.Frozen || p.Mode != protocol.ModeObserve || p.FrozenReason == "" {
		t.Errorf("report: %+v", p)
	}
	if err := s.Unfreeze(); err != nil || s.Frozen().Frozen {
		t.Errorf("unfreeze: %v", err)
	}
	// A corrupt file counts as frozen.
	os.WriteFile(s.FrozenPath(), []byte("{"), 0o600)
	if !s.Frozen().Frozen {
		t.Error("corrupt freeze file should count as frozen")
	}
}

func TestEffective(t *testing.T) {
	tests := []struct {
		local, job, want protocol.Mode
		ok               bool
	}{
		{protocol.ModeObserve, protocol.ModeAuto, "", false},
		{protocol.ModeObserve, protocol.ModeDryRun, "", false},
		{protocol.ModeDryRun, protocol.ModeAuto, protocol.ModeDryRun, true},
		{protocol.ModeDryRun, protocol.ModeDryRun, protocol.ModeDryRun, true},
		{protocol.ModeAuto, protocol.ModeAuto, protocol.ModeAuto, true},
		{protocol.ModeAuto, protocol.ModeDryRun, protocol.ModeDryRun, true},
		{protocol.ModeAuto, protocol.ModeObserve, "", false},
		{protocol.ModeAuto, "turbo", "", false},
	}
	for _, tt := range tests {
		got, reason, ok := Effective(tt.local, tt.job)
		if got != tt.want || ok != tt.ok || (!ok && reason == "") {
			t.Errorf("Effective(%s, %s) = %s %q %v", tt.local, tt.job, got, reason, ok)
		}
		if strings.Contains(reason, "!") {
			t.Errorf("no exclamation marks: %q", reason)
		}
	}
}
