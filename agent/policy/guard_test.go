package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

func TestPolicyFileMustBeLockedDown(t *testing.T) {
	s := store(t)
	if err := s.SetMode(protocol.ModeAuto); err != nil {
		t.Fatal(err)
	}
	if m, err := s.Mode(); m != protocol.ModeAuto || err != nil {
		t.Fatalf("%s %v", m, err)
	}
	os.Chmod(s.Path, 0o666)
	if m, err := s.Mode(); m != protocol.ModeObserve || err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("world-writable file: %s %v", m, err)
	}
	os.Chmod(s.Path, 0o644)
	os.Chmod(filepath.Dir(s.Path), 0o777)
	if m, err := s.Mode(); m != protocol.ModeObserve || err == nil {
		t.Errorf("world-writable dir: %s %v", m, err)
	}
	os.Chmod(filepath.Dir(s.Path), 0o755)
	other := os.Getuid() + 1
	s2 := s
	s2.OwnerUID = &other
	if m, err := s2.Mode(); m != protocol.ModeObserve || err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Errorf("wrong owner: %s %v", m, err)
	}
	// A symlink to a valid file isn't accepted.
	real := filepath.Join(filepath.Dir(s.Path), "real.yaml")
	os.Rename(s.Path, real)
	os.Symlink(real, s.Path)
	if m, err := s.Mode(); m != protocol.ModeObserve || err == nil {
		t.Errorf("symlink: %s %v", m, err)
	}
}

func TestWindow(t *testing.T) {
	w, err := ParseWindow("sun 03:00-05:00")
	if err != nil {
		t.Fatal(err)
	}
	w.Loc = time.UTC
	sun := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC) // a Sunday
	if end, in := w.End(sun.Add(4 * time.Hour)); !in || !end.Equal(sun.Add(5*time.Hour)) {
		t.Errorf("inside: %v %v", end, in)
	}
	for _, at := range []time.Duration{2 * time.Hour, 5 * time.Hour, 24*time.Hour + 4*time.Hour} {
		if _, in := w.End(sun.Add(at)); in {
			t.Errorf("%s after Sunday midnight should be outside", at)
		}
	}
	n, err := ParseWindow("sat 23:00-01:00")
	if err != nil {
		t.Fatal(err)
	}
	n.Loc = time.UTC
	if end, in := n.End(sun.Add(30 * time.Minute)); !in || !end.Equal(sun.Add(time.Hour)) {
		t.Errorf("past midnight: %v %v", end, in)
	}
	for in, want := range map[string]string{"daily 03:00-04:00": "daily 03:00-04:00", "mon,thu 02:00-04:30": "mon,thu 02:00-04:30"} {
		w, err := ParseWindow(in)
		if err != nil || w.String() != want {
			t.Errorf("%s: %q %v", in, w.String(), err)
		}
	}
	for _, bad := range []string{"", "sun", "funday 03:00-04:00", "sun 3-4", "sun 00:00-23:00"} {
		if _, err := ParseWindow(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	s := store(t)
	s.SetMode(protocol.ModeAuto)
	if err := s.SetWindow(&w); err != nil {
		t.Fatal(err)
	}
	st, err := s.Load()
	if err != nil || st.Mode != protocol.ModeAuto || st.Window == nil || st.Window.String() != "sun 03:00-05:00" {
		t.Errorf("window round trip: %+v %v", st, err)
	}
	if p := s.Report(); p.Window != "sun 03:00-05:00" {
		t.Errorf("report: %+v", p)
	}
}

func TestAdmit(t *testing.T) {
	now := time.Date(2026, 11, 15, 3, 30, 0, 0, time.UTC)
	full := protocol.Job{Mode: protocol.ModeAuto}
	sec := protocol.Job{Mode: protocol.ModeAuto, SecurityOnly: true}
	s := store(t)

	if _, _, _, reason, ok := s.Admit(full, now); ok || !strings.Contains(reason, "observe") {
		t.Errorf("observe: %v %q", ok, reason)
	}
	s.SetMode(protocol.ModeAuto)
	// First run after the policy became auto: dry run.
	mode, _, note, _, ok := s.Admit(full, now)
	if !ok || mode != protocol.ModeDryRun || note == "" {
		t.Fatalf("first auto job: %s %v %q", mode, ok, note)
	}
	if err := s.RecordDryRun(now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// File mtime is "now" in real time; use the real clock for the next checks.
	time.Sleep(10 * time.Millisecond)
	real := time.Now()
	s.RecordDryRun(real)
	if mode, _, _, _, ok := s.Admit(full, real); !ok || mode != protocol.ModeAuto {
		t.Fatalf("after a dry run: %s %v", mode, ok)
	}
	s.RecordStart(full, protocol.ModeAuto, real)
	if _, _, _, reason, ok := s.Admit(full, real.Add(19*time.Hour)); ok || !strings.Contains(reason, "one every 20 hours") {
		t.Errorf("rate limit: %v %q", ok, reason)
	}
	if mode, _, _, _, ok := s.Admit(sec, real.Add(time.Hour)); !ok || mode != protocol.ModeAuto {
		t.Errorf("security run is counted separately: %s %v", mode, ok)
	}
	if _, _, _, _, ok := s.Admit(full, real.Add(21*time.Hour)); !ok {
		t.Error("after 21 h a full run is allowed")
	}
	// Dry-run jobs are never rate limited.
	if mode, _, _, _, ok := s.Admit(protocol.Job{Mode: protocol.ModeDryRun}, real.Add(time.Hour)); !ok || mode != protocol.ModeDryRun {
		t.Error("dry run limited")
	}
	// Changing the policy again means another dry run first.
	time.Sleep(10 * time.Millisecond)
	s.SetMode(protocol.ModeAuto)
	if mode, _, _, _, _ := s.Admit(full, real.Add(21*time.Hour)); mode != protocol.ModeDryRun {
		t.Errorf("policy rewritten: want dry run, got %s", mode)
	}

	// Local window.
	w, _ := ParseWindow("sun 03:00-05:00")
	w.Loc = time.UTC
	s.SetWindow(&w)
	if _, _, _, reason, ok := s.Admit(protocol.Job{Mode: protocol.ModeDryRun}, now.Add(3*time.Hour)); ok || !strings.Contains(reason, "outside this server's local maintenance window") {
		t.Errorf("outside window: %v %q", ok, reason)
	}
	// Load drops Loc, so compare against time.Local: just check that a
	// job inside the window is admitted with a window end.
	inLocal := time.Date(2026, 11, 15, 4, 0, 0, 0, time.Local)
	if _, end, _, reason, ok := s.Admit(protocol.Job{Mode: protocol.ModeDryRun}, inLocal); !ok || end.IsZero() {
		t.Errorf("inside window: %v %q", ok, reason)
	}

	// A corrupt history blocks runs.
	os.WriteFile(s.historyPath(), []byte("{"), 0o600)
	if _, _, _, reason, ok := s.Admit(protocol.Job{Mode: protocol.ModeDryRun}, inLocal); ok || !strings.Contains(reason, "can't be read") {
		t.Errorf("corrupt history: %v %q", ok, reason)
	}
}
