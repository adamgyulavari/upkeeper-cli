package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "upkeeper", "agent.json")
	if _, err := Load(path); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("want ErrNotEnrolled, got %v", err)
	}
	in := Config{URL: "https://upkeeper.sh", ServerID: "srv_1", AgentToken: "upk_a_x", ReportEvery: 0}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st.Mode(), err)
	}
	if dst, _ := os.Stat(filepath.Dir(path)); dst.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", dst.Mode())
	}
	got, err := Load(path)
	in.ReportEvery = DefaultEvery
	if err != nil || got != in {
		t.Errorf("got %+v %v", got, err)
	}
	os.WriteFile(path, []byte(`{"url":"https://upkeeper.sh"}`), 0o600)
	if _, err := Load(path); err == nil {
		t.Error("config without token accepted")
	}
}
