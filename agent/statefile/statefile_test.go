package statefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteReadRemove(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "x.json")
	var v struct{ A int }
	if ok, err := ReadJSON(p, &v); ok || err != nil {
		t.Fatalf("missing file: %v %v", ok, err)
	}
	if err := WriteJSON(p, map[string]int{"A": 3}); err != nil {
		t.Fatal(err)
	}
	if ok, err := ReadJSON(p, &v); !ok || err != nil || v.A != 3 {
		t.Fatalf("read back: %v %v %+v", ok, err, v)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	if err := Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := Remove(p); err != nil {
		t.Fatal("second remove:", err)
	}
	if ents, _ := os.ReadDir(filepath.Dir(p)); len(ents) != 0 {
		t.Errorf("temp files left: %v", ents)
	}
}
