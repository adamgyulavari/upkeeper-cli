package versions

import "testing"

func TestCompareDebian(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.0~rc1", "1.0", -1},
		{"1:0.1", "2.0", 1},
		{"2.36-9+deb12u7", "2.36-9+deb12u8", -1},
		{"3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5", -1},
		{"5:28.3.2-1~ubuntu.24.04~noble", "5:28.3.10-1~ubuntu.24.04~noble", -1},
		{"6.8.0-49.49", "6.8.0-50.51", -1},
		{"1.2a", "1.2", 1},
		{"1.0-1", "1.0", 1},
		{"1.0+b1", "1.0", 1},
		{"0011", "11", 0},
	}
	for _, tt := range tests {
		if got := CompareDebian(tt.a, tt.b); got != tt.want {
			t.Errorf("CompareDebian(%q,%q)=%d want %d", tt.a, tt.b, got, tt.want)
		}
		if got := CompareDebian(tt.b, tt.a); got != -tt.want {
			t.Errorf("CompareDebian(%q,%q)=%d want %d", tt.b, tt.a, got, -tt.want)
		}
	}
}

func TestUpstreamDebian(t *testing.T) {
	for in, want := range map[string]string{
		"5:28.3.2-1~ubuntu.24.04~noble":      "28.3.2",
		"27.5.1-0ubuntu3~24.04.2":            "27.5.1",
		"20.10.24+dfsg1-1+b3":                "20.10.24",
		"2.29.7-1~ubuntu.24.04~noble":        "2.29.7",
		"1.29.2-6":                           "1.29.2",
		"5:29.0.0~rc.1-1~ubuntu.24.04~noble": "29.0.0-rc.1",
		"1.6.20~ds1-1+b1":                    "1.6.20",
	} {
		if got := UpstreamDebian(in); got != want {
			t.Errorf("UpstreamDebian(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseTagAndDiff(t *testing.T) {
	tests := []struct {
		a, b   string
		change Change
		compat bool
	}{
		{"v1.2.3", "v1.2.4", Patch, true},
		{"1.2.3", "1.3.0", Minor, true},
		{"1.2.3", "2.0.0", Major, true},
		{"0.105.1", "0.106.0", Major, true},
		{"0.105.1", "0.105.2", Patch, true},
		{"16.4-alpine3.20", "16.6-alpine3.21", Minor, true},
		{"16.4-alpine", "16.6-bookworm", Minor, false},
		{"v1.2.3", "1.2.4", Patch, false},
		{"16", "17", Major, true},
		{"16", "16.1", Minor, false},
		{"0.7.2-pg16", "0.7.4-pg16", Patch, true},
		{"0.7.2-pg16", "0.7.4-pg17", Patch, false}, // other family: a different line
		{"16-alpine", "17-alpine", Major, true},
		{"20-alpine3.19", "20-alpine3.20", Patch, true},
		{"1.0.0-alpine3.9", "1.0.0-alpine3.10", Patch, true},
		{"4.0.10-ls260", "4.0.11-ls262", Patch, true},
		{"1.2.3-1", "1.2.4-2", Patch, true},
	}
	for _, tt := range tests {
		a, ok1 := ParseTag(tt.a)
		b, ok2 := ParseTag(tt.b)
		if !ok1 || !ok2 {
			t.Fatalf("parse %q/%q failed", tt.a, tt.b)
		}
		if got := Diff(a, b); got != tt.change {
			t.Errorf("Diff(%s,%s)=%v want %v", tt.a, tt.b, got, tt.change)
		}
		if got := a.Compatible(b); got != tt.compat {
			t.Errorf("Compatible(%s,%s)=%v want %v", tt.a, tt.b, got, tt.compat)
		}
	}
	for _, s := range []string{"latest", "release", "main", "sha-abc123", ""} {
		if _, ok := ParseTag(s); ok {
			t.Errorf("ParseTag(%q) should fail", s)
		}
	}
	a, _ := ParseTag("0.7.2-pg16")
	b, _ := ParseTag("0.7.4-pg17")
	if a.Family != "-pg16" || FamilyChange(a, b) != "pg 16 → 17" || !FamilyNewer(a, b) || FamilyNewer(b, a) || !a.SameKind(b) {
		t.Errorf("pg family: %+v %q", a, FamilyChange(a, b))
	}
	x, _ := ParseTag("1.0.0-alpine3.9")
	y, _ := ParseTag("1.0.0-alpine3.10")
	if Compare(x, y) >= 0 || x.Family != "-alpine3" {
		t.Errorf("alpine3.9 vs 3.10: %d %q", Compare(x, y), x.Family)
	}
	rc, _ := ParseTag("2.0.0-rc1")
	if !rc.Prerelease() {
		t.Error("2.0.0-rc1 should be a prerelease")
	}
	al, _ := ParseTag("3.20-alpine")
	if al.Prerelease() || al.Precise() {
		t.Error("3.20-alpine: not prerelease, not precise")
	}
}
