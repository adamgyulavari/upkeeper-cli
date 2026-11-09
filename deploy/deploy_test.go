// Package deploy holds the installer and systemd unit; this test keeps them honest.
package deploy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestInstallerEmbedsTheUnit(t *testing.T) {
	script, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile("upkeeper.service")
	if err != nil {
		t.Fatal(err)
	}
	s := string(script)
	start := strings.Index(s, "<<'UNIT'\n")
	end := strings.Index(s, "\nUNIT\n")
	if start < 0 || end < 0 {
		t.Fatal("no unit heredoc in install.sh")
	}
	if embedded := s[start+len("<<'UNIT'\n") : end+1]; embedded != string(unit) {
		t.Errorf("install.sh's unit differs from deploy/upkeeper.service")
	}
}

func TestInstallerSyntax(t *testing.T) {
	for _, sh := range []string{"sh", "dash", "bash"} {
		if _, err := exec.LookPath(sh); err != nil {
			continue
		}
		if out, err := exec.Command(sh, "-n", "install.sh").CombinedOutput(); err != nil {
			t.Errorf("%s -n: %v\n%s", sh, err, out)
		}
	}
}

func TestInstallerRefusesBadChecksum(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root so the installer doesn't stop at the sudo check")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/checksums.txt"):
			w.Write([]byte("0000000000000000000000000000000000000000000000000000000000000000  upkeeper_linux_amd64\n" +
				"0000000000000000000000000000000000000000000000000000000000000000  upkeeper_linux_arm64\n"))
		default:
			w.Write([]byte("#!/bin/sh\necho tampered\n"))
		}
	}))
	defer srv.Close()
	cmd := exec.Command("sh", "install.sh", "upk_e_test", "--url", "http://localhost:8080")
	cmd.Env = append(os.Environ(), "UPKEEPER_DOWNLOAD_BASE="+srv.URL+"/dl")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "checksum mismatch") || !strings.Contains(string(out), "Nothing was installed") {
		t.Errorf("err=%v out=%s", err, out)
	}
}
