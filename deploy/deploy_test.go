// Package deploy holds the installer and systemd unit; this test keeps them honest.
package deploy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	cmd.Env = append(os.Environ(), "UPKEEPER_DOWNLOAD_BASE="+srv.URL+"/dl", "UPKEEPER_INSECURE_SKIP_SIGNATURE=1")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "checksum mismatch") || !strings.Contains(string(out), "Nothing was installed") {
		t.Errorf("err=%v out=%s", err, out)
	}
}

func TestInstallerFailsClosedWithoutSignature(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root so the installer doesn't stop at the sudo check")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("x\n"))
	}))
	defer srv.Close()
	cmd := exec.Command("sh", "install.sh", "--url", "http://localhost:8080")
	cmd.Env = append(os.Environ(), "UPKEEPER_DOWNLOAD_BASE="+srv.URL+"/dl")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "Nothing was installed") || !strings.Contains(string(out), "signature") {
		t.Errorf("err=%v out=%s", err, out)
	}
}

// TestInstallerChecksSignature signs checksums.txt with a throwaway SSH key,
// puts that key into a copy of install.sh and checks a good and a bad signature.
func TestInstallerChecksSignature(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root so the installer doesn't stop at the sudo check")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("no ssh-keygen")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "release")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	pub, _ := os.ReadFile(key + ".pub")
	f := strings.Fields(string(pub))
	script, _ := os.ReadFile("install.sh")
	signers := `release@upkeeper.sh namespaces="upkeeper-release" ` + f[0] + " " + f[1]
	s := regexp.MustCompile(`(?m)^ALLOWED_SIGNERS=.*$`).ReplaceAllString(string(script), "ALLOWED_SIGNERS='"+signers+"'")
	os.WriteFile(filepath.Join(dir, "install.sh"), []byte(s), 0o755)

	sums := []byte("0000000000000000000000000000000000000000000000000000000000000000  upkeeper_linux_amd64\n" +
		"0000000000000000000000000000000000000000000000000000000000000000  upkeeper_linux_arm64\n")
	os.WriteFile(filepath.Join(dir, "checksums.txt"), sums, 0o644)
	if out, err := exec.Command("ssh-keygen", "-Y", "sign", "-n", "upkeeper-release", "-f", key, filepath.Join(dir, "checksums.txt")).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	sig, _ := os.ReadFile(filepath.Join(dir, "checksums.txt.sig"))
	serve := func(sums []byte) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/checksums.txt"):
				w.Write(sums)
			case strings.HasSuffix(r.URL.Path, ".sig"):
				w.Write(sig)
			default:
				w.Write([]byte("#!/bin/sh\necho tampered\n"))
			}
		}))
	}
	run := func(srv *httptest.Server) string {
		cmd := exec.Command("sh", filepath.Join(dir, "install.sh"), "--url", "http://localhost:8080")
		cmd.Env = append(os.Environ(), "UPKEEPER_DOWNLOAD_BASE="+srv.URL+"/dl")
		out, _ := cmd.CombinedOutput()
		return string(out)
	}
	good := serve(sums)
	defer good.Close()
	if out := run(good); !strings.Contains(out, "release signature ok") || !strings.Contains(out, "checksum mismatch") {
		t.Errorf("good signature: %s", out)
	}
	bad := serve(append([]byte("1111111111111111111111111111111111111111111111111111111111111111  upkeeper_linux_amd64\n"), sums...))
	defer bad.Close()
	if out := run(bad); !strings.Contains(out, "doesn't verify") {
		t.Errorf("tampered checksums: %s", out)
	}
}

func TestUnit(t *testing.T) {
	b, _ := os.ReadFile("upkeeper.service")
	unit := string(b)
	for _, want := range []string{"ReadOnlyPaths=/etc/upkeeper", "KillMode=process", "StateDirectory=upkeeper", "UMask=0022"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %s", want)
		}
	}
	// apt, dpkg and maintainer scripts (update-grub, update-initramfs, DKMS)
	// run as children of the service, so nothing may restrict them: no
	// device policy (ProtectClock and ProtectKernelLogs imply one), no
	// memory or task cap, no private /tmp, no read-only /home (the override
	// file can live there), no syscall or address-family filter (foreign-
	// architecture maintainer scripts). See README, Security.
	forbidden := []string{
		"DeviceAllow", "DevicePolicy", "PrivateDevices", "ProtectClock", "ProtectKernelLogs",
		"ProtectKernelModules", "ProtectKernelTunables", "ProtectControlGroups",
		"MemoryMax", "MemoryHigh", "MemoryLimit", "MemorySwapMax", "TasksMax", "CPUQuota", "IOWeight",
		"ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateNetwork", "PrivateUsers", "PrivateMounts",
		"InaccessiblePaths", "TemporaryFileSystem", "RootDirectory", "RootImage",
		"SystemCallFilter", "SystemCallArchitectures", "RestrictAddressFamilies", "RestrictNamespaces",
		"RestrictSUIDSGID", "NoNewPrivileges", "CapabilityBoundingSet", "MemoryDenyWriteExecute",
		"ProtectHostname", "RestrictRealtime", "LockPersonality", "UMask=0077",
	}
	for _, line := range strings.Split(unit, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, f := range forbidden {
			if strings.HasPrefix(line, f) {
				t.Errorf("unit has %q, which can break package upgrades run by the agent", line)
			}
		}
	}
}

func TestInstallLinesUseHTTPS(t *testing.T) {
	for _, f := range []string{"install.sh", "../README.md"} {
		b, _ := os.ReadFile(f)
		for _, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "upkeeper.sh |") && !strings.Contains(line, "https://upkeeper.sh") {
				t.Errorf("%s: install line without https: %s", f, line)
			}
		}
	}
}
