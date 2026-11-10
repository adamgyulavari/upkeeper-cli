package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

func TestRootSignsOnlineKey(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := run([]string{"gen-root", "-id", "r1", "-out", filepath.Join(dir, "root.key")}, nil, &out); err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(`ROOT_KEYS=(\S+)`).FindStringSubmatch(out.String())
	roots, err := protocol.ParseRootKeys(line[1])
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"gen-online", "-id", "k1", "-out", filepath.Join(dir, "online.key")}, nil, &out); err != nil {
		t.Fatal(err)
	}
	pub := regexp.MustCompile(`Public key: (\S+)`).FindStringSubmatch(out.String())[1]
	out.Reset()
	if err := run([]string{"sign-cert", "-root", filepath.Join(dir, "root.key"), "-root-id", "r1", "-key-id", "k1", "-pub", pub}, nil, &out); err != nil {
		t.Fatal(err)
	}
	var c protocol.KeyCert
	if err := json.Unmarshal(out.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(roots, time.Now()); err != nil {
		t.Fatalf("cert doesn't verify: %v", err)
	}
	var shown bytes.Buffer
	if err := run([]string{"show-cert"}, strings.NewReader(out.String()), &shown); err != nil || !strings.Contains(shown.String(), "Key ID: k1") {
		t.Errorf("%s %v", shown.String(), err)
	}
	// Never overwrite a key file.
	if err := run([]string{"gen-root", "-id", "r1", "-out", filepath.Join(dir, "root.key")}, nil, &out); err == nil {
		t.Error("overwrote the root key")
	}
}
