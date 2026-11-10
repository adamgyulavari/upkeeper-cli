package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamgyulavari/upkeeper-cli/agent/config"
	"github.com/adamgyulavari/upkeeper-cli/agent/fakes"
)

func TestVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 || !strings.HasPrefix(out.String(), "upkeeper dev (protocol 2)") {
		t.Errorf("code=%d out=%q", code, out.String())
	}
}

func TestEnrollFlagsAfterToken(t *testing.T) {
	cloud := fakes.NewCloud()
	defer cloud.Srv.Close()
	token := "upk_e_AbC-dEf_0123456789abcdefghijklmnopqrstuvwxyz0"
	cloud.EnrollToken = token
	cfgPath := filepath.Join(t.TempDir(), "agent.json")

	var out, errb bytes.Buffer
	code := run([]string{"enroll", token, "--url", cloud.Srv.URL, "--config", cfgPath}, &out, &errb)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errb.String())
	}
	if got := cloud.Enrolls[0].EnrollToken; got != token {
		t.Errorf("token altered: %q", got)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg.AgentToken != "agt_secret" || cfg.ServerID != "srv_1" || cfg.ReportEvery != 60 || cfg.URL != cloud.Srv.URL {
		t.Errorf("config %+v %v", cfg, err)
	}

	// Reusing the token fails cleanly.
	out.Reset()
	errb.Reset()
	if code := run([]string{"enroll", "--config", cfgPath, "--url", cloud.Srv.URL, token}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "401") {
		t.Errorf("reuse: code=%d %s", code, errb.String())
	}
}

func TestEnrollRejectsPlainHTTP(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"enroll", "upk_e_x", "--url", "http://upkeeper.sh", "--config", filepath.Join(t.TempDir(), "a.json")}, &out, &errb)
	if code != 1 || !strings.Contains(errb.String(), "must use https") {
		t.Errorf("code=%d %s", code, errb.String())
	}
}

func TestRunNotEnrolled(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"run", "--config", filepath.Join(t.TempDir(), "none.json")}, &out, &errb)
	if code != 1 || !strings.Contains(errb.String(), "not enrolled") {
		t.Errorf("code=%d %s", code, errb.String())
	}
}

func TestUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 || !strings.Contains(errb.String(), "Usage:") {
		t.Errorf("code=%d", code)
	}
	if code := run([]string{"apply"}, &out, &errb); code != 2 {
		t.Errorf("unknown command code=%d", code)
	}
}
