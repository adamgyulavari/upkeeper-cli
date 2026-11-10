package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamgyulavari/upkeeper-cli/agent/config"
	"github.com/adamgyulavari/upkeeper-cli/agent/fakes"
	"github.com/adamgyulavari/upkeeper-cli/agent/policy"
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

func dirs(t *testing.T) []string {
	uid := os.Getuid()
	policyOwner = &uid
	d := t.TempDir()
	os.Chmod(d, 0o755)
	os.MkdirAll(filepath.Join(d, "etc"), 0o755)
	return []string{"--policy", filepath.Join(d, "etc", "policy.yaml"), "--state-dir", filepath.Join(d, "state"), "--config", filepath.Join(d, "etc", "agent.json")}
}

func TestPolicyCommands(t *testing.T) {
	flags := dirs(t)
	var out, errb bytes.Buffer
	isRoot = func() bool { return false }
	if code := run(append([]string{"policy", "set", "auto"}, flags...), &out, &errb); code != 1 || !strings.Contains(errb.String(), "needs root") {
		t.Errorf("non-root set: %d %s", code, errb.String())
	}
	isRoot = func() bool { return true }
	defer func() { isRoot = func() bool { return os.Geteuid() == 0 } }()
	out.Reset()
	if code := run(append([]string{"policy", "show"}, flags...), &out, &errb); code != 0 || !strings.Contains(out.String(), "Mode: observe") {
		t.Errorf("show: %s", out.String())
	}
	out.Reset()
	if code := run(append([]string{"policy", "set", "auto"}, flags...), &out, &errb); code != 0 || !strings.Contains(out.String(), "dry run first") {
		t.Errorf("set: %d %s %s", code, out.String(), errb.String())
	}
	if code := run(append([]string{"policy", "set", "yolo"}, flags...), &out, &errb); code != 2 {
		t.Errorf("bad mode: %d", code)
	}
	out.Reset()
	if code := run(append([]string{"policy", "window", "sun 03:00-05:00"}, flags...), &out, &errb); code != 0 {
		t.Errorf("window: %d %s", code, errb.String())
	}
	out.Reset()
	run(append([]string{"status"}, flags...), &out, &errb)
	for _, want := range []string{"Mode: auto", "Window: sun 03:00-05:00", "Frozen: no", "Root keys: none in this build", "Job key: no job has arrived yet"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status lacks %q:\n%s", want, out.String())
		}
	}
}

func TestUnfreeze(t *testing.T) {
	flags := dirs(t)
	isRoot = func() bool { return true }
	defer func() { isRoot = func() bool { return os.Geteuid() == 0 } }()
	var out, errb bytes.Buffer
	stateDir := flags[3]
	uid := os.Getuid()
	s := policy.Store{Path: flags[1], StateDir: stateDir, OwnerUID: &uid}
	s.FreezeNow("redis didn't come back.", "job_1")
	if code := run(append([]string{"unfreeze"}, flags...), &out, &errb); code != 0 || !strings.Contains(out.String(), "redis didn't come back.") {
		t.Errorf("unfreeze: %d %s %s", code, out.String(), errb.String())
	}
	if s.Frozen().Frozen {
		t.Error("still frozen")
	}
	out.Reset()
	run(append([]string{"unfreeze"}, flags...), &out, &errb)
	if !strings.Contains(out.String(), "isn't frozen") {
		t.Error(out.String())
	}
}

func TestEnrollTokenFromEnvAndStdin(t *testing.T) {
	cloud := fakes.NewCloud()
	defer cloud.Srv.Close()
	cfgPath := filepath.Join(t.TempDir(), "agent.json")
	var out, errb bytes.Buffer
	if code := runCLI([]string{"enroll", "-", "--url", cloud.Srv.URL, "--config", cfgPath}, strings.NewReader("enr_test\n"), &out, &errb); code != 0 {
		t.Fatalf("stdin: %d %s", code, errb.String())
	}
	cloud.EnrollToken = "enr_two"
	t.Setenv("UPKEEPER_ENROLL_TOKEN", "enr_two")
	if code := run([]string{"enroll", "--url", cloud.Srv.URL, "--config", cfgPath}, &out, &errb); code != 0 {
		t.Fatalf("env: %d %s", code, errb.String())
	}
}
