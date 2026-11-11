package run_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/classify"
	"github.com/adamgyulavari/upkeeper-cli/agent/run"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

func composeRan(ev *env) bool {
	for _, c := range ev.w.Calls {
		if strings.HasPrefix(c, "compose up") {
			return true
		}
	}
	return false
}

func skipReason(res protocol.RunResult, subject string) string {
	for _, s := range res.Skipped {
		if s.Item.Subject == subject {
			return s.Reason
		}
	}
	return ""
}

// H-01: a stopped service (or a finished one-shot job) is never started.
func TestStoppedServiceIsLeftAlone(t *testing.T) {
	ev := setup(t)
	fkey := ev.floating()
	c := ev.w.Container("app", "web")
	c.State, c.Health, c.RestartPolicy = "exited", "none", "no"
	res := ev.run(ev.job(protocol.ModeAuto, fkey))
	if composeRan(ev) || ev.w.Container("app", "web").State != "exited" || len(res.Applied) != 0 {
		t.Fatalf("stopped service touched: %+v %v", res, ev.w.Calls)
	}
	if !strings.Contains(skipReason(res, "app/web"), "wasn't running") {
		t.Errorf("%+v", res.Skipped)
	}
}

// B-01: compose files edited since the last `up` → skip with a risk.
func TestComposeDriftSkipsProject(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	ev.w.Drift["app/redis"] = "volumes changed"
	res := ev.run(ev.job(protocol.ModeAuto, key))
	if ev.wrote() || len(res.Applied) != 0 || res.Frozen {
		t.Fatalf("%+v %v", res, ev.w.Calls)
	}
	var r protocol.SkippedItem
	for _, s := range res.Skipped {
		if s.Item.Subject == "app/redis" {
			r = s
		}
	}
	if r.Code != run.RiskComposeMismatch || !strings.Contains(r.Reason, "no longer match what's running") || !strings.Contains(r.Reason, "docker compose up -d") {
		t.Errorf("%+v", r)
	}
	if len(res.Risks) != 1 || res.Risks[0].Code != run.RiskComposeMismatch || res.Risks[0].Subject != "app" {
		t.Errorf("risks %+v", res.Risks)
	}
	// The report sees the risk until a run finds the project fine again.
	mem := &run.Memory{Dir: filepath.Dir(ev.e.StatePath)}
	if rs := mem.Risks(ev.clock.Now()); len(rs) != 1 {
		t.Errorf("stored risks %+v", rs)
	}
	delete(ev.w.Drift, "app/redis")
	ev.clock.T = ev.clock.T.Add(21 * time.Hour)
	if res := ev.run(ev.job(protocol.ModeAuto, key)); res.Outcome != protocol.OutcomeDone {
		t.Fatalf("after fixing: %+v", res)
	}
	if rs := mem.Risks(ev.clock.Now()); len(rs) != 0 {
		t.Errorf("risk not cleared: %+v", rs)
	}
}

// B-01: variables set in a shell when the project was started.
func TestUnsetVariablesSkipProject(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	ev.w.Unset["app"] = []string{"DB_PASSWORD"}
	res := ev.run(ev.job(protocol.ModeAuto, key))
	if ev.wrote() || !strings.Contains(skipReason(res, "app/redis"), "DB_PASSWORD") {
		t.Fatalf("%+v %v", res, ev.w.Calls)
	}
}

// B-01: started with --scale.
func TestScaledServiceSkipsProject(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	ev.w.AddService("app", "redis", "redis:7.4.1", 0) // a second container
	res := ev.run(ev.job(protocol.ModeAuto, key))
	if ev.wrote() || !strings.Contains(skipReason(res, "app/redis"), "--scale") {
		t.Fatalf("%+v %v", res, ev.w.Calls)
	}
}

// H-02: after one version update the project is still updatable.
func TestSecondUpdateAfterOverride(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	if res := ev.run(ev.job(protocol.ModeAuto, key)); res.Outcome != protocol.OutcomeDone {
		t.Fatalf("first: %+v", res)
	}
	// The redis container now lists the override in its labels; web doesn't.
	ev.w.Updates = nil
	fkey := ev.floating()
	ev.clock.T = ev.clock.T.Add(21 * time.Hour)
	ev.w.Calls = nil
	res := ev.run(ev.job(protocol.ModeAuto, fkey))
	if res.Outcome != protocol.OutcomeDone || len(res.Applied) != 1 {
		t.Fatalf("second: %+v %v", res, ev.w.Calls)
	}
}

// H-03: an override that can't be written changes nothing and recreates nothing.
func TestOverrideWriteErrorChangesNothing(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write a read-only directory")
	}
	ev := setup(t)
	key := ev.versionBump()
	dir := filepath.Join(ev.w.Root, "app")
	os.Chmod(dir, 0o555)
	defer os.Chmod(dir, 0o755)
	res := ev.run(ev.job(protocol.ModeAuto, key))
	if ev.wrote() || len(res.Undone) != 0 || res.Frozen {
		t.Fatalf("%+v %v", res, ev.w.Calls)
	}
}

// H-04: a job container that finishes on its own doesn't freeze the server.
func TestFinishedJobDoesntFreeze(t *testing.T) {
	ev := setup(t)
	c := ev.w.AddService("cron", "backup", "restic:0.17.0", 0)
	c.RestartPolicy = "no"
	ev.e.Runner = hookRunner{ev, func() { c.State, c.ExitCode = "exited", 0 }}
	res := ev.run(ev.job(protocol.ModeAuto, opensslKey))
	if res.Frozen || res.Outcome != protocol.OutcomeDone {
		t.Fatalf("%+v", res)
	}
	// The same container failing (exit 1) is a real problem.
	ev2 := setup(t)
	c2 := ev2.w.AddService("cron", "backup", "restic:0.17.0", 0)
	c2.RestartPolicy = "no"
	ev2.e.Runner = hookRunner{ev2, func() { c2.State, c2.ExitCode = "exited", 1 }}
	if res := ev2.run(ev2.job(protocol.ModeAuto, opensslKey)); !res.Frozen {
		t.Fatalf("exit 1 passed: %+v", res)
	}
}

type hookRunner struct {
	ev    *env
	after func()
}

func (h hookRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := h.ev.w.Run(ctx, name, args...)
	if name == "apt-get" && strings.Contains(strings.Join(args, " "), "install --only-upgrade") && !strings.Contains(strings.Join(args, " "), " -s ") {
		h.after()
	}
	return out, err
}

// H-05: a healthcheck that can't report within the longest wait skips the project.
func TestSlowHealthcheckSkipsProject(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	ev.w.Container("app", "redis").HealthFirst = 15 * time.Minute
	res := ev.run(ev.job(protocol.ModeAuto, key))
	if ev.wrote() || !strings.Contains(skipReason(res, "app/redis"), "first reports after") {
		t.Fatalf("%+v", res)
	}
}

type panicPlanner struct{}

func (panicPlanner) Plan(context.Context) (protocol.Report, classify.Input) { panic("boom") }

// M-04: a panic still returns a deliverable result.
func TestPanicResultNamesTheJob(t *testing.T) {
	ev := setup(t)
	ev.e.Planner = panicPlanner{}
	res := ev.run(ev.job(protocol.ModeAuto, opensslKey))
	if res.JobID != "job_1" || res.Outcome != protocol.OutcomeStopped || !res.Frozen || res.Summary == "" {
		t.Fatalf("%+v", res)
	}
}

// M-07: a stop during the project check leaves the update in place and freezes, without undo.
func TestInterruptedCheckDoesntUndo(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	ev.e.Checker.Sleep = func(c context.Context, d time.Duration) bool {
		n++
		if n == 2 {
			cancel()
		}
		return ev.clock.Sleep(c, d)
	}
	res := ev.e.Run(ctx, ev.job(protocol.ModeAuto, key), func(protocol.RunEvent) {})
	if len(res.Undone) != 0 || !res.Frozen || !strings.Contains(res.FrozenReason, "was stopped") {
		t.Fatalf("%+v %v", res, ev.w.Calls)
	}
	ups := 0
	for _, c := range ev.w.Calls {
		if strings.HasPrefix(c, "compose up") {
			ups++
		}
	}
	if ups != 1 {
		t.Errorf("compose up %d times: %v", ups, ev.w.Calls)
	}
}

// M-01: an image that was put back isn't tried again.
func TestUndoneImageIsRemembered(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	ev.w.CrashLoop["sha256:redis-7.4.2"] = true
	if res := ev.run(ev.job(protocol.ModeAuto, key)); res.Outcome != protocol.OutcomeUndone {
		t.Fatalf("%+v", res)
	}
	ev.clock.T = ev.clock.T.Add(21 * time.Hour)
	ev.w.Calls = nil
	res := ev.run(ev.job(protocol.ModeAuto, key))
	if ev.wrote() || !strings.Contains(skipReason(res, "app/redis"), "was put back on") {
		t.Fatalf("%+v %v", res, ev.w.Calls)
	}
}

// Docker installed but not answering: pre-flight fails.
func TestPreflightFailsWithoutDocker(t *testing.T) {
	ev := setup(t)
	ev.w.NoDocker = true
	ev.e.DockerInstalled = func() bool { return true }
	res := ev.run(ev.job(protocol.ModeAuto, opensslKey))
	if res.Outcome != protocol.OutcomeRejected || ev.wrote() || !strings.Contains(res.Summary, "isn't answering") {
		t.Fatalf("%+v", res)
	}
}

// Approved items a stopped run didn't reach are listed as skipped.
func TestStoppedRunListsUnreachedItems(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	ev.e.Runner = breakAfterInstall{ev.w}
	res := ev.run(ev.job(protocol.ModeAuto, opensslKey, key))
	if !res.Frozen || !strings.Contains(skipReason(res, "app/redis"), "stopped before") {
		t.Fatalf("%+v", res)
	}
}

// The daily security run lists approved non-security items as skipped.
func TestSecurityRunListsOthers(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	j := ev.job(protocol.ModeAuto, opensslKey, key)
	j.SecurityOnly = true
	res := ev.run(j)
	if !strings.Contains(skipReason(res, "app/redis"), "security run") {
		t.Fatalf("%+v", res.Skipped)
	}
}
