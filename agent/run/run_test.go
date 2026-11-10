package run_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/discover"
	"github.com/adamgyulavari/upkeeper-cli/agent/fakes"
	"github.com/adamgyulavari/upkeeper-cli/agent/policy"
	"github.com/adamgyulavari/upkeeper-cli/agent/run"
	"github.com/adamgyulavari/upkeeper-cli/agent/statefile"
	"github.com/adamgyulavari/upkeeper-cli/agent/verify"
	"github.com/adamgyulavari/upkeeper-cli/agent/versions"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

const (
	dgNew   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	dgLatst = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

type env struct {
	w      *fakes.World
	e      *run.Engine
	clock  *fakes.Clock
	pol    policy.Store
	events []protocol.RunEvent
}

// setup: one project "app" with redis:7.4.1 (port 6379) and web nginx:latest
// (port 8080), one pending security update, local policy auto (dry run
// already done).
func setup(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	w := fakes.NewWorld(filepath.Join(root, "srv"))
	os.MkdirAll(w.Root, 0o755)
	w.AddService("app", "redis", "redis:7.4.1", 6379)
	w.AddService("app", "web", "nginx:latest", 8080)
	w.Apt = []collect.AptUpgrade{{Package: "openssl", From: "3.0.13-0ubuntu3.4", To: "3.0.13-0ubuntu3.5", Security: true, Origins: []string{"Ubuntu:24.04/noble-security"}}}
	w.Registry["redis@"+dgNew] = "sha256:redis-7.4.2"
	w.Registry["nginx@"+dgLatst] = "sha256:nginx-new"

	uid := os.Getuid()
	pol := policy.Store{Path: filepath.Join(root, "etc", "policy.yaml"), StateDir: filepath.Join(root, "state"), OwnerUID: &uid}
	if err := pol.SetMode(protocol.ModeAuto); err != nil {
		t.Fatal(err)
	}
	clock := &fakes.Clock{T: time.Now().Add(time.Second).Truncate(time.Second)}
	if err := pol.RecordDryRun(time.Now()); err != nil {
		t.Fatal(err)
	}
	ev := &env{w: w, clock: clock, pol: pol}
	ev.e = &run.Engine{
		Planner: w, Runner: w, Docker: w, FS: w,
		Checker:   &verify.Checker{Source: w, Now: clock.Now, Sleep: clock.Sleep},
		Locked:    func() (string, bool, error) { return "", false, nil },
		Policy:    pol,
		Trust:     run.PathChecker{OwnerUID: uid, Root: w.Root},
		StatePath: filepath.Join(root, "state", "run.json"),
		Now:       clock.Now,
	}
	return ev
}

func (ev *env) versionBump() string {
	ev.w.Updates = append(ev.w.Updates, discover.ImageUpdate{Project: "app", Service: "redis", Image: "redis:7.4.1", FromTag: "7.4.1", ToTag: "7.4.2", Change: versions.Patch, ToDigest: dgNew})
	return "image|app/redis|7.4.2"
}

func (ev *env) floating() string {
	ev.w.Updates = append(ev.w.Updates, discover.ImageUpdate{Project: "app", Service: "web", Image: "nginx:latest", FromTag: "latest", ToTag: "latest", NewDigest: true, FromDigest: "sha256:1111111111111111", ToDigest: dgLatst})
	return "image|app/web|latest@333333333333"
}

const opensslKey = "os|openssl|3.0.13-0ubuntu3.5"

func (ev *env) job(mode protocol.Mode, approved ...string) protocol.Job {
	now := ev.clock.Now()
	return protocol.Job{ID: "job_1", ServerID: "srv_1", Kind: protocol.KindRun, Mode: mode, Trigger: protocol.TriggerManual,
		Approved: approved, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(3 * time.Hour), WindowEnd: now.Add(2 * time.Hour)}
}

func (ev *env) run(j protocol.Job) protocol.RunResult {
	return ev.e.Run(context.Background(), j, func(e protocol.RunEvent) { ev.events = append(ev.events, e) })
}

func (ev *env) wrote() bool {
	for _, c := range ev.w.Calls {
		if strings.HasPrefix(c, "apt-get install") || strings.HasPrefix(c, "compose up") || strings.HasPrefix(c, "tag ") || strings.HasPrefix(c, "pull ") || c == "apt-get update" {
			return true
		}
	}
	return false
}

func checkVoice(t *testing.T, ev *env, res protocol.RunResult) {
	t.Helper()
	texts := []string{res.Summary, res.FrozenReason}
	for _, e := range ev.events {
		texts = append(texts, e.Message)
	}
	for _, s := range res.Skipped {
		texts = append(texts, s.Reason)
	}
	for _, s := range texts {
		if strings.Contains(s, "!") {
			t.Errorf("no exclamation marks: %q", s)
		}
	}
	for i, e := range ev.events {
		if e.Seq != i+1 {
			t.Errorf("event %d has seq %d", i, e.Seq)
		}
	}
}

func TestAutoRunAppliesAndVerifies(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	fkey := ev.floating()
	res := ev.run(ev.job(protocol.ModeAuto, opensslKey, key, fkey))
	if res.Outcome != protocol.OutcomeDone || len(res.Applied) != 3 || res.Frozen {
		t.Fatalf("result %+v\ncalls %v", res, ev.w.Calls)
	}
	if res.Summary != "Updated 1 package and 2 images. All 2 containers healthy." {
		t.Errorf("summary %q", res.Summary)
	}
	if c := ev.w.Container("app", "redis"); c.ImageID != "sha256:redis-7.4.2" {
		t.Errorf("redis runs %s", c.ImageID)
	}
	if c := ev.w.Container("app", "web"); c.ImageID != "sha256:nginx-new" {
		t.Errorf("web runs %s", c.ImageID)
	}
	ov, ok, err := run.ReadOverride(filepath.Join(ev.w.Root, "app", run.OverrideName))
	if !ok || err != nil || ov["redis"] != "redis:7.4.2@"+dgNew || len(ov) != 1 {
		t.Errorf("override %v %v %v", ov, ok, err)
	}
	want := []string{"apt-get update", "apt-get install openssl=3.0.13-0ubuntu3.5", "pull redis@" + dgNew, "tag sha256:redis-7.4.2 redis:7.4.2", "pull nginx@" + dgLatst, "tag sha256:nginx-new nginx:latest", "compose up app redis,web files=2"}
	if !slices.Equal(ev.w.Calls, want) {
		t.Errorf("calls\n got %v\nwant %v", ev.w.Calls, want)
	}
	if _, err := os.Stat(ev.e.StatePath); !os.IsNotExist(err) {
		t.Error("run.json left behind")
	}
	// Pulled by digest, never by tag.
	for _, c := range ev.w.Calls {
		if strings.HasPrefix(c, "pull ") && !strings.Contains(c, "@sha256:") {
			t.Errorf("pulled by tag: %s", c)
		}
	}
	checkVoice(t, ev, res)
}

func TestCrashLoopingImageIsUndone(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	ev.w.CrashLoop["sha256:redis-7.4.2"] = true
	res := ev.run(ev.job(protocol.ModeAuto, key))
	if res.Outcome != protocol.OutcomeUndone || len(res.Undone) != 1 || res.Frozen {
		t.Fatalf("result %+v", res)
	}
	if res.Summary != "redis 7.4.2 didn't come back healthy, so 7.4.1 is running again. Nothing else changed." {
		t.Errorf("summary %q", res.Summary)
	}
	if c := ev.w.Container("app", "redis"); c.ImageID != "sha256:redis:7.4.1" || c.State != "running" {
		t.Errorf("redis after L1: %+v", c)
	}
	if _, err := os.Lstat(filepath.Join(ev.w.Root, "app", run.OverrideName)); !os.IsNotExist(err) {
		t.Error("override entry not removed (file should be gone)")
	}
	undo := false
	for _, e := range ev.events {
		if e.Status == protocol.StepUndo {
			undo = true
		}
	}
	if !undo {
		t.Error("no undo event")
	}
	checkVoice(t, ev, res)
}

func TestUnhealthyFloatingTagIsRetagged(t *testing.T) {
	ev := setup(t)
	key := ev.floating()
	ev.w.Unhealthy["sha256:nginx-new"] = true
	res := ev.run(ev.job(protocol.ModeAuto, key))
	if res.Outcome != protocol.OutcomeUndone {
		t.Fatalf("result %+v", res)
	}
	if !slices.Contains(ev.w.Calls, "tag sha256:nginx:latest nginx:latest") {
		t.Errorf("old image not tagged back: %v", ev.w.Calls)
	}
	if c := ev.w.Container("app", "web"); c.ImageID != "sha256:nginx:latest" || c.Health != "healthy" {
		t.Errorf("web after L1: %+v", c)
	}
	if !strings.HasPrefix(res.Summary, "The new web image (latest) didn't come back healthy, so the previous one is running again.") {
		t.Errorf("summary %q", res.Summary)
	}
	checkVoice(t, ev, res)
}

func TestStillRedAfterUndoFreezes(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	ev.w.CrashLoop["sha256:redis-7.4.2"] = true
	ev.e.Runner = oldImageBreaks{ev.w} // the old one doesn't come back either
	res := ev.run(ev.job(protocol.ModeAuto, key))
	if res.Outcome != protocol.OutcomeStopped || !res.Frozen || !ev.pol.Frozen().Frozen {
		t.Fatalf("result %+v", res)
	}
	if !strings.Contains(res.FrozenReason, "still unhealthy after the previous images were put back") {
		t.Errorf("reason %q", res.FrozenReason)
	}
	checkVoice(t, ev, res)
}

func TestAptFailureStopsAndFreezes(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	ev.w.AptInstallErr = errors.New("apt-get: exit status 100: E: Sub-process /usr/bin/dpkg returned an error code (1)")
	res := ev.run(ev.job(protocol.ModeAuto, opensslKey, key))
	if res.Outcome != protocol.OutcomeStopped || !res.Frozen || len(res.Applied) != 0 {
		t.Fatalf("result %+v", res)
	}
	if f := ev.pol.Frozen(); !f.Frozen || !strings.Contains(f.Reason, "dpkg --audit") {
		t.Errorf("freeze %+v", f)
	}
	for _, c := range ev.w.Calls {
		if strings.HasPrefix(c, "pull") || strings.HasPrefix(c, "compose") {
			t.Errorf("went on after apt failed: %v", ev.w.Calls)
		}
	}
	if !strings.HasPrefix(res.Summary, "Stopped: apt-get stopped with an error") || !strings.HasSuffix(res.Summary, "The server is frozen until you unfreeze it.") {
		t.Errorf("summary %q", res.Summary)
	}
	// Frozen: the next job is rejected without touching anything.
	ev.w.Calls = nil
	res = ev.run(ev.job(protocol.ModeAuto, opensslKey))
	if res.Outcome != protocol.OutcomeRejected || ev.wrote() || !strings.Contains(res.Summary, "frozen") {
		t.Errorf("frozen server ran: %+v", res)
	}
	checkVoice(t, ev, res)
}

func TestAptUpdateFailureFreezes(t *testing.T) {
	ev := setup(t)
	ev.w.AptUpdateErr = errors.New("apt-get: exit status 100")
	res := ev.run(ev.job(protocol.ModeAuto, opensslKey))
	if res.Outcome != protocol.OutcomeStopped || !res.Frozen {
		t.Fatalf("%+v", res)
	}
}

func TestDpkgLockRejectsWithoutChanges(t *testing.T) {
	ev := setup(t)
	ev.versionBump()
	ev.e.Locked = func() (string, bool, error) { return "/var/lib/dpkg/lock-frontend", true, nil }
	res := ev.run(ev.job(protocol.ModeAuto, opensslKey, "image|app/redis|7.4.2"))
	if res.Outcome != protocol.OutcomeRejected || res.Frozen || ev.wrote() || ev.pol.Frozen().Frozen {
		t.Fatalf("result %+v calls %v", res, ev.w.Calls)
	}
	if !strings.Contains(res.Summary, "lock-frontend is locked") {
		t.Errorf("summary %q", res.Summary)
	}
	// The rejected run doesn't count against the run limit.
	ev.e.Locked = func() (string, bool, error) { return "", false, nil }
	if res := ev.run(ev.job(protocol.ModeAuto, opensslKey)); res.Outcome != protocol.OutcomeDone {
		t.Errorf("after the lock cleared: %+v", res)
	}
}

func TestUnapprovedItemsAreSkipped(t *testing.T) {
	ev := setup(t)
	ev.versionBump()
	res := ev.run(ev.job(protocol.ModeAuto, opensslKey, "image|app/ghost|9.9.9"))
	if res.Outcome != protocol.OutcomePartial {
		t.Fatalf("result %+v", res)
	}
	reasons := map[string]string{}
	for _, s := range res.Skipped {
		reasons[s.Item.Subject] = s.Reason
	}
	if !strings.Contains(reasons["app/redis"], "Not approved") {
		t.Errorf("redis: %q", reasons["app/redis"])
	}
	if !strings.Contains(reasons["app/ghost"], "No longer pending") {
		t.Errorf("ghost: %q", reasons["app/ghost"])
	}
	for _, c := range ev.w.Calls {
		if strings.Contains(c, "redis") {
			t.Errorf("unapproved redis touched: %s", c)
		}
	}
}

func TestApprovedButFlaggedIsSkipped(t *testing.T) {
	ev := setup(t)
	// The cloud approves a major version; the agent's classifier says flagged.
	ev.w.Updates = append(ev.w.Updates, discover.ImageUpdate{Project: "app", Service: "redis", FromTag: "7.4.1", ToTag: "8.0.0", Change: versions.Major, ToDigest: dgNew})
	res := ev.run(ev.job(protocol.ModeAuto, "image|app/redis|8.0.0"))
	if len(res.Applied) != 0 || ev.wrote() || res.Outcome != protocol.OutcomePartial {
		t.Fatalf("flagged item applied: %+v %v", res, ev.w.Calls)
	}
	if !strings.Contains(res.Skipped[len(res.Skipped)-1].Reason, "now rates this flagged") {
		t.Errorf("%+v", res.Skipped)
	}
}

func TestImageSettingComposeLabelsIsNeverTouched(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	ev.w.ImageLabels["sha256:redis:7.4.1"] = map[string]string{"com.docker.compose.project.working_dir": "/var/lib/docker/volumes/x/_data"}
	res := ev.run(ev.job(protocol.ModeAuto, key))
	if len(res.Applied) != 0 || ev.wrote() {
		t.Fatalf("applied: %+v %v", res, ev.w.Calls)
	}
}

func TestObservePolicyRejects(t *testing.T) {
	ev := setup(t)
	ev.pol.SetMode(protocol.ModeObserve)
	res := ev.run(ev.job(protocol.ModeAuto, opensslKey))
	if res.Outcome != protocol.OutcomeRejected || ev.wrote() || !strings.Contains(res.Summary, "upkeeper policy set auto") {
		t.Fatalf("%+v", res)
	}
	checkVoice(t, ev, res)
}

func TestFirstRunAfterAutoIsDryRun(t *testing.T) {
	ev := setup(t)
	time.Sleep(10 * time.Millisecond)
	ev.pol.SetMode(protocol.ModeAuto) // rewritten after the recorded dry run
	ev.clock.T = time.Now().Add(time.Second)
	res := ev.run(ev.job(protocol.ModeAuto, opensslKey))
	if res.Mode != protocol.ModeDryRun || ev.wrote() {
		t.Fatalf("%+v %v", res, ev.w.Calls)
	}
	// And now the auto run goes ahead.
	ev.clock.T = ev.clock.T.Add(time.Minute)
	if res := ev.run(ev.job(protocol.ModeAuto, opensslKey)); res.Mode != protocol.ModeAuto || res.Outcome != protocol.OutcomeDone {
		t.Errorf("second run: %+v", res)
	}
	// A third full run within 20 hours is refused locally.
	ev.clock.T = ev.clock.T.Add(time.Hour)
	if res := ev.run(ev.job(protocol.ModeAuto, opensslKey)); res.Outcome != protocol.OutcomeRejected || !strings.Contains(res.Summary, "one every 20 hours") {
		t.Errorf("third run: %+v", res)
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	fkey := ev.floating()
	res := ev.run(ev.job(protocol.ModeDryRun, opensslKey, key, fkey))
	if ev.wrote() || res.Mode != protocol.ModeDryRun || res.Outcome != protocol.OutcomeDone {
		t.Fatalf("%+v calls %v", res, ev.w.Calls)
	}
	if res.Summary != "Dry run: would update 1 package and 2 images. Nothing was changed." {
		t.Errorf("summary %q", res.Summary)
	}
	would := 0
	for _, e := range ev.events {
		if strings.HasPrefix(e.Message, "Would ") {
			would++
		}
	}
	if would < 4 {
		t.Errorf("only %d would-events: %+v", would, ev.events)
	}
	if _, err := os.Lstat(filepath.Join(ev.w.Root, "app", run.OverrideName)); !os.IsNotExist(err) {
		t.Error("dry run wrote the override")
	}
	checkVoice(t, ev, res)
}

func TestLocalDryRunPolicyNarrowsAutoJob(t *testing.T) {
	ev := setup(t)
	ev.pol.SetMode(protocol.ModeDryRun)
	res := ev.run(ev.job(protocol.ModeAuto, opensslKey))
	if res.Mode != protocol.ModeDryRun || ev.wrote() {
		t.Fatalf("%+v", res)
	}
}

func TestWindowEndsMidRun(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	j := ev.job(protocol.ModeAuto, opensslKey, key)
	j.WindowEnd = ev.clock.Now().Add(time.Minute) // the OS check alone takes 3 minutes
	res := ev.run(j)
	if res.Outcome != protocol.OutcomePartial || len(res.Applied) != 1 {
		t.Fatalf("%+v", res)
	}
	if res.Skipped[0].Reason != "The maintenance window ended before this project's turn." {
		t.Errorf("%+v", res.Skipped)
	}
	for _, c := range ev.w.Calls {
		if strings.HasPrefix(c, "pull") {
			t.Errorf("pulled after the window: %v", ev.w.Calls)
		}
	}
	// A job that arrives after its window is rejected.
	j2 := ev.job(protocol.ModeAuto, opensslKey)
	j2.WindowEnd = ev.clock.Now().Add(-time.Minute)
	if res := ev.run(j2); res.Outcome != protocol.OutcomeRejected {
		t.Errorf("late job: %+v", res)
	}
}

func TestCrashRecovery(t *testing.T) {
	ev := setup(t)
	statefile.WriteJSON(ev.e.StatePath, run.State{JobID: "job_9", Mode: protocol.ModeAuto, Step: protocol.StepImages,
		Applied: []protocol.Item{{Layer: protocol.LayerOS, Subject: "openssl"}}})
	// A job can't start while a run is recorded.
	if res := ev.run(ev.job(protocol.ModeAuto, opensslKey)); res.Outcome != protocol.OutcomeRejected || ev.wrote() {
		t.Fatalf("ran over a leftover run: %+v", res)
	}
	res := ev.e.Recover()
	if res == nil || res.JobID != "job_9" || res.Outcome != protocol.OutcomeStopped || !res.Frozen || len(res.Applied) != 1 {
		t.Fatalf("recover: %+v", res)
	}
	if f := ev.pol.Frozen(); !f.Frozen || !strings.Contains(f.Reason, "images step") {
		t.Errorf("freeze %+v", f)
	}
	if ev.e.Recover() != nil {
		t.Error("recovered twice")
	}
	// A cut-off dry run doesn't freeze.
	ev.pol.Unfreeze()
	statefile.WriteJSON(ev.e.StatePath, run.State{JobID: "job_10", Mode: protocol.ModeDryRun, Step: protocol.StepOS})
	if res := ev.e.Recover(); res == nil || res.Frozen || ev.pol.Frozen().Frozen {
		t.Errorf("dry run recovery: %+v", res)
	}
}

func TestAptSimulationGuards(t *testing.T) {
	t.Run("would remove a package", func(t *testing.T) {
		ev := setup(t)
		ev.w.AptSimExtra = []string{"Remv libfoo1 [1.0]"}
		res := ev.run(ev.job(protocol.ModeAuto, opensslKey))
		if res.Outcome != protocol.OutcomePartial || slices.ContainsFunc(ev.w.Calls, func(c string) bool { return strings.HasPrefix(c, "apt-get install") }) {
			t.Fatalf("%+v %v", res, ev.w.Calls)
		}
		if !strings.Contains(res.Skipped[0].Reason, "would remove libfoo1") {
			t.Errorf("%+v", res.Skipped)
		}
	})
	t.Run("would change an unplanned package", func(t *testing.T) {
		ev := setup(t)
		ev.w.AptSimExtra = []string{"Inst docker-ce [5:28.3.1] (5:28.3.2 Docker CE [amd64])"}
		res := ev.run(ev.job(protocol.ModeAuto, opensslKey))
		if !strings.Contains(res.Skipped[0].Reason, "would also change docker-ce") {
			t.Errorf("%+v", res.Skipped)
		}
	})
	t.Run("planned version gone after apt-get update", func(t *testing.T) {
		ev := setup(t)
		ev.w.Apt = append(ev.w.Apt, collect.AptUpgrade{Package: "curl", From: "8.5.0-2ubuntu10.4", To: "8.5.0-2ubuntu10.5", Security: true, Origins: []string{"Ubuntu:24.04/noble-security"}})
		ev.w.AptGone["curl"] = true
		res := ev.run(ev.job(protocol.ModeAuto, opensslKey, "os|curl|8.5.0-2ubuntu10.5"))
		if res.Outcome != protocol.OutcomePartial || !slices.Contains(ev.w.Calls, "apt-get install openssl=3.0.13-0ubuntu3.5") {
			t.Fatalf("%+v %v", res, ev.w.Calls)
		}
		if !strings.Contains(res.Skipped[0].Reason, "newer version replaced it") {
			t.Errorf("%+v", res.Skipped)
		}
	})
	t.Run("docker family and held packages never reach apt", func(t *testing.T) {
		ev := setup(t)
		ev.w.Apt = append(ev.w.Apt,
			collect.AptUpgrade{Package: "containerd.io", From: "1.7.24-1", To: "1.7.25-1", Origins: []string{"Docker CE:noble/noble"}},
			collect.AptUpgrade{Package: "vim", From: "2:9.1.0016-1ubuntu7.3", To: "2:9.1.0016-1ubuntu7.4", Origins: []string{"Ubuntu:24.04/noble-updates"}})
		ev.w.Held = []string{"vim"}
		res := ev.run(ev.job(protocol.ModeAuto, opensslKey, "docker|containerd.io|1.7.25-1", "os|vim|2:9.1.0016-1ubuntu7.4"))
		if !slices.Contains(ev.w.Calls, "apt-get install openssl=3.0.13-0ubuntu3.5") {
			t.Fatalf("%v", ev.w.Calls)
		}
		for _, c := range ev.w.Calls {
			if strings.Contains(c, "containerd") || strings.Contains(c, "vim") {
				t.Errorf("touched: %s", c)
			}
		}
		if res.Outcome != protocol.OutcomePartial {
			t.Errorf("%+v", res)
		}
	})
}

func TestSecurityOnlyRun(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	ev.w.Apt = append(ev.w.Apt, collect.AptUpgrade{Package: "tzdata", From: "2024a-3ubuntu1.1", To: "2024b-0ubuntu0.24.04", Origins: []string{"Ubuntu:24.04/noble-updates"}})
	j := ev.job(protocol.ModeAuto, opensslKey, key, "os|tzdata|2024b-0ubuntu0.24.04")
	j.SecurityOnly = true
	res := ev.run(j)
	if len(res.Applied) != 1 || res.Applied[0].Subject != "openssl" || res.Outcome != protocol.OutcomeDone {
		t.Fatalf("%+v %v", res, ev.w.Calls)
	}
}

func TestPullFailureSkipsWithoutChanges(t *testing.T) {
	ev := setup(t)
	key := ev.versionBump()
	delete(ev.w.Registry, "redis@"+dgNew)
	res := ev.run(ev.job(protocol.ModeAuto, key))
	if res.Outcome != protocol.OutcomePartial || res.Frozen {
		t.Fatalf("%+v", res)
	}
	for _, c := range ev.w.Calls {
		if strings.HasPrefix(c, "compose") || strings.HasPrefix(c, "tag") {
			t.Errorf("changed after a failed pull: %v", ev.w.Calls)
		}
	}
}

func TestOSUpdateBreakingAContainerFreezes(t *testing.T) {
	ev := setup(t)
	// The OS update takes a host service down (as needrestart might).
	ev.w.AptInstallErr = nil
	orig := ev.w.Apt
	_ = orig
	ev.e.Runner = breakAfterInstall{ev.w}
	res := ev.run(ev.job(protocol.ModeAuto, opensslKey))
	if res.Outcome != protocol.OutcomeStopped || !res.Frozen || !strings.Contains(res.FrozenReason, "OS updates can't be undone automatically") {
		t.Fatalf("%+v", res)
	}
}

type breakAfterInstall struct{ w *fakes.World }

func (b breakAfterInstall) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := b.w.Run(ctx, name, args...)
	if name == "apt-get" && slices.Contains(args, "--only-upgrade") && !slices.Contains(args, "-s") {
		b.w.FailedUnits = append(b.w.FailedUnits, "nginx.service")
	}
	return out, err
}

// oldImageBreaks makes redis 7.4.1 crash too once anything was recreated.
type oldImageBreaks struct{ w *fakes.World }

func (o oldImageBreaks) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := o.w.Run(ctx, name, args...)
	if name == "docker" {
		o.w.CrashLoop["sha256:redis:7.4.1"] = true
	}
	return out, err
}
