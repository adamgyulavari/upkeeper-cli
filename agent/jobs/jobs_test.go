package jobs

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/cloudclient"
	"github.com/adamgyulavari/upkeeper-cli/agent/fakes"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

type fakeEngine struct {
	ran     []string
	recover *protocol.RunResult
}

func (f *fakeEngine) Run(ctx context.Context, j protocol.Job, emit func(protocol.RunEvent)) protocol.RunResult {
	f.ran = append(f.ran, j.ID)
	for i := 1; i <= 3; i++ {
		emit(protocol.RunEvent{Seq: i, Step: protocol.StepPlan, Status: protocol.StepOK, Message: "step"})
	}
	return protocol.RunResult{JobID: j.ID, Mode: j.Mode, Outcome: protocol.OutcomeDone, Summary: "Nothing to update."}
}

func (f *fakeEngine) Recover() *protocol.RunResult {
	r := f.recover
	f.recover = nil
	return r
}

type tenv struct {
	cloud  *fakes.Cloud
	signer *fakes.Signer
	eng    *fakeEngine
	loop   *Loop
	now    time.Time
}

func newEnv(t *testing.T) *tenv {
	now := time.Now().UTC().Truncate(time.Second)
	cloud := fakes.NewCloud()
	t.Cleanup(cloud.Srv.Close)
	s := fakes.NewSigner(now)
	eng := &fakeEngine{}
	l := &Loop{
		Client:   &cloudclient.Client{Base: cloud.Srv.URL, Token: cloud.AgentToken},
		ServerID: "srv_1", Roots: s.Roots, Engine: eng, StateDir: t.TempDir(), Wait: time.Second,
		Now: func() time.Time { return now }, Logf: t.Logf,
	}
	return &tenv{cloud: cloud, signer: s, eng: eng, loop: l, now: now}
}

func (e *tenv) job(id string) protocol.Job {
	return protocol.Job{ID: id, ServerID: "srv_1", Kind: protocol.KindRun, Mode: protocol.ModeDryRun, Trigger: protocol.TriggerManual,
		IssuedAt: e.now, NotBefore: e.now, ExpiresAt: e.now.Add(2 * time.Hour), WindowEnd: e.now.Add(time.Hour)}
}

func TestGoodJobRunsAndReports(t *testing.T) {
	e := newEnv(t)
	e.cloud.AddJob(e.signer.Sign(e.job("job_1")))
	if err := e.loop.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(e.eng.ran) != 1 {
		t.Fatalf("ran %v", e.eng.ran)
	}
	if evs := e.cloud.RunEvents("job_1"); len(evs) != 3 {
		t.Errorf("events %v", evs)
	}
	if rs := e.cloud.RunResults("job_1"); len(rs) != 1 || rs[0].Outcome != protocol.OutcomeDone {
		t.Errorf("results %v", rs)
	}
	if k, ok := LoadKeyInfo(e.loop.StateDir); !ok || k.KeyID != "online-1" || !strings.HasPrefix(k.Fingerprint, "SHA256:") {
		t.Errorf("key info %+v", k)
	}
	// Nothing queued: the poll returns no job.
	if err := e.loop.Once(context.Background()); err != nil || len(e.eng.ran) != 1 {
		t.Errorf("empty poll: %v %v", err, e.eng.ran)
	}
}

func TestBadJobsAreRefusedAndReported(t *testing.T) {
	e := newEnv(t)
	tampered := e.signer.Sign(e.job("job_t"))
	tampered.Payload = []byte(strings.Replace(string(tampered.Payload), `"dry-run"`, `"auto"   `, 1))
	noCert := e.signer.Sign(e.job("job_n"))
	noCert.Cert = nil
	other := fakes.NewSigner(e.now) // a key no root of ours certified
	foreign := other.Sign(e.job("job_f"))
	expired := e.job("job_e")
	expired.IssuedAt, expired.NotBefore, expired.ExpiresAt, expired.WindowEnd = e.now.Add(-5*time.Hour), e.now.Add(-5*time.Hour), e.now.Add(-time.Hour), e.now.Add(-2*time.Hour)
	long := e.job("job_l")
	long.ExpiresAt = e.now.Add(24 * time.Hour)
	for _, sj := range []protocol.SignedJob{tampered, noCert, foreign, e.signer.Sign(expired), e.signer.Sign(long)} {
		e.cloud.AddJob(sj)
		if err := e.loop.Once(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.eng.ran) != 0 {
		t.Fatalf("ran a bad job: %v", e.eng.ran)
	}
	want := map[string]string{
		"job_t": "signature doesn't verify",
		"job_n": "isn't signed with a key this agent trusts",
		"job_f": "isn't signed with a key this agent trusts",
		"job_e": "expired",
		"job_l": "longer than this agent allows",
	}
	for id, w := range want {
		rs := e.cloud.RunResults(id)
		if len(rs) != 1 || rs[0].Outcome != protocol.OutcomeRejected || !strings.Contains(rs[0].Summary, w) {
			t.Errorf("%s: %+v", id, rs)
		}
	}
}

func TestNoRootsMeansNoJobs(t *testing.T) {
	e := newEnv(t)
	e.loop.Roots = nil
	e.cloud.AddJob(e.signer.Sign(e.job("job_1")))
	e.loop.Once(context.Background())
	if len(e.eng.ran) != 0 {
		t.Fatal("ran without roots")
	}
	if rs := e.cloud.RunResults("job_1"); len(rs) != 1 || !strings.Contains(rs[0].Summary, "no job-signing root key") {
		t.Errorf("%+v", rs)
	}
}

func TestReplayIsNotRun(t *testing.T) {
	e := newEnv(t)
	sj := e.signer.Sign(e.job("job_1"))
	e.cloud.AddJob(sj)
	e.cloud.AddJob(sj) // redelivered, or replayed by someone on the path
	e.loop.Once(context.Background())
	e.loop.Once(context.Background())
	if len(e.eng.ran) != 1 {
		t.Fatalf("ran %d times", len(e.eng.ran))
	}
	if rs := e.cloud.RunResults("job_1"); len(rs) != 2 || rs[1].Outcome != protocol.OutcomeDone {
		t.Errorf("result not re-sent: %+v", rs)
	}
	// A job that was started but has no result (agent restarted mid-run) is refused.
	seen, _ := loadSeen(e.loop.StateDir)
	seen.Jobs["job_2"] = &seenJob{ExpiresAt: e.now.Add(time.Hour)}
	saveSeen(e.loop.StateDir, seen)
	e.cloud.AddJob(e.signer.Sign(e.job("job_2")))
	e.loop.Once(context.Background())
	if len(e.eng.ran) != 1 {
		t.Errorf("re-ran a started job")
	}
	if rs := e.cloud.RunResults("job_2"); len(rs) != 1 || rs[0].Outcome != protocol.OutcomeRejected {
		t.Errorf("%+v", rs)
	}
	// An unreadable replay store blocks jobs.
	os.WriteFile(seenPath(e.loop.StateDir), []byte("{"), 0o600)
	e.cloud.AddJob(e.signer.Sign(e.job("job_3")))
	e.loop.Once(context.Background())
	if len(e.eng.ran) != 1 {
		t.Error("ran with a corrupt replay store")
	}
}

func TestSeenPrune(t *testing.T) {
	now := time.Now()
	f := seenFile{Jobs: map[string]*seenJob{"old": {ExpiresAt: now.Add(-2 * time.Hour)}, "new": {ExpiresAt: now.Add(time.Hour)}}}
	f.prune(now)
	if _, ok := f.Jobs["old"]; ok || f.Jobs["new"] == nil {
		t.Errorf("%v", f.Jobs)
	}
}

func TestResultsWaitInTheOutbox(t *testing.T) {
	e := newEnv(t)
	e.cloud.FailPosts.Store(100)
	e.eng.recover = &protocol.RunResult{JobID: "job_crashed", Outcome: protocol.OutcomeStopped, Frozen: true}
	ctx, cancel := context.WithCancel(context.Background())
	e.loop.Sleep = func(context.Context, time.Duration) bool { cancel(); return false }
	e.loop.Client.Base = "http://127.0.0.1:1" // cloud unreachable
	e.loop.Run(ctx)
	if _, err := os.Stat(e.loop.outboxPath()); err != nil {
		t.Fatal("result not kept for later")
	}
	e.loop.Client.Base = e.cloud.Srv.URL
	e.cloud.FailPosts.Store(0)
	e.loop.deliver(context.Background())
	if rs := e.cloud.RunResults("job_crashed"); len(rs) != 1 || !rs[0].Frozen {
		t.Errorf("%+v", rs)
	}
	if _, err := os.Stat(e.loop.outboxPath()); !os.IsNotExist(err) {
		t.Error("outbox not emptied")
	}
}

func TestEventsRetry(t *testing.T) {
	e := newEnv(t)
	e.cloud.FailPosts.Store(2)
	e.cloud.AddJob(e.signer.Sign(e.job("job_1")))
	e.loop.Once(context.Background())
	if evs := e.cloud.RunEvents("job_1"); len(evs) != 3 {
		t.Errorf("events after retries: %d", len(evs))
	}
	if rs := e.cloud.RunResults("job_1"); len(rs) != 1 {
		t.Errorf("results %+v", rs)
	}
}

// M-05: a cut-off run's result survives a redelivery of the same job.
func TestRecoveredResultIsNotReplaced(t *testing.T) {
	e := newEnv(t)
	// The job was admitted (seen) and then the agent died during it.
	seen, _ := loadSeen(e.loop.StateDir)
	seen.Jobs["job_7"] = &seenJob{ExpiresAt: e.now.Add(time.Hour)}
	saveSeen(e.loop.StateDir, seen)
	e.eng.recover = &protocol.RunResult{JobID: "job_7", Outcome: protocol.OutcomeStopped, Frozen: true, Summary: "Stopped: cut off."}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.loop.Run(ctx) // recovers, then stops at once
	e.cloud.AddJob(e.signer.Sign(e.job("job_7")))
	if err := e.loop.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.loop.deliver(context.Background())
	rs := e.cloud.RunResults("job_7")
	if len(rs) == 0 || rs[len(rs)-1].Outcome != protocol.OutcomeStopped || !rs[len(rs)-1].Frozen {
		t.Fatalf("results %+v", rs)
	}
	if len(e.eng.ran) != 0 {
		t.Errorf("ran again: %v", e.eng.ran)
	}
}
