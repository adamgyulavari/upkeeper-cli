package jobs_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/cloudclient"
	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/discover"
	"github.com/adamgyulavari/upkeeper-cli/agent/fakes"
	"github.com/adamgyulavari/upkeeper-cli/agent/jobs"
	"github.com/adamgyulavari/upkeeper-cli/agent/policy"
	"github.com/adamgyulavari/upkeeper-cli/agent/run"
	"github.com/adamgyulavari/upkeeper-cli/agent/verify"
	"github.com/adamgyulavari/upkeeper-cli/agent/versions"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// TestEndToEnd (X-10, agent half): a fake control plane hands out signed
// jobs; the job client verifies them and the real engine runs them on a
// fake server (fake Docker, fake apt): first the dry run, then an auto run
// whose new image crash-loops and is undone.
func TestEndToEnd(t *testing.T) {
	root := t.TempDir()
	w := fakes.NewWorld(filepath.Join(root, "srv"))
	os.MkdirAll(w.Root, 0o755)
	w.AddService("shop", "redis", "redis:7.4.1", 6379)
	w.AddService("shop", "web", "ghcr.io/acme/web:2.3.0", 8080)
	w.Apt = []collect.AptUpgrade{{Package: "openssl", From: "3.0.13-0ubuntu3.4", To: "3.0.13-0ubuntu3.5", Security: true, Origins: []string{"Ubuntu:24.04/noble-security"}}}
	dgRedis := "sha256:" + strings.Repeat("a", 64)
	dgWeb := "sha256:" + strings.Repeat("b", 64)
	w.Updates = []discover.ImageUpdate{
		{Project: "shop", Service: "redis", FromTag: "7.4.1", ToTag: "7.4.2", Change: versions.Patch, ToDigest: dgRedis},
		{Project: "shop", Service: "web", FromTag: "2.3.0", ToTag: "2.3.1", Change: versions.Patch, ToDigest: dgWeb},
	}
	w.Registry["redis@"+dgRedis] = "sha256:redis-new"
	w.Registry["ghcr.io/acme/web@"+dgWeb] = "sha256:web-new"
	w.CrashLoop["sha256:web-new"] = true // the deliberately broken next tag

	uid := os.Getuid()
	pol := policy.Store{Path: filepath.Join(root, "etc", "policy.yaml"), StateDir: filepath.Join(root, "state"), OwnerUID: &uid}
	pol.SetMode(protocol.ModeAuto)
	clock := &fakes.Clock{T: time.Now().Add(time.Second).Truncate(time.Second)}
	engine := &run.Engine{
		Planner: w, Runner: w, Docker: w, FS: w,
		Checker:   &verify.Checker{Source: w, Now: clock.Now, Sleep: clock.Sleep},
		Locked:    func() (string, bool, error) { return "", false, nil },
		Policy:    pol,
		Trust:     run.PathChecker{OwnerUID: uid, Root: w.Root},
		StatePath: filepath.Join(root, "state", "run.json"),
		Now:       clock.Now,
	}
	cloud := fakes.NewCloud()
	defer cloud.Srv.Close()
	signer := fakes.NewSigner(clock.Now())
	loop := &jobs.Loop{
		Client:   &cloudclient.Client{Base: cloud.Srv.URL, Token: cloud.AgentToken},
		ServerID: "srv_1", Roots: signer.Roots, Engine: engine, StateDir: pol.StateDir, Wait: time.Second,
		Now: clock.Now, Logf: t.Logf,
	}
	report, _ := w.Plan(context.Background())
	var approved []string
	for _, it := range report.Items {
		if it.Decision == protocol.Auto {
			approved = append(approved, protocol.ItemKey(it))
		}
	}
	if len(approved) != 3 {
		t.Fatalf("approved %v", approved)
	}
	job := func(id string, mode protocol.Mode) protocol.SignedJob {
		now := clock.Now()
		return signer.Sign(protocol.Job{ID: id, ServerID: "srv_1", Kind: protocol.KindRun, Mode: mode, Trigger: protocol.TriggerSchedule,
			Approved: approved, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(4 * time.Hour), WindowEnd: now.Add(3 * time.Hour)})
	}

	// 1. The first job after enabling: a dry run. (Even an auto job would
	// run dry here, since the policy just became auto.)
	cloud.AddJob(job("job_dry", protocol.ModeAuto))
	if err := loop.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	dry := cloud.RunResults("job_dry")
	if len(dry) != 1 || dry[0].Mode != protocol.ModeDryRun || dry[0].Outcome != protocol.OutcomeDone || len(w.Calls) != 0 {
		t.Fatalf("dry run: %+v calls %v", dry, w.Calls)
	}
	if dry[0].Summary != "Dry run: would update 1 package and 2 images. Nothing was changed." {
		t.Errorf("dry summary %q", dry[0].Summary)
	}
	if evs := cloud.RunEvents("job_dry"); len(evs) < 5 {
		t.Errorf("dry events: %d", len(evs))
	}

	// 2. The auto run: openssl and redis are applied, the web image
	// crash-loops and L1 puts 2.3.0 back.
	clock.T = clock.T.Add(time.Hour)
	cloud.AddJob(job("job_auto", protocol.ModeAuto))
	if err := loop.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	res := cloud.RunResults("job_auto")
	if len(res) != 1 {
		t.Fatalf("no auto result")
	}
	r := res[0]
	if r.Mode != protocol.ModeAuto || r.Outcome != protocol.OutcomeUndone || r.Frozen || len(r.Applied) != 2 || len(r.Undone) != 1 {
		t.Fatalf("auto run: %+v\ncalls %v", r, w.Calls)
	}
	want := "web 2.3.1 didn't come back healthy, so 2.3.0 is running again. Updated 1 package and 1 image."
	if r.Summary != want {
		t.Errorf("summary\n got %q\nwant %q", r.Summary, want)
	}
	if c := w.Container("shop", "web"); c.ImageID != "sha256:ghcr.io/acme/web:2.3.0" || c.State != "running" {
		t.Errorf("web: %+v", c)
	}
	if c := w.Container("shop", "redis"); c.ImageID != "sha256:redis-new" {
		t.Errorf("redis: %+v", c)
	}
	ov, _, _ := run.ReadOverride(filepath.Join(w.Root, "shop", run.OverrideName))
	if len(ov) != 1 || ov["redis"] != "redis:7.4.2" {
		t.Errorf("override %v", ov)
	}
	evs := cloud.RunEvents("job_auto")
	for i, e := range evs {
		if e.Seq != i+1 {
			t.Fatalf("event seqs out of order: %+v", evs)
		}
	}
	undo := false
	for _, e := range evs {
		undo = undo || e.Status == protocol.StepUndo
	}
	if !undo {
		t.Error("no undo event reached the cloud")
	}

	// 3. The same signed job delivered again isn't run again.
	calls := len(w.Calls)
	cloud.AddJob(job("job_auto", protocol.ModeAuto))
	loop.Once(context.Background())
	if len(w.Calls) != calls {
		t.Errorf("replayed job ran: %v", w.Calls[calls:])
	}
}
