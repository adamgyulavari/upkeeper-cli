// Package run is the run engine (A-12, A-15, A-16): the only part of the
// agent that changes the server. A run goes
//
//	pre-flight → plan → OS packages → images (one project at a time, L1) → verify → keep
//
// Every step emits events for the run record. The engine re-plans locally
// and applies an item only if the job approved it, the agent's own
// classifier still says auto, and the local policy allows it. Anything
// unexpected stops the run and freezes the server.
//
// Writes go only through the agent/host allowlist (apt-get, docker compose)
// and the two Engine API calls in docker.go (pull, tag). In a dry run every
// write is replaced by a "would …" event.
package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/classify"
	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/discover"
	"github.com/adamgyulavari/upkeeper-cli/agent/host"
	"github.com/adamgyulavari/upkeeper-cli/agent/policy"
	"github.com/adamgyulavari/upkeeper-cli/agent/statefile"
	"github.com/adamgyulavari/upkeeper-cli/agent/verify"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// Planner re-plans: a fresh report plus the classifier's input.
type Planner interface {
	Plan(ctx context.Context) (protocol.Report, classify.Input)
}

// Engine runs jobs. Zero durations get the defaults in the comments.
type Engine struct {
	Planner   Planner
	Runner    host.Runner
	Docker    DockerOps
	Checker   *verify.Checker
	FS        host.FS                                         // disk space
	Locked    func() (string, bool, error)                    // dpkg/apt locks; default host.Locked(host.DpkgLockFiles)
	Policy    policy.Store                                    // local policy, freeze, run history
	Trust     PathChecker                                     // compose file checks
	StatePath string                                          // run.json; default /var/lib/upkeeper/run.json
	Settings  classify.Settings                               // MinReleaseAge, clock
	Now       func() time.Time                                // default time.Now
	Sleep     func(ctx context.Context, d time.Duration) bool // default: a timer; false if ctx ended
	Logf      func(format string, args ...any)                // default: discard
	// DockerInstalled reports whether Docker Engine is installed, so a
	// Docker that doesn't answer can be told from no Docker at all.
	// Default: the socket or dockerd exists.
	DockerInstalled func() bool
	// Memory is where the engine remembers images it had to put back and
	// projects it couldn't update; default in the state directory.
	Memory *Memory

	OSVerify      time.Duration // whole-server check after OS packages; default 3 min
	ProjectVerify time.Duration // per project after an image update; default 3 min
	FinalVerify   time.Duration // whole-server check at the end; default 1 min
	MinFreeBytes  uint64        // on / and /var/lib/docker; default 2 GB
}

const (
	aptUpdateTimeout  = 10 * time.Minute
	aptInstallTimeout = 45 * time.Minute
	pullTimeout       = 20 * time.Minute
	composeTimeout    = 10 * time.Minute
)

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) dockerInstalled() bool {
	if e.DockerInstalled != nil {
		return e.DockerInstalled()
	}
	for _, p := range []string{"/var/run/docker.sock", "/run/docker.sock", "/usr/bin/dockerd", "/usr/sbin/dockerd"} {
		if _, err := os.Lstat(p); err == nil {
			return true
		}
	}
	return false
}

func (r *runner) memory() *Memory {
	if r.e.Memory != nil {
		return r.e.Memory
	}
	return &Memory{Dir: filepath.Dir(r.e.statePath())}
}

func (e *Engine) statePath() string {
	if e.StatePath != "" {
		return e.StatePath
	}
	return policy.DefaultStateDir + "/run.json"
}

func dur(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// planned is one item the run will apply.
type planned struct {
	item protocol.Item
	img  *discover.ImageUpdate
}

type runner struct {
	e    *Engine
	ctx  context.Context
	job  protocol.Job
	mode protocol.Mode
	dry  bool
	emit func(protocol.RunEvent)
	seq  int

	res       protocol.RunResult
	state     State
	windowEnd time.Time
	before    verify.Inventory
	report    protocol.Report
	in        classify.Input

	approvedSkipped int
	changed         bool // something on the server really changed
	stopped         bool
	undone          []undoneNote
	lastRunning     int
	kernel          bool

	planned      []protocol.Item          // every item the run meant to apply
	risks        map[string]protocol.Risk // project → why it couldn't be updated
	risksChecked map[string]bool          // projects checked and found fine
}

type undoneNote struct {
	name, from, to string
	data           bool
}

func (r *runner) ev(step string, st protocol.StepStatus, msg string, kv ...string) {
	r.seq++
	ev := protocol.RunEvent{Seq: r.seq, At: r.e.now().UTC(), Step: step, Status: st, Message: msg}
	if len(kv) > 1 {
		ev.Detail = map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			ev.Detail[kv[i]] = kv[i+1]
		}
	}
	if r.emit != nil {
		r.emit(ev)
	}
	if r.e.Logf != nil {
		r.e.Logf("run %s: %s %s: %s", r.job.ID, step, st, msg)
	}
}

func (r *runner) skip(it protocol.Item, reason string, counts bool) {
	r.res.Skipped = append(r.res.Skipped, protocol.SkippedItem{Item: it, Reason: reason})
	if counts {
		r.approvedSkipped++
	}
}

// skipCode skips an approved item with a risk code the dashboard can show.
func (r *runner) skipCode(it protocol.Item, reason, code string) {
	r.res.Skipped = append(r.res.Skipped, protocol.SkippedItem{Item: it, Reason: reason, Code: code})
	r.approvedSkipped++
}

// policyChanged re-reads the local policy and freeze state: a run stops
// starting new steps once someone sets the policy to observe or freezes
// the server by hand.
func (r *runner) policyChanged() string {
	if f := r.e.Policy.Frozen(); f.Frozen && !r.stopped {
		return "The server was frozen during the run, so no further updates were started."
	}
	if r.dry {
		return ""
	}
	if m, err := r.e.Policy.Mode(); err != nil || m != protocol.ModeAuto {
		return "The local policy changed during the run, so no further updates were started."
	}
	return ""
}

// sweep records every planned item that was neither applied, undone nor
// skipped (the run stopped before it) as skipped, with the reason.
func (r *runner) sweep() {
	done := map[string]bool{}
	for _, it := range r.res.Applied {
		done[protocol.ItemKey(it)] = true
	}
	for _, it := range r.res.Undone {
		done[protocol.ItemKey(it)] = true
	}
	for _, s := range r.res.Skipped {
		done[protocol.ItemKey(s.Item)] = true
	}
	for _, it := range r.planned {
		if !done[protocol.ItemKey(it)] {
			r.skip(it, "The run stopped before this update, so it wasn't applied.", true)
			done[protocol.ItemKey(it)] = true
		}
	}
}

func (r *runner) applied(it protocol.Item) {
	r.res.Applied = append(r.res.Applied, it)
	if !r.dry {
		r.state.Applied = append(r.state.Applied, it)
		r.save()
	}
}

func (r *runner) save() {
	if r.dry {
		return
	}
	if err := saveState(r.e.statePath(), r.state); err != nil && r.e.Logf != nil {
		r.e.Logf("couldn't save %s: %v", r.e.statePath(), err)
	}
}

func (r *runner) step(name string) {
	r.state.Step = name
	r.save()
}

// stop ends the run on doubt and freezes the server.
func (r *runner) stop(step, reason string) {
	r.ev(step, protocol.StepFail, reason)
	r.stopped = true
	r.res.Outcome = protocol.OutcomeStopped
	if r.dry {
		r.res.FrozenReason = reason
		return // a dry run changed nothing, so there's nothing to freeze for
	}
	r.res.Frozen, r.res.FrozenReason = true, reason
	if err := r.e.Policy.FreezeNow(reason, r.job.ID); err != nil && r.e.Logf != nil {
		r.e.Logf("couldn't write the freeze file: %v", err)
	}
}

func (r *runner) windowPassed() bool {
	return !r.windowEnd.IsZero() && r.e.now().After(r.windowEnd)
}

// write returns a context for a write that must finish even if the agent
// is asked to stop: killing apt or compose halfway is worse than waiting.
func (r *runner) write(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.ctx), d)
}

func reject(job protocol.Job, mode protocol.Mode, started time.Time, reason string) protocol.RunResult {
	return protocol.RunResult{JobID: job.ID, Mode: mode, Outcome: protocol.OutcomeRejected,
		Applied: []protocol.Item{}, Undone: []protocol.Item{}, Skipped: []protocol.SkippedItem{},
		Summary: "Not run: " + lowerFirst(reason), StartedAt: started, FinishedAt: started}
}

func lowerFirst(s string) string {
	if s == "" || (len(s) > 1 && s[1] >= 'A' && s[1] <= 'Z') {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// Reject builds a rejected result for a job that never reached the engine
// (bad signature, replay).
func Reject(job protocol.Job, at time.Time, reason string) protocol.RunResult {
	return reject(job, job.Mode, at.UTC(), reason)
}

// Run executes a verified job. It always returns a result, also after an
// internal error.
func (e *Engine) Run(ctx context.Context, job protocol.Job, emit func(protocol.RunEvent)) (res protocol.RunResult) {
	started := e.now().UTC()
	if job.Kind != protocol.KindRun {
		return reject(job, job.Mode, started, fmt.Sprintf("This agent doesn't know jobs of kind %q.", job.Kind))
	}
	if f := e.Policy.Frozen(); f.Frozen {
		return reject(job, job.Mode, started, "This server is frozen since an earlier run: "+f.Reason+" Run `sudo upkeeper unfreeze` on the server once it's checked.")
	}
	if !job.WindowEnd.IsZero() && started.After(job.WindowEnd) {
		return reject(job, job.Mode, started, "The maintenance window had already ended when the job arrived.")
	}
	if _, ok, _ := loadState(e.statePath()); ok {
		return reject(job, job.Mode, started, "Another run is still recorded as in progress.")
	}
	mode, localEnd, note, reason, ok := e.Policy.Admit(job, started)
	if !ok {
		return reject(job, job.Mode, started, reason)
	}
	r := &runner{e: e, ctx: ctx, job: job, mode: mode, dry: mode == protocol.ModeDryRun, emit: emit,
		risks: map[string]protocol.Risk{}, risksChecked: map[string]bool{}}
	r.windowEnd = job.WindowEnd
	if !localEnd.IsZero() && (r.windowEnd.IsZero() || localEnd.Before(r.windowEnd)) {
		r.windowEnd = localEnd
	}
	r.res = protocol.RunResult{JobID: job.ID, Mode: mode, Applied: []protocol.Item{}, Undone: []protocol.Item{}, Skipped: []protocol.SkippedItem{}, StartedAt: started}
	r.state = State{JobID: job.ID, Mode: mode, StartedAt: started, Step: protocol.StepPreflight}
	if mode != job.Mode {
		if note == "" {
			note = "The local policy is dry-run, so this run changes nothing."
		}
		r.ev(protocol.StepPreflight, protocol.StepWarn, note)
	}
	r.save()
	finished := false
	defer func() {
		if p := recover(); p != nil {
			// A bug, not a server problem; the result must still name the
			// job so it's delivered, and the server is frozen.
			r.changed = true
			r.stop("run", fmt.Sprintf("The agent hit an internal error during the run (%v).", p))
			r.resumeTimers()
			r.finish()
			res = r.res
		}
		statefile.Remove(e.statePath())
		if finished && r.dry && !r.stopped {
			e.Policy.RecordDryRun(e.now())
		}
	}()

	if rej := r.preflight(); rej != "" {
		statefile.Remove(e.statePath())
		res := reject(job, mode, started, rej)
		res.FinishedAt = e.now().UTC()
		return res
	}
	osItems, imgItems, rej := r.plan()
	if rej != "" {
		statefile.Remove(e.statePath())
		res := reject(job, mode, started, rej)
		res.FinishedAt = e.now().UTC()
		return res
	}
	for _, p := range append(slices.Clone(osItems), imgItems...) {
		r.planned = append(r.planned, p.item)
	}
	if !r.dry && len(osItems)+len(imgItems) > 0 {
		// Counts against the local run limit from the first possible write.
		if err := e.Policy.RecordStart(job, mode, started); err != nil {
			statefile.Remove(e.statePath())
			res := reject(job, mode, started, "The run history can't be written ("+err.Error()+").")
			res.FinishedAt = e.now().UTC()
			return res
		}
	}
	if len(osItems) > 0 && !r.stopped {
		r.osStep(osItems)
	}
	if len(imgItems) > 0 && !r.stopped {
		r.imageStep(imgItems)
	}
	if !r.stopped {
		r.finalVerify()
	}
	r.resumeTimers()
	if !r.stopped {
		r.ev(protocol.StepKeep, protocol.StepOK, "Old images stay on the server so they can be put back. Nothing was pruned.")
	}
	if !r.dry {
		r.memory().SaveRisks(r.risks, r.risksChecked, e.now())
	}
	r.finish()
	finished = true
	return r.res
}

func (r *runner) finish() {
	r.sweep()
	r.res.FinishedAt = r.e.now().UTC()
	switch {
	case r.stopped:
		r.res.Outcome = protocol.OutcomeStopped
	case len(r.res.Undone) > 0:
		r.res.Outcome = protocol.OutcomeUndone
	case r.approvedSkipped > 0:
		r.res.Outcome = protocol.OutcomePartial
	default:
		r.res.Outcome = protocol.OutcomeDone
	}
	r.res.Summary = r.summary()
}

// ---- pre-flight ----

func (r *runner) preflight() string {
	e := r.e
	r.ev(protocol.StepPreflight, protocol.StepStart, "Checking the server before changing anything.")
	locked := e.Locked
	if locked == nil {
		locked = func() (string, bool, error) { return host.Locked(host.DpkgLockFiles) }
	}
	if p, busy, err := locked(); busy {
		// Not a reason to stop: apt waits up to two minutes for its lock,
		// and image updates don't need apt at all.
		r.ev(protocol.StepPreflight, protocol.StepWarn, fmt.Sprintf("Another program is using apt or dpkg right now (%s is locked), often unattended-upgrades. The OS step waits up to two minutes for it.", p))
	} else if err != nil {
		r.ev(protocol.StepPreflight, protocol.StepWarn, fmt.Sprintf("Couldn't check the dpkg lock (%v).", err))
	}
	minFree := e.MinFreeBytes
	if minFree == 0 {
		minFree = 2 << 30
	}
	for _, mnt := range []string{"/", "/var/lib/docker"} {
		total, used, err := e.FS.Statfs(mnt)
		if err != nil {
			if mnt == "/" {
				return fmt.Sprintf("Couldn't check free disk space on / (%v). Nothing was changed.", err)
			}
			continue
		}
		if free := total - used; free < minFree {
			return fmt.Sprintf("Only %.1f GB is free on %s; a run needs at least %.0f GB. Nothing was changed.", float64(free)/(1<<30), mnt, float64(minFree)/(1<<30))
		}
	}
	r.before = e.Checker.Snapshot(r.ctx, nil)
	if !r.before.DockerOK && e.dockerInstalled() {
		reason := "Docker is installed but isn't answering (" + r.before.DockerErr + "). Nothing was changed."
		r.ev(protocol.StepPreflight, protocol.StepFail, reason)
		return reason
	}
	r.ev(protocol.StepPreflight, protocol.StepOK, fmt.Sprintf("Recorded the current state: %d containers running, %d failed systemd units.", r.before.Running(), len(r.before.FailedUnits)),
		"containers", fmt.Sprint(len(r.before.Containers)), "docker_ok", fmt.Sprint(r.before.DockerOK))
	return ""
}

// ---- plan ----

func parseKey(k string) protocol.Item {
	parts := strings.SplitN(k, "|", 3)
	it := protocol.Item{Subject: k}
	if len(parts) == 3 {
		it = protocol.Item{Layer: protocol.Layer(parts[0]), Subject: parts[1], To: parts[2]}
	}
	return it
}

func (r *runner) plan() (osItems, imgItems []planned, reject string) {
	r.step(protocol.StepPlan)
	r.ev(protocol.StepPlan, protocol.StepStart, "Planning: looking for updates again on this server.")
	r.report, r.in = r.e.Planner.Plan(r.ctx)
	if r.report.System.OSID != "" && !r.report.System.Supported {
		return nil, nil, fmt.Sprintf("%s %s isn't supported for automatic runs yet (supported: Ubuntu 22.04 and 24.04, Debian 12 and 13). Nothing was changed.", r.report.System.OSID, r.report.System.OSVersion)
	}
	if r.report.Docker.Installed && !r.before.DockerOK {
		r.ev(protocol.StepPlan, protocol.StepFail, "Docker isn't answering ("+r.before.DockerErr+").")
		return nil, nil, "Docker isn't answering (" + r.before.DockerErr + "). Nothing was changed."
	}
	approved := map[string]bool{}
	for _, k := range r.job.Approved {
		approved[k] = true
	}
	seen := map[string]bool{}
	held := map[string]bool{}
	for _, h := range r.report.Packages.Held {
		held[h] = true
	}
	images := map[string]*discover.ImageUpdate{}
	for i := range r.in.Images {
		u := &r.in.Images[i]
		images[protocol.ItemKey(protocol.Item{Layer: protocol.LayerImage, Subject: u.Project + "/" + u.Service, To: classify.ImageTo(*u)})] = u
	}
	serviceTaken := map[string]bool{}
	for _, it := range r.report.Items {
		key := protocol.ItemKey(it)
		ok := approved[key]
		if ok {
			seen[key] = true
		}
		if r.job.SecurityOnly && !(it.Layer == protocol.LayerOS && it.Security) {
			if ok {
				r.skip(it, "The daily security run applies only OS security updates; this one waits for the weekly run.", false)
			}
			continue
		}
		if it.Decision != protocol.Auto {
			if ok {
				r.skip(it, "upkeeper.sh now rates this "+string(it.Decision)+": "+it.Reason, true)
			}
			continue
		}
		if it.Layer == protocol.LayerDocker {
			if ok {
				r.skip(it, "This agent version doesn't update Docker Engine yet, so Docker stays as it is.", true)
			}
			continue
		}
		if !ok {
			r.skip(it, "Not approved for automatic runs in the dashboard.", false)
			continue
		}
		switch it.Layer {
		case protocol.LayerOS:
			if held[it.Subject] || host.IsDockerFamily(it.Subject) {
				r.skip(it, "Held or part of Docker, so the OS step leaves it alone.", true)
				continue
			}
			if it.From != "" && !host.ValidPinned(host.PkgVersion{Name: it.Subject, Version: it.To}) {
				r.skip(it, "Its name or version ends in a character apt would read as an instruction, so it's left for a supervised run.", true)
				continue
			}
			osItems = append(osItems, planned{item: it})
		case protocol.LayerKernel:
			osItems = append(osItems, planned{item: it})
		case protocol.LayerImage:
			u := images[key]
			if u == nil {
				r.skip(it, "The update the classifier found isn't there any more.", true)
				continue
			}
			if young, why := r.e.Settings.TooNew(*u); young {
				r.skip(it, why, true)
				continue
			}
			if at, ok := r.memory().WasUndone(u.Project, u.Service, u.ToDigest); ok {
				r.skip(it, fmt.Sprintf("This exact image was put back on %s because the service didn't come back healthy with it. It's tried again when a newer image is published.", at.UTC().Format("2006-01-02")), true)
				continue
			}
			if serviceTaken[it.Subject] {
				r.skip(it, "Another update to this service is in this run; this one waits for the next.", true)
				continue
			}
			serviceTaken[it.Subject] = true
			imgItems = append(imgItems, planned{item: it, img: u})
		}
	}
	var gone []string
	for _, k := range r.job.Approved {
		if !seen[k] {
			gone = append(gone, k)
		}
	}
	sort.Strings(gone)
	for _, k := range gone {
		r.skip(parseKey(k), "No longer pending on this server: already updated, or a newer version replaced it.", true)
	}
	r.ev(protocol.StepPlan, protocol.StepOK, fmt.Sprintf("Plan: %d OS updates and %d image updates to apply, %d skipped.", len(osItems), len(imgItems), len(r.res.Skipped)),
		"os", fmt.Sprint(len(osItems)), "images", fmt.Sprint(len(imgItems)))
	return osItems, imgItems, ""
}

// ---- OS packages ----

// aptRetryWait is how long the OS step waits before the one retry of
// apt-get update (apt-daily usually finishes its refresh within a minute).
const aptRetryWait = 90 * time.Second

func (r *runner) sleep(d time.Duration) bool {
	if r.e.Sleep != nil {
		return r.e.Sleep(r.ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-r.ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// pauseTimers stops the apt timers that are active, so apt-daily and
// unattended-upgrades can't start halfway through the run. resumeTimers
// starts them again; Recover does it after a crash.
func (r *runner) pauseTimers() {
	for _, t := range host.AptTimers {
		out, _ := r.e.Runner.Run(r.ctx, "systemctl", host.TimerIsActive(t)...)
		if strings.TrimSpace(string(out)) != "active" {
			continue
		}
		ctx, cancel := r.write(30 * time.Second)
		_, err := r.e.Runner.Run(ctx, "systemctl", host.TimerStop(t)...)
		cancel()
		if err != nil {
			r.ev(protocol.StepOS, protocol.StepWarn, fmt.Sprintf("Couldn't pause %s (%v); apt may be busy for a moment if it starts.", t, err))
			continue
		}
		r.state.PausedTimers = append(r.state.PausedTimers, t)
		r.save()
	}
	if len(r.state.PausedTimers) > 0 {
		r.ev(protocol.StepOS, protocol.StepOK, "Paused "+strings.Join(r.state.PausedTimers, " and ")+" for the run; they're started again at the end.")
	}
}

func (e *Engine) resumeTimers(ctx context.Context, timers []string) []string {
	var failed []string
	for _, t := range timers {
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		if _, err := e.Runner.Run(c, "systemctl", host.TimerStart(t)...); err != nil {
			failed = append(failed, t)
		}
		cancel()
	}
	return failed
}

func (r *runner) resumeTimers() {
	if len(r.state.PausedTimers) == 0 {
		return
	}
	if failed := r.e.resumeTimers(r.ctx, r.state.PausedTimers); len(failed) > 0 {
		r.ev(protocol.StepKeep, protocol.StepWarn, fmt.Sprintf("Couldn't start %s again; start it with `sudo systemctl start %s`.", strings.Join(failed, " and "), strings.Join(failed, " ")))
	} else {
		r.ev(protocol.StepKeep, protocol.StepOK, "Started "+strings.Join(r.state.PausedTimers, " and ")+" again.")
	}
	r.state.PausedTimers = nil
	r.save()
}

// aptBusy reports whether an apt error says another program held a lock.
func aptBusy(err error) bool {
	s := err.Error()
	for _, m := range []string{"Could not get lock", "Unable to acquire the dpkg frontend lock", "Unable to lock directory", "Unable to lock the administration directory"} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func (r *runner) skipOS(items []planned, reason string) {
	for _, p := range items {
		r.skip(p.item, reason, true)
	}
	r.ev(protocol.StepOS, protocol.StepSkip, reason)
}

func (r *runner) osStep(items []planned) {
	r.step(protocol.StepOS)
	if r.windowPassed() {
		for _, p := range items {
			r.skip(p.item, "The maintenance window ended before the OS step.", true)
		}
		r.ev(protocol.StepOS, protocol.StepSkip, "The maintenance window ended, so no packages were installed.")
		return
	}
	if why := r.policyChanged(); why != "" {
		r.skipOS(items, why)
		return
	}
	allowed := map[string]bool{}
	var pkgs []host.PkgVersion
	// Security updates first in the list; apt installs them in one transaction.
	sort.SliceStable(items, func(i, j int) bool { return items[i].item.Security && !items[j].item.Security })
	for _, p := range items {
		switch p.item.Layer {
		case protocol.LayerOS:
			allowed[p.item.Subject] = true
			if p.item.From != "" {
				pkgs = append(pkgs, host.PkgVersion{Name: p.item.Subject, Version: p.item.To})
			}
		case protocol.LayerKernel:
			r.kernel = true
			for _, u := range r.in.Apt.Upgrades {
				if classify.IsKernelPackage(u.Package) {
					allowed[u.Package] = true
					if u.From != "" && host.ValidPinned(host.PkgVersion{Name: u.Package, Version: u.To}) {
						pkgs = append(pkgs, host.PkgVersion{Name: u.Package, Version: u.To})
					}
				}
			}
		}
	}
	if len(pkgs) == 0 {
		for _, p := range items {
			r.skip(p.item, "Nothing to install directly; it comes with another update.", false)
		}
		return
	}
	names := make([]string, len(pkgs))
	for i, p := range pkgs {
		names[i] = p.Name
	}
	r.ev(protocol.StepOS, protocol.StepStart, fmt.Sprintf("Upgrading %d packages: %s.", len(pkgs), strings.Join(names, ", ")))

	if !r.dry {
		r.pauseTimers()
		var err error
		for attempt := 0; attempt < 2; attempt++ {
			if attempt > 0 {
				r.ev(protocol.StepOS, protocol.StepWarn, fmt.Sprintf("apt-get update failed (%v); trying once more in %s.", err, aptRetryWait))
				if !r.sleep(aptRetryWait) {
					break
				}
			}
			ctx, cancel := r.write(aptUpdateTimeout)
			_, err = r.e.Runner.Run(ctx, "apt-get", host.AptUpdate...)
			cancel()
			if err == nil {
				break
			}
		}
		if err != nil {
			r.skipOS(items, fmt.Sprintf("apt-get update failed twice (%v). No packages were installed; the next run tries again.", err))
			return
		}
	} else {
		r.ev(protocol.StepOS, protocol.StepOK, "Would pause the apt timers and refresh the package lists (apt-get update).")
	}

	// Simulate the exact install first (read-only): it must touch only
	// planned packages and remove nothing.
	pkgs, dropped, simErr := r.simulate(pkgs, allowed)
	for _, d := range dropped {
		for _, p := range items {
			if p.item.Subject == d {
				r.skip(p.item, "A newer version replaced it after this run was planned; it's in the next run.", true)
			}
		}
	}
	if simErr != "" {
		for _, p := range items {
			if !slices.Contains(dropped, p.item.Subject) {
				r.skip(p.item, simErr, true)
			}
		}
		r.ev(protocol.StepOS, protocol.StepWarn, simErr+" No packages were installed.")
		return
	}
	if len(pkgs) == 0 {
		return
	}
	if r.dry {
		r.ev(protocol.StepOS, protocol.StepOK, fmt.Sprintf("Would upgrade %d packages. apt's simulation shows no other changes.", len(pkgs)))
		for _, p := range items {
			if !slices.Contains(dropped, p.item.Subject) {
				r.applied(p.item)
			}
		}
		return
	}
	before, _ := r.installed(pkgs)
	ctx, cancel := r.write(aptInstallTimeout)
	_, err := r.e.Runner.Run(ctx, "apt-get", host.AptInstallArgs(pkgs)...)
	cancel()
	after, qerr := r.installed(pkgs)
	if err != nil {
		if qerr == nil && unchanged(before, after) {
			why := fmt.Sprintf("apt-get couldn't install the updates (%v). Nothing was installed; the next run tries again.", err)
			if aptBusy(err) {
				why = "Another program kept apt busy for more than two minutes (often unattended-upgrades). Nothing was installed; the next run tries again."
			}
			r.skipOS(items, why)
			return
		}
		r.changed = true
		r.stop(protocol.StepOS, fmt.Sprintf("apt-get stopped with an error while upgrading packages (%v). Some packages may be only partly installed; check with `sudo dpkg --audit`. OS updates can't be undone automatically.", err))
		return
	}
	r.changed = true
	if qerr != nil {
		r.stop(protocol.StepOS, fmt.Sprintf("apt-get finished, but the installed versions can't be read back (%v). Check with `sudo dpkg --audit`.", qerr))
		return
	}
	var missed []string
	for _, p := range pkgs {
		if st := after[p.Name]; st.version != p.Version || st.status != "installed" {
			missed = append(missed, fmt.Sprintf("%s (%s %s, planned %s)", p.Name, st.status, st.version, p.Version))
		}
	}
	if len(missed) > 0 {
		r.stop(protocol.StepOS, fmt.Sprintf("apt-get finished, but these packages aren't at the planned version: %s. Check with `sudo dpkg --audit`. OS updates can't be undone automatically.", strings.Join(missed, ", ")))
		return
	}
	for _, p := range items {
		if !slices.Contains(dropped, p.item.Subject) {
			r.applied(p.item)
		}
	}
	msg := fmt.Sprintf("Upgraded %d packages.", len(pkgs))
	if r.kernel {
		msg += " The new kernel is used after the next reboot; this version doesn't reboot."
	}
	r.ev(protocol.StepOS, protocol.StepOK, msg)
	r.ev(protocol.StepOS, protocol.StepOK, "Running services keep the old versions of updated libraries until they restart; this version doesn't restart them.")

	r.ev(protocol.StepVerify, protocol.StepStart, "Checking the whole server after the OS updates.")
	res := r.verify(nil, dur(r.e.OSVerify, 3*time.Minute))
	r.notes(res)
	if res.Interrupted {
		r.stop(protocol.StepVerify, "The agent was stopped while checking the server after the OS updates, so the check didn't finish. OS updates can't be undone automatically.")
		return
	}
	if !res.Green {
		r.stop(protocol.StepVerify, "After the OS updates: "+strings.Join(res.Reasons, " ")+" OS updates can't be undone automatically, so the run stopped here.")
		return
	}
	r.lastRunning = res.Running
	r.ev(protocol.StepVerify, protocol.StepOK, fmt.Sprintf("Still healthy after the OS updates: %d containers running.", res.Running))
}

type pkgState struct{ version, status string }

// installed reads the installed version and dpkg status of pkgs
// (dpkg-query, read-only).
func (r *runner) installed(pkgs []host.PkgVersion) (map[string]pkgState, error) {
	args := []string{"-W", host.DpkgQueryFormat}
	for _, p := range pkgs {
		args = append(args, p.Name)
	}
	out, err := r.e.Runner.Run(r.ctx, "dpkg-query", args...)
	if err != nil {
		return nil, err
	}
	m := map[string]pkgState{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) == 3 {
			m[f[0]] = pkgState{version: f[1], status: f[2]}
		}
	}
	return m, nil
}

func unchanged(a, b map[string]pkgState) bool {
	if a == nil || len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v || v.status != "installed" {
			return false
		}
	}
	return true
}

func (r *runner) notes(res verify.Result) {
	for _, n := range res.Notes {
		r.ev(protocol.StepVerify, protocol.StepWarn, n)
	}
}

// simulate runs `apt-get -s install --only-upgrade` for pkgs. Packages
// whose planned version is gone are dropped (and the simulation repeated
// once). It returns a reason when the OS step must not go ahead.
func (r *runner) simulate(pkgs []host.PkgVersion, allowed map[string]bool) ([]host.PkgVersion, []string, string) {
	var dropped []string
	for attempt := 0; attempt < 2; attempt++ {
		out, err := r.e.Runner.Run(r.ctx, "apt-get", host.AptSimInstallArgs(pkgs)...)
		if err != nil {
			missing := missingVersions(err.Error() + "\n" + string(out))
			if len(missing) == 0 || attempt == 1 {
				return pkgs, dropped, fmt.Sprintf("apt's simulation of the upgrade failed (%v).", err)
			}
			var keep []host.PkgVersion
			for _, p := range pkgs {
				if missing[p.Name] {
					dropped = append(dropped, p.Name)
				} else {
					keep = append(keep, p)
				}
			}
			pkgs = keep
			if len(pkgs) == 0 {
				return pkgs, dropped, ""
			}
			continue
		}
		var extra, removed []string
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			switch f[0] {
			case "Inst":
				if !allowed[f[1]] {
					extra = append(extra, f[1])
				}
			case "Remv", "Purg":
				removed = append(removed, f[1])
			}
		}
		if len(removed) > 0 {
			return pkgs, dropped, fmt.Sprintf("apt would remove %s to do this upgrade, so it waits for a supervised run.", strings.Join(removed, ", "))
		}
		if len(extra) > 0 {
			return pkgs, dropped, fmt.Sprintf("apt would also change %s, which isn't in the plan, so it waits.", strings.Join(extra, ", "))
		}
		return pkgs, dropped, ""
	}
	return pkgs, dropped, ""
}

func missingVersions(s string) map[string]bool {
	m := map[string]bool{}
	for _, line := range strings.Split(s, "\n") {
		// E: Version '3.0.13-0ubuntu3.5' for 'openssl' was not found
		i := strings.Index(line, "Version '")
		if i < 0 {
			continue
		}
		rest := line[i:]
		if j := strings.Index(rest, "' for '"); j >= 0 {
			name := rest[j+len("' for '"):]
			if k := strings.Index(name, "'"); k >= 0 {
				m[name[:k]] = true
			}
		}
	}
	return m
}

// ---- final verify ----

func (r *runner) finalVerify() {
	r.step(protocol.StepVerify)
	if !r.changed {
		if r.dry {
			r.ev(protocol.StepVerify, protocol.StepOK, "Would check the whole server against the state recorded at the start.")
		} else {
			r.ev(protocol.StepVerify, protocol.StepOK, "Nothing changed, so there's nothing to check.")
		}
		r.lastRunning = r.before.Running()
		return
	}
	r.ev(protocol.StepVerify, protocol.StepStart, "Checking the whole server against the state recorded at the start.")
	res := r.verify(nil, dur(r.e.FinalVerify, time.Minute))
	r.notes(res)
	if !res.Green {
		r.stop(protocol.StepVerify, "The final check found problems: "+strings.Join(res.Reasons, " "))
		return
	}
	r.lastRunning = res.Running
	r.ev(protocol.StepVerify, protocol.StepOK, fmt.Sprintf("All %d containers healthy.", res.Running))
}

// ---- images ----

func (r *runner) service(project, svc string) (protocol.Service, bool) {
	for _, p := range r.report.Projects {
		if p.Name != project {
			continue
		}
		for _, s := range p.Services {
			if s.Name == svc {
				return s, true
			}
		}
	}
	return protocol.Service{}, false
}

func projectHealthy(inv verify.Inventory, project string) string {
	for _, c := range inv.Project(project) {
		if c.State == "restarting" || c.Health == "unhealthy" {
			return fmt.Sprintf("%s/%s wasn't healthy before the run", c.Project, c.Service)
		}
	}
	return ""
}

// notRunning says why a service's containers weren't all running at
// pre-flight, or "". A run never starts a service that was stopped or
// that had finished (a one-shot job).
func notRunning(inv verify.Inventory, project, service string) string {
	n, running := 0, 0
	for _, c := range inv.Project(project) {
		if c.Service != service {
			continue
		}
		n++
		if c.State == "running" {
			running++
		}
	}
	switch {
	case n == 0:
		return "It has no container on the server, so upkeeper.sh doesn't create one."
	case running < n:
		return "It wasn't running when the run started (stopped, or a job that had finished), so upkeeper.sh doesn't start it."
	}
	return ""
}

// slowHealth says why a project's healthchecks can't give a first result
// within the longest wait, or "".
func slowHealth(inv verify.Inventory, project string) string {
	for _, c := range inv.Project(project) {
		if c.HealthFirst > verify.MaxHealthWait {
			return fmt.Sprintf("The healthcheck of %s first reports after %s, longer than upkeeper.sh waits (%s), so its images are left alone.", c.Service, c.HealthFirst, verify.MaxHealthWait)
		}
	}
	return ""
}

func (r *runner) imageStep(items []planned) {
	r.step(protocol.StepImages)
	byProject := map[string][]planned{}
	var names []string
	for _, p := range items {
		if _, ok := byProject[p.img.Project]; !ok {
			names = append(names, p.img.Project)
		}
		byProject[p.img.Project] = append(byProject[p.img.Project], p)
	}
	sort.Strings(names)
	cv, ok := versionOf(r.report.Docker.ComposeVersion)
	composeOK := ok && (cv[0] > 2 || (cv[0] == 2 && cv[1] >= 20))
	for _, name := range names {
		ps := byProject[name]
		sort.Slice(ps, func(i, j int) bool { return ps[i].item.Subject < ps[j].item.Subject })
		skipAll := func(reason string) {
			for _, p := range ps {
				r.skip(p.item, reason, true)
			}
			r.ev(protocol.StepImages, protocol.StepSkip, name+": "+reason)
		}
		switch {
		case r.stopped:
			return
		case r.windowPassed():
			skipAll("The maintenance window ended before this project's turn.")
			continue
		case r.policyChanged() != "":
			skipAll(r.policyChanged())
			continue
		case !composeOK:
			skipAll(fmt.Sprintf("Docker Compose %s is too old for safe image updates (needs 2.20 or newer).", r.report.Docker.ComposeVersion))
			continue
		case name == collect.StandaloneProject:
			skipAll("These containers aren't part of a Compose project, so upkeeper.sh leaves their images alone.")
			continue
		}
		if len(r.before.Project(name)) == 0 {
			skipAll("It wasn't in the inventory taken at the start, so there's nothing to check it against.")
			continue
		}
		if why := projectHealthy(r.before, name); why != "" {
			skipAll("Skipped: " + why + ".")
			continue
		}
		if why := slowHealth(r.before, name); why != "" {
			skipAll(why)
			continue
		}
		var run []planned
		for _, p := range ps {
			if why := notRunning(r.before, name, p.img.Service); why != "" {
				r.skip(p.item, why, true)
				r.ev(protocol.StepImages, protocol.StepSkip, fmt.Sprintf("%s/%s: %s", name, p.img.Service, why))
				continue
			}
			run = append(run, p)
		}
		if len(run) > 0 {
			r.project(name, run)
		}
	}
}

func versionOf(s string) ([2]int, bool) {
	var v [2]int
	_, err := fmt.Sscanf(strings.TrimPrefix(s, "v"), "%d.%d", &v[0], &v[1])
	return v, err == nil
}

// composeFiles is the -f list: the user's files, then the override if it exists.
func composeFiles(pi ProjectInfo, haveOverride bool) []string {
	files := slices.Clone(pi.ConfigFiles)
	if haveOverride {
		files = append(files, pi.Override)
	}
	return files
}

// RiskComposeMismatch is the risk code for a project whose compose files
// (with the agent's environment) don't reproduce what's running.
const RiskComposeMismatch = "compose_mismatch"

func (r *runner) projectRisk(name, msg string) {
	risk := protocol.Risk{Code: RiskComposeMismatch, Severity: protocol.Warning, Subject: name, Message: msg}
	r.res.Risks = append(r.res.Risks, risk)
	r.risks[name] = risk
}

func (r *runner) project(name string, ps []planned) {
	e := r.e
	skipAll := func(reason, code string) {
		for _, p := range ps {
			r.skipCode(p.item, reason, code)
		}
		r.ev(protocol.StepImages, protocol.StepSkip, name+": "+reason)
	}
	pi, err := e.Docker.Project(r.ctx, name)
	if err == nil {
		err = e.Trust.CheckProject(&pi, pi.MountSources)
	}
	if err != nil {
		skipAll("Can't verify where this project's compose file lives ("+err.Error()+"), so its images are left alone.", "")
		return
	}
	if err := e.Trust.CheckPath(dirOf(pi.Override), true, pi.MountSources); err != nil {
		skipAll("Can't verify the directory for "+OverrideName+" ("+err.Error()+").", "")
		return
	}
	ov, haveOv, err := ReadOverride(pi.Override)
	if err != nil {
		skipAll(err.Error()+".", "")
		return
	}
	services := make([]string, len(ps))
	for i, p := range ps {
		services[i] = p.img.Service
	}
	if why := r.checkCompose(pi, composeFiles(pi, haveOv), services); why != "" {
		r.projectRisk(name, why)
		skipAll(why, RiskComposeMismatch)
		return
	}
	delete(r.risks, name)
	r.risksChecked[name] = true
	r.ev(protocol.StepImages, protocol.StepStart, fmt.Sprintf("%s: updating %d services.", name, len(ps)), "project", name, "dir", pi.WorkDir)

	// One item at a time, so a red check undoes only the update that broke.
	for _, p := range ps {
		if r.stopped {
			r.skip(p.item, "The run stopped before this update.", true)
			continue
		}
		if r.windowPassed() {
			r.skip(p.item, "The maintenance window ended before this update's turn.", true)
			continue
		}
		if why := r.policyChanged(); why != "" {
			r.skip(p.item, why, true)
			continue
		}
		r.imageItem(name, pi, ov, p)
		// The override may have changed; read it again for the next item.
		if ov, _, err = ReadOverride(pi.Override); err != nil && !r.stopped {
			r.stop(protocol.StepImages, "Couldn't read "+OverrideName+" back ("+err.Error()+"). The server is frozen so nothing else changes until you look.")
		}
	}
}

// configHashes asks Compose for the config hash of services, using exactly
// files. It returns the hashes, variables Compose said aren't set, or why
// it couldn't.
func (r *runner) configHashes(pi ProjectInfo, files, services []string) (map[string]string, []string, error) {
	c := host.ComposeConfig{ProjectDir: pi.WorkDir, Project: pi.Name, Files: files, Services: services}
	out, stderr, err := r.composeConfig(c)
	if err != nil {
		return nil, nil, err
	}
	hashes := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && slices.Contains(services, f[0]) && hashRe.MatchString(f[1]) {
			hashes[f[0]] = f[1]
		}
	}
	for _, s := range services {
		if hashes[s] == "" {
			return nil, nil, fmt.Errorf("Compose printed no config hash for %s", s)
		}
	}
	var unset []string
	for _, m := range unsetVarRe.FindAllStringSubmatch(string(stderr)+"\n"+string(out), -1) {
		if !slices.Contains(unset, m[1]) {
			unset = append(unset, m[1])
		}
	}
	sort.Strings(unset)
	return hashes, unset, nil
}

var (
	hashRe      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	unsetVarRe  = regexp.MustCompile(`The \\?"([A-Za-z_][A-Za-z0-9_]*)\\?" variable is not set`)
	configLimit = 4 << 20
)

func (r *runner) composeConfig(c host.ComposeConfig) ([]byte, []byte, error) {
	if !c.Valid() {
		return nil, nil, errors.New("the compose command for this project doesn't pass the agent's checks")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 2*time.Minute)
	defer cancel()
	if sr, ok := r.e.Runner.(host.StderrRunner); ok {
		return sr.RunStderr(ctx, "docker", c.Args()...)
	}
	out, err := r.e.Runner.Run(ctx, "docker", c.Args()...)
	return out, nil, err
}

// replicas reads how many containers each service should have.
func (r *runner) replicas(pi ProjectInfo, files, services []string) (map[string]int, error) {
	out, _, err := r.composeConfig(host.ComposeConfig{ProjectDir: pi.WorkDir, Project: pi.Name, Files: files, Services: services, JSON: true})
	if err != nil {
		return nil, err
	}
	if len(out) > configLimit {
		return nil, errors.New("Compose's output is too large")
	}
	var cfg struct {
		Services map[string]struct {
			Scale  *int `json:"scale"`
			Deploy *struct {
				Mode     string `json:"mode"`
				Replicas *int   `json:"replicas"`
			} `json:"deploy"`
		} `json:"services"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		return nil, fmt.Errorf("can't read Compose's output: %w", err)
	}
	n := map[string]int{}
	for _, s := range services {
		sc, ok := cfg.Services[s]
		if !ok {
			return nil, fmt.Errorf("the compose files don't define %s any more", s)
		}
		n[s] = 1
		switch {
		case sc.Deploy != nil && sc.Deploy.Mode == "global":
			n[s] = -1
		case sc.Deploy != nil && sc.Deploy.Replicas != nil:
			n[s] = *sc.Deploy.Replicas
		case sc.Scale != nil:
			n[s] = *sc.Scale
		}
	}
	return n, nil
}

// checkCompose makes sure `docker compose up` with files and the agent's
// environment would recreate services exactly as they run now, apart from
// the image: each service's config hash must equal the one on its
// containers, no variable may be missing, and the replica count must match.
// It returns why not, or "".
func (r *runner) checkCompose(pi ProjectInfo, files, services []string) string {
	hashes, unset, err := r.configHashes(pi, files, services)
	if err != nil {
		return "Compose couldn't read this project's files (" + err.Error() + "), so its images are left alone."
	}
	if len(unset) > 0 {
		return fmt.Sprintf("Its compose files use variables that aren't set when upkeeper.sh runs Compose (%s), probably set in a shell or a script when the project was started. upkeeper.sh can't reproduce that, so it leaves the project alone. Put them in the project's .env file to allow image updates.", strings.Join(unset, ", "))
	}
	how := "run `docker compose up -d` in the project yourself first"
	if slices.Contains(files, pi.Override) {
		how = "run `docker compose -f <your files> -f " + OverrideName + " up -d` in the project yourself first"
	}
	for _, s := range services {
		si := pi.Services[s]
		got, ok := si.ConfigHash()
		if !ok || got != hashes[s] {
			return fmt.Sprintf("The compose files on disk no longer match what's running for %s; %s. Until then upkeeper.sh leaves the project alone.", s, how)
		}
	}
	reps, err := r.replicas(pi, files, services)
	if err != nil {
		return "Compose couldn't read this project's files (" + err.Error() + "), so its images are left alone."
	}
	for _, s := range services {
		if reps[s] != pi.Services[s].Containers {
			return fmt.Sprintf("%s runs %d containers, but its compose files ask for %s (it may have been started with --scale). Recreating it would change that, so upkeeper.sh leaves the project alone.", s, pi.Services[s].Containers, replicaText(reps[s]))
		}
	}
	return ""
}

func replicaText(n int) string {
	if n < 0 {
		return "one per node (deploy mode global)"
	}
	return fmt.Sprint(n)
}

// imageItem changes one service's image and checks the project; red means L1.
//
// Order, so a failure before `compose up` leaves the running service alone:
// write the override (version updates), pull by digest, tag, ask Compose
// for the hash the service will have, check the files once more, then
// recreate. Undo puts the override entry and the old tag back and recreates
// from the same, re-checked files; the service must come back with exactly
// its old config hash.
func (r *runner) imageItem(name string, pi ProjectInfo, ov Override, p planned) {
	e := r.e
	u := p.img
	si, ok := pi.Services[u.Service]
	if !ok || si.ImageID == "" {
		r.skip(p.item, "The service isn't running any more.", true)
		return
	}
	oldHash, _ := si.ConfigHash()
	repo, _ := splitRef(si.Image)
	if svc, ok := r.service(u.Project, u.Service); ok && svc.Image != "" {
		repo, _ = splitRef(svc.Image)
	}
	if u.ToDigest == "" {
		r.skip(p.item, "The new version's digest couldn't be confirmed when planning, so it waits for the next run.", true)
		return
	}
	target := repo + "@" + u.ToDigest
	label := u.Service + " " + u.ToTag
	if u.NewDigest {
		label = u.Service + " (new " + u.ToTag + " image)"
	}
	if r.dry {
		r.ev(protocol.StepImages, protocol.StepOK, fmt.Sprintf("Would pull %s, recreate %s and check %s for %s.", target, u.Service, name, dur(e.ProjectVerify, 3*time.Minute)), "service", u.Service, "image", target)
		r.applied(p.item)
		return
	}
	ch := Change{Item: p.item, Project: name, Service: u.Service, Floating: u.NewDigest, Repo: repo, Tag: u.ToTag,
		OldImageID: si.ImageID, OldImage: si.Image, OldHash: oldHash, NewImage: target, Override: pi.Override,
		Data: r.hasData(name, u.Service)}
	if old, had := ov[u.Service]; had {
		ch.OldEntry, ch.HadEntry = old, true
	}
	newOv := Override{}
	for k, v := range ov {
		newOv[k] = v
	}
	if !u.NewDigest {
		// The tag, not tag@digest: the run tags the pulled digest with it
		// and checks the new container's image ID after `compose up`. A
		// digest in the image reference would read as a pin to the user's
		// own digest in later reports, and the service would never be
		// updated again.
		newOv[u.Service] = repo + ":" + u.ToTag
		if err := WriteOverride(pi.Override, newOv); err != nil {
			r.skip(p.item, "Couldn't write "+OverrideName+" ("+err.Error()+"). Nothing changed.", true)
			r.ev(protocol.StepImages, protocol.StepWarn, fmt.Sprintf("Couldn't write %s; %s stays as it is.", pi.Override, u.Service))
			return
		}
		r.state.Changes = []Change{ch}
		r.save()
	}
	// back out of a step before compose ran: nothing was recreated.
	back := func(reason string) {
		r.restoreBeforeUp(ch, ov, reason)
	}
	ctx, cancel := r.write(pullTimeout)
	err := e.Docker.Pull(ctx, target)
	cancel()
	if err != nil {
		back(fmt.Sprintf("Couldn't download the new image (%v). Nothing changed.", err))
		r.ev(protocol.StepImages, protocol.StepWarn, fmt.Sprintf("Couldn't download %s; %s stays as it is.", target, u.Service))
		return
	}
	newID, err := e.Docker.ImageID(r.ctx, target)
	if err != nil {
		back(fmt.Sprintf("The pulled image can't be found (%v). Nothing changed.", err))
		return
	}
	if newID == si.ImageID {
		r.restoreBeforeUp(ch, ov, "")
		r.skip(p.item, "It already runs this exact image, so it wasn't recreated.", false)
		return
	}
	ch.NewImageID = newID
	ctx, cancel = r.write(time.Minute)
	err = e.Docker.Tag(ctx, newID, repo, u.ToTag)
	cancel()
	if err != nil {
		back(fmt.Sprintf("Couldn't tag the new image (%v). The service wasn't recreated.", err))
		return
	}
	r.changed = true
	files := composeFiles(pi, len(newOv) > 0)
	hashes, unset, err := r.configHashes(pi, files, []string{u.Service})
	switch {
	case err != nil:
		back("Compose couldn't read the project's files with the new version (" + err.Error() + "). The service wasn't recreated.")
		return
	case len(unset) > 0:
		back("Compose reports variables that aren't set (" + strings.Join(unset, ", ") + "). The service wasn't recreated.")
		return
	}
	ch.ExpectedHash = hashes[u.Service]
	r.state.Changes = []Change{ch}
	r.save()
	r.ev(protocol.StepImages, protocol.StepOK, "Pulled "+label+".", "service", u.Service, "image", target, "expected_config_hash", ch.ExpectedHash)
	if err := e.Trust.Recheck(pi, pi.MountSources); err != nil {
		back("The project's files changed during the run (" + err.Error() + "). The service wasn't recreated.")
		return
	}
	reasons := r.composeUp(pi, files, []string{u.Service})
	if len(reasons) == 0 {
		reasons = r.sameConfig(name, u.Service, ch.ExpectedHash, newID, si.Containers, "after the update")
	}
	if len(reasons) == 0 {
		r.ev(protocol.StepVerify, protocol.StepStart, fmt.Sprintf("Checking %s for %s.", name, dur(e.ProjectVerify, 3*time.Minute)))
		res := r.verify([]string{name}, dur(e.ProjectVerify, 3*time.Minute))
		r.notes(res)
		reasons = res.Reasons
		if res.Interrupted {
			// The agent is being stopped: leave the new version in place
			// rather than undo a change that may be fine. The next start
			// finds run.json and freezes the server for a person to check.
			r.stop(protocol.StepVerify, fmt.Sprintf("The agent was stopped while checking %s with %s, so the check didn't finish. The new version is left in place.", name, label))
			return
		}
		if res.Green {
			r.applied(ch.Item)
			r.state.Changes = nil
			r.save()
			r.ev(protocol.StepVerify, protocol.StepOK, fmt.Sprintf("%s is healthy with %s.", name, label))
			return
		}
	}
	r.undo(name, label, pi, ov, ch, strings.Join(reasons, " "))
}

func (r *runner) hasData(project, service string) bool {
	s, ok := r.service(project, service)
	return ok && len(s.HostPathMounts) > 0
}

// restoreBeforeUp puts the override back after a failure before compose
// ran. reason "" means no skip is recorded.
func (r *runner) restoreBeforeUp(ch Change, ov Override, reason string) {
	defer func() {
		r.state.Changes = nil
		r.save()
	}()
	if !ch.Floating {
		if err := WriteOverride(ch.Override, ov); err != nil {
			r.stop(protocol.StepImages, fmt.Sprintf("%s wasn't recreated, but %s couldn't be put back (%v). The server is frozen so nothing else changes until you look.", ch.Service, OverrideName, err))
			return
		}
	}
	if ch.Floating && ch.NewImageID != "" && ch.OldImageID != "" {
		// The floating tag was moved to the new image: point it back.
		if t, ok := tagOf(ch.OldImage); ok {
			ctx, cancel := r.write(time.Minute)
			err := r.e.Docker.Tag(ctx, ch.OldImageID, ch.Repo, t)
			cancel()
			if err != nil {
				r.stop(protocol.StepImages, fmt.Sprintf("%s wasn't recreated, but its tag couldn't be pointed back at the previous image (%v). The server is frozen so nothing else changes until you look.", ch.Service, err))
				return
			}
		}
	}
	if reason != "" {
		r.skip(ch.Item, reason, true)
	}
}

// tagOf returns the tag of an image reference written as name:tag (not by digest).
func tagOf(image string) (string, bool) {
	if strings.Contains(image, "@") {
		return "", false
	}
	_, t := splitRef(image)
	return t, true
}

// sameConfig checks that after `compose up` the service's containers carry
// the expected config hash and image, and that there are as many as before.
func (r *runner) sameConfig(project, service, want, imageID string, containers int, when string) []string {
	pi, err := r.e.Docker.Project(r.ctx, project)
	if err != nil {
		return []string{fmt.Sprintf("Couldn't read %s's containers %s (%v).", service, when, err)}
	}
	si := pi.Services[service]
	got, ok := si.ConfigHash()
	if !ok || got != want {
		return []string{fmt.Sprintf("%s's configuration %s isn't the one Compose predicted, so more than the image may have changed.", service, when)}
	}
	if si.Containers != containers {
		return []string{fmt.Sprintf("%s has %d containers %s; it had %d.", service, si.Containers, when, containers)}
	}
	if imageID != "" && si.ImageID != imageID {
		return []string{fmt.Sprintf("%s doesn't run the expected image %s.", service, when)}
	}
	return nil
}

func dirOf(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func (r *runner) composeUp(pi ProjectInfo, files, services []string) []string {
	c := host.ComposeUp{ProjectDir: pi.WorkDir, Project: pi.Name, Files: files, Services: services}
	if !c.Valid() {
		return []string{"The compose command for this project doesn't pass the agent's checks."}
	}
	ctx, cancel := r.write(composeTimeout)
	defer cancel()
	if _, err := r.e.Runner.Run(ctx, "docker", c.Args()...); err != nil {
		return []string{fmt.Sprintf("docker compose up failed (%v).", err)}
	}
	return nil
}

// verify checks against the pre-flight inventory. If the agent is asked to
// stop, the check ends with Result.Interrupted; the callers then stop the
// run without undoing anything (a stop isn't evidence that an update is
// bad), and the next start freezes the server through run.json.
func (r *runner) verify(projects []string, window time.Duration) verify.Result {
	return r.e.Checker.Verify(r.ctx, r.before, projects, window)
}

// undo is L1: put the previous image back, recreate, verify again.
func (r *runner) undo(name, label string, pi ProjectInfo, ov Override, ch Change, why string) {
	e := r.e
	r.ev(protocol.StepImages, protocol.StepFail, fmt.Sprintf("%s didn't come back healthy: %s", label, why))
	var failed []string
	if !ch.Floating {
		if err := WriteOverride(ch.Override, ov); err != nil {
			failed = append(failed, OverrideName+" ("+err.Error()+")")
		}
	}
	// Point the old tag at the old image, so Compose resolves exactly the
	// image that ran before (for a floating tag this is the undo itself).
	if t, ok := tagOf(ch.OldImage); ok && ch.OldImageID != "" {
		repo, _ := splitRef(ch.OldImage)
		ctx, cancel := r.write(time.Minute)
		if err := e.Docker.Tag(ctx, ch.OldImageID, repo, t); err != nil {
			failed = append(failed, fmt.Sprintf("%s (%v)", ch.Service, err))
		}
		cancel()
	} else if ch.Floating {
		failed = append(failed, ch.Service+" (old image unknown)")
	}
	if len(failed) > 0 {
		r.stop(protocol.StepImages, fmt.Sprintf("%s didn't come back healthy, and putting the previous image back failed for %s. The server is frozen so nothing else changes until you look.", label, strings.Join(failed, ", ")))
		return
	}
	// The files must still be the ones checked at the start, or recreating
	// would apply someone's edit instead of putting the old service back.
	if err := e.Trust.Recheck(pi, pi.MountSources); err != nil {
		r.stop(protocol.StepImages, fmt.Sprintf("%s didn't come back healthy, and the project's files changed during the run (%v), so upkeeper.sh can't put the previous version back exactly. The server is frozen so nothing else changes until you look.", label, err))
		return
	}
	_, haveOv, _ := ReadOverride(ch.Override)
	reasons := r.composeUp(pi, composeFiles(pi, haveOv), []string{ch.Service})
	if len(reasons) == 0 && ch.OldHash != "" {
		reasons = r.sameConfig(name, ch.Service, ch.OldHash, ch.OldImageID, pi.Services[ch.Service].Containers, "after putting the previous image back")
	}
	if len(reasons) == 0 {
		res := r.verify([]string{name}, dur(e.ProjectVerify, 3*time.Minute))
		r.notes(res)
		reasons = res.Reasons
		if res.Interrupted {
			r.stop(protocol.StepVerify, fmt.Sprintf("The agent was stopped while checking %s after putting the previous image back, so the check didn't finish.", name))
			return
		}
		if res.Green || res.OnlyStarting {
			r.res.Undone = append(r.res.Undone, ch.Item)
			from := strings.TrimSuffix(ch.Item.From, "@")
			r.undone = append(r.undone, undoneNote{name: ch.Service, from: from, to: ch.Item.To, data: ch.Data})
			msg := fmt.Sprintf("Put the previous image of %s back; it's healthy again.", ch.Service)
			if res.OnlyStarting {
				msg = fmt.Sprintf("Put the previous image of %s back. Its healthcheck was still starting when the check ended; have a look when you can.", ch.Service)
			}
			if ch.Data {
				msg += " The new version ran on the service's data for a few minutes; putting the old image back doesn't undo changes it made to that data."
			}
			r.ev(protocol.StepImages, protocol.StepUndo, msg, "service", ch.Service)
			r.rememberUndone(ch)
			r.state.Changes = nil
			r.save()
			return
		}
	}
	r.stop(protocol.StepVerify, fmt.Sprintf("%s is still unhealthy after the previous images were put back: %s The server is frozen so nothing else changes until you look.", name, strings.Join(reasons, " ")))
}

// ---- crash recovery ----

// Recover checks for a run that was cut off (agent crash, kill, reboot).
// If there was one, it freezes the server (unless it was a dry run),
// removes run.json and returns the result to report.
func (e *Engine) Recover() *protocol.RunResult {
	st, ok, err := loadState(e.statePath())
	if !ok && err == nil {
		return nil
	}
	now := e.now().UTC()
	reason := fmt.Sprintf("The agent stopped in the middle of a run (during the %s step), so the server may be partly updated. Check it, then run `sudo upkeeper unfreeze`.", st.Step)
	if err != nil {
		reason = fmt.Sprintf("%s is unreadable (%v), so a run may have been cut off. Check the server, then run `sudo upkeeper unfreeze`.", e.statePath(), err)
	}
	res := &protocol.RunResult{JobID: st.JobID, Mode: st.Mode, Outcome: protocol.OutcomeStopped,
		Applied: st.Applied, Undone: []protocol.Item{}, Skipped: []protocol.SkippedItem{}, StartedAt: st.StartedAt, FinishedAt: now}
	if res.Applied == nil {
		res.Applied = []protocol.Item{}
	}
	if len(st.PausedTimers) > 0 {
		e.resumeTimers(context.Background(), st.PausedTimers)
	}
	if st.Mode == protocol.ModeDryRun && err == nil {
		res.FrozenReason = "The agent stopped in the middle of a dry run. Nothing was changed."
		res.Summary = res.FrozenReason
	} else {
		res.Frozen, res.FrozenReason = true, reason
		res.Summary = "Stopped: the agent was cut off during the " + st.Step + " step. The server is frozen until you check it and unfreeze it."
		e.Policy.FreezeNow(reason, st.JobID)
	}
	statefile.Remove(e.statePath())
	return res
}
