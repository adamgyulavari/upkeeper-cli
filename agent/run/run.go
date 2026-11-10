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
	"fmt"
	"path/filepath"
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
	FS        host.FS                          // disk space
	Locked    func() (string, bool, error)     // dpkg/apt locks; default host.Locked(host.DpkgLockFiles)
	Policy    policy.Store                     // local policy, freeze, run history
	Trust     PathChecker                      // compose file checks
	StatePath string                           // run.json; default /var/lib/upkeeper/run.json
	Settings  classify.Settings                // MinReleaseAge, clock
	Now       func() time.Time                 // default time.Now
	Logf      func(format string, args ...any) // default: discard

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
}

type undoneNote struct {
	name, from, to string
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

// Run executes a verified job. It always returns a result.
func (e *Engine) Run(ctx context.Context, job protocol.Job, emit func(protocol.RunEvent)) protocol.RunResult {
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
	r := &runner{e: e, ctx: ctx, job: job, mode: mode, dry: mode == protocol.ModeDryRun, emit: emit}
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
			r.stop("run", fmt.Sprintf("The agent hit an internal error during the run (%v).", p))
			r.finish()
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
	if !r.stopped {
		r.ev(protocol.StepKeep, protocol.StepOK, "Old images stay on the server so they can be put back. Nothing was pruned.")
	}
	r.finish()
	finished = true
	return r.res
}

func (r *runner) finish() {
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
		return fmt.Sprintf("Another program is using apt or dpkg right now (%s is locked), often unattended-upgrades. Nothing was changed; the next run tries again.", p)
	} else if err != nil {
		return fmt.Sprintf("Couldn't check the dpkg lock (%v). Nothing was changed.", err)
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
		return nil, nil, fmt.Sprintf("%s %s isn't supported for automatic runs.", r.report.System.OSID, r.report.System.OSVersion)
	}
	if r.report.Docker.Installed && !r.before.DockerOK {
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
			continue // the daily security run only applies OS security updates
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

func (r *runner) osStep(items []planned) {
	r.step(protocol.StepOS)
	if r.windowPassed() {
		for _, p := range items {
			r.skip(p.item, "The maintenance window ended before the OS step.", true)
		}
		r.ev(protocol.StepOS, protocol.StepSkip, "The maintenance window ended, so no packages were installed.")
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
		ctx, cancel := r.write(aptUpdateTimeout)
		_, err := r.e.Runner.Run(ctx, "apt-get", host.AptUpdate...)
		cancel()
		if err != nil {
			r.stop(protocol.StepOS, fmt.Sprintf("apt-get update failed (%v). No packages were installed.", err))
			return
		}
	} else {
		r.ev(protocol.StepOS, protocol.StepOK, "Would refresh the package lists (apt-get update).")
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
	ctx, cancel := r.write(aptInstallTimeout)
	_, err := r.e.Runner.Run(ctx, "apt-get", host.AptInstallArgs(pkgs)...)
	cancel()
	r.changed = true
	if err != nil {
		r.stop(protocol.StepOS, fmt.Sprintf("apt-get stopped with an error while upgrading packages (%v). Some packages may be only partly installed; check with `sudo dpkg --audit`. OS updates can't be undone automatically.", err))
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

	r.ev(protocol.StepVerify, protocol.StepStart, "Checking the whole server after the OS updates.")
	res := r.e.Checker.Verify(r.ctx, r.before, nil, dur(r.e.OSVerify, 3*time.Minute))
	r.notes(res)
	if !res.Green {
		r.stop(protocol.StepVerify, "After the OS updates: "+strings.Join(res.Reasons, " ")+" OS updates can't be undone automatically, so the run stopped here.")
		return
	}
	r.lastRunning = res.Running
	r.ev(protocol.StepVerify, protocol.StepOK, fmt.Sprintf("Still healthy after the OS updates: %d containers running.", res.Running))
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
	res := r.e.Checker.Verify(r.ctx, r.before, nil, dur(r.e.FinalVerify, time.Minute))
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
		case !composeOK:
			skipAll(fmt.Sprintf("Docker Compose %s is too old for safe image updates (needs 2.20 or newer).", r.report.Docker.ComposeVersion))
			continue
		case name == collect.StandaloneProject:
			skipAll("These containers aren't part of a Compose project, so upkeeper.sh leaves their images alone.")
			continue
		}
		if why := projectHealthy(r.before, name); why != "" {
			skipAll("Skipped: " + why + ".")
			continue
		}
		r.project(name, ps)
	}
}

func versionOf(s string) ([2]int, bool) {
	var v [2]int
	_, err := fmt.Sscanf(strings.TrimPrefix(s, "v"), "%d.%d", &v[0], &v[1])
	return v, err == nil
}

func composeFiles(pi ProjectInfo, override string, haveOverride bool) []string {
	var files []string
	for _, f := range pi.ConfigFiles {
		if f != override && !slices.Contains(files, f) {
			files = append(files, f)
		}
	}
	if haveOverride {
		files = append(files, override)
	}
	return files
}

func (r *runner) project(name string, ps []planned) {
	e := r.e
	skipAll := func(reason string) {
		for _, p := range ps {
			r.skip(p.item, reason, true)
		}
		r.ev(protocol.StepImages, protocol.StepSkip, name+": "+reason)
	}
	pi, err := e.Docker.Project(r.ctx, name)
	if err == nil {
		err = e.Trust.CheckProject(&pi, pi.MountSources)
	}
	if err != nil {
		skipAll("Can't verify where this project's compose file lives (" + err.Error() + "), so its images are left alone.")
		return
	}
	overridePath := filepath.Join(filepath.Dir(pi.ConfigFiles[0]), OverrideName)
	if err := e.Trust.CheckPath(dirOf(overridePath), true, pi.MountSources); err != nil {
		skipAll("Can't verify the directory for " + OverrideName + " (" + err.Error() + ").")
		return
	}
	ov, haveOv, err := ReadOverride(overridePath)
	if err != nil {
		skipAll(err.Error() + ".")
		return
	}
	r.ev(protocol.StepImages, protocol.StepStart, fmt.Sprintf("%s: updating %d services.", name, len(ps)), "project", name, "dir", pi.WorkDir)

	var changes []Change
	var services []string
	for _, p := range ps {
		u := p.img
		svc, ok := r.service(u.Project, u.Service)
		if !ok {
			r.skip(p.item, "The service isn't running any more.", true)
			continue
		}
		repo, _ := splitRef(svc.Image)
		if u.ToDigest == "" {
			r.skip(p.item, "The new version's digest couldn't be confirmed when planning, so it waits for the next run.", true)
			continue
		}
		target := repo + "@" + u.ToDigest
		label := u.Service + " " + u.ToTag
		if u.NewDigest {
			label = u.Service + " (new " + u.ToTag + " image)"
		}
		if r.dry {
			r.ev(protocol.StepImages, protocol.StepOK, fmt.Sprintf("Would pull %s and recreate %s.", target, u.Service), "service", u.Service, "image", target)
			r.applied(p.item)
			continue
		}
		ctx, cancel := r.write(pullTimeout)
		err := e.Docker.Pull(ctx, target)
		cancel()
		if err != nil {
			r.skip(p.item, fmt.Sprintf("Couldn't download the new image (%v). Nothing changed.", err), true)
			r.ev(protocol.StepImages, protocol.StepWarn, fmt.Sprintf("Couldn't download %s; %s stays as it is.", target, u.Service))
			continue
		}
		newID, err := e.Docker.ImageID(r.ctx, target)
		if err != nil {
			r.skip(p.item, fmt.Sprintf("The pulled image can't be found (%v). Nothing changed.", err), true)
			continue
		}
		oldID := pi.ImageIDs[u.Service]
		if newID == oldID {
			r.skip(p.item, "It already runs this exact image, so it wasn't recreated.", false)
			continue
		}
		ch := Change{Item: p.item, Project: name, Service: u.Service, Floating: u.NewDigest, Repo: repo, Tag: u.ToTag, OldImageID: oldID, NewImage: target, Override: overridePath}
		ctx, cancel = r.write(time.Minute)
		err = e.Docker.Tag(ctx, newID, repo, u.ToTag)
		cancel()
		if err != nil {
			r.skip(p.item, fmt.Sprintf("Couldn't tag the new image (%v).", err), true)
			continue
		}
		if !u.NewDigest {
			ch.OldEntry = ov[u.Service]
			ov[u.Service] = repo + ":" + u.ToTag + "@" + u.ToDigest
		}
		changes = append(changes, ch)
		services = append(services, u.Service)
		r.state.Changes = append(r.state.Changes, ch)
		r.save()
		r.ev(protocol.StepImages, protocol.StepOK, "Pulled "+label+".", "service", u.Service, "image", target)
	}
	if r.dry || len(changes) == 0 {
		return
	}
	r.changed = true
	versioned := false
	for _, c := range changes {
		if !c.Floating {
			versioned = true
		}
	}
	if versioned {
		if err := WriteOverride(overridePath, ov); err != nil {
			r.undo(name, pi, overridePath, ov, changes, services, "Couldn't write "+OverrideName+" ("+err.Error()+").")
			return
		}
		haveOv = len(ov) > 0
	}
	if err := e.Trust.Recheck(pi, pi.MountSources); err != nil {
		r.undo(name, pi, overridePath, ov, changes, services, "The project's files changed during the run ("+err.Error()+").")
		return
	}
	reasons := r.composeUp(pi, overridePath, haveOv, services)
	if len(reasons) == 0 {
		r.ev(protocol.StepVerify, protocol.StepStart, fmt.Sprintf("Checking %s for %s.", name, dur(e.ProjectVerify, 3*time.Minute)))
		res := e.Checker.Verify(r.ctx, r.before, []string{name}, dur(e.ProjectVerify, 3*time.Minute))
		r.notes(res)
		reasons = res.Reasons
		if res.Green {
			for _, c := range changes {
				r.applied(c.Item)
			}
			r.state.Changes = nil
			r.save()
			r.ev(protocol.StepVerify, protocol.StepOK, fmt.Sprintf("%s is healthy with the new images.", name))
			return
		}
	}
	r.undo(name, pi, overridePath, ov, changes, services, strings.Join(reasons, " "))
}

func dirOf(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func (r *runner) composeUp(pi ProjectInfo, override string, haveOv bool, services []string) []string {
	c := host.ComposeUp{ProjectDir: pi.WorkDir, Project: pi.Name, Files: composeFiles(pi, override, haveOv), Services: services}
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

// undo is L1: put the previous images back, recreate, verify again.
func (r *runner) undo(name string, pi ProjectInfo, overridePath string, ov Override, changes []Change, services []string, why string) {
	e := r.e
	r.ev(protocol.StepImages, protocol.StepFail, fmt.Sprintf("%s didn't come back healthy: %s", name, why))
	var failed []string
	for _, c := range changes {
		if c.Floating {
			if c.OldImageID == "" {
				failed = append(failed, c.Service+" (old image unknown)")
				continue
			}
			ctx, cancel := r.write(time.Minute)
			if err := e.Docker.Tag(ctx, c.OldImageID, c.Repo, c.Tag); err != nil {
				failed = append(failed, fmt.Sprintf("%s (%v)", c.Service, err))
			}
			cancel()
		} else if c.OldEntry == "" {
			delete(ov, c.Service)
		} else {
			ov[c.Service] = c.OldEntry
		}
	}
	if err := WriteOverride(overridePath, ov); err != nil {
		failed = append(failed, OverrideName+" ("+err.Error()+")")
	}
	if len(failed) > 0 {
		r.stop(protocol.StepImages, fmt.Sprintf("%s didn't come back healthy, and putting the previous images back failed for %s. The server is frozen so nothing else changes until you look.", name, strings.Join(failed, ", ")))
		return
	}
	_, haveOv, _ := ReadOverride(overridePath)
	reasons := r.composeUp(pi, overridePath, haveOv, services)
	if len(reasons) == 0 {
		res := e.Checker.Verify(r.ctx, r.before, []string{name}, dur(e.ProjectVerify, 3*time.Minute))
		r.notes(res)
		reasons = res.Reasons
		if res.Green {
			for _, c := range changes {
				r.res.Undone = append(r.res.Undone, c.Item)
				from := strings.TrimSuffix(c.Item.From, "@")
				r.undone = append(r.undone, undoneNote{name: c.Service, from: from, to: c.Item.To})
				r.ev(protocol.StepImages, protocol.StepUndo, fmt.Sprintf("Put the previous image of %s back; it's healthy again.", c.Service), "service", c.Service)
			}
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
