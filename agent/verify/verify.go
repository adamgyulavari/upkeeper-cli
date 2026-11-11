// Package verify is the generic health check (A-14, scope §6, M1 spec §2).
// It knows nothing about the apps: it compares the server now with the
// inventory taken before the run and says green or red, with reasons in
// plain language.
//
// Rules, for everything that was fine before:
//   - every container that was running is running, except one that
//     finished on its own: it exited with code 0 and Docker wasn't asked to
//     keep it running (restart policy "no" or "on-failure"), or it was
//     started with --rm and is gone. Cron-started backups and CI jobs end
//     like that. A container with restart policy "always" or
//     "unless-stopped" must keep running;
//   - healthy wherever a healthcheck is defined. "starting" is waited for
//     as long as the healthcheck itself can take (start_period, then
//     retries × (interval + timeout)), at most MaxHealthWait;
//   - restart counts don't rise during the window; no new OOM kills;
//   - published ports that accepted TCP still do. The probe goes to the
//     container's own address and port where it has one, because the
//     published port on the host is answered by docker-proxy whenever the
//     container runs, listening or not;
//   - ports that answered HTTP answer with the same status class;
//   - no new failed systemd units (whole-system checks only);
//   - Docker answers, if it answered before.
//
// Log lines that look bad are notes for the run record, never a reason for red.
package verify

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// Container is one container as the check sees it.
type Container struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Project      string          `json:"project"`
	Service      string          `json:"service"`
	State        string          `json:"state"`  // running | exited | restarting …
	Health       string          `json:"health"` // healthy | unhealthy | starting | none
	RestartCount int             `json:"restart_count"`
	OOMKilled    bool            `json:"oom_killed,omitempty"`
	Ports        []protocol.Port `json:"ports,omitempty"`
	// RestartPolicy is Docker's restart policy name ("no" when unset).
	RestartPolicy string `json:"restart_policy,omitempty"`
	AutoRemove    bool   `json:"auto_remove,omitempty"` // started with --rm
	ExitCode      int    `json:"exit_code,omitempty"`
	// HealthWait is how long the healthcheck can stay "starting" before it
	// must report (0: no healthcheck config known, StartCap applies).
	HealthWait time.Duration `json:"health_wait,omitempty"`
	// HealthFirst is the earliest a first health result can arrive.
	HealthFirst time.Duration `json:"health_first,omitempty"`
}

// MaxHealthWait is the longest the check waits for a healthcheck that is
// still starting.
const MaxHealthWait = 10 * time.Minute

// HealthTimes works out HealthWait and HealthFirst from a healthcheck's
// settings, with Docker's defaults for zero values (interval 30 s, timeout
// 30 s, 3 retries, start interval 5 s).
func HealthTimes(interval, timeout, startPeriod, startInterval time.Duration, retries int) (wait, first time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if retries <= 0 {
		retries = 3
	}
	if startInterval <= 0 {
		startInterval = 5 * time.Second
	}
	first = interval
	if startPeriod > 0 && startInterval < interval {
		first = startInterval // probes run every start interval during the start period
	}
	wait = startPeriod + time.Duration(retries)*(interval+timeout) + 30*time.Second
	return wait, first
}

// finished reports whether a container ended on its own and cleanly.
func (c Container) finished() bool {
	return c.State == "exited" && c.ExitCode == 0 && c.mayStop()
}

// mayStop: Docker wasn't asked to keep it running.
func (c Container) mayStop() bool {
	switch c.RestartPolicy {
	case "", "no", "on-failure":
		return true
	}
	return false
}

// Key is project/service.
func (c Container) Key() string { return c.Project + "/" + c.Service }

// Inventory is a snapshot of what the check compares.
type Inventory struct {
	At          time.Time   `json:"at"`
	DockerOK    bool        `json:"docker_ok"`
	DockerErr   string      `json:"docker_err,omitempty"`
	Containers  []Container `json:"containers"`
	FailedUnits []string    `json:"failed_units"`
	UnitsOK     bool        `json:"units_ok"`
}

// Running counts running containers.
func (inv Inventory) Running() int {
	n := 0
	for _, c := range inv.Containers {
		if c.State == "running" {
			n++
		}
	}
	return n
}

// Project returns the containers of one project.
func (inv Inventory) Project(name string) []Container {
	var out []Container
	for _, c := range inv.Containers {
		if c.Project == name {
			out = append(out, c)
		}
	}
	return out
}

// Source takes snapshots. projects limits it to some Compose projects (nil:
// everything). It never fails: problems show up as DockerOK/UnitsOK false.
type Source interface {
	Snapshot(ctx context.Context, projects []string) Inventory
}

// LogScanner looks for alarming log lines (notes only).
type LogScanner interface {
	Scan(ctx context.Context, containers []Container, since time.Time) []string
}

// Checker runs the check.
type Checker struct {
	Source   Source
	Logs     LogScanner    // optional
	Poll     time.Duration // between snapshots; default 10 s
	StartCap time.Duration // longest wait for "starting"; default 3 min
	Now      func() time.Time
	// Sleep returns false if ctx ended.
	Sleep func(ctx context.Context, d time.Duration) bool
}

// Result of a check.
type Result struct {
	Green   bool     `json:"green"`
	Reasons []string `json:"reasons,omitempty"` // why it's red
	Notes   []string `json:"notes,omitempty"`   // log lines worth a look
	Running int      `json:"running"`           // containers running at the end (in scope)
	// Interrupted: the check was cut short (the agent is stopping), so it
	// says nothing either way.
	Interrupted bool `json:"interrupted,omitempty"`
	// OnlyStarting: red only because a healthcheck was still starting
	// after the full wait.
	OnlyStarting bool `json:"only_starting,omitempty"`
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Checker) sleep(ctx context.Context, d time.Duration) bool {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (c *Checker) poll() time.Duration {
	if c.Poll > 0 {
		return c.Poll
	}
	return 10 * time.Second
}

func (c *Checker) startCap() time.Duration {
	if c.StartCap > 0 {
		return c.StartCap
	}
	return 3 * time.Minute
}

// healthWait is how long a container may stay "starting".
func (c *Checker) healthWait(ct Container) time.Duration {
	if ct.HealthWait <= 0 {
		return c.startCap()
	}
	return min(ct.HealthWait, MaxHealthWait)
}

func (c *Checker) longestWait(inv Inventory) time.Duration {
	d := c.startCap()
	for _, ct := range inv.Containers {
		d = max(d, c.healthWait(ct))
	}
	return d
}

// Snapshot takes one inventory.
func (c *Checker) Snapshot(ctx context.Context, projects []string) Inventory {
	inv := c.Source.Snapshot(ctx, projects)
	if inv.At.IsZero() {
		inv.At = c.now()
	}
	return inv
}

// Verify watches the server for window and compares it with before.
// projects limits the check to some Compose projects; nil checks the whole
// server, including systemd units.
func (c *Checker) Verify(ctx context.Context, before Inventory, projects []string, window time.Duration) Result {
	start := c.now()
	deadline := start.Add(window)
	before = scope(before, projects)
	base := map[string]int{} // container ID → restart count when first seen
	var last Inventory
	interrupted := func() Result {
		return c.finish(ctx, Result{Interrupted: true, Reasons: []string{"The check was interrupted before it finished."}}, last, start)
	}
	for {
		last = scope(c.Snapshot(ctx, projects), projects)
		for _, ct := range last.Containers {
			if _, ok := base[ct.ID]; !ok {
				base[ct.ID] = ct.RestartCount
			}
		}
		elapsed := c.now().Sub(start)
		ev := c.evaluate(before, last, base, projects == nil, false, elapsed)
		if len(ev.hard) > 0 {
			return c.finish(ctx, Result{Reasons: ev.hard, OnlyStarting: ev.onlyStarting}, last, start)
		}
		hardDeadline := start.Add(max(window, c.longestWait(last)))
		if (!c.now().Before(deadline) && !ev.pending) || !c.now().Before(hardDeadline) {
			break
		}
		if !c.sleep(ctx, c.poll()) {
			return interrupted()
		}
	}
	// Final comparison, including ports and units. Ports get two more
	// chances a poll apart, so one slow answer isn't a failure.
	var ev evaluation
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			if !c.sleep(ctx, c.poll()) {
				return interrupted()
			}
			last = scope(c.Snapshot(ctx, projects), projects)
		}
		ev = c.evaluate(before, last, base, projects == nil, true, MaxHealthWait+time.Hour)
		if len(ev.hard) == 0 {
			break
		}
	}
	return c.finish(ctx, Result{Green: len(ev.hard) == 0, Reasons: ev.hard, OnlyStarting: ev.onlyStarting}, last, start)
}

func (c *Checker) finish(ctx context.Context, r Result, last Inventory, start time.Time) Result {
	r.Running = last.Running()
	if c.Logs != nil {
		r.Notes = c.Logs.Scan(ctx, last.Containers, start)
	}
	return r
}

func scope(inv Inventory, projects []string) Inventory {
	if projects == nil {
		return inv
	}
	out := inv
	out.Containers = nil
	for _, ct := range inv.Containers {
		if slices.Contains(projects, ct.Project) {
			out.Containers = append(out.Containers, ct)
		}
	}
	return out
}

type group struct {
	running, restarting int
	healthy, unhealthy  int
	oom                 bool
	containers          []Container
}

func groups(inv Inventory) (map[string]*group, []string) {
	m := map[string]*group{}
	var keys []string
	for _, ct := range inv.Containers {
		g := m[ct.Key()]
		if g == nil {
			g = &group{}
			m[ct.Key()] = g
			keys = append(keys, ct.Key())
		}
		g.containers = append(g.containers, ct)
		switch ct.State {
		case "running":
			g.running++
		case "restarting":
			g.restarting++
		}
		switch ct.Health {
		case "healthy", "starting":
			g.healthy++
		case "unhealthy":
			g.unhealthy++
		}
		if ct.OOMKilled {
			g.oom = true
		}
	}
	sort.Strings(keys)
	return m, keys
}

func displayName(key string) string {
	p, s, _ := strings.Cut(key, "/")
	if p == "(standalone)" {
		return s
	}
	return key
}

type evaluation struct {
	hard         []string // red now
	pending      bool     // something is still settling (worth waiting for)
	onlyStarting bool     // every hard reason is a healthcheck still starting
}

// stoppedOK counts, for one group, the containers that were running
// before and have since finished on their own (see the package comment),
// and how many of the before-running containers had to keep running.
func stoppedOK(b, n *group, now Inventory) (finished, mustRun int) {
	ids := map[string]bool{}
	for _, ct := range now.Containers {
		ids[ct.ID] = true
	}
	for _, ct := range b.containers {
		if ct.State != "running" {
			continue
		}
		if !ct.mayStop() {
			mustRun++
		} else if ct.AutoRemove && !ids[ct.ID] {
			finished++ // --rm: gone once it's done
		}
	}
	for _, ct := range n.containers {
		if ct.finished() {
			finished++
		}
	}
	return finished, mustRun
}

func (c *Checker) evaluate(before, now Inventory, base map[string]int, system, final bool, elapsed time.Duration) evaluation {
	var ev evaluation
	starting := 0
	if !now.DockerOK {
		if final && before.DockerOK {
			ev.hard = append(ev.hard, "Docker isn't answering: "+now.DockerErr)
		}
		ev.pending = before.DockerOK
		return ev
	}
	bg, keys := groups(before)
	ng, _ := groups(now)
	for _, k := range keys {
		b := bg[k]
		n := ng[k]
		if n == nil {
			n = &group{}
		}
		name := displayName(k)
		if b.restarting > 0 {
			continue // wasn't fine before the run; nothing to compare
		}
		if b.running > 0 && n.running < b.running {
			finished, mustRun := stoppedOK(b, n, now)
			if n.running < mustRun || b.running-n.running > finished {
				if final {
					if b.running == 1 {
						ev.hard = append(ev.hard, fmt.Sprintf("%s isn't running (it was before the run).", name))
					} else {
						ev.hard = append(ev.hard, fmt.Sprintf("%s has %d of %d containers running.", name, n.running, b.running))
					}
				} else {
					ev.pending = true
				}
			}
		}
		if n.unhealthy > 0 && b.unhealthy == 0 {
			ev.hard = append(ev.hard, fmt.Sprintf("%s reports unhealthy.", name))
		}
		for _, ct := range n.containers {
			if ct.State == "running" && ct.Health == "starting" {
				if elapsed >= c.healthWait(ct) {
					ev.hard = append(ev.hard, fmt.Sprintf("%s is still starting after the full wait (%s).", name, c.healthWait(ct).Round(time.Second)))
					starting++
				} else {
					ev.pending = true
				}
				break
			}
		}
		for _, ct := range n.containers {
			if r, ok := base[ct.ID]; ok && ct.RestartCount > r {
				ev.hard = append(ev.hard, fmt.Sprintf("%s restarted %d times during the check.", name, ct.RestartCount-r))
				break
			}
		}
		if n.oom && !b.oom {
			ev.hard = append(ev.hard, fmt.Sprintf("%s was killed for running out of memory.", name))
		}
		if final {
			ev.hard = append(ev.hard, portReasons(name, b, n)...)
		}
	}
	if system && final && before.UnitsOK && now.UnitsOK {
		var added []string
		for _, u := range now.FailedUnits {
			if !slices.Contains(before.FailedUnits, u) {
				added = append(added, u)
			}
		}
		if len(added) == 1 {
			ev.hard = append(ev.hard, fmt.Sprintf("The systemd unit %s failed.", added[0]))
		} else if len(added) > 1 {
			ev.hard = append(ev.hard, fmt.Sprintf("These systemd units failed: %s.", strings.Join(added, ", ")))
		}
	}
	ev.onlyStarting = len(ev.hard) > 0 && starting == len(ev.hard)
	return ev
}

func portReasons(name string, b, n *group) []string {
	type pk struct {
		port  int
		proto string
	}
	after := map[pk]protocol.Port{}
	for _, ct := range n.containers {
		for _, p := range ct.Ports {
			k := pk{p.HostPort, p.Proto}
			if cur, ok := after[k]; !ok || (!cur.TCPOpen && p.TCPOpen) {
				after[k] = p
			}
		}
	}
	var out []string
	seen := map[pk]bool{}
	for _, ct := range b.containers {
		for _, p := range ct.Ports {
			k := pk{p.HostPort, p.Proto}
			if seen[k] || !p.TCPOpen {
				continue
			}
			seen[k] = true
			a := after[k]
			switch {
			case !a.TCPOpen:
				out = append(out, fmt.Sprintf("%s doesn't accept connections on port %d any more.", name, p.HostPort))
			case p.HTTPStatus > 0 && a.HTTPStatus == 0:
				out = append(out, fmt.Sprintf("%s answered HTTP %d on port %d before the run and doesn't answer HTTP now.", name, p.HTTPStatus, p.HostPort))
			case p.HTTPStatus > 0 && p.HTTPStatus/100 != a.HTTPStatus/100:
				out = append(out, fmt.Sprintf("%s answers HTTP %d on port %d; it was %d before the run.", name, a.HTTPStatus, p.HostPort, p.HTTPStatus))
			}
		}
	}
	return out
}

func protoPort(port int, proto string) protocol.Port {
	return protocol.Port{HostPort: port, Proto: proto}
}
