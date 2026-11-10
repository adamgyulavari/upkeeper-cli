// Package verify is the generic health check (A-14, scope §6, M1 spec §2).
// It knows nothing about the apps: it compares the server now with the
// inventory taken before the run and says green or red, with reasons in
// plain language.
//
// Rules, for everything that was fine before:
//   - every container that was running is running;
//   - healthy wherever a healthcheck is defined (waits up to StartCap);
//   - restart counts don't rise during the window; no new OOM kills;
//   - published ports that accepted TCP still do;
//   - ports that answered HTTP answer with the same status class;
//   - no new failed systemd units (whole-system checks only).
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
	hardDeadline := start.Add(max(window, c.startCap()))
	before = scope(before, projects)
	base := map[string]int{} // container ID → restart count when first seen
	var last Inventory
	for {
		last = scope(c.Snapshot(ctx, projects), projects)
		for _, ct := range last.Containers {
			if _, ok := base[ct.ID]; !ok {
				base[ct.ID] = ct.RestartCount
			}
		}
		elapsed := c.now().Sub(start)
		hard, pending := evaluate(before, last, base, projects == nil, false, elapsed >= c.startCap())
		if len(hard) > 0 {
			return c.finish(ctx, Result{Reasons: hard}, last, start)
		}
		if (!c.now().Before(deadline) && !pending) || !c.now().Before(hardDeadline) {
			break
		}
		if !c.sleep(ctx, c.poll()) {
			return c.finish(ctx, Result{Reasons: []string{"The check was interrupted before it finished."}}, last, start)
		}
	}
	// Final comparison, including ports and units. Ports get two more
	// chances a poll apart, so one slow answer isn't a failure.
	var reasons []string
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			if !c.sleep(ctx, c.poll()) {
				break
			}
			last = scope(c.Snapshot(ctx, projects), projects)
		}
		reasons, _ = evaluate(before, last, base, projects == nil, true, true)
		if len(reasons) == 0 {
			break
		}
	}
	return c.finish(ctx, Result{Green: len(reasons) == 0, Reasons: reasons}, last, start)
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

// evaluate returns hard reasons (red now) and whether something is still
// settling (worth waiting for).
func evaluate(before, now Inventory, base map[string]int, system, final, capReached bool) ([]string, bool) {
	var hard []string
	pending := false
	if !now.DockerOK {
		if final {
			hard = append(hard, "Docker isn't answering: "+now.DockerErr)
		}
		return hard, true
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
			if final {
				if b.running == 1 {
					hard = append(hard, fmt.Sprintf("%s isn't running (it was before the run).", name))
				} else {
					hard = append(hard, fmt.Sprintf("%s has %d of %d containers running.", name, n.running, b.running))
				}
			} else {
				pending = true
			}
		}
		if n.unhealthy > 0 && b.unhealthy == 0 {
			hard = append(hard, fmt.Sprintf("%s reports unhealthy.", name))
		}
		for _, ct := range n.containers {
			if ct.State == "running" && ct.Health == "starting" {
				if capReached {
					hard = append(hard, fmt.Sprintf("%s is still starting after the full wait.", name))
				} else {
					pending = true
				}
				break
			}
		}
		for _, ct := range n.containers {
			if r, ok := base[ct.ID]; ok && ct.RestartCount > r {
				hard = append(hard, fmt.Sprintf("%s restarted %d times during the check.", name, ct.RestartCount-r))
				break
			}
		}
		if n.oom && !b.oom {
			hard = append(hard, fmt.Sprintf("%s was killed for running out of memory.", name))
		}
		if final {
			hard = append(hard, portReasons(name, b, n)...)
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
			hard = append(hard, fmt.Sprintf("The systemd unit %s failed.", added[0]))
		} else if len(added) > 1 {
			hard = append(hard, fmt.Sprintf("These systemd units failed: %s.", strings.Join(added, ", ")))
		}
	}
	return hard, pending
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
