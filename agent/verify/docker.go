package verify

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/dockerapi"
	"github.com/adamgyulavari/upkeeper-cli/agent/host"
)

// HostSource takes snapshots of the real server: containers through the
// Engine API (read-only), ports with collect.Prober, failed units with
// systemctl.
type HostSource struct {
	API    *dockerapi.Client
	Run    host.Runner
	Prober collect.Prober
}

func (h HostSource) Snapshot(ctx context.Context, projects []string) Inventory {
	inv := Inventory{At: time.Now().UTC(), Containers: []Container{}, FailedUnits: []string{}}
	if h.Run != nil {
		out, err := h.Run.Run(ctx, "systemctl", host.SystemctlFailed...)
		if err == nil {
			inv.FailedUnits, inv.UnitsOK = collect.ParseFailedUnits(out), true
		}
	}
	if h.API == nil {
		inv.DockerErr = "no Docker client"
		return inv
	}
	if _, err := h.API.Version(ctx); err != nil {
		inv.DockerErr = err.Error()
		return inv
	}
	list, err := h.API.Containers(ctx)
	if err != nil {
		inv.DockerErr = err.Error()
		return inv
	}
	inv.DockerOK = true
	type probe struct {
		ci, pi int
		addr   string
	}
	var probes []probe
	for _, cs := range list {
		labels := cs.Labels
		if labels["com.docker.compose.oneoff"] == "True" {
			continue
		}
		ci, err := h.API.Inspect(ctx, cs.ID)
		if err != nil {
			continue // removed between list and inspect (a recreate in progress)
		}
		if ci.Config.Labels != nil {
			labels = ci.Config.Labels
		}
		c := Container{
			ID:           ci.ID,
			Name:         strings.TrimPrefix(ci.Name, "/"),
			Project:      labels["com.docker.compose.project"],
			Service:      labels["com.docker.compose.service"],
			State:        ci.State.Status,
			Health:       "none",
			RestartCount: ci.RestartCount,
			OOMKilled:    ci.State.OOMKilled,
		}
		if c.Project == "" {
			c.Project, c.Service = collect.StandaloneProject, c.Name
		}
		if projects != nil && !slices.Contains(projects, c.Project) {
			continue
		}
		if ci.State.Health != nil && ci.State.Health.Status != "" {
			c.Health = ci.State.Health.Status
		}
		binds := collect.PortBindIPs(cs.Ports)
		seen := map[string]bool{}
		for _, p := range cs.Ports {
			proto := p.Type
			if proto == "" {
				proto = "tcp"
			}
			k := strconv.Itoa(p.PublicPort) + "/" + proto
			if p.PublicPort == 0 || seen[k] {
				continue
			}
			seen[k] = true
			c.Ports = append(c.Ports, protoPort(p.PublicPort, proto))
			if proto == "tcp" && c.State == "running" {
				probes = append(probes, probe{len(inv.Containers), len(c.Ports) - 1, collect.ProbeTarget(binds[k], p.PublicPort)})
			}
		}
		inv.Containers = append(inv.Containers, c)
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, pr := range probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			port := &inv.Containers[pr.ci].Ports[pr.pi]
			port.TCPOpen, port.HTTPStatus = h.Prober.Probe(ctx, pr.addr)
		}()
	}
	wg.Wait()
	sort.Slice(inv.Containers, func(i, j int) bool {
		a, b := inv.Containers[i], inv.Containers[j]
		if a.Key() != b.Key() {
			return a.Key() < b.Key()
		}
		return a.Name < b.Name
	})
	return inv
}

// LogPatterns are log lines worth a note in the run record.
var LogPatterns = []string{"panic:", "FATAL", "migration failed", "Migration failed"}

// DockerLogs scans recent container logs for LogPatterns.
type DockerLogs struct {
	API *dockerapi.Client
}

func (d DockerLogs) Scan(ctx context.Context, cs []Container, since time.Time) []string {
	var notes []string
	for _, c := range cs {
		b, err := d.API.Logs(ctx, c.ID, since, 2000)
		if err != nil {
			continue
		}
		if n := ScanLog(displayName(c.Key()), b); n != "" {
			notes = append(notes, n)
		}
	}
	return notes
}

// ScanLog returns a note if a log contains one of LogPatterns.
func ScanLog(name string, b []byte) string {
	for _, p := range LogPatterns {
		if i := bytes.Index(b, []byte(p)); i >= 0 {
			line := b[i:]
			if j := bytes.IndexByte(line, '\n'); j >= 0 {
				line = line[:j]
			}
			s := strings.Map(func(r rune) rune {
				if r < 0x20 {
					return -1
				}
				return r
			}, string(line))
			if len(s) > 160 {
				s = s[:160] + "…"
			}
			return fmt.Sprintf("%s logged %q. This is only a note; it didn't decide the check.", name, s)
		}
	}
	return ""
}
