// Package report runs every collector once and builds a protocol.Report.
// A collector that fails or panics adds a line to Report.Errors; the report
// itself always comes back.
package report

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/classify"
	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/discover"
	"github.com/adamgyulavari/upkeeper-cli/agent/dockerapi"
	"github.com/adamgyulavari/upkeeper-cli/agent/host"
	"github.com/adamgyulavari/upkeeper-cli/agent/registry"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// Collector holds everything needed to build a report. Zero fields get defaults.
type Collector struct {
	Env          collect.Env
	Docker       *dockerapi.Client
	Registry     discover.Registry
	AptMeta      discover.AptMeta
	Prober       collect.Prober
	AgentVersion string
	Settings     classify.Settings
	Now          func() time.Time
	// Offline skips everything that leaves the machine (registries, Docker's repo).
	Offline bool
	// Cache is saved after each report (registry and apt metadata).
	Cache *registry.Cache
	// Policy, if set, fills Report.Policy (protocol 2).
	Policy func() *protocol.Policy
}

// Default builds a Collector for the real host.
func Default(agentVersion, cacheDir string) *Collector {
	cache := registry.OpenCache(cacheDir, nil)
	env := collect.Env{FS: host.RootFS{Root: "/"}, Run: host.ExecRunner{}, Arch: DebianArch(runtime.GOARCH)}
	reg := registry.New(cache, "upkeeper/"+agentVersion)
	return &Collector{
		Env:          env,
		Docker:       dockerapi.NewUnix(dockerapi.DefaultSocket),
		Registry:     reg,
		AptMeta:      discover.AptMeta{Cache: cache, Env: env},
		Cache:        cache,
		AgentVersion: agentVersion,
		Settings:     classify.Settings{MinReleaseAge: classify.DefaultMinReleaseAge},
	}
}

// DebianArch maps GOARCH to Debian's architecture names.
func DebianArch(goarch string) string {
	switch goarch {
	case "arm":
		return "armhf"
	case "386":
		return "i386"
	}
	return goarch
}

// Collect builds one report. It never returns an error: problems end up in Errors.
func (c *Collector) Collect(ctx context.Context) protocol.Report {
	r, _ := c.Plan(ctx)
	return r
}

// Plan builds a report and also returns everything the classifier looked
// at, which the run engine needs to act on the items (apt's simulation,
// image references, Docker facts).
func (c *Collector) Plan(ctx context.Context) (protocol.Report, classify.Input) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	r := protocol.Report{
		ProtocolVersion: protocol.Version,
		AgentVersion:    c.AgentVersion,
		CollectedAt:     now().UTC(),
		Projects:        []protocol.Project{},
		Risks:           []protocol.Risk{},
		Items:           []protocol.Item{},
	}
	var errs collect.Errs
	in := classify.Input{Settings: c.Settings}

	step := func(name string, timeout time.Duration, fn func(ctx context.Context)) {
		sctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		defer func() {
			if p := recover(); p != nil {
				errs.Addf(name, "collector crashed: %v", p)
			}
		}()
		fn(sctx)
	}

	var dpkg map[string]collect.DpkgPkg
	step("dpkg", 30*time.Second, func(ctx context.Context) {
		var err error
		dpkg, err = collect.QueryDpkg(ctx, c.Env, collect.DpkgPatterns...)
		errs.Add("dpkg", err)
	})
	step("system", 30*time.Second, func(ctx context.Context) {
		r.System, in.SystemFacts = collect.System(ctx, c.Env, dpkg, &errs)
	})
	step("packages", 2*time.Minute, func(ctx context.Context) {
		r.Packages, in.Apt = collect.Packages(ctx, c.Env, &errs)
	})
	if c.Docker != nil {
		step("docker", time.Minute, func(ctx context.Context) {
			r.Docker, r.Projects, in.DockerFacts = collect.Docker(ctx, c.Env, c.Docker, dpkg, &errs)
		})
		step("ports", 30*time.Second, func(ctx context.Context) {
			c.Prober.ProbeAll(ctx, r.Projects, in.DockerFacts)
		})
	}
	if !c.Offline {
		step("docker versions", time.Minute, func(ctx context.Context) {
			in.DockerVers = discover.Docker(ctx, c.AptMeta, r.System, &r.Docker, in.DockerFacts, &errs)
		})
		if c.Registry != nil {
			step("images", 5*time.Minute, func(ctx context.Context) {
				in.Images = discover.Images(ctx, c.Registry, r.Projects, in.DockerFacts, &errs)
			})
		}
	}
	step("classify", 10*time.Second, func(context.Context) {
		in.System, in.Packages, in.Docker, in.Projects = r.System, r.Packages, r.Docker, r.Projects
		r.Items = classify.Items(in)
		r.Risks = classify.Risks(in)
	})

	// Persist registry/apt caches; failure only costs extra lookups next time.
	if c.Cache != nil {
		if err := c.Cache.Save(); err != nil {
			errs.Add("cache", fmt.Errorf("couldn't save: %w", err))
		}
	}
	if len(errs) > 0 {
		r.Errors = errs
	}
	if c.Policy != nil {
		r.Policy = c.Policy()
	}
	return r, in
}
