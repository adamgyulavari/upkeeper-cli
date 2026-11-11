package fakes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/classify"
	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/discover"
	"github.com/adamgyulavari/upkeeper-cli/agent/host"
	"github.com/adamgyulavari/upkeeper-cli/agent/registry"
	"github.com/adamgyulavari/upkeeper-cli/agent/run"
	"github.com/adamgyulavari/upkeeper-cli/agent/verify"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// World is a fake server for run-engine tests: Docker containers that
// `docker compose up` really recreates, images that can crash-loop or fail
// their healthcheck, apt that can fail, and a registry to pull from. It
// implements run.Planner, run.DockerOps, verify.Source, host.Runner (with
// the real allowlist) and host.FS.
type World struct {
	mu sync.Mutex

	Root string // temp dir holding the compose projects

	Containers []*Container
	// Compose is project → service → image as written in the compose file.
	Compose map[string]map[string]string
	// Local images: reference ("redis:7.4.1", "redis@sha256:…") → image ID.
	Images map[string]string
	// Registry: "name@sha256:…" → image ID it pulls as.
	Registry map[string]string
	// Bad image IDs and how they misbehave once started.
	CrashLoop map[string]bool
	Unhealthy map[string]bool
	// ImageLabels: image ID → labels the image sets.
	ImageLabels map[string]map[string]string

	Apt           []collect.AptUpgrade
	AptUpdateErr  error
	AptInstallErr error
	// AptInstallChanges: with AptInstallErr, dpkg got halfway (the
	// packages are left half-configured).
	AptInstallChanges bool
	AptGone           map[string]bool // package → planned version vanished after apt-get update
	AptSimExtra       []string        // extra lines in the install simulation
	Held              []string
	Updates           []discover.ImageUpdate
	FreeMB            uint64
	FailedUnits       []string
	ComposeVersion    string
	// Installed is package → installed version (dpkg-query); filled from
	// Apt's From when a package isn't listed.
	Installed map[string]string
	// Timers is apt timer → active.
	Timers map[string]bool

	// Drift is project/service → an edit to the compose files that hasn't
	// been applied: Compose's hash for the service changes, the running
	// container's label doesn't.
	Drift map[string]string
	// Unset is project → variables Compose warns aren't set.
	Unset map[string][]string
	// Replicas is project/service → what the compose file asks for (default 1).
	Replicas map[string]int
	// NoDocker: Docker doesn't answer.
	NoDocker bool

	Calls []string // every write, in order
	seq   int
}

// Container is one fake container.
type Container struct {
	ID, Project, Service, ImageID string
	State, Health                 string
	Restarts                      int
	Port                          int
	Mounts                        []string // writable mount sources
	// Compose labels, as `compose up` wrote them.
	Image       string   // Config.Image
	ConfigHash  string   // com.docker.compose.config-hash
	ConfigFiles []string // com.docker.compose.project.config_files
	// RestartPolicy defaults to unless-stopped; ExitCode for exited ones.
	RestartPolicy string
	ExitCode      int
	AutoRemove    bool
	HealthWait    time.Duration
	HealthFirst   time.Duration
}

// NewWorld builds a world with one Compose project per (project, service,
// image) triple, all healthy, files under root (owned by the test user).
func NewWorld(root string) *World {
	return &World{
		Root: root, Compose: map[string]map[string]string{}, Images: map[string]string{}, Registry: map[string]string{},
		CrashLoop: map[string]bool{}, Unhealthy: map[string]bool{}, ImageLabels: map[string]map[string]string{},
		AptGone: map[string]bool{}, FreeMB: 50000, ComposeVersion: "2.29.1",
		Installed: map[string]string{}, Timers: map[string]bool{"apt-daily.timer": true, "apt-daily-upgrade.timer": true},
		Drift: map[string]string{}, Unset: map[string][]string{}, Replicas: map[string]int{},
	}
}

// configHash is the fake Compose config hash of a service: its image as
// written plus any unapplied edit.
func configHash(project, service, image, drift string) string {
	h := sha256.Sum256([]byte(project + "\x00" + service + "\x00" + image + "\x00" + drift))
	return hex.EncodeToString(h[:])
}

// imageFor is the image Compose would use for a service with files.
func (w *World) imageFor(project, service string, files []string) (string, error) {
	ref := w.Compose[project][service]
	for _, f := range files {
		if filepath.Base(f) == run.OverrideName {
			o, _, err := run.ReadOverride(f)
			if err != nil {
				return "", err
			}
			if v, ok := o[service]; ok {
				ref = v
			}
		}
	}
	return ref, nil
}

// AddService adds a running, healthy service. The image ID is derived
// from the image reference.
func (w *World) AddService(project, service, image string, port int) *Container {
	w.mu.Lock()
	defer w.mu.Unlock()
	dir := filepath.Join(w.Root, project)
	os.MkdirAll(dir, 0o755)
	os.Chmod(dir, 0o755)
	if w.Compose[project] == nil {
		w.Compose[project] = map[string]string{}
	}
	w.Compose[project][service] = image
	var b strings.Builder
	b.WriteString("services:\n")
	for s, img := range w.Compose[project] {
		fmt.Fprintf(&b, "  %s:\n    image: %s\n", s, img)
	}
	os.WriteFile(filepath.Join(dir, "compose.yml"), []byte(b.String()), 0o644)
	id := "sha256:" + image
	w.Images[image] = id
	c := &Container{ID: w.newID(), Project: project, Service: service, ImageID: id, State: "running", Health: "healthy", Port: port,
		Image: image, ConfigHash: configHash(project, service, image, ""), ConfigFiles: []string{filepath.Join(dir, "compose.yml")}, RestartPolicy: "unless-stopped"}
	w.Containers = append(w.Containers, c)
	return c
}

func (w *World) newID() string {
	w.seq++
	return fmt.Sprintf("c%04d", w.seq)
}

// ComposeFile is the project's compose file.
func (w *World) ComposeFile(project string) string {
	return filepath.Join(w.Root, project, "compose.yml")
}

// ---- host.FS ----

func (w *World) ReadFile(p string) ([]byte, error)       { return nil, os.ErrNotExist }
func (w *World) Stat(p string) (os.FileInfo, error)      { return nil, os.ErrNotExist }
func (w *World) ReadDir(p string) ([]os.DirEntry, error) { return nil, os.ErrNotExist }
func (w *World) Glob(string) ([]string, error)           { return nil, nil }
func (w *World) Statfs(string) (uint64, uint64, error) {
	return 100000 << 20, (100000 - w.FreeMB) << 20, nil
}

// ---- run.Planner ----

func (w *World) Plan(ctx context.Context) (protocol.Report, classify.Input) {
	w.mu.Lock()
	defer w.mu.Unlock()
	sys := protocol.System{OSID: "ubuntu", OSVersion: "24.04", OSCodename: "noble", Supported: true, KernelRunning: "6.8.0-49-generic"}
	in := classify.Input{
		System:      sys,
		Packages:    protocol.Packages{Held: append([]string{}, w.Held...)},
		Apt:         collect.AptSim{Upgrades: append([]collect.AptUpgrade{}, w.Apt...)},
		Docker:      protocol.Docker{Installed: true, Family: "docker-ce", EngineVersion: "28.3.2", ComposeVersion: w.ComposeVersion},
		DockerFacts: collect.DockerFacts{Reachable: true, EnginePackage: "docker-ce", Services: map[string]collect.ServiceFacts{}},
	}
	byProject := map[string]*protocol.Project{}
	for _, c := range w.Containers {
		p := byProject[c.Project]
		if p == nil {
			p = &protocol.Project{Name: c.Project, WorkDir: filepath.Join(w.Root, c.Project)}
			byProject[c.Project] = p
		}
		img := w.Compose[c.Project][c.Service]
		ref, err := registry.ParseRef(img)
		p.Services = append(p.Services, protocol.Service{Name: c.Service, Image: img, State: c.State, Health: c.Health, RestartCount: c.Restarts, RestartPolicy: "unless-stopped"})
		f := collect.ServiceFacts{Ref: ref, RefErr: err}
		f.ImageComposeLabels = collect.ImageComposeLabels(w.ImageLabels[c.ImageID])
		in.DockerFacts.Services[c.Project+"/"+c.Service] = f
	}
	for _, p := range byProject {
		in.Projects = append(in.Projects, *p)
	}
	sort.Slice(in.Projects, func(i, j int) bool { return in.Projects[i].Name < in.Projects[j].Name })
	for _, u := range w.Updates {
		in.Images = append(in.Images, u)
	}
	r := protocol.Report{ProtocolVersion: protocol.Version, System: sys, Packages: in.Packages, Docker: in.Docker, Projects: in.Projects}
	r.Items = classify.Items(in)
	r.Risks = classify.Risks(in)
	return r, in
}

// ---- run.DockerOps ----

func (w *World) Project(ctx context.Context, name string) (run.ProjectInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	pi := run.ProjectInfo{Name: name, ImageIDs: map[string]string{}, Services: map[string]run.ServiceInfo{}}
	for _, c := range w.Containers {
		pi.MountSources = append(pi.MountSources, c.Mounts...)
		if c.Project != name {
			continue
		}
		files, override := run.UserFiles(c.ConfigFiles)
		if pi.WorkDir == "" {
			pi.WorkDir = filepath.Join(w.Root, name)
			pi.ConfigFiles, pi.Override = files, override
		} else if strings.Join(files, ",") != strings.Join(pi.ConfigFiles, ",") {
			pi.Inconsistent = "its containers disagree about the project's directory or compose files"
		}
		si := pi.Services[c.Service]
		si.Containers++
		if c.State == "running" {
			si.Running++
		}
		if !slices.Contains(si.Hashes, c.ConfigHash) {
			si.Hashes = append(si.Hashes, c.ConfigHash)
			sort.Strings(si.Hashes)
		}
		si.ImageID, si.Image = c.ImageID, c.Image
		pi.Services[c.Service] = si
		pi.ImageIDs[c.Service] = c.ImageID
		for k := range w.ImageLabels[c.ImageID] {
			if strings.HasPrefix(k, "com.docker.compose.") {
				pi.ImageLabels = append(pi.ImageLabels, k)
				pi.ImageLabelsFrom = c.Service
			}
		}
	}
	if pi.WorkDir == "" {
		return pi, errors.New("no such project")
	}
	return pi, nil
}

func (w *World) Pull(ctx context.Context, image string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Calls = append(w.Calls, "pull "+image)
	id, ok := w.Registry[image]
	if !ok {
		return fmt.Errorf("pull %s: manifest unknown", image)
	}
	w.Images[image] = id
	return nil
}

func (w *World) ImageID(ctx context.Context, image string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if id, ok := w.Images[image]; ok {
		return id, nil
	}
	return "", fmt.Errorf("no such image %s", image)
}

func (w *World) Tag(ctx context.Context, imageID, repo, tag string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Calls = append(w.Calls, fmt.Sprintf("tag %s %s:%s", imageID, repo, tag))
	w.Images[repo+":"+tag] = imageID
	return nil
}

// ---- verify.Source ----

func (w *World) Snapshot(ctx context.Context, projects []string) verify.Inventory {
	w.mu.Lock()
	defer w.mu.Unlock()
	inv := verify.Inventory{DockerOK: true, UnitsOK: true, FailedUnits: append([]string{}, w.FailedUnits...)}
	if w.NoDocker {
		inv.DockerOK, inv.DockerErr = false, "no answer on /var/run/docker.sock"
		return inv
	}
	for _, c := range w.Containers {
		if projects != nil && !slices.Contains(projects, c.Project) {
			continue
		}
		if w.CrashLoop[c.ImageID] {
			c.Restarts++
			c.State = "restarting"
		}
		open := c.State == "running" && c.Health != "unhealthy"
		vc := verify.Container{ID: c.ID, Name: c.Project + "-" + c.Service + "-1", Project: c.Project, Service: c.Service, State: c.State, Health: c.Health, RestartCount: c.Restarts,
			RestartPolicy: c.RestartPolicy, ExitCode: c.ExitCode, AutoRemove: c.AutoRemove, HealthWait: c.HealthWait, HealthFirst: c.HealthFirst}
		if c.Port > 0 {
			p := protocol.Port{HostPort: c.Port, Proto: "tcp", TCPOpen: open}
			if open {
				p.HTTPStatus = 200
			}
			vc.Ports = []protocol.Port{p}
		}
		inv.Containers = append(inv.Containers, vc)
	}
	return inv
}

// ---- host.Runner ----

func (w *World) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, _, err := w.RunStderr(ctx, name, args...)
	return out, err
}

// RunStderr implements host.StderrRunner.
func (w *World) RunStderr(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	if err := host.Allowed(name, args); err != nil {
		return nil, nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if name == "docker" {
		if c, ok := host.ParseComposeConfig(args); ok {
			return w.composeConfig(c)
		}
	}
	out, err := w.run(name, args)
	return out, nil, err
}

func (w *World) composeConfig(c host.ComposeConfig) ([]byte, []byte, error) {
	var out, stderr strings.Builder
	for _, v := range w.Unset[c.Project] {
		fmt.Fprintf(&stderr, "time=\"2026-11-10T03:00:00Z\" level=warning msg=\"The \\\"%s\\\" variable is not set. Defaulting to a blank string.\"\n", v)
	}
	if c.JSON {
		out.WriteString(`{"name":"` + c.Project + `","services":{`)
		for i, svc := range c.Services {
			if i > 0 {
				out.WriteString(",")
			}
			n := 1
			if r, ok := w.Replicas[c.Project+"/"+svc]; ok {
				n = r
			}
			fmt.Fprintf(&out, `"%s":{"image":"x","deploy":{"replicas":%d}}`, svc, n)
		}
		out.WriteString("}}")
		return []byte(out.String()), []byte(stderr.String()), nil
	}
	for _, svc := range c.Services {
		if _, ok := w.Compose[c.Project][svc]; !ok {
			return nil, nil, fmt.Errorf("docker: exit status 1: no such service: %s", svc)
		}
		img, err := w.imageFor(c.Project, svc, c.Files)
		if err != nil {
			return nil, nil, err
		}
		fmt.Fprintf(&out, "%s %s\n", svc, configHash(c.Project, svc, img, w.Drift[c.Project+"/"+svc]))
	}
	return []byte(out.String()), []byte(stderr.String()), nil
}

func (w *World) installed(pkg string) string {
	if v, ok := w.Installed[pkg]; ok {
		return v
	}
	for _, u := range w.Apt {
		if u.Package == pkg {
			return u.From
		}
	}
	return ""
}

func (w *World) run(name string, args []string) ([]byte, error) {
	switch {
	case name == "apt-get" && slices.Equal(args, host.AptUpdate):
		w.Calls = append(w.Calls, "apt-get update")
		return nil, w.AptUpdateErr
	case name == "apt-get" && slices.Contains(args, "-s"):
		var out, missing strings.Builder
		for _, a := range args[len(args)-countPinned(args):] {
			pkg, ver, _ := strings.Cut(a, "=")
			if w.AptGone[pkg] {
				fmt.Fprintf(&missing, "E: Version '%s' for '%s' was not found\n", ver, pkg)
				continue
			}
			from := ""
			for _, u := range w.Apt {
				if u.Package == pkg {
					from = u.From
				}
			}
			fmt.Fprintf(&out, "Inst %s [%s] (%s Ubuntu:24.04/noble-updates [amd64])\n", pkg, from, ver)
		}
		for _, l := range w.AptSimExtra {
			out.WriteString(l + "\n")
		}
		if missing.Len() > 0 {
			return []byte(out.String()), fmt.Errorf("apt-get: exit status 100: %s", missing.String())
		}
		return []byte(out.String()), nil
	case name == "apt-get":
		w.Calls = append(w.Calls, "apt-get install "+strings.Join(args[len(args)-countPinned(args):], " "))
		if w.AptInstallErr != nil {
			if w.AptInstallChanges {
				for _, u := range w.Apt {
					if slices.Contains(args, u.Package+"="+u.To) {
						w.Installed[u.Package] = u.To + " half-configured"
					}
				}
			}
			return nil, w.AptInstallErr
		}
		var keep []collect.AptUpgrade
		for _, u := range w.Apt {
			if !slices.Contains(args, u.Package+"="+u.To) {
				keep = append(keep, u)
			} else {
				w.Installed[u.Package] = u.To
			}
		}
		w.Apt = keep
		return nil, nil
	case name == "dpkg-query":
		var out strings.Builder
		for _, p := range args[2:] {
			if v := w.installed(p); v != "" {
				st := "installed"
				if ver, half, ok := strings.Cut(v, " "); ok {
					v, st = ver, half
				}
				fmt.Fprintf(&out, "%s\t%s\t%s\n", p, v, st)
			}
		}
		return []byte(out.String()), nil
	case name == "systemctl" && len(args) == 2 && args[0] == "is-active":
		if w.Timers[args[1]] {
			return []byte("active\n"), nil
		}
		return []byte("inactive\n"), errors.New("systemctl: exit status 3")
	case name == "systemctl" && len(args) == 2:
		w.Calls = append(w.Calls, "systemctl "+args[0]+" "+args[1])
		w.Timers[args[1]] = args[0] == "start"
		return nil, nil
	case name == "docker":
		c, _ := host.ParseComposeUp(args)
		w.Calls = append(w.Calls, fmt.Sprintf("compose up %s %s files=%d", c.Project, strings.Join(c.Services, ","), len(c.Files)))
		return nil, w.composeUp(c)
	case name == "systemctl":
		return []byte(strings.Join(w.FailedUnits, "\n")), nil
	}
	return nil, fmt.Errorf("fake world: unexpected %s %v", name, args)
}

func countPinned(args []string) int {
	n := 0
	for i := len(args) - 1; i >= 0 && strings.Contains(args[i], "="); i-- {
		if strings.HasPrefix(args[i], "Dpkg::") || strings.HasPrefix(args[i], "Dir::") {
			break
		}
		n++
	}
	return n
}

// composeUp recreates services from the compose file plus the override.
func (w *World) composeUp(c host.ComposeUp) error {
	ov := run.Override{}
	for _, f := range c.Files {
		if filepath.Base(f) == run.OverrideName {
			o, _, err := run.ReadOverride(f)
			if err != nil {
				return err
			}
			ov = o
		}
	}
	for _, svc := range c.Services {
		ref := w.Compose[c.Project][svc]
		if o, ok := ov[svc]; ok {
			ref = o
		}
		hash := configHash(c.Project, svc, ref, w.Drift[c.Project+"/"+svc])
		id, ok := w.resolve(ref)
		if !ok {
			return fmt.Errorf("compose: image %s not found locally and --pull never", ref)
		}
		for _, ct := range w.Containers {
			if ct.Project != c.Project || ct.Service != svc {
				continue
			}
			ct.ID, ct.ImageID, ct.Restarts, ct.State, ct.Health = w.newID(), id, 0, "running", "healthy"
			ct.Image, ct.ConfigHash, ct.ConfigFiles, ct.ExitCode = ref, hash, slices.Clone(c.Files), 0
			if w.Unhealthy[id] {
				ct.Health = "unhealthy"
			}
		}
	}
	return nil
}

// resolve finds a local image for "name:tag", "name@digest" or "name:tag@digest".
func (w *World) resolve(ref string) (string, bool) {
	if id, ok := w.Images[ref]; ok {
		return id, true
	}
	if i := strings.Index(ref, "@"); i >= 0 {
		name := ref[:i]
		if j := strings.LastIndex(name, ":"); j > strings.LastIndex(name, "/") {
			name = name[:j]
		}
		id, ok := w.Images[name+ref[i:]]
		return id, ok
	}
	return "", false
}

// Container returns the container of project/service.
func (w *World) Container(project, service string) *Container {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, c := range w.Containers {
		if c.Project == project && c.Service == service {
			return c
		}
	}
	return nil
}

// Clock is a fake clock whose Sleep advances it.
type Clock struct {
	mu sync.Mutex
	T  time.Time
}

func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.T
}

func (c *Clock) Sleep(ctx context.Context, d time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	c.mu.Lock()
	c.T = c.T.Add(d)
	c.mu.Unlock()
	return true
}
