package collect

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/adamgyulavari/upkeeper-cli/agent/dockerapi"
	"github.com/adamgyulavari/upkeeper-cli/agent/host"
	"github.com/adamgyulavari/upkeeper-cli/agent/registry"
	"github.com/adamgyulavari/upkeeper-cli/agent/versions"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// StandaloneProject groups containers that aren't part of a Compose project.
// Compose project names can't contain parentheses, so it can't collide.
const StandaloneProject = "(standalone)"

// PolicyLabel lets a user mark a service: "pin" (never update) or
// "supervised" (always flag). It can only make the agent more cautious.
const PolicyLabel = "upkeeper.policy"

// ServiceFacts are per-service details for the classifier.
type ServiceFacts struct {
	Ref       registry.Ref
	RefErr    error
	Policy    string // value of upkeeper.policy
	OOMKilled bool
	BindIPs   map[string]string // "port/proto" → host IP it is published on
	Coolify   bool              // managed by Coolify: Coolify updates it, upkeeper.sh leaves it alone
	// MountDests are container paths of writable volumes and bind mounts.
	MountDests []string
	// ImageComposeLabels lists com.docker.compose.* labels the image itself
	// sets. Container labels with those names may be inherited from the
	// image rather than written by Compose, so they can't be trusted.
	ImageComposeLabels []string
	// LabelMismatch: the image sets a Compose label to a different value
	// than the container has (Compose overwrote it).
	LabelMismatch bool
}

// ImageComposeLabels returns the com.docker.compose.* labels an image
// defines, sorted.
func ImageComposeLabels(imageLabels map[string]string) []string {
	var out []string
	for k := range imageLabels {
		if strings.HasPrefix(k, "com.docker.compose.") {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// CoolifyManaged reports whether a container belongs to Coolify (Coolify
// itself, its proxy, or an app it deployed). Coolify updates these; on a
// Coolify host upkeeper.sh only maintains the OS, kernel and Docker.
func CoolifyManaged(labels map[string]string, repo, workDir string) bool {
	return labels["coolify.managed"] == "true" ||
		strings.Contains(repo, "coollabsio/") ||
		strings.HasPrefix(workDir, "/data/coolify/")
}

// DockerFacts holds what the classifier and discovery need beyond the protocol.
type DockerFacts struct {
	Reachable       bool
	ComposePackage  string                  // docker-compose-plugin | docker-compose-v2 | ""
	ComposeFromDpkg string                  // full Debian version, if known
	EnginePackage   string                  // docker-ce | docker.io | moby-engine
	EngineDpkg      string                  // full Debian version of the engine package
	Services        map[string]ServiceFacts // key: project/service
	CoolifyHost     bool                    // at least one Coolify-managed container
}

// Docker collects Docker Engine, Compose and container inventory (A-04).
// The engine is only read through its API; nothing is ever started or pulled.
func Docker(ctx context.Context, env Env, api *dockerapi.Client, dpkg map[string]DpkgPkg, errs *Errs) (protocol.Docker, []protocol.Project, DockerFacts) {
	var d protocol.Docker
	facts := DockerFacts{Services: map[string]ServiceFacts{}}
	projects := []protocol.Project{}

	// Family, from the package that provides dockerd.
	for _, name := range []string{"docker-ce", "docker.io", "moby-engine"} {
		if p, ok := dpkg[name]; ok && p.Installed() {
			facts.EnginePackage, facts.EngineDpkg = name, p.Version
			break
		}
	}
	switch facts.EnginePackage {
	case "docker-ce", "docker.io":
		d.Family = facts.EnginePackage
	case "":
	default:
		d.Family = "other"
	}

	// Compose v2 plugin
	for _, name := range []string{"docker-compose-plugin", "docker-compose-v2"} {
		if p, ok := dpkg[name]; ok && p.Installed() {
			facts.ComposePackage, facts.ComposeFromDpkg = name, p.Version
			d.ComposeVersion = versions.UpstreamDebian(p.Version)
			break
		}
	}
	if d.ComposeVersion == "" {
		for _, p := range host.ComposePluginPaths {
			if _, err := env.FS.Stat(p); err != nil {
				continue
			}
			out, err := env.Run.Run(ctx, p, "version", "--short")
			if err != nil {
				errs.Add("compose", err)
				break
			}
			d.ComposeVersion = strings.TrimPrefix(strings.TrimSpace(string(out)), "v")
			break
		}
	}
	d.ComposeV1 = composeV1Present(env, dpkg)

	ver, err := api.Version(ctx)
	if err != nil {
		errs.Add("docker", explainDockerErr(err))
		d.Installed = d.Family != ""
		if facts.EngineDpkg != "" {
			d.EngineVersion = versions.UpstreamDebian(facts.EngineDpkg) // installed, even if not answering
		}
		return d, projects, facts
	}
	facts.Reachable = true
	d.Installed = true
	d.EngineVersion = ver.Version
	if d.Family == "" {
		d.Family = "other"
	}

	list, err := api.Containers(ctx)
	if err != nil {
		errs.Add("docker containers", err)
		return d, projects, facts
	}
	byProject := map[string]*protocol.Project{}
	imageCache := map[string]dockerapi.Image{}
	for _, c := range list {
		ci, err := api.Inspect(ctx, c.ID)
		if err != nil {
			errs.Add("docker inspect "+shortID(c.ID), err)
			continue
		}
		labels := ci.Config.Labels
		if labels == nil {
			labels = c.Labels
		}
		projName := labels["com.docker.compose.project"]
		svcName := labels["com.docker.compose.service"]
		workDir := labels["com.docker.compose.project.working_dir"]
		if projName == "" {
			projName = StandaloneProject
			svcName = strings.TrimPrefix(ci.Name, "/")
		}
		p := byProject[projName]
		if p == nil {
			p = &protocol.Project{Name: projName, WorkDir: workDir, Services: []protocol.Service{}}
			byProject[projName] = p
		}

		imageStr := ci.Config.Image
		if imageStr == "" {
			imageStr = c.Image
		}
		ref, refErr := registry.ParseRef(imageStr)
		sf := ServiceFacts{Ref: ref, RefErr: refErr, Policy: strings.ToLower(strings.TrimSpace(labels[PolicyLabel])), OOMKilled: ci.State.OOMKilled, BindIPs: PortBindIPs(c.Ports)}
		sf.Coolify = CoolifyManaged(labels, ref.Repo, workDir)
		if sf.Coolify {
			facts.CoolifyHost = true
		}

		svc := protocol.Service{
			Name:           svcName,
			Image:          imageStr,
			State:          ci.State.Status,
			Health:         "none",
			RestartCount:   ci.RestartCount,
			RestartPolicy:  ci.HostConfig.RestartPolicy.Name,
			Ports:          ports(c.Ports),
			HostPathMounts: dataMounts(ci.Mounts),
			Pinned:         ref.Digest != "" || sf.Policy == "pin",
		}
		if svc.RestartPolicy == "" {
			svc.RestartPolicy = "no"
		}
		if ci.State.Health != nil && ci.State.Health.Status != "" {
			svc.Health = ci.State.Health.Status
		}
		var im dockerapi.Image
		if ci.Image != "" {
			var ok bool
			im, ok = imageCache[ci.Image]
			if !ok {
				im, err = api.Image(ctx, ci.Image)
				if err != nil {
					errs.Add("docker image "+shortID(ci.Image), err)
				}
				imageCache[ci.Image] = im
			}
		}
		sf.MountDests = dataMountDests(ci.Mounts)
		sf.ImageComposeLabels = ImageComposeLabels(im.Config.Labels)
		for _, k := range sf.ImageComposeLabels {
			if im.Config.Labels[k] != labels[k] {
				sf.LabelMismatch = true
			}
		}
		if ref.Digest != "" {
			svc.Digest = ref.Digest
		} else if ci.Image != "" {
			for _, rd := range im.RepoDigests {
				if refErr == nil && ref.SameRepo(rd) {
					_, dg, _ := strings.Cut(rd, "@")
					svc.Digest = dg
					break
				}
			}
		}
		p.Services = append(p.Services, svc)
		facts.Services[projName+"/"+svcName] = sf
	}
	for _, p := range byProject {
		sort.SliceStable(p.Services, func(i, j int) bool { return p.Services[i].Name < p.Services[j].Name })
		projects = append(projects, *p)
	}
	sort.Slice(projects, func(i, j int) bool { return projects[i].Name < projects[j].Name })
	return d, projects, facts
}

func explainDockerErr(err error) error {
	var ne *net.OpError
	if errors.As(err, &ne) {
		return errors.New("no answer on " + dockerapi.DefaultSocket + " (is Docker installed and running?)")
	}
	return err
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func ports(ps []dockerapi.PortSummary) []protocol.Port {
	out := []protocol.Port{}
	seen := map[string]bool{}
	for _, p := range ps {
		if p.PublicPort == 0 {
			continue
		}
		proto := p.Type
		if proto == "" {
			proto = "tcp"
		}
		k := strconv.Itoa(p.PublicPort) + "/" + proto
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, protocol.Port{HostPort: p.PublicPort, Proto: proto})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].HostPort != out[j].HostPort {
			return out[i].HostPort < out[j].HostPort
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

// PortBindIPs maps "port/proto" to the host IP it was published on, so the
// probe can reach ports bound to one address.
func PortBindIPs(ps []dockerapi.PortSummary) map[string]string {
	m := map[string]string{}
	for _, p := range ps {
		if p.PublicPort == 0 {
			continue
		}
		k := strconv.Itoa(p.PublicPort) + "/" + p.Type
		if _, ok := m[k]; !ok || m[k] == "0.0.0.0" || m[k] == "::" {
			m[k] = p.IP
		}
	}
	return m
}

var nonDataBinds = []string{
	"/var/run/docker.sock", "/run/docker.sock", "/etc/localtime", "/etc/timezone",
	"/etc/hosts", "/etc/resolv.conf", "/etc/hostname", "/etc/machine-id",
}

var nonDataPrefixes = []string{"/dev/", "/proc/", "/sys/", "/run/"}

// dataMounts lists host paths that hold data written by the container:
// writable bind mounts and named volumes. Sockets and clock files are skipped.
func dataMounts(ms []dockerapi.Mount) []string {
	out := []string{}
	for _, m := range ms {
		if !m.RW || m.Source == "" {
			continue
		}
		switch m.Type {
		case "bind":
			if contains(nonDataBinds, m.Source) {
				continue
			}
			skip := false
			for _, p := range nonDataPrefixes {
				if strings.HasPrefix(m.Source, p) {
					skip = true
				}
			}
			if skip {
				continue
			}
		case "volume":
		default:
			continue
		}
		out = append(out, m.Source)
	}
	sort.Strings(out)
	return out
}

// dataMountDests lists container paths of writable volumes and bind mounts.
func dataMountDests(ms []dockerapi.Mount) []string {
	out := []string{}
	for _, m := range ms {
		if m.RW && (m.Type == "volume" || m.Type == "bind") && m.Destination != "" {
			out = append(out, m.Destination)
		}
	}
	sort.Strings(out)
	return out
}

// composeV1Present detects the EOL Python docker-compose (v1): Ubuntu's
// docker-compose package (1.29.x) or a standalone v1 binary or script.
func composeV1Present(env Env, dpkg map[string]DpkgPkg) bool {
	if p, ok := dpkg["docker-compose"]; ok && p.Installed() && strings.HasPrefix(versions.UpstreamDebian(p.Version), "1.") {
		return true
	}
	for _, path := range []string{"/usr/local/bin/docker-compose", "/usr/bin/docker-compose"} {
		b, err := env.FS.ReadFile(path)
		if err != nil {
			continue
		}
		if bytes.HasPrefix(b, []byte("#!")) {
			first, _, _ := bytes.Cut(b, []byte("\n"))
			if bytes.Contains(first, []byte("python")) {
				return true
			}
			continue
		}
		// v1 standalone binaries are PyInstaller bundles; v2 is a Go binary.
		tail := b
		if len(tail) > 256<<10 {
			tail = tail[len(tail)-256<<10:]
		}
		if bytes.Contains(tail, []byte("MEI\x0c\x0b\x0a\x0b\x0e")) || bytes.Contains(b, []byte("_MEIPASS")) {
			return true
		}
	}
	return false
}
