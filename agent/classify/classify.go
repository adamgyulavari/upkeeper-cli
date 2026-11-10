// Package classify sorts every pending update into auto, flagged or never
// (scope §5) and lists the risks that make updating harder. Reasons are shown
// to users as written: calm, plain, concrete.
package classify

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/discover"
	"github.com/adamgyulavari/upkeeper-cli/agent/versions"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// ReleaseNote is the release-note reader's verdict (M3). In M0 nothing
// produces notes, but the rules that depend on them are already here.
type ReleaseNote struct {
	Breaking    bool
	ManualSteps bool
	Migration   bool // DB or storage migration
}

// NoteKey identifies the release notes for an update.
func NoteKey(layer protocol.Layer, subject, to string) string {
	return string(layer) + " " + subject + " " + to
}

// Settings are per-server choices that can only make runs more cautious.
type Settings struct {
	SupervisedReboots bool
}

// LatestReleases is the newest stable release per distro, for the
// "release upgrade available" line. Release upgrades are never done by
// upkeeper.sh; they're only reported.
var LatestReleases = map[string]string{"ubuntu": "26.04", "debian": "13"}

// Input is everything the classifier looks at.
type Input struct {
	System      protocol.System
	SystemFacts collect.SystemFacts
	Packages    protocol.Packages
	Apt         collect.AptSim
	Docker      protocol.Docker
	DockerFacts collect.DockerFacts
	DockerVers  discover.DockerVersions
	Projects    []protocol.Project
	Images      []discover.ImageUpdate
	Notes       map[string]ReleaseNote
	Settings    Settings
}

var (
	kernelImageRe = regexp.MustCompile(`^linux-image-(?:unsigned-)?(\d.*)$`)
	kernelPkgRe   = regexp.MustCompile(`^linux-(image|modules|modules-extra|headers|kbuild|tools|cloud-tools|signatures|generic|virtual|aws|azure|gcp|oracle|kvm|lowlatency|hwe|base)(-|$)`)
)

// engine packages are folded into the Docker Engine item.
var enginePkgs = map[string]bool{
	"docker-ce": true, "docker-ce-cli": true, "docker-ce-rootless-extras": true, "docker.io": true,
}
var composePkgs = map[string]bool{"docker-compose-plugin": true, "docker-compose-v2": true}
var dockerAuxPkgs = map[string]bool{
	"containerd.io": true, "containerd": true, "runc": true, "docker-buildx-plugin": true, "docker-buildx": true,
}

func osName(s protocol.System) string {
	switch s.OSID {
	case "ubuntu":
		return "Ubuntu " + s.OSVersion
	case "debian":
		return "Debian " + s.OSVersion
	case "":
		return "this OS release"
	}
	return s.OSID + " " + s.OSVersion
}

// Items classifies every pending update.
func Items(in Input) []protocol.Item {
	held := map[string]bool{}
	for _, h := range in.Packages.Held {
		held[h] = true
	}
	items := []protocol.Item{}
	add := func(it protocol.Item) { items = append(items, it) }
	note := func(layer protocol.Layer, subject, to string) ReleaseNote {
		return in.Notes[NoteKey(layer, subject, to)]
	}

	// ---- OS packages and the kernel ----
	var kernelPkgs []collect.AptUpgrade
	var dockerApt []collect.AptUpgrade
	for _, u := range in.Apt.Upgrades {
		switch {
		case kernelPkgRe.MatchString(u.Package):
			kernelPkgs = append(kernelPkgs, u)
		case enginePkgs[u.Package] || composePkgs[u.Package] || dockerAuxPkgs[u.Package]:
			dockerApt = append(dockerApt, u)
		default:
			add(osItem(in.System, u))
		}
	}
	for _, h := range in.Packages.Held {
		if kernelPkgRe.MatchString(h) || enginePkgs[h] || composePkgs[h] || dockerAuxPkgs[h] {
			continue // reported with their layer below
		}
		add(protocol.Item{Layer: protocol.LayerOS, Subject: h, Decision: protocol.Never,
			Reason: fmt.Sprintf("Held with apt-mark hold, so upkeeper.sh leaves it alone. Run `apt-mark unhold %s` if you want it updated.", h)})
	}
	if it, ok := kernelItem(in, kernelPkgs, held); ok {
		add(it)
	}
	if it, ok := releaseUpgradeItem(in.System); ok {
		add(it)
	}

	// ---- Docker Engine and Compose ----
	items = append(items, dockerItems(in, dockerApt, held, note)...)

	// ---- Images ----
	items = append(items, imageItems(in, note)...)

	sortItems(items)
	return items
}

func osItem(sys protocol.System, u collect.AptUpgrade) protocol.Item {
	it := protocol.Item{Layer: protocol.LayerOS, Subject: u.Package, From: u.From, To: u.To, Security: u.Security, Decision: protocol.Auto}
	switch {
	case u.From == "":
		it.Reason = fmt.Sprintf("New package that another %s update depends on. Installed with it in the weekly run.", osName(sys))
	case u.Security:
		it.Reason = fmt.Sprintf("Security update within %s. Applied in the daily security run and checked afterwards.", osName(sys))
	default:
		it.Reason = fmt.Sprintf("Regular update within %s. Applied in the weekly run and checked afterwards.", osName(sys))
	}
	return it
}

func kernelItem(in Input, pkgs []collect.AptUpgrade, held map[string]bool) (protocol.Item, bool) {
	newest, newestVer, security := "", "", false
	for _, u := range pkgs {
		if u.Security {
			security = true
		}
		m := kernelImageRe.FindStringSubmatch(u.Package)
		if m == nil {
			continue
		}
		if newest == "" || versions.CompareKernel(m[1], newest) > 0 {
			newest, newestVer = m[1], u.To
		}
	}
	// A kernel metapackage update alone (linux-image-generic) still means a new kernel.
	if newest == "" {
		for _, u := range pkgs {
			if strings.HasPrefix(u.Package, "linux-image-") {
				newest, newestVer = u.Package, u.To
				break
			}
		}
	}
	var heldKernel []string
	for h := range held {
		if strings.HasPrefix(h, "linux-image") {
			heldKernel = append(heldKernel, h)
		}
	}
	sort.Strings(heldKernel)
	if newest == "" && len(heldKernel) == 0 {
		return protocol.Item{}, false
	}
	to := newest
	if newest != "" && newest == in.System.KernelRunning && newestVer != "" {
		to = newest + " (" + newestVer + ")" // same ABI, new build (Debian)
	}
	it := protocol.Item{Layer: protocol.LayerKernel, Subject: "kernel", From: in.System.KernelRunning, To: to, Security: security}
	switch {
	case len(heldKernel) > 0:
		it.Decision = protocol.Never
		it.Reason = fmt.Sprintf("The kernel is held with apt-mark hold (%s), so upkeeper.sh leaves it alone.", strings.Join(heldKernel, ", "))
	case len(in.SystemFacts.DKMSModules) > 0 || in.SystemFacts.ZFS:
		mods := in.SystemFacts.DKMSModules
		what := "kernel modules built with DKMS (" + strings.Join(mods, ", ") + ")"
		if len(mods) == 0 {
			what = "a ZFS filesystem"
		}
		it.Decision = protocol.Never
		it.Reason = fmt.Sprintf("This server uses %s. A new kernel can boot without them, so kernel updates are held here and reported only.", what)
	case in.Settings.SupervisedReboots:
		it.Decision = protocol.Flagged
		it.Reason = "A new kernel needs a reboot, and this server is set to reboot only in a supervised run."
	default:
		it.Decision = protocol.Auto
		it.Reason = "New kernel, installed and then booted once inside the maintenance window. If it doesn't come up, the server falls back to the current kernel."
	}
	return it, true
}

func releaseUpgradeItem(sys protocol.System) (protocol.Item, bool) {
	latest, ok := LatestReleases[sys.OSID]
	if !ok || sys.OSVersion == "" {
		return protocol.Item{}, false
	}
	cur, ok1 := versions.ParseVersion(sys.OSVersion)
	lt, ok2 := versions.ParseVersion(latest)
	if !ok1 || !ok2 || versions.Compare(cur, lt) >= 0 {
		return protocol.Item{}, false
	}
	return protocol.Item{
		Layer: protocol.LayerOS, Subject: "release upgrade", From: sys.OSVersion, To: latest, Decision: protocol.Never,
		Reason: fmt.Sprintf("%s is available. upkeeper.sh doesn't do release upgrades; plan this one yourself, with a backup.", osName(protocol.System{OSID: sys.OSID, OSVersion: latest})),
	}, true
}

func dockerItems(in Input, dockerApt []collect.AptUpgrade, held map[string]bool, note func(protocol.Layer, string, string) ReleaseNote) []protocol.Item {
	d := in.Docker
	var items []protocol.Item
	if !d.Installed {
		return nil
	}
	enginePkg := in.DockerFacts.EnginePackage
	if enginePkg == "" {
		enginePkg = d.Family
	}
	subject := enginePkg
	if subject == "" || subject == "other" {
		subject = "docker"
	}
	engineHeld := held["docker-ce"] || held["docker.io"] || held["docker-ce-cli"] || held["containerd.io"]

	cur, curOK := versions.ParseVersion(d.EngineVersion)
	addEngine := func(to string) {
		t, ok := versions.ParseVersion(to)
		if !ok || !curOK || versions.Compare(t, cur) <= 0 {
			return
		}
		it := protocol.Item{Layer: protocol.LayerDocker, Subject: subject, From: d.EngineVersion, To: to}
		n := note(protocol.LayerDocker, subject, to)
		change := versions.Diff(cur, t)
		switch {
		case engineHeld:
			it.Decision = protocol.Never
			it.Reason = "Docker is held with apt-mark hold, so upkeeper.sh leaves it alone."
		case n.Breaking || n.ManualSteps || n.Migration:
			it.Decision = protocol.Flagged
			it.Reason = noteReason(n, "Docker "+to)
		case change == versions.Patch:
			it.Decision = protocol.Auto
			it.Reason = fmt.Sprintf("Patch release within Docker %d.%d. Containers restart; if any don't come back, upkeeper.sh reinstalls %s.", cur.Nums[0], minorOf(cur), d.EngineVersion)
		default:
			it.Decision = protocol.Flagged
			it.Reason = fmt.Sprintf("Docker %s → %s is a %s upgrade. Upgrades like this have broken working setups before, so it waits for a supervised run.", d.EngineVersion, to, change)
		}
		items = append(items, it)
	}
	addEngine(d.LatestPatch)
	if d.LatestVersion != d.LatestPatch {
		addEngine(d.LatestVersion)
	}

	// Engine package rebuilds visible only in apt (same upstream version, new
	// Debian revision), or apt candidates when discovery had nothing.
	haveEngine := len(items) > 0
	for _, u := range dockerApt {
		up := versions.UpstreamDebian(u.To)
		switch {
		case enginePkgs[u.Package]:
			if haveEngine || u.Package != enginePkg {
				continue
			}
			if up == d.EngineVersion || !curOK {
				it := protocol.Item{Layer: protocol.LayerDocker, Subject: subject, From: u.From, To: u.To, Security: u.Security}
				if engineHeld {
					it.Decision, it.Reason = protocol.Never, "Docker is held with apt-mark hold, so upkeeper.sh leaves it alone."
				} else {
					it.Decision, it.Reason = protocol.Auto, "New package build of the same Docker version. Containers restart; if any don't come back, upkeeper.sh reinstalls the current build."
				}
				items = append(items, it)
			} else {
				addEngine(up)
			}
			haveEngine = true
		case composePkgs[u.Package]:
			// handled with the Compose item below
		case dockerAuxPkgs[u.Package]:
			from, to := versions.UpstreamDebian(u.From), versions.UpstreamDebian(u.To)
			ft, ok1 := versions.ParseVersion(from)
			tt, ok2 := versions.ParseVersion(to)
			it := protocol.Item{Layer: protocol.LayerDocker, Subject: u.Package, From: u.From, To: u.To, Security: u.Security}
			switch {
			case held[u.Package]:
				it.Decision, it.Reason = protocol.Never, "Held with apt-mark hold, so upkeeper.sh leaves it alone."
			case ok1 && ok2 && versions.Diff(ft, tt) == versions.Major:
				it.Decision = protocol.Flagged
				it.Reason = fmt.Sprintf("%s %s → %s is a major upgrade of a part every container runs on, so it waits for a supervised run.", u.Package, from, to)
			default:
				it.Decision = protocol.Auto
				it.Reason = fmt.Sprintf("Update to %s, installed with Docker in the weekly run. If containers don't come back, the previous version is reinstalled.", u.Package)
			}
			items = append(items, it)
		}
	}
	if engineHeld && !haveEngine && len(items) == 0 {
		items = append(items, protocol.Item{Layer: protocol.LayerDocker, Subject: subject, From: d.EngineVersion, Decision: protocol.Never,
			Reason: "Docker is held with apt-mark hold, so upkeeper.sh leaves it alone and doesn't look for updates."})
	}

	// Compose plugin
	composeTo := in.DockerVers.ComposeLatest
	composePkg := in.DockerFacts.ComposePackage
	if composeTo == "" {
		for _, u := range dockerApt {
			if composePkgs[u.Package] {
				composeTo, composePkg = versions.UpstreamDebian(u.To), u.Package
			}
		}
	}
	if composePkg == "" {
		composePkg = "docker-compose-plugin"
	}
	if cv, ok := versions.ParseVersion(d.ComposeVersion); ok && composeTo != "" {
		if tv, ok := versions.ParseVersion(composeTo); ok && versions.Compare(tv, cv) > 0 {
			it := protocol.Item{Layer: protocol.LayerDocker, Subject: composePkg, From: d.ComposeVersion, To: composeTo}
			n := note(protocol.LayerDocker, composePkg, composeTo)
			switch {
			case held[composePkg]:
				it.Decision, it.Reason = protocol.Never, "Held with apt-mark hold, so upkeeper.sh leaves it alone."
			case n.Breaking || n.ManualSteps || n.Migration:
				it.Decision, it.Reason = protocol.Flagged, noteReason(n, "Compose "+composeTo)
			case tv.Nums[0] != cv.Nums[0]:
				it.Decision = protocol.Flagged
				it.Reason = fmt.Sprintf("Compose %d → %d is a major upgrade and can change how compose files are read, so it waits for a supervised run.", cv.Nums[0], tv.Nums[0])
			default:
				it.Decision = protocol.Auto
				it.Reason = fmt.Sprintf("%s update within Compose %d, installed with Docker in the weekly run.", capitalize(versions.Diff(cv, tv).String()), cv.Nums[0])
			}
			items = append(items, it)
		}
	}
	return items
}

func minorOf(t versions.Tag) int {
	if len(t.Nums) > 1 {
		return t.Nums[1]
	}
	return 0
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func noteReason(n ReleaseNote, what string) string {
	switch {
	case n.Migration:
		return fmt.Sprintf("The release notes for %s mention a database or storage migration, which can't be undone automatically. It waits for a supervised run.", what)
	case n.ManualSteps:
		return fmt.Sprintf("The release notes for %s ask for manual steps, so it waits for a supervised run.", what)
	default:
		return fmt.Sprintf("The release notes for %s list breaking changes, so it waits for a supervised run.", what)
	}
}

func imageItems(in Input, note func(protocol.Layer, string, string) ReleaseNote) []protocol.Item {
	var items []protocol.Item
	svcs := map[string]protocol.Service{}
	for _, p := range in.Projects {
		for _, s := range p.Services {
			key := p.Name + "/" + s.Name
			svcs[key] = s
			if s.Pinned && !in.DockerFacts.Services[key].Coolify {
				f := in.DockerFacts.Services[key]
				it := protocol.Item{Layer: protocol.LayerImage, Subject: key, From: s.Image, Decision: protocol.Never}
				if f.Ref.Digest != "" || strings.Contains(s.Image, "@sha256:") {
					it.Reason = "Pinned to a digest, so upkeeper.sh doesn't look for updates or change it."
				} else {
					it.Reason = "Labelled upkeeper.policy=pin, so upkeeper.sh doesn't look for updates or change it."
				}
				items = append(items, it)
			}
		}
	}
	seen := map[string]bool{}
	for _, u := range in.Images {
		key := u.Project + "/" + u.Service
		dedupe := key + " " + u.ToTag + " " + u.ToDigest
		if seen[dedupe] {
			continue // replicas of one service
		}
		seen[dedupe] = true
		s := svcs[key]
		f := in.DockerFacts.Services[key]
		it := protocol.Item{Layer: protocol.LayerImage, Subject: key, From: u.FromTag, To: u.ToTag}
		if u.NewDigest {
			it.From = u.FromTag + "@" + shortDigest(u.FromDigest)
			it.To = u.ToTag + "@" + shortDigest(u.ToDigest)
		}
		n := note(protocol.LayerImage, key, u.ToTag)
		hostData := len(s.HostPathMounts) > 0
		switch {
		case s.Pinned, f.Coolify:
			continue // Coolify-managed containers are Coolify's job
		case f.Policy == "supervised":
			it.Decision = protocol.Flagged
			it.Reason = "Labelled upkeeper.policy=supervised, so every update to it waits for a supervised run."
		case n.Migration && hostData:
			it.Decision = protocol.Flagged
			it.Reason = fmt.Sprintf("The release notes mention a migration, and this service keeps data on the host (%s). Swapping the image back can't undo a migration, so it waits for a supervised run.", strings.Join(s.HostPathMounts, ", "))
		case n.Breaking || n.ManualSteps || n.Migration:
			it.Decision = protocol.Flagged
			it.Reason = noteReason(n, it.To)
		case u.FamilyChange != "":
			it.Decision = protocol.Flagged
			it.Reason = familyReason(u)
		case u.NewDigest:
			it.Decision = protocol.Auto
			it.Reason = fmt.Sprintf("New image published under the same tag (%s). Pulled in the weekly run; if the service doesn't come back healthy, the previous image is put back.", u.FromTag)
		case u.Change == versions.Major:
			it.Decision = protocol.Flagged
			ft, _ := versions.ParseTag(u.FromTag)
			if len(ft.Nums) > 0 && ft.Nums[0] == 0 {
				it.Reason = fmt.Sprintf("%s → %s. Below version 1.0 a minor release can change anything, so it's treated as a major upgrade and waits for a supervised run.", u.FromTag, u.ToTag)
			} else {
				it.Reason = fmt.Sprintf("%s → %s is a major version. Major versions often change config or data formats, so it waits for a supervised run.", u.FromTag, u.ToTag)
			}
		default:
			it.Decision = protocol.Auto
			it.Reason = fmt.Sprintf("%s release (%s → %s). Pulled in the weekly run; if the service doesn't come back healthy, the previous image is put back.", capitalize(u.Change.String()), u.FromTag, u.ToTag)
		}
		items = append(items, it)
	}
	return items
}

// bundledNames names software that tag suffixes often carry.
var bundledNames = map[string]string{
	"pg": "Postgres", "postgres": "Postgres", "postgresql": "Postgres", "mysql": "MySQL", "mariadb": "MariaDB",
	"mongo": "MongoDB", "redis": "Redis", "php": "PHP", "python": "Python", "py": "Python", "node": "Node.js",
	"jdk": "Java", "jre": "Java", "java": "Java", "openjdk": "Java", "temurin": "Java", "ruby": "Ruby",
	"go": "Go", "golang": "Go", "debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine",
}

var databases = map[string]bool{"Postgres": true, "MySQL": true, "MariaDB": true, "MongoDB": true}

func familyReason(u discover.ImageUpdate) string {
	ft, _ := versions.ParseTag(u.FromTag)
	tt, _ := versions.ParseTag(u.ToTag)
	if len(ft.Embedded) == len(tt.Embedded) {
		for i := range ft.Embedded {
			a, b := ft.Embedded[i], tt.Embedded[i]
			if a.Major == b.Major {
				continue
			}
			name, ok := bundledNames[a.Word]
			if !ok {
				name = a.Word
			}
			if databases[name] {
				return fmt.Sprintf("%s → %s also moves %s %d → %d, which needs a data migration, so it waits for a supervised run.", u.FromTag, u.ToTag, name, a.Major, b.Major)
			}
			return fmt.Sprintf("%s → %s also moves %s %d → %d inside the image, a major upgrade, so it waits for a supervised run.", u.FromTag, u.ToTag, name, a.Major, b.Major)
		}
	}
	return fmt.Sprintf("%s → %s changes the tag's suffix (%s), so it waits for a supervised run.", u.FromTag, u.ToTag, u.FamilyChange)
}

func shortDigest(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		d = d[:12]
	}
	return d
}

var layerOrder = map[protocol.Layer]int{protocol.LayerOS: 0, protocol.LayerKernel: 1, protocol.LayerDocker: 2, protocol.LayerImage: 3}
var decisionOrder = map[protocol.Decision]int{protocol.Flagged: 0, protocol.Auto: 1, protocol.Never: 2}

func sortItems(items []protocol.Item) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if layerOrder[a.Layer] != layerOrder[b.Layer] {
			return layerOrder[a.Layer] < layerOrder[b.Layer]
		}
		if decisionOrder[a.Decision] != decisionOrder[b.Decision] {
			return decisionOrder[a.Decision] < decisionOrder[b.Decision]
		}
		if a.Security != b.Security {
			return a.Security
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		return a.To < b.To
	})
}
