package collect

import (
	"bufio"
	"bytes"
	"context"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/host"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// AptUpgrade is one "Inst" line of a simulated upgrade.
type AptUpgrade struct {
	Package  string
	From     string // empty for a newly installed package (a new kernel ABI)
	To       string
	Origins  []string
	Security bool
}

// AptSim is the parsed output of `apt-get -s upgrade`.
type AptSim struct {
	Upgrades []AptUpgrade
	KeptBack []string // kept back or deferred by phasing
}

var instRe = regexp.MustCompile(`^Inst (\S+) (?:\[([^\]]+)\] )?\((\S+) (.*?) ?\[[^\]]+\]\)`)

// ParseAptSim parses `apt-get -s upgrade` output (C locale).
func ParseAptSim(out []byte) AptSim {
	var sim AptSim
	sc := bufio.NewScanner(bytes.NewReader(out))
	inKept := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "The following") {
			inKept = strings.Contains(line, "kept back") || strings.Contains(line, "deferred due to phasing")
			continue
		}
		if inKept {
			if strings.HasPrefix(line, " ") {
				sim.KeptBack = append(sim.KeptBack, strings.Fields(line)...)
				continue
			}
			inKept = false
		}
		m := instRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		u := AptUpgrade{Package: m[1], From: m[2], To: m[3]}
		for _, o := range strings.Split(m[4], ",") {
			if o = strings.TrimSpace(o); o != "" {
				u.Origins = append(u.Origins, o)
				if strings.Contains(o, "-security") {
					u.Security = true
				}
			}
		}
		sim.Upgrades = append(sim.Upgrades, u)
	}
	sort.Strings(sim.KeptBack)
	return sim
}

// Packages collects pending apt updates without refreshing the lists (A-03).
// M0 never runs `apt update`; the lists' age goes into LastAptUpdate instead.
func Packages(ctx context.Context, env Env, errs *Errs) (protocol.Packages, AptSim) {
	p := protocol.Packages{Held: []string{}}
	var sim AptSim

	out, err := env.Run.Run(ctx, "apt-get", host.AptSimulateUpgrade...)
	if err != nil {
		errs.Add("apt", err)
	} else {
		sim = ParseAptSim(out)
		for _, u := range sim.Upgrades {
			if u.From == "" {
				continue // new packages ride along with an upgrade; count the upgrade
			}
			if u.Security {
				p.SecurityUpdates++
			} else {
				p.OtherUpdates++
			}
		}
	}

	if out, err := env.Run.Run(ctx, "apt-mark", "showhold"); err != nil {
		errs.Add("apt-mark", err)
	} else {
		for _, l := range strings.Split(string(out), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				p.Held = append(p.Held, l)
			}
		}
		sort.Strings(p.Held)
	}

	p.LastAptUpdate = lastAptUpdate(env)
	return p, sim
}

func lastAptUpdate(env Env) *time.Time {
	var newest time.Time
	var files []string
	for _, pat := range []string{"/var/lib/apt/lists/*InRelease", "/var/lib/apt/lists/*_Release"} {
		m, _ := env.FS.Glob(pat)
		files = append(files, m...)
	}
	files = append(files, "/var/lib/apt/periodic/update-success-stamp")
	for _, f := range files {
		if st, err := env.FS.Stat(f); err == nil && st.ModTime().After(newest) {
			newest = st.ModTime()
		}
	}
	if newest.IsZero() {
		return nil
	}
	t := newest.UTC()
	return &t
}
