package classify

import (
	"fmt"
	"sort"
	"strings"

	"github.com/adamgyulavari/upkeeper-cli/agent/versions"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// Risk codes (stable; listed in protocol).
const (
	RiskComposeV1     = "compose_v1"
	RiskUUConflict    = "unattended_upgrades_conflict"
	RiskNoRestart     = "no_restart_policy"
	RiskDockerEOL     = "docker_eol"
	RiskOSUnsupported = "os_unsupported"
	RiskDiskLow       = "disk_low"
	RiskRebootPending = "reboot_pending"
	RiskFailedUnits   = "failed_units"
	RiskFloatingTag   = "floating_tag"
	RiskCoolifyHost   = "coolify_host"
)

// Disk thresholds: below either is a warning; below the problem pair is a problem.
const (
	diskWarnPct    = 10.0
	diskWarnMB     = 2048
	diskProblemPct = 5.0
	diskProblemMB  = 512
	bootWarnMB     = 200 // a kernel needs roughly 100 MB in /boot
	bootProblemMB  = 100
)

// Risks lists what makes updating this server harder or riskier.
func Risks(in Input) []protocol.Risk {
	risks := []protocol.Risk{}
	add := func(code string, sev protocol.Severity, subject, msg string) {
		risks = append(risks, protocol.Risk{Code: code, Severity: sev, Subject: subject, Message: msg})
	}
	sys, d := in.System, in.Docker

	if sys.OSID != "" && !sys.Supported {
		add(RiskOSUnsupported, protocol.Problem, osName(sys),
			fmt.Sprintf("upkeeper.sh supports Ubuntu 22.04 and 24.04 and Debian 12 and 13. %s gets this report, but no automatic runs.", osName(sys)))
	}

	if sys.RebootRequired {
		msg := "A reboot is pending. Some updates only take effect after it."
		if sys.KernelInstalled != "" && sys.KernelRunning != "" && sys.KernelInstalled != sys.KernelRunning {
			msg = fmt.Sprintf("A reboot is pending: kernel %s is installed, but %s is still running.", sys.KernelInstalled, sys.KernelRunning)
		}
		add(RiskRebootPending, protocol.Warning, "kernel", msg)
	}

	if in.DockerFacts.CoolifyHost {
		n := 0
		for _, f := range in.DockerFacts.Services {
			if f.Coolify {
				n++
			}
		}
		add(RiskCoolifyHost, protocol.Info, "coolify",
			fmt.Sprintf("Coolify manages %s on this server, including itself. Coolify updates those; upkeeper.sh keeps the OS, kernel and Docker up to date and leaves the containers to Coolify.", plural(n, "container", "containers")))
	}

	if len(sys.FailedUnits) > 0 {
		add(RiskFailedUnits, protocol.Warning, strings.Join(sys.FailedUnits, ", "),
			fmt.Sprintf("%s already failed before any update. Runs compare against this, but it's worth fixing first.", plural(len(sys.FailedUnits), "systemd unit has", "systemd units have")))
	}

	for _, disk := range sys.Disks {
		free := disk.SizeMB - disk.UsedMB
		pct := 100 * float64(free) / float64(max(disk.SizeMB, 1))
		// Absolute minimums apply where updates land: / and /var (packages,
		// images) and /boot (kernels). Other filesystems only by percentage.
		var warnMB, probMB int64
		switch disk.Mount {
		case "/boot/efi":
			continue // small by design; kernels don't go there
		case "/boot":
			warnMB, probMB = bootWarnMB, bootProblemMB
		case "/", "/var", "/var/lib", "/var/lib/docker":
			warnMB, probMB = diskWarnMB, diskProblemMB
		}
		var sev protocol.Severity
		switch {
		case pct < diskProblemPct || free < probMB:
			sev = protocol.Problem
		case pct < diskWarnPct || free < warnMB:
			sev = protocol.Warning
		default:
			continue
		}
		msg := fmt.Sprintf("%s has %s free (%.0f%%). Updates and new images need room; a run stops if there isn't enough.", disk.Mount, humanMB(free), pct)
		if strings.HasPrefix(disk.Mount, "/boot") {
			msg = fmt.Sprintf("%s has %s free (%.0f%%). A new kernel needs about 100 MB there; remove old kernels with `apt autoremove`.", disk.Mount, humanMB(free), pct)
		}
		add(RiskDiskLow, sev, disk.Mount, msg)
	}

	if sys.UnattendedUpgrades {
		if in.SystemFacts.UUDockerOrigin {
			add(RiskUUConflict, protocol.Problem, "unattended-upgrades",
				"unattended-upgrades is allowed to upgrade Docker from Docker's repository, so Docker can change outside any checks. Remove the Docker origin from its Allowed-Origins.")
		} else {
			add(RiskUUConflict, protocol.Info, "unattended-upgrades",
				"unattended-upgrades is on. Once automatic runs start, upkeeper.sh asks to pause its timer so two updaters don't compete for apt.")
		}
	}

	if d.ComposeV1 {
		add(RiskComposeV1, protocol.Problem, "docker-compose",
			"Compose v1 (docker-compose 1.x) is installed. It has had no updates since 2023, and upkeeper.sh works only with the Compose v2 plugin (`docker compose`).")
	}

	if d.EngineEOL {
		latest := in.DockerVers.UpstreamLatest
		msg := fmt.Sprintf("Docker %s is out of upstream support and no longer gets fixes.", d.EngineVersion)
		if latest != "" {
			msg = fmt.Sprintf("Docker %s is out of upstream support and no longer gets fixes; the newest is %s. Getting there is a major upgrade, done in a supervised run.", d.EngineVersion, latest)
		}
		if d.Family == "docker.io" {
			msg += " This server uses the distro's docker.io package, which may still get security patches from the distro."
		}
		add(RiskDockerEOL, protocol.Problem, d.Family, msg)
	}

	for _, p := range in.Projects {
		for _, s := range p.Services {
			key := p.Name + "/" + s.Name
			if s.RestartPolicy == "" || s.RestartPolicy == "no" {
				add(RiskNoRestart, protocol.Warning, key,
					"No restart policy. When Docker restarts during an update, this container stays stopped. Add `restart: unless-stopped` to the service.")
			}
			f := in.DockerFacts.Services[key]
			if s.Pinned || f.Coolify || f.RefErr != nil {
				continue
			}
			if _, ok := versions.ParseTag(f.Ref.Tag); !ok && f.Ref.Tag != "" {
				add(RiskFloatingTag, protocol.Info, key,
					fmt.Sprintf("Uses the floating tag %q, so versions can't be told apart. Updates are tracked by digest, and a major version can arrive as a routine update. Use a version tag to have major versions flagged.", f.Ref.Tag))
			}
		}
	}

	dedupeRisks(&risks)
	sev := map[protocol.Severity]int{protocol.Problem: 0, protocol.Warning: 1, protocol.Info: 2}
	sort.SliceStable(risks, func(i, j int) bool {
		if sev[risks[i].Severity] != sev[risks[j].Severity] {
			return sev[risks[i].Severity] < sev[risks[j].Severity]
		}
		if risks[i].Code != risks[j].Code {
			return risks[i].Code < risks[j].Code
		}
		return risks[i].Subject < risks[j].Subject
	})
	return risks
}

func dedupeRisks(rs *[]protocol.Risk) {
	seen := map[string]bool{}
	out := (*rs)[:0]
	for _, r := range *rs {
		k := r.Code + "\x00" + r.Subject
		if !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	*rs = out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func humanMB(mb int64) string {
	if mb >= 1024 {
		return fmt.Sprintf("%.1f GB", float64(mb)/1024)
	}
	return fmt.Sprintf("%d MB", mb)
}
