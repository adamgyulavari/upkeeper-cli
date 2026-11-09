package collect

import (
	"bufio"
	"bytes"
	"context"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/adamgyulavari/upkeeper-cli/agent/host"
	"github.com/adamgyulavari/upkeeper-cli/agent/versions"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// SupportedReleases is the MVP surface (scope §3).
var SupportedReleases = map[string][]string{
	"ubuntu": {"22.04", "24.04"},
	"debian": {"12", "13"},
}

// SystemFacts are details the classifier needs that the protocol doesn't carry.
type SystemFacts struct {
	DKMSModules      []string // modules built with DKMS (kernel updates are held)
	ZFS              bool     // a ZFS filesystem is mounted
	UUDockerOrigin   bool     // unattended-upgrades is allowed to upgrade Docker's repo
	DiskFreePct      map[string]float64
	MachineID        string
	Hostname         string
	OSPrettyName     string
	KernelPkgVersion map[string]string // linux-image-<release> → package version
}

// System collects the System part of the report (A-02).
func System(ctx context.Context, env Env, dpkg map[string]DpkgPkg, errs *Errs) (protocol.System, SystemFacts) {
	var s protocol.System
	f := SystemFacts{DiskFreePct: map[string]float64{}, KernelPkgVersion: map[string]string{}}
	s.Arch = env.Arch
	s.Disks = []protocol.Disk{}
	s.FailedUnits = []string{}

	// OS release
	osr, err := env.FS.ReadFile("/etc/os-release")
	if err != nil {
		osr, err = env.FS.ReadFile("/usr/lib/os-release")
	}
	if err != nil {
		errs.Add("os-release", err)
	} else {
		kv := parseKV(osr)
		s.OSID = kv["ID"]
		s.OSVersion = kv["VERSION_ID"]
		s.OSCodename = kv["VERSION_CODENAME"]
		if s.OSCodename == "" {
			s.OSCodename = kv["UBUNTU_CODENAME"]
		}
		f.OSPrettyName = kv["PRETTY_NAME"]
		for _, v := range SupportedReleases[s.OSID] {
			if v == s.OSVersion {
				s.Supported = true
			}
		}
	}

	if b, err := env.FS.ReadFile("/etc/hostname"); err == nil {
		f.Hostname = strings.TrimSpace(string(b))
	}
	if b, err := env.FS.ReadFile("/etc/machine-id"); err == nil {
		f.MachineID = strings.TrimSpace(string(b))
	}

	// Kernel
	if b, err := env.FS.ReadFile("/proc/sys/kernel/osrelease"); err != nil {
		errs.Add("kernel", err)
	} else {
		s.KernelRunning = strings.TrimSpace(string(b))
	}
	s.KernelInstalled = newestKernel(env, dpkg, f.KernelPkgVersion)
	if s.KernelInstalled == "" {
		errs.Addf("kernel", "could not find any installed linux-image package")
	}

	for _, p := range []string{"/run/reboot-required", "/var/run/reboot-required"} {
		if _, err := env.FS.Stat(p); err == nil {
			s.RebootRequired = true
		}
	}
	// Debian has no reboot-required flag for kernels; compare instead.
	if s.KernelRunning != "" && s.KernelInstalled != "" &&
		versions.CompareKernel(s.KernelInstalled, s.KernelRunning) > 0 {
		s.RebootRequired = true
	}

	// Uptime, memory
	if b, err := env.FS.ReadFile("/proc/uptime"); err != nil {
		errs.Add("uptime", err)
	} else if fields := strings.Fields(string(b)); len(fields) > 0 {
		if v, err := strconv.ParseFloat(fields[0], 64); err == nil {
			s.UptimeSeconds = int64(v)
		}
	}
	if b, err := env.FS.ReadFile("/proc/meminfo"); err != nil {
		errs.Add("memory", err)
	} else {
		s.MemTotalMB = parseMemTotalMB(b)
	}

	// Disks
	if b, err := env.FS.ReadFile("/proc/mounts"); err != nil {
		errs.Add("disks", err)
	} else {
		mounts := ParseMounts(b)
		for _, m := range mounts {
			if m.FSType == "zfs" {
				f.ZFS = true
			}
		}
		for _, m := range realFilesystems(mounts) {
			total, used, err := env.FS.Statfs(m.Mount)
			if err != nil {
				errs.Add("disk "+m.Mount, err)
				continue
			}
			if total == 0 {
				continue
			}
			s.Disks = append(s.Disks, protocol.Disk{Mount: m.Mount, SizeMB: int64(total >> 20), UsedMB: int64(used >> 20)})
			f.DiskFreePct[m.Mount] = 100 * float64(total-used) / float64(total)
		}
	}

	// Failed systemd units
	if out, err := env.Run.Run(ctx, "systemctl", host.SystemctlFailed...); err != nil {
		errs.Add("systemd", err)
	} else {
		s.FailedUnits = ParseFailedUnits(out)
	}

	// unattended-upgrades
	s.UnattendedUpgrades, f.UUDockerOrigin = unattendedUpgrades(env, dpkg)

	// DKMS modules (kernels on these hosts are held, scope §5)
	if entries, err := env.FS.ReadDir("/var/lib/dkms"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				f.DKMSModules = append(f.DKMSModules, e.Name())
			}
		}
	}
	if p, ok := dpkg["zfs-dkms"]; ok && p.Installed() && !contains(f.DKMSModules, "zfs") {
		f.DKMSModules = append(f.DKMSModules, "zfs")
	}
	sort.Strings(f.DKMSModules)
	return s, f
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

var kernelPkgRe = regexp.MustCompile(`^linux-image-(?:unsigned-)?(\d.*)$`)

// newestKernel returns the newest installed kernel release, from dpkg, then
// /boot, then /lib/modules.
func newestKernel(env Env, dpkg map[string]DpkgPkg, pkgVersions map[string]string) string {
	var releases []string
	for _, p := range dpkg {
		if m := kernelPkgRe.FindStringSubmatch(p.Name); m != nil && p.Installed() {
			releases = append(releases, m[1])
			pkgVersions[p.Name] = p.Version
		}
	}
	if len(releases) == 0 {
		if files, _ := env.FS.Glob("/boot/vmlinuz-*"); len(files) > 0 {
			for _, f := range files {
				releases = append(releases, strings.TrimPrefix(path.Base(f), "vmlinuz-"))
			}
		} else if entries, err := env.FS.ReadDir("/lib/modules"); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					releases = append(releases, e.Name())
				}
			}
		}
	}
	newest := ""
	for _, r := range releases {
		if newest == "" || versions.CompareKernel(r, newest) > 0 {
			newest = r
		}
	}
	return newest
}

func parseMemTotalMB(b []byte) int {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "MemTotal:" {
			kb, _ := strconv.ParseInt(f[1], 10, 64)
			return int(kb / 1024)
		}
	}
	return 0
}

// Mount is one line of /proc/mounts.
type Mount struct {
	Device, Mount, FSType string
}

func ParseMounts(b []byte) []Mount {
	var out []Mount
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 {
			continue
		}
		out = append(out, Mount{Device: unescapeMount(f[0]), Mount: unescapeMount(f[1]), FSType: f[2]})
	}
	return out
}

func unescapeMount(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}

var realFSTypes = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true,
	"f2fs": true, "jfs": true, "reiserfs": true, "bcachefs": true, "vfat": true,
}

// Mounts at or below these are skipped. /var/lib/docker itself is kept (a
// dedicated Docker disk matters), but the storage driver mounts below it are not.
var skipMountPrefixes = []string{"/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker/", "/var/lib/containers/"}

// realFilesystems keeps disk-backed filesystems, one entry per device (the
// shortest mount path wins, so btrfs subvolumes and bind mounts collapse).
func realFilesystems(mounts []Mount) []Mount {
	byDev := map[string]Mount{}
	for _, m := range mounts {
		if !realFSTypes[m.FSType] {
			continue
		}
		skip := false
		for _, p := range skipMountPrefixes {
			if m.Mount == p || strings.HasPrefix(m.Mount, strings.TrimSuffix(p, "/")+"/") {
				skip = true
			}
		}
		if skip {
			continue
		}
		if cur, ok := byDev[m.Device]; !ok || len(m.Mount) < len(cur.Mount) {
			byDev[m.Device] = m
		}
	}
	out := make([]Mount, 0, len(byDev))
	for _, m := range byDev {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mount < out[j].Mount })
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

// ParseFailedUnits reads `systemctl list-units --state=failed --plain --no-legend`.
func ParseFailedUnits(out []byte) []string {
	units := []string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(strings.TrimLeft(sc.Text(), "●* "))
		if len(f) > 0 && strings.Contains(f[0], ".") {
			units = append(units, f[0])
		}
	}
	return units
}

var aptPeriodicUURe = regexp.MustCompile(`APT::Periodic::Unattended-Upgrade\s+"([^"]*)"`)

// unattendedUpgrades reports whether unattended-upgrades is installed and
// switched on, and whether its configuration allows Docker's repository.
func unattendedUpgrades(env Env, dpkg map[string]DpkgPkg) (enabled, dockerOrigin bool) {
	installed := false
	if p, ok := dpkg["unattended-upgrades"]; ok {
		installed = p.Installed()
	} else if _, err := env.FS.Stat("/usr/bin/unattended-upgrade"); err == nil {
		installed = true
	}

	files := []string{"/etc/apt/apt.conf"}
	if entries, err := env.FS.ReadDir("/etc/apt/apt.conf.d"); err == nil {
		for _, e := range entries {
			files = append(files, "/etc/apt/apt.conf.d/"+e.Name()) // ReadDir is sorted, like apt
		}
	}
	value := ""
	for _, file := range files {
		b, err := env.FS.ReadFile(file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
				continue
			}
			if m := aptPeriodicUURe.FindStringSubmatch(line); m != nil {
				value = m[1]
			}
			if strings.Contains(file, "unattended-upgrades") &&
				(strings.Contains(line, `"Docker:`) || strings.Contains(line, "origin=Docker") ||
					strings.Contains(line, "download.docker.com")) {
				dockerOrigin = true
			}
		}
	}
	enabled = installed && value != "" && value != "0"
	return enabled, dockerOrigin && enabled
}
