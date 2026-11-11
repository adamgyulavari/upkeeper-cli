package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Runner runs a command and returns its stdout. Every implementation used by
// the agent must refuse commands that Allowed rejects.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// The command allowlist. Read-only commands: apt only simulates, with its
// on-disk caches switched off so it writes nothing; dpkg-query, apt-mark
// showhold and systemctl list-units only read; the Compose plugin is only
// asked for its version.
//
// From M1 there are these write commands, each with one exact argument shape
// (see writes.go): `apt-get update`, `apt-get … install --only-upgrade
// pkg=version…`, `docker compose … up … <services>`, and `systemctl
// stop|start` of the two apt timers. Only agent/run may build them (a
// source-scan test enforces it). `docker compose … config` and `systemctl
// is-active` of those timers are read-only.
var (
	// AptNoCache makes apt build its package cache in memory instead of
	// writing /var/cache/apt/*.bin.
	AptNoCache = []string{"-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache="}

	// AptSimulateUpgrade is the only apt-get invocation the agent can make.
	// -s simulates; --with-new-pkgs shows new kernel ABI packages the way a
	// real upgrade would install them.
	AptSimulateUpgrade = append(slices.Clone(AptNoCache), "-s", "--with-new-pkgs", "upgrade")

	// DpkgQueryFormat is the only output format dpkg-query is called with.
	DpkgQueryFormat = `-f=${Package}\t${Version}\t${db:Status-Status}\n`

	SystemctlFailed = []string{"list-units", "--state=failed", "--no-legend", "--plain", "--no-pager"}

	// ComposePluginPaths are the places Docker's CLI looks for the system-wide
	// Compose v2 plugin. Only these exact files may be run, only with "version --short".
	ComposePluginPaths = []string{
		"/usr/libexec/docker/cli-plugins/docker-compose",
		"/usr/lib/docker/cli-plugins/docker-compose",
		"/usr/local/libexec/docker/cli-plugins/docker-compose",
		"/usr/local/lib/docker/cli-plugins/docker-compose",
	}
)

var (
	pkgNameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]*$`)
	pkgPatternRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.+*\[\]-]*$`)
)

// ErrNotAllowed is returned for any command outside the allowlist.
var ErrNotAllowed = errors.New("command not in the allowlist")

// Allowed reports whether name+args is one of the commands above.
func Allowed(name string, args []string) error {
	ok := false
	switch name {
	case "apt-get":
		ok = slices.Equal(args, AptSimulateUpgrade) || aptWriteAllowed(args)
	case "docker":
		_, up := ParseComposeUp(args)
		_, cfg := ParseComposeConfig(args)
		ok = up || cfg
	case "apt-mark":
		ok = slices.Equal(args, []string{"showhold"})
	case "apt-cache":
		n := len(AptNoCache)
		ok = len(args) > n+1 && slices.Equal(args[:n], AptNoCache) && args[n] == "madison" &&
			allMatch(args[n+1:], pkgNameRe)
	case "dpkg-query":
		ok = len(args) > 2 && args[0] == "-W" && args[1] == DpkgQueryFormat && allMatch(args[2:], pkgPatternRe)
	case "systemctl":
		ok = slices.Equal(args, SystemctlFailed) || systemctlWriteAllowed(args) ||
			(len(args) == 2 && args[0] == "is-active" && slices.Contains(AptTimers, args[1]))
	default:
		ok = slices.Contains(ComposePluginPaths, name) && slices.Equal(args, []string{"version", "--short"})
	}
	if !ok {
		return fmt.Errorf("%w: %s %s", ErrNotAllowed, name, strings.Join(args, " "))
	}
	return nil
}

func allMatch(ss []string, re *regexp.Regexp) bool {
	for _, s := range ss {
		if !re.MatchString(s) {
			return false
		}
	}
	return true
}

// ExecRunner runs allowlisted commands on the real host with a fixed PATH and
// the C locale, so output is parseable.
type ExecRunner struct{}

var searchPath = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// Env is the complete environment of every command the agent runs. Nothing
// is inherited from the agent's own environment.
//   - C locale, so output is parseable;
//   - apt and dpkg never ask questions (noninteractive, needrestart only
//     lists services instead of restarting them, no changelog pager);
//   - the Docker CLI reads its config from the agent's state directory, not
//     from root's home, so a user's CLI settings can't change what runs.
var Env = []string{
	"PATH=" + strings.Join(searchPath, ":"),
	"LC_ALL=C", "LANG=C",
	"DEBIAN_FRONTEND=noninteractive",
	"NEEDRESTART_MODE=l",
	"APT_LISTCHANGES_FRONTEND=none",
	"UCF_FORCE_CONFFOLD=1",
	"DOCKER_CONFIG=/var/lib/upkeeper/docker-cli",
	"HOME=/var/lib/upkeeper",
}

// StderrRunner is implemented by runners that can also return a command's
// stderr when it succeeds (Compose prints warnings there, such as a
// variable that isn't set).
type StderrRunner interface {
	RunStderr(ctx context.Context, name string, args ...string) (stdout, stderr []byte, err error)
}

func (r ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, _, err := r.RunStderr(ctx, name, args...)
	return out, err
}

// RunStderr is Run, also returning stderr.
func (ExecRunner) RunStderr(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	if err := Allowed(name, args); err != nil {
		return nil, nil, err
	}
	bin := name
	if !filepath.IsAbs(bin) {
		bin = ""
		for _, d := range searchPath {
			p := filepath.Join(d, name)
			if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
				bin = p
				break
			}
		}
		if bin == "" {
			return nil, nil, fmt.Errorf("%s: %w", name, exec.ErrNotFound)
		}
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = Env
	cmd.Stdin = nil // /dev/null: nothing may ever wait for input
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		msg := strings.Join(strings.Fields(stderr.String()), " ")
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		if msg != "" {
			err = fmt.Errorf("%s: %w: %s", name, err, msg)
		} else {
			err = fmt.Errorf("%s: %w", name, err)
		}
	}
	return stdout.Bytes(), stderr.Bytes(), err
}
