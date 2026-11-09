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

// The read-only command allowlist. M0 contains no command that changes the
// system: apt only simulates, with its on-disk caches switched off so it
// writes nothing; dpkg-query, apt-mark showhold and systemctl list-units only
// read; the Compose plugin is only asked for its version.
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
var ErrNotAllowed = errors.New("command not in the read-only allowlist")

// Allowed reports whether name+args is one of the read-only commands above.
func Allowed(name string, args []string) error {
	ok := false
	switch name {
	case "apt-get":
		ok = slices.Equal(args, AptSimulateUpgrade)
	case "apt-mark":
		ok = slices.Equal(args, []string{"showhold"})
	case "apt-cache":
		n := len(AptNoCache)
		ok = len(args) > n+1 && slices.Equal(args[:n], AptNoCache) && args[n] == "madison" &&
			allMatch(args[n+1:], pkgNameRe)
	case "dpkg-query":
		ok = len(args) > 2 && args[0] == "-W" && args[1] == DpkgQueryFormat && allMatch(args[2:], pkgPatternRe)
	case "systemctl":
		ok = slices.Equal(args, SystemctlFailed)
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

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := Allowed(name, args); err != nil {
		return nil, err
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
			return nil, fmt.Errorf("%s: %w", name, exec.ErrNotFound)
		}
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = []string{"PATH=" + strings.Join(searchPath, ":"), "LC_ALL=C", "LANG=C", "DEBIAN_FRONTEND=noninteractive"}
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
	return stdout.Bytes(), err
}
