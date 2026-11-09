// Package collect gathers the read-only inventory of a server. Collectors
// never fail the whole report: problems are returned as plain error strings.
package collect

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/adamgyulavari/upkeeper-cli/agent/host"
)

// Env is what collectors may touch.
type Env struct {
	FS   host.FS
	Run  host.Runner
	Arch string // Debian arch name: amd64 | arm64
}

// Errs collects collector errors in a stable, readable form.
type Errs []string

func (e *Errs) Add(area string, err error) {
	if err != nil {
		*e = append(*e, fmt.Sprintf("%s: %v", area, err))
	}
}

func (e *Errs) Addf(area, format string, args ...any) {
	*e = append(*e, area+": "+fmt.Sprintf(format, args...))
}

// DpkgPkg is one line of dpkg-query output.
type DpkgPkg struct {
	Name, Version, Status string
}

func (p DpkgPkg) Installed() bool { return p.Status == "installed" }

// DpkgPatterns are queried once per report and shared by collectors.
var DpkgPatterns = []string{
	"linux-image-[0-9]*", "linux-image-unsigned-[0-9]*",
	"unattended-upgrades",
	"docker-ce", "docker-ce-cli", "docker.io", "moby-engine",
	"docker-compose-plugin", "docker-compose-v2", "docker-compose",
	"containerd.io", "containerd",
	"zfs-dkms", "zfsutils-linux", "dkms",
}

// QueryDpkg returns installed state for the patterns. dpkg-query exits 1
// when some names are unknown; that is normal and not an error here.
func QueryDpkg(ctx context.Context, env Env, patterns ...string) (map[string]DpkgPkg, error) {
	out, err := env.Run.Run(ctx, "dpkg-query", append([]string{"-W", host.DpkgQueryFormat}, patterns...)...)
	pkgs := ParseDpkgQuery(out)
	if err != nil && len(pkgs) == 0 && !strings.Contains(err.Error(), "no packages found") {
		return pkgs, err
	}
	return pkgs, nil
}

func ParseDpkgQuery(out []byte) map[string]DpkgPkg {
	pkgs := map[string]DpkgPkg{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 3 || f[0] == "" {
			continue
		}
		pkgs[f[0]] = DpkgPkg{Name: f[0], Version: f[1], Status: strings.TrimSpace(f[2])}
	}
	return pkgs
}

// installedWithPrefix returns installed packages whose name starts with prefix, sorted.
func installedWithPrefix(pkgs map[string]DpkgPkg, prefix string) []DpkgPkg {
	var out []DpkgPkg
	for _, p := range pkgs {
		if p.Installed() && strings.HasPrefix(p.Name, prefix) {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// parseKV parses os-release style KEY="value" files.
func parseKV(b []byte) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		m[strings.TrimSpace(k)] = v
	}
	return m
}
