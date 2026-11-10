package host

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Write commands (M1). Each one has a single exact argument shape; anything
// else is refused by Allowed. Only agent/run builds them.

// DockerFamily are the packages that make up Docker Engine. The apt step
// never touches them: Docker Engine updates come with L2 in M2.
var DockerFamily = map[string]bool{
	"docker-ce": true, "docker-ce-cli": true, "docker-ce-rootless-extras": true,
	"docker.io": true, "moby-engine": true, "moby-cli": true,
	"containerd.io": true, "containerd": true, "runc": true,
	"docker-compose-plugin": true, "docker-compose-v2": true, "docker-compose": true,
	"docker-buildx-plugin": true, "docker-buildx": true,
}

// IsDockerFamily reports whether pkg is part of Docker Engine.
func IsDockerFamily(pkg string) bool {
	return DockerFamily[pkg] || strings.HasPrefix(pkg, "docker-ce-") || strings.HasPrefix(pkg, "moby-")
}

var (
	// AptUpdate refreshes the package lists.
	AptUpdate = []string{"update"}

	// aptInstallPrefix upgrades already installed packages to exact
	// versions, keeping the user's changed config files (confold) and
	// taking the package's default where there is no change (confdef).
	aptInstallPrefix = []string{
		"-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold",
		"install", "--only-upgrade",
	}
	// aptSimInstallPrefix simulates that install without writing apt's caches.
	aptSimInstallPrefix = append(slices.Clone(AptNoCache), "-s", "install", "--only-upgrade")

	// pkg=version. Neither part may end in "-" or "+", which apt reads as
	// "remove" or "install" suffixes.
	pinnedPkgRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.+-]*[a-z0-9])?=[0-9](?:[A-Za-z0-9.+~:-]*[A-Za-z0-9~])?$`)
)

// PkgVersion is one package at an exact version.
type PkgVersion struct {
	Name, Version string
}

func (p PkgVersion) arg() string { return p.Name + "=" + p.Version }

func pinnedArgs(pkgs []PkgVersion) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, p.arg())
	}
	return out
}

// AptInstallArgs is `apt-get -y -o … install --only-upgrade pkg=ver…`.
func AptInstallArgs(pkgs []PkgVersion) []string {
	return append(slices.Clone(aptInstallPrefix), pinnedArgs(pkgs)...)
}

// AptSimInstallArgs simulates AptInstallArgs (read-only).
func AptSimInstallArgs(pkgs []PkgVersion) []string {
	return append(slices.Clone(aptSimInstallPrefix), pinnedArgs(pkgs)...)
}

func pinnedPkgsOK(args []string) bool {
	if len(args) == 0 {
		return false
	}
	for _, a := range args {
		if !pinnedPkgRe.MatchString(a) {
			return false
		}
		name, _, _ := strings.Cut(a, "=")
		if IsDockerFamily(name) {
			return false
		}
	}
	return true
}

func aptWriteAllowed(args []string) bool {
	switch {
	case slices.Equal(args, AptUpdate):
		return true
	case len(args) > len(aptInstallPrefix) && slices.Equal(args[:len(aptInstallPrefix)], aptInstallPrefix):
		return pinnedPkgsOK(args[len(aptInstallPrefix):])
	case len(args) > len(aptSimInstallPrefix) && slices.Equal(args[:len(aptSimInstallPrefix)], aptSimInstallPrefix):
		return pinnedPkgsOK(args[len(aptSimInstallPrefix):])
	}
	return false
}

// ComposeUp recreates named services of one Compose project:
//
//	docker compose --project-directory DIR -p NAME -f FILE…
//	  up -d --no-deps --no-build --force-recreate --pull never SERVICE…
//
// There is no --env-file: Compose reads only DIR/.env, which agent/run
// checks like the compose files.
//
// --pull never makes Compose use exactly the image the agent pulled or put
// back, whatever pull_policy the project sets.
type ComposeUp struct {
	ProjectDir string
	Project    string
	Files      []string
	Services   []string
}

var composeUpTail = []string{"up", "-d", "--no-deps", "--no-build", "--force-recreate", "--pull", "never"}

var (
	composeProjectRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	composeServiceRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
)

// Args returns the argument list for the docker CLI.
func (c ComposeUp) Args() []string {
	a := []string{"compose", "--project-directory", c.ProjectDir, "-p", c.Project}
	for _, f := range c.Files {
		a = append(a, "-f", f)
	}
	a = append(a, composeUpTail...)
	return append(a, c.Services...)
}

// Valid checks every part of the command.
func (c ComposeUp) Valid() bool {
	if !absPath(c.ProjectDir) || !composeProjectRe.MatchString(c.Project) || len(c.Files) == 0 || len(c.Services) == 0 {
		return false
	}
	for _, f := range c.Files {
		if !absPath(f) {
			return false
		}
	}
	for _, s := range c.Services {
		if !composeServiceRe.MatchString(s) {
			return false
		}
	}
	return true
}

// absPath accepts clean absolute paths without control characters, so a
// path can never be read as an option.
func absPath(p string) bool {
	if !strings.HasPrefix(p, "/") || filepath.Clean(p) != p {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// ParseComposeUp parses args back into a ComposeUp, accepting only the exact
// shape Args produces.
func ParseComposeUp(args []string) (ComposeUp, bool) {
	var c ComposeUp
	if len(args) < 5 || args[0] != "compose" || args[1] != "--project-directory" || args[3] != "-p" {
		return c, false
	}
	c.ProjectDir, c.Project = args[2], args[4]
	i := 5
	for i+1 < len(args) && args[i] == "-f" {
		c.Files = append(c.Files, args[i+1])
		i += 2
	}
	if len(args) < i+len(composeUpTail) || !slices.Equal(args[i:i+len(composeUpTail)], composeUpTail) {
		return c, false
	}
	c.Services = slices.Clone(args[i+len(composeUpTail):])
	if !c.Valid() || !slices.Equal(c.Args(), args) {
		return c, false
	}
	return c, true
}

// ValidPinned reports whether p can be passed to apt-get install. Packages
// whose name or version ends in "-" or "+" (g++, for one) can't, because
// apt would read the suffix as an instruction; the run skips them.
func ValidPinned(p PkgVersion) bool {
	return pinnedPkgRe.MatchString(p.arg()) && !IsDockerFamily(p.Name)
}
