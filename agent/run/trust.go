package run

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// Container labels say where a Compose project's files are, but an image
// can set those labels itself, and a container can write into a directory
// it has mounted. So the agent runs `docker compose` only with files it can
// vouch for:
//
//   - the image doesn't set any com.docker.compose.* label, and every
//     container of the project names the same directory and files;
//   - every path is absolute, outside /proc, /sys, /dev, /run and
//     /var/lib/docker, and not inside any container's writable mount;
//   - every file is a regular file (not a symlink), and it and every
//     directory above it are owned by root and not writable by group or
//     others;
//   - no compose file uses include: or extends:, which read other files;
//   - the files' content is the same right before `compose up` as when
//     they were checked.
//
// On top of that, agent/run asks Compose for each service's config hash
// and requires it to equal the running container's label, so a run only
// ever changes the image.
//
// A project that fails any of this is skipped, with the reason.

var forbiddenPrefixes = []string{"/proc", "/sys", "/dev", "/run", "/var/run", "/var/lib/docker", "/var/lib/containerd"}

// PathChecker checks ownership and placement of compose files.
type PathChecker struct {
	OwnerUID int    // default 0 (root)
	Root     string // stop checking parents here (default "/"); tests use a temp dir
}

func (pc PathChecker) root() string {
	if pc.Root == "" {
		return "/"
	}
	return pc.Root
}

func under(p, dir string) bool {
	dir = strings.TrimSuffix(dir, "/")
	return p == dir || strings.HasPrefix(p, dir+"/")
}

func (pc PathChecker) checkOwner(p string, wantDir bool) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", p)
	}
	if wantDir && !fi.IsDir() {
		return fmt.Errorf("%s isn't a directory", p)
	}
	if !wantDir && !fi.Mode().IsRegular() {
		return fmt.Errorf("%s isn't a regular file", p)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: owner unknown", p)
	}
	if int(st.Uid) != pc.OwnerUID {
		return fmt.Errorf("%s is owned by uid %d, not root", p, st.Uid)
	}
	perm := fi.Mode().Perm()
	if perm&0o022 != 0 && !(wantDir && fi.Mode()&fs.ModeSticky != 0 && p == pc.root()) {
		return fmt.Errorf("%s is writable by group or others (mode %04o)", p, perm)
	}
	return nil
}

// CheckPath checks one file (or directory) and every directory above it.
func (pc PathChecker) CheckPath(p string, isDir bool, mountSources []string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("%s isn't a clean absolute path", p)
	}
	for _, f := range forbiddenPrefixes {
		if under(p, f) {
			return fmt.Errorf("%s is inside %s", p, f)
		}
	}
	for _, m := range mountSources {
		if m != "" && under(p, filepath.Clean(m)) {
			return fmt.Errorf("%s is inside %s, which a container can write to", p, m)
		}
	}
	if !under(p, pc.root()) {
		return fmt.Errorf("%s is outside %s", p, pc.root())
	}
	if err := pc.checkOwner(p, isDir); err != nil {
		return err
	}
	for d := filepath.Dir(p); ; d = filepath.Dir(d) {
		if err := pc.checkOwner(d, true); err != nil {
			return err
		}
		if d == pc.root() || d == "/" {
			return nil
		}
	}
}

// hashFile reads a file without following a symlink and returns its sha256.
func hashFile(p string) (string, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 16<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CheckProject vouches for a project's files and records their hashes.
func (pc PathChecker) CheckProject(pi *ProjectInfo, mountSources []string) error {
	if len(pi.ImageLabels) > 0 {
		return fmt.Errorf("the image of %s sets Docker Compose labels itself (%s)", pi.ImageLabelsFrom, strings.Join(pi.ImageLabels, ", "))
	}
	if pi.Inconsistent != "" {
		return errors.New(pi.Inconsistent)
	}
	if pi.EnvFileLabel != "" && pi.EnvFileLabel != filepath.Join(pi.WorkDir, ".env") {
		return fmt.Errorf("it was started with a custom env file (%s), which upkeeper.sh doesn't pass to compose", pi.EnvFileLabel)
	}
	if err := pc.CheckPath(pi.WorkDir, true, mountSources); err != nil {
		return err
	}
	pi.Hashes = map[string]string{}
	files := append([]string{}, pi.ConfigFiles...)
	if _, err := os.Lstat(filepath.Join(pi.WorkDir, ".env")); err == nil {
		files = append(files, filepath.Join(pi.WorkDir, ".env"))
	}
	for i, f := range files {
		if err := pc.CheckPath(f, false, mountSources); err != nil {
			return err
		}
		h, err := hashFile(f)
		if err != nil {
			return err
		}
		pi.Hashes[f] = h
		if i < len(pi.ConfigFiles) {
			if what := pullsInFiles(f); what != "" {
				return fmt.Errorf("%s uses %s, which pulls in other files that upkeeper.sh doesn't check yet", f, what)
			}
		}
	}
	return nil
}

var (
	includeRe = regexp.MustCompile(`(?m)^include\s*:`)
	extendsRe = regexp.MustCompile(`(?m)^\s+extends\s*:`)
)

// pullsInFiles reports whether a compose file uses include: or extends:,
// which can read other compose files. The agent can't vouch for those
// files, so such projects are skipped (a plain text check: it may also skip
// an extends: within the same file).
func pullsInFiles(p string) string {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 16<<20))
	if err != nil {
		return ""
	}
	switch {
	case includeRe.Match(b):
		return "include:"
	case extendsRe.Match(b):
		return "extends:"
	}
	return ""
}

// Recheck confirms the files are unchanged since CheckProject.
func (pc PathChecker) Recheck(pi ProjectInfo, mountSources []string) error {
	for f, want := range pi.Hashes {
		if err := pc.CheckPath(f, false, mountSources); err != nil {
			return err
		}
		h, err := hashFile(f)
		if err != nil {
			return err
		}
		if h != want {
			return fmt.Errorf("%s changed during the run", f)
		}
	}
	if _, err := os.Lstat(filepath.Join(pi.WorkDir, ".env")); err == nil {
		if _, ok := pi.Hashes[filepath.Join(pi.WorkDir, ".env")]; !ok {
			return errors.New(".env appeared during the run")
		}
	}
	return nil
}
