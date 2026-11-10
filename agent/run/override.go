package run

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/adamgyulavari/upkeeper-cli/agent/statefile"
)

// OverrideName is the file the agent writes next to a project's first
// compose file. The user's own compose files are never changed.
const OverrideName = "compose.override.upkeeper.yml"

const overrideHeader = `# Written by upkeeper.sh. Please don't edit this file by hand.
#
# It holds the image versions upkeeper.sh updated in this Compose project.
# Your own compose files are not changed: upkeeper.sh adds this file after
# them (-f) when it runs ` + "`docker compose up`" + `.
#
# If you run docker compose yourself, add ` + "`-f " + OverrideName + "`" + ` after
# your own files, or copy these tags into your compose file to make them
# permanent and then delete the entry here.
`

// ErrHandEdited means the override file isn't in the form the agent writes.
var ErrHandEdited = errors.New(OverrideName + " was changed by hand, so upkeeper.sh leaves it alone")

var (
	ovServiceRe = regexp.MustCompile(`^  ([a-zA-Z0-9][a-zA-Z0-9._-]*):$`)
	ovImageRe   = regexp.MustCompile(`^    image: ("[^"\\]*")$`)
	imageRefRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:@-]*$`)
)

// Override is service → image as written in the override file.
type Override map[string]string

// ReadOverride parses an override file the agent wrote. A missing file is
// an empty override.
func ReadOverride(path string) (Override, bool, error) {
	o := Override{}
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return o, false, nil
	}
	if err != nil {
		return o, true, err
	}
	if !fi.Mode().IsRegular() {
		return o, true, fmt.Errorf("%s isn't a regular file, so upkeeper.sh leaves it alone", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return o, true, err
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	f.Close()
	if err != nil {
		return o, true, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	seenServices := false
	cur := ""
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#"):
		case line == "services:" && !seenServices:
			seenServices = true
		case seenServices && ovServiceRe.MatchString(line) && cur == "":
			cur = ovServiceRe.FindStringSubmatch(line)[1]
			if _, dup := o[cur]; dup {
				return o, true, ErrHandEdited
			}
		case cur != "" && ovImageRe.MatchString(line):
			v, err := strconv.Unquote(ovImageRe.FindStringSubmatch(line)[1])
			if err != nil || !imageRefRe.MatchString(v) {
				return o, true, ErrHandEdited
			}
			o[cur], cur = v, ""
		default:
			return o, true, ErrHandEdited
		}
	}
	if cur != "" {
		return o, true, ErrHandEdited
	}
	return o, true, nil
}

// Render returns the file content.
func (o Override) Render() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(overrideHeader)
	b.WriteString("services:\n")
	names := make([]string, 0, len(o))
	for s := range o {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, s := range names {
		if !ovServiceRe.MatchString("  "+s+":") || !imageRefRe.MatchString(o[s]) {
			return nil, fmt.Errorf("override: refusing to write service %q image %q", s, o[s])
		}
		fmt.Fprintf(&b, "  %s:\n    image: %s\n", s, strconv.Quote(o[s]))
	}
	return b.Bytes(), nil
}

// WriteOverride writes o, or removes the file when o is empty. It never
// follows a symlink: the directory must be a real directory, an existing
// file must be a regular file, and the new content goes to a fresh temp
// file (O_CREAT|O_EXCL|O_NOFOLLOW) in the same directory that is then
// renamed over it.
func WriteOverride(path string, o Override) error {
	dir := filepath.Dir(path)
	di, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !di.IsDir() {
		return fmt.Errorf("%s isn't a directory", dir)
	}
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("%s isn't a regular file, so upkeeper.sh won't replace it", path)
	}
	if len(o) == 0 {
		return statefile.Remove(path)
	}
	b, err := o.Render()
	if err != nil {
		return err
	}
	var rnd [8]byte
	rand.Read(rnd[:])
	tmp := filepath.Join(dir, "."+OverrideName+"-"+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
