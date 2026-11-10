// Package policy is the server's local half of the two-key opt-in (A-10).
//
// /etc/upkeeper/policy.yaml says what this server allows: observe (read
// only, the default), dry-run or auto. Only root on the server changes it,
// with `upkeeper policy set`. The control plane can ask for less, never for
// more. /var/lib/upkeeper/frozen.json, when present, stops every run until
// someone unfreezes the server.
package policy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/statefile"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

const (
	DefaultPath     = "/etc/upkeeper/policy.yaml"
	DefaultStateDir = "/var/lib/upkeeper"
)

// Store reads and writes the policy file and the freeze state.
type Store struct {
	Path     string // policy.yaml
	StateDir string // holds frozen.json and runs.json
	Now      func() time.Time
	// OwnerUID is who must own policy.yaml and its directory (default root).
	// Tests set it to their own uid.
	OwnerUID *int
}

func (s Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s Store) path() string {
	if s.Path == "" {
		return DefaultPath
	}
	return s.Path
}

func (s Store) stateDir() string {
	if s.StateDir == "" {
		return DefaultStateDir
	}
	return s.StateDir
}

// FrozenPath is the freeze state file.
func (s Store) FrozenPath() string { return s.stateDir() + "/frozen.json" }

// ParseMode accepts the three modes.
func ParseMode(v string) (protocol.Mode, error) {
	switch m := protocol.Mode(strings.TrimSpace(v)); m {
	case protocol.ModeObserve, protocol.ModeDryRun, protocol.ModeAuto:
		return m, nil
	}
	return protocol.ModeObserve, fmt.Errorf("unknown mode %q (use observe, dry-run or auto)", v)
}

// Settings is the content of policy.yaml.
type Settings struct {
	Mode   protocol.Mode
	Window *Window // nil: no local window
}

// Mode returns the local mode. A missing file means observe. A file that
// can't be read or parsed, or that isn't owned by root with no group or
// world write permission (in a directory that's the same), also means
// observe, with the error: a broken file never allows more than the default.
func (s Store) Mode() (protocol.Mode, error) {
	st, err := s.Load()
	return st.Mode, err
}

// Load reads policy.yaml (see Mode for the fail-safe rules).
func (s Store) Load() (Settings, error) {
	obs := Settings{Mode: protocol.ModeObserve}
	b, err := s.readChecked()
	if errors.Is(err, fs.ErrNotExist) {
		return obs, nil
	}
	if err != nil {
		return obs, err
	}
	st, err := parseFile(b)
	if err != nil {
		return obs, fmt.Errorf("%s: %w", s.path(), err)
	}
	return st, nil
}

func (s Store) owner() int {
	if s.OwnerUID != nil {
		return *s.OwnerUID
	}
	return 0
}

// readChecked reads the policy file only if it and its directory are
// owned by the expected user and not writable by group or others, and the
// file is a regular file (not a symlink).
func (s Store) readChecked() ([]byte, error) {
	p := s.path()
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if err := checkOwner(fi, s.owner(), false); err != nil {
		return nil, fmt.Errorf("%s: %w, so the policy counts as observe", p, err)
	}
	di, err := os.Lstat(filepath.Dir(p))
	if err != nil {
		return nil, err
	}
	if err := checkOwner(di, s.owner(), true); err != nil {
		return nil, fmt.Errorf("%s: %w, so the policy counts as observe", filepath.Dir(p), err)
	}
	return os.ReadFile(p)
}

func checkOwner(fi fs.FileInfo, uid int, dir bool) error {
	if dir && !fi.IsDir() {
		return errors.New("isn't a directory")
	}
	if !dir && !fi.Mode().IsRegular() {
		return errors.New("isn't a regular file")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("owner unknown")
	}
	if int(st.Uid) != uid {
		return fmt.Errorf("is owned by uid %d, not %d", st.Uid, uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("is writable by group or others (mode %04o)", fi.Mode().Perm())
	}
	return nil
}

func parseFile(b []byte) (Settings, error) {
	var mode, window string
	found, foundWindow := false, false
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			return Settings{Mode: protocol.ModeObserve}, fmt.Errorf("line %d: expected `key: value`", n)
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "mode":
			if found {
				return Settings{Mode: protocol.ModeObserve}, fmt.Errorf("line %d: mode is set twice", n)
			}
			mode, found = v, true
		case "window":
			if foundWindow {
				return Settings{Mode: protocol.ModeObserve}, fmt.Errorf("line %d: window is set twice", n)
			}
			window, foundWindow = v, true
		default:
			return Settings{Mode: protocol.ModeObserve}, fmt.Errorf("line %d: unknown setting %q", n, k)
		}
	}
	st := Settings{Mode: protocol.ModeObserve}
	if foundWindow && window != "" && window != "none" {
		w, err := ParseWindow(window)
		if err != nil {
			return st, err
		}
		st.Window = &w
	}
	if !found {
		return st, nil
	}
	m, err := ParseMode(mode)
	if err != nil {
		return Settings{Mode: protocol.ModeObserve}, err
	}
	st.Mode = m
	return st, nil
}

const header = `# upkeeper.sh local policy. Change it with ` + "`sudo upkeeper policy set <mode>`" + `.
#
#   observe  read and report only (the default)
#   dry-run  go through every step of a maintenance run, but change nothing
#   auto     apply updates that can be undone automatically
#
# window (optional) limits runs to a local maintenance window, in this
# server's time zone, for example "sun 03:00-05:00", "mon,thu 02:00-04:00"
# or "daily 03:00-04:00". Set it with: sudo upkeeper policy window "<window>"
#
# Automatic runs also need "Automatic runs" switched on in the dashboard.
# The dashboard can never allow more than this file does.
`

// Save writes the policy file (root only, 0644).
func (s Store) Save(st Settings) error {
	if _, err := ParseMode(string(st.Mode)); err != nil {
		return err
	}
	body := header + "mode: " + string(st.Mode) + "\n"
	if st.Window != nil {
		body += "window: \"" + st.Window.String() + "\"\n"
	}
	return statefile.Write(s.path(), []byte(body), 0o644, 0o755)
}

// SetMode changes the mode and keeps the window. A file that can't be read
// is replaced (it counted as observe anyway).
func (s Store) SetMode(m protocol.Mode) error {
	st, _ := s.Load()
	st.Mode = m
	return s.Save(st)
}

// SetWindow changes the window (nil removes it) and keeps the mode.
func (s Store) SetWindow(w *Window) error {
	st, err := s.Load()
	if err != nil {
		return err
	}
	st.Window = w
	return s.Save(st)
}

// ModTime is when policy.yaml last changed (zero if it doesn't exist).
func (s Store) ModTime() time.Time {
	fi, err := os.Lstat(s.path())
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// Freeze is the content of frozen.json.
type Freeze struct {
	Frozen bool      `json:"frozen"`
	Reason string    `json:"reason"`
	JobID  string    `json:"job_id,omitempty"`
	At     time.Time `json:"at"`
}

// Frozen returns the freeze state. A file that exists but can't be read
// counts as frozen: when in doubt, don't run.
func (s Store) Frozen() Freeze {
	var f Freeze
	ok, err := statefile.ReadJSON(s.FrozenPath(), &f)
	if err != nil {
		return Freeze{Frozen: true, Reason: fmt.Sprintf("%s can't be read (%v). Run `sudo upkeeper unfreeze` once you've checked the server.", s.FrozenPath(), err)}
	}
	if !ok {
		return Freeze{}
	}
	f.Frozen = true
	return f
}

// FreezeNow freezes the server with a plain-language reason.
func (s Store) FreezeNow(reason, jobID string) error {
	return statefile.WriteJSON(s.FrozenPath(), Freeze{Frozen: true, Reason: reason, JobID: jobID, At: s.now().UTC()})
}

// Unfreeze removes the freeze.
func (s Store) Unfreeze() error {
	return statefile.Remove(s.FrozenPath())
}

// Report is the policy as it goes into a report.
func (s Store) Report() *protocol.Policy {
	st, _ := s.Load()
	f := s.Frozen()
	p := &protocol.Policy{Mode: st.Mode, Frozen: f.Frozen, FrozenReason: f.Reason}
	if st.Window != nil {
		p.Window = st.Window.String()
	}
	return p
}

// Effective is the mode a job runs in: the narrower of the local policy and
// what the job asks for. ok is false when the job can't run at all, with a
// reason for the user.
func Effective(local, job protocol.Mode) (protocol.Mode, string, bool) {
	switch job {
	case protocol.ModeAuto, protocol.ModeDryRun:
	default:
		return "", fmt.Sprintf("The job asked for mode %q, which this agent doesn't know.", job), false
	}
	switch local {
	case protocol.ModeAuto:
		return job, "", true
	case protocol.ModeDryRun:
		return protocol.ModeDryRun, "", true
	}
	return "", "The local policy on this server is observe, so it only reports. Run `sudo upkeeper policy set auto` on the server to allow automatic runs.", false
}
