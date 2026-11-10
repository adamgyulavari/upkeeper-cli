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
	"strings"
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
	StateDir string // holds frozen.json
	Now      func() time.Time
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

// Mode returns the local mode. A missing file means observe. A file that
// can't be read or parsed also means observe, with the error, so a broken
// file never allows more than the default.
func (s Store) Mode() (protocol.Mode, error) {
	b, err := os.ReadFile(s.path())
	if errors.Is(err, fs.ErrNotExist) {
		return protocol.ModeObserve, nil
	}
	if err != nil {
		return protocol.ModeObserve, err
	}
	m, err := parseFile(b)
	if err != nil {
		return protocol.ModeObserve, fmt.Errorf("%s: %w", s.path(), err)
	}
	return m, nil
}

func parseFile(b []byte) (protocol.Mode, error) {
	var mode string
	found := false
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
			return protocol.ModeObserve, fmt.Errorf("line %d: expected `key: value`", n)
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
		if k != "mode" {
			return protocol.ModeObserve, fmt.Errorf("line %d: unknown setting %q", n, k)
		}
		if found {
			return protocol.ModeObserve, fmt.Errorf("line %d: mode is set twice", n)
		}
		mode, found = v, true
	}
	if !found {
		return protocol.ModeObserve, nil
	}
	return ParseMode(mode)
}

const header = `# upkeeper.sh local policy. Change it with ` + "`sudo upkeeper policy set <mode>`" + `.
#
#   observe  read and report only (the default)
#   dry-run  go through every step of a maintenance run, but change nothing
#   auto     apply updates that can be undone automatically
#
# Automatic runs also need "Automatic runs" switched on in the dashboard.
# The dashboard can never allow more than this file does.
`

// SetMode writes the policy file.
func (s Store) SetMode(m protocol.Mode) error {
	if _, err := ParseMode(string(m)); err != nil {
		return err
	}
	return statefile.Write(s.path(), []byte(header+"mode: "+string(m)+"\n"), 0o644, 0o700)
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
	m, _ := s.Mode()
	f := s.Frozen()
	return &protocol.Policy{Mode: m, Frozen: f.Frozen, FrozenReason: f.Reason}
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
