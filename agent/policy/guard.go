package policy

import (
	"fmt"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/statefile"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// MinRunGap is the shortest time between two runs of the same kind that
// change things. The control plane schedules far less often; this is a
// floor the agent keeps on its own, whatever jobs arrive.
const MinRunGap = 20 * time.Hour

// History is /var/lib/upkeeper/runs.json.
type History struct {
	LastFullRun     time.Time `json:"last_full_run,omitempty"`
	LastSecurityRun time.Time `json:"last_security_run,omitempty"`
	// LastDryRun is the last dry run that finished while the local policy
	// was auto.
	LastDryRun time.Time `json:"last_dry_run_under_auto,omitempty"`
}

func (s Store) historyPath() string { return s.stateDir() + "/runs.json" }

// History reads runs.json. A file that can't be read counts as "a run
// just happened", so nothing runs until someone looks.
func (s Store) History() (History, error) {
	var h History
	if _, err := statefile.ReadJSON(s.historyPath(), &h); err != nil {
		now := s.now()
		return History{LastFullRun: now, LastSecurityRun: now}, err
	}
	return h, nil
}

func (s Store) saveHistory(h History) error { return statefile.WriteJSON(s.historyPath(), h) }

// Admit decides, before a job starts, the mode it really runs in. It applies
// the local floors: the policy mode, the local window, at most one run of
// each kind per MinRunGap (dry runs don't count), and a dry run first after
// the policy became auto. ok is false when the job must be rejected; reason
// says why in plain language. windowEnd is the end of the local window, if
// one is set.
func (s Store) Admit(job protocol.Job, now time.Time) (mode protocol.Mode, windowEnd time.Time, note string, reason string, ok bool) {
	st, err := s.Load()
	if err != nil {
		return "", time.Time{}, "", "The local policy file can't be used (" + err.Error() + "), so this server counts as observe.", false
	}
	mode, reason, ok = Effective(st.Mode, job.Mode)
	if !ok {
		return "", time.Time{}, "", reason, false
	}
	if st.Window != nil {
		end, in := st.Window.End(now)
		if !in {
			return "", time.Time{}, "", fmt.Sprintf("The job arrived outside this server's local maintenance window (%s).", st.Window.String()), false
		}
		windowEnd = end
	}
	h, err := s.History()
	if err != nil {
		return "", time.Time{}, "", "The run history in " + s.historyPath() + " can't be read, so no run starts until it's fixed or removed.", false
	}
	if mode == protocol.ModeAuto {
		last, kind := h.LastFullRun, "full run"
		if job.SecurityOnly {
			last, kind = h.LastSecurityRun, "security run"
		}
		if !last.IsZero() && now.Sub(last) < MinRunGap && now.After(last.Add(-time.Minute)) {
			return "", time.Time{}, "", fmt.Sprintf("The last %s was %s ago. This server allows one every %d hours.", kind, now.Sub(last).Round(time.Minute), int(MinRunGap.Hours())), false
		}
		if h.LastDryRun.IsZero() || h.LastDryRun.Before(s.ModTime()) {
			mode = protocol.ModeDryRun
			note = "This is the first run since the local policy became auto, so it runs as a dry run and changes nothing."
		}
	}
	return mode, windowEnd, note, "", true
}

// RecordStart notes that a run that may change things has started.
func (s Store) RecordStart(job protocol.Job, mode protocol.Mode, now time.Time) error {
	if mode != protocol.ModeAuto {
		return nil
	}
	h, _ := s.History()
	if job.SecurityOnly {
		h.LastSecurityRun = now
	} else {
		h.LastFullRun = now
	}
	return s.saveHistory(h)
}

// RecordDryRun notes a finished dry run, if the local policy is auto.
func (s Store) RecordDryRun(now time.Time) error {
	if m, _ := s.Mode(); m != protocol.ModeAuto {
		return nil
	}
	h, _ := s.History()
	h.LastDryRun = now
	return s.saveHistory(h)
}
