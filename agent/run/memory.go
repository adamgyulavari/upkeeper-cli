package run

import (
	"sort"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/statefile"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// Memory is what the engine keeps between runs, in the state directory:
//
//   - undone-images.json: images that were put back because the service
//     didn't come back healthy, so the next run doesn't pull, start and
//     undo the same broken image again;
//   - project-risks.json: projects a run couldn't update and why, so the
//     report can show it as a risk until a later run finds them fine.
type Memory struct {
	Dir string
}

// UndoneTTL is how long an undone image is remembered.
const UndoneTTL = 60 * 24 * time.Hour

type undoneImage struct {
	Digest string    `json:"digest"`
	At     time.Time `json:"at"`
}

func (m *Memory) undonePath() string { return m.Dir + "/undone-images.json" }
func (m *Memory) risksPath() string  { return m.Dir + "/project-risks.json" }

func (m *Memory) undoneImages() map[string]undoneImage {
	u := map[string]undoneImage{}
	statefile.ReadJSON(m.undonePath(), &u)
	return u
}

// WasUndone reports whether project/service was put back from digest.
func (m *Memory) WasUndone(project, service, digest string) (time.Time, bool) {
	if digest == "" {
		return time.Time{}, false
	}
	u, ok := m.undoneImages()[project+"/"+service]
	if !ok || u.Digest != digest || time.Since(u.At) > UndoneTTL {
		return time.Time{}, false
	}
	return u.At, true
}

// RememberUndone records that project/service was put back from digest.
func (m *Memory) RememberUndone(project, service, digest string, at time.Time) error {
	u := m.undoneImages()
	u[project+"/"+service] = undoneImage{Digest: digest, At: at.UTC()}
	return statefile.WriteJSON(m.undonePath(), u)
}

func (r *runner) rememberUndone(ch Change) {
	_, dg := splitRef(ch.NewImage)
	if err := r.memory().RememberUndone(ch.Project, ch.Service, dg, r.e.now()); err != nil && r.e.Logf != nil {
		r.e.Logf("couldn't remember the undone image: %v", err)
	}
}

type projectRisk struct {
	Risk protocol.Risk `json:"risk"`
	At   time.Time     `json:"at"`
}

// RiskTTL is how long a project risk found by a run is reported.
const RiskTTL = 14 * 24 * time.Hour

// SaveRisks stores the projects a run couldn't update and forgets the ones
// it checked and found fine.
func (m *Memory) SaveRisks(found map[string]protocol.Risk, fine map[string]bool, now time.Time) error {
	if len(found) == 0 && len(fine) == 0 {
		return nil
	}
	all := map[string]projectRisk{}
	statefile.ReadJSON(m.risksPath(), &all)
	for p := range fine {
		delete(all, p)
	}
	for p, r := range found {
		all[p] = projectRisk{Risk: r, At: now.UTC()}
	}
	return statefile.WriteJSON(m.risksPath(), all)
}

// Risks returns the stored project risks younger than RiskTTL, sorted.
func (m *Memory) Risks(now time.Time) []protocol.Risk {
	all := map[string]projectRisk{}
	statefile.ReadJSON(m.risksPath(), &all)
	var out []protocol.Risk
	for _, r := range all {
		if now.Sub(r.At) <= RiskTTL {
			out = append(out, r.Risk)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out
}
