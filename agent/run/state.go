package run

import (
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/statefile"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// State is /var/lib/upkeeper/run.json: what a run in progress has done so
// far. It exists only while a run is going. If the agent starts and finds
// one, the run was cut off (crash, reboot, kill), so the server is frozen.
type State struct {
	JobID     string          `json:"job_id"`
	Mode      protocol.Mode   `json:"mode"`
	StartedAt time.Time       `json:"started_at"`
	Step      string          `json:"step"`
	Applied   []protocol.Item `json:"applied"`
	Changes   []Change        `json:"changes,omitempty"` // image changes not yet verified
	// PausedTimers are apt timers the run stopped; they're started again at
	// the end, or by Recover after a crash.
	PausedTimers []string `json:"paused_timers,omitempty"`
}

// Change is one image change, with what's needed to put it back.
type Change struct {
	Item       protocol.Item `json:"item"`
	Project    string        `json:"project"`
	Service    string        `json:"service"`
	Floating   bool          `json:"floating"`
	Repo       string        `json:"repo"`         // image name as written, without tag
	Tag        string        `json:"tag"`          // floating tag
	OldImageID string        `json:"old_image_id"` // image that ran before
	OldImage   string        `json:"old_image"`    // the container's image reference before (Config.Image)
	OldHash    string        `json:"old_config_hash"`
	OldEntry   string        `json:"old_entry"` // version: previous override entry
	HadEntry   bool          `json:"had_entry"` // version: the override had an entry before
	NewImage   string        `json:"new_image"` // what we pulled (repo@digest)
	NewImageID string        `json:"new_image_id,omitempty"`
	// ExpectedHash is the config hash Compose said the service will have
	// after the update; the new container must carry exactly this one.
	ExpectedHash string `json:"expected_config_hash,omitempty"`
	Override     string `json:"override_path"`
	Data         bool   `json:"data,omitempty"` // the service has writable volumes or bind mounts
}

func saveState(path string, s State) error { return statefile.WriteJSON(path, s) }

func loadState(path string) (State, bool, error) {
	var s State
	ok, err := statefile.ReadJSON(path, &s)
	return s, ok, err
}
