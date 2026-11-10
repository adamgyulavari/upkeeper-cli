package protocol

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ---- jobs (protocol 2) ----

// JobKind is what a job asks for. M1 has only "run".
type JobKind string

const KindRun JobKind = "run"

// Trigger says why a job exists.
type Trigger string

const (
	TriggerSchedule Trigger = "schedule"
	TriggerManual   Trigger = "manual"
)

// Job is what the control plane asks an agent to do. The agent re-plans
// locally and applies an item only if it's in Approved, its own classifier
// still says Auto, and the local policy allows it.
type Job struct {
	ID           string    `json:"id"`
	ServerID     string    `json:"server_id"`
	Kind         JobKind   `json:"kind"`
	Mode         Mode      `json:"mode"` // ModeAuto or ModeDryRun
	Trigger      Trigger   `json:"trigger"`
	SecurityOnly bool      `json:"security_only,omitempty"` // daily security run
	Approved     []string  `json:"approved"`                // ItemKey values
	IssuedAt     time.Time `json:"issued_at"`
	NotBefore    time.Time `json:"not_before"`
	ExpiresAt    time.Time `json:"expires_at"`
	WindowEnd    time.Time `json:"window_end"` // no new step starts after this
}

// SignedJob is the wire form: Payload is the exact JSON of a Job that was
// signed, so both sides verify the same bytes.
type SignedJob struct {
	KeyID     string `json:"key_id"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// ItemKey identifies an update across reports and jobs.
func ItemKey(it Item) string {
	return string(it.Layer) + "|" + it.Subject + "|" + it.To
}

// SignJob serialises and signs a job.
func SignJob(priv ed25519.PrivateKey, keyID string, j Job) (SignedJob, error) {
	b, err := json.Marshal(j)
	if err != nil {
		return SignedJob{}, err
	}
	return SignedJob{KeyID: keyID, Payload: b, Signature: ed25519.Sign(priv, b)}, nil
}

var (
	ErrBadSignature = errors.New("job signature does not verify")
	ErrWrongKey     = errors.New("job signed with an unknown key")
	ErrExpired      = errors.New("job has expired")
	ErrNotYet       = errors.New("job is not valid yet")
	ErrWrongServer  = errors.New("job is for another server")
)

// VerifyJob checks the signature, key, server and validity window, and
// returns the job. now is the agent's clock; a few minutes of skew are allowed.
func VerifyJob(pub ed25519.PublicKey, keyID, serverID string, sj SignedJob, now time.Time) (Job, error) {
	if sj.KeyID != keyID {
		return Job{}, ErrWrongKey
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, sj.Payload, sj.Signature) {
		return Job{}, ErrBadSignature
	}
	var j Job
	if err := json.Unmarshal(sj.Payload, &j); err != nil {
		return Job{}, fmt.Errorf("job payload: %w", err)
	}
	if j.ServerID != serverID {
		return Job{}, ErrWrongServer
	}
	const skew = 5 * time.Minute
	if now.Add(skew).Before(j.NotBefore) {
		return Job{}, ErrNotYet
	}
	if now.After(j.ExpiresAt) {
		return Job{}, ErrExpired
	}
	return j, nil
}

// ---- run progress (protocol 2) ----

type StepStatus string

const (
	StepStart StepStatus = "start"
	StepOK    StepStatus = "ok"
	StepSkip  StepStatus = "skip"
	StepWarn  StepStatus = "warn"
	StepFail  StepStatus = "fail"
	StepUndo  StepStatus = "undo" // an L1/L2/L3 undo happened
)

// Steps, in order.
const (
	StepPreflight = "preflight"
	StepPlan      = "plan"
	StepOS        = "os"
	StepImages    = "images"
	StepVerify    = "verify"
	StepKeep      = "keep"
)

// RunEvent is one line of the run record. Message is plain language, shown
// to users; Detail holds evidence (versions, exit codes, probe results).
type RunEvent struct {
	Seq     int               `json:"seq"`
	At      time.Time         `json:"at"`
	Step    string            `json:"step"`
	Status  StepStatus        `json:"status"`
	Message string            `json:"message"`
	Detail  map[string]string `json:"detail,omitempty"`
}

type Outcome string

const (
	OutcomeDone     Outcome = "done"     // everything planned was applied and verified
	OutcomePartial  Outcome = "partial"  // some items skipped, nothing broken
	OutcomeUndone   Outcome = "undone"   // something broke and was undone; server healthy
	OutcomeStopped  Outcome = "stopped"  // stopped on doubt; server frozen
	OutcomeRejected Outcome = "rejected" // job refused (policy, frozen, signature, window)
)

type SkippedItem struct {
	Item   Item   `json:"item"`
	Reason string `json:"reason"`
}

type RunResult struct {
	JobID        string        `json:"job_id"`
	Mode         Mode          `json:"mode"`
	Outcome      Outcome       `json:"outcome"`
	Applied      []Item        `json:"applied"`
	Undone       []Item        `json:"undone"`
	Skipped      []SkippedItem `json:"skipped"`
	Frozen       bool          `json:"frozen"`
	FrozenReason string        `json:"frozen_reason,omitempty"`
	Summary      string        `json:"summary"` // one plain sentence
	StartedAt    time.Time     `json:"started_at"`
	FinishedAt   time.Time     `json:"finished_at"`
}
