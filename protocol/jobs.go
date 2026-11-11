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
// signed, so both sides verify the same bytes. Cert certifies the online
// key that signed it; the agent accepts it only if an embedded root key
// signed the cert (see KeyCert).
type SignedJob struct {
	KeyID     string   `json:"key_id"`
	Payload   []byte   `json:"payload"`
	Signature []byte   `json:"signature"`
	Cert      *KeyCert `json:"cert,omitempty"`
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
	ErrNoCert       = errors.New("job has no key certificate")
	ErrBadCert      = errors.New("job key certificate isn't signed by a trusted root key")
	ErrCertExpired  = errors.New("job key certificate is outside its validity period")
	ErrLifetime     = errors.New("job is valid for longer than allowed")
	ErrIssuedFuture = errors.New("job was issued in the future")
	ErrBadWindow    = errors.New("job's window ends after the job expires")
)

const (
	// Skew is the clock difference allowed between agent and control plane.
	Skew = 5 * time.Minute
	// MaxJobLifetime is the longest ExpiresAt − IssuedAt an agent accepts.
	MaxJobLifetime = 6 * time.Hour
)

// VerifyJob checks a job end to end and returns it:
//   - sj.Cert is signed by one of roots and its validity covers now;
//   - the job is signed by the certified key (KeyID must match the cert);
//   - it's for serverID, IssuedAt isn't in the future, NotBefore/ExpiresAt
//     cover now, it lives at most MaxJobLifetime, and WindowEnd isn't after
//     ExpiresAt.
//
// now is the agent's clock; Skew is allowed. Replay protection (a job ID
// used once) is the agent's job: see agent/jobs.
func VerifyJob(roots []RootKey, serverID string, sj SignedJob, now time.Time) (Job, error) {
	if sj.Cert == nil {
		return Job{}, ErrNoCert
	}
	if err := sj.Cert.Verify(roots, now); err != nil {
		return Job{}, err
	}
	if sj.KeyID != sj.Cert.KeyID {
		return Job{}, ErrWrongKey
	}
	pub := ed25519.PublicKey(sj.Cert.PublicKey)
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
	if j.IssuedAt.After(now.Add(Skew)) {
		return Job{}, ErrIssuedFuture
	}
	if now.Add(Skew).Before(j.NotBefore) {
		return Job{}, ErrNotYet
	}
	if now.After(j.ExpiresAt) {
		return Job{}, ErrExpired
	}
	if j.IssuedAt.IsZero() || j.ExpiresAt.Sub(j.IssuedAt) > MaxJobLifetime {
		return Job{}, ErrLifetime
	}
	if !j.WindowEnd.IsZero() && j.WindowEnd.After(j.ExpiresAt) {
		return Job{}, ErrBadWindow
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
	// Code is a Risk code when the item was skipped because of one (for
	// example compose_mismatch). Optional; older agents never set it.
	Code string `json:"code,omitempty"`
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
	// Risks the run found that keep items from being applied (for example
	// a project whose compose files no longer match what's running).
	// Optional; older agents never set it. Reports carry them too.
	Risks []Risk `json:"risks,omitempty"`
}
