// Package jobs is the agent's job client (A-11): it long-polls the control
// plane for signed jobs, verifies them against the root keys compiled into
// the binary, refuses replays, hands good jobs to the run engine, streams
// the run's events and delivers its result, retrying until the cloud has it.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/cloudclient"
	"github.com/adamgyulavari/upkeeper-cli/agent/policy"
	"github.com/adamgyulavari/upkeeper-cli/agent/statefile"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// Engine runs verified jobs (agent/run.Engine).
type Engine interface {
	Run(ctx context.Context, job protocol.Job, emit func(protocol.RunEvent)) protocol.RunResult
	Recover() *protocol.RunResult
}

// Loop is the job client.
type Loop struct {
	Client   *cloudclient.Client
	ServerID string
	Roots    []protocol.RootKey
	Engine   Engine
	StateDir string // jobs-seen.json, outbox.json, jobkey.json; default /var/lib/upkeeper
	Wait     time.Duration
	Now      func() time.Time
	Logf     func(format string, args ...any)
	// Sleep returns false if ctx ended.
	Sleep func(ctx context.Context, d time.Duration) bool

	mu sync.Mutex
}

func (l *Loop) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func (l *Loop) logf(format string, args ...any) {
	if l.Logf != nil {
		l.Logf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (l *Loop) sleep(ctx context.Context, d time.Duration) bool {
	if l.Sleep != nil {
		return l.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (l *Loop) dir() string {
	if l.StateDir != "" {
		return l.StateDir
	}
	return policy.DefaultStateDir
}

// Run polls until ctx ends.
func (l *Loop) Run(ctx context.Context) {
	if res := l.Engine.Recover(); res != nil {
		l.logf("found a run that was cut off (job %s); the server is frozen and the result will be reported.", res.JobID)
		l.recordRecovered(*res)
		l.queue(*res)
	}
	if len(l.Roots) == 0 {
		l.logf("this build has no job-signing root key, so it accepts no jobs; automatic runs are off.")
	}
	backoff := time.Duration(0)
	for ctx.Err() == nil {
		l.deliver(ctx)
		if err := l.Once(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			backoff = min(max(backoff*2, 15*time.Second), 5*time.Minute)
			if cloudclient.Unauthorized(err) {
				backoff = 15 * time.Minute
			}
			l.logf("job poll failed: %v. Retrying in %s.", err, backoff)
			if !l.sleep(ctx, backoff) {
				return
			}
			continue
		}
		backoff = 0
	}
}

// Once polls one time and handles a job if there is one.
func (l *Loop) Once(ctx context.Context) error {
	wait := l.Wait
	if wait <= 0 {
		wait = 25 * time.Second
	}
	sj, err := l.Client.NextJob(ctx, wait)
	if err != nil || sj == nil {
		return err
	}
	l.Handle(ctx, *sj)
	return nil
}

// Reasons for rejected jobs, in plain language.
func rejectReason(err error) string {
	switch {
	case errors.Is(err, protocol.ErrNoCert), errors.Is(err, protocol.ErrBadCert):
		return "The job isn't signed with a key this agent trusts, so it was refused."
	case errors.Is(err, protocol.ErrCertExpired):
		return "The key that signed the job is outside its certificate's validity, so it was refused."
	case errors.Is(err, protocol.ErrBadSignature), errors.Is(err, protocol.ErrWrongKey):
		return "The job's signature doesn't verify, so it was refused."
	case errors.Is(err, protocol.ErrExpired):
		return "The job had expired when it arrived."
	case errors.Is(err, protocol.ErrNotYet), errors.Is(err, protocol.ErrIssuedFuture):
		return "The job isn't valid yet. Check that the server's clock is right."
	case errors.Is(err, protocol.ErrLifetime), errors.Is(err, protocol.ErrBadWindow):
		return "The job asks to stay valid for longer than this agent allows, so it was refused."
	case errors.Is(err, protocol.ErrWrongServer):
		return "The job is for another server."
	}
	return "The job couldn't be read (" + err.Error() + ")."
}

func rejected(id string, mode protocol.Mode, at time.Time, reason string) protocol.RunResult {
	return protocol.RunResult{JobID: id, Mode: mode, Outcome: protocol.OutcomeRejected, Applied: []protocol.Item{}, Undone: []protocol.Item{},
		Skipped: []protocol.SkippedItem{}, Summary: "Not run: " + lower(reason), StartedAt: at.UTC(), FinishedAt: at.UTC()}
}

func lower(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// Handle verifies one signed job and runs it.
func (l *Loop) Handle(ctx context.Context, sj protocol.SignedJob) {
	l.mu.Lock()
	defer l.mu.Unlock()
	defer l.deliver(ctx)
	now := l.now()
	var peek protocol.Job
	_ = json.Unmarshal(sj.Payload, &peek) // only to name the job in a rejection
	if len(l.Roots) == 0 {
		l.reject(peek, now, "This agent build has no job-signing root key, so it accepts no jobs.")
		return
	}
	job, err := protocol.VerifyJob(l.Roots, l.ServerID, sj, now)
	if err != nil {
		l.logf("refused a job: %v", err)
		l.reject(peek, now, rejectReason(err))
		return
	}
	if !cloudclient.JobIDOK(job.ID) {
		l.logf("refused a job with an unusable id")
		return
	}
	saveKeyInfo(l.dir(), *sj.Cert, now)

	seen, err := loadSeen(l.dir())
	if err != nil {
		l.reject(job, now, "The list of jobs already run can't be read ("+err.Error()+"), so no job runs until it's fixed.")
		return
	}
	if e, ok := seen.Jobs[job.ID]; ok {
		if e.Result != nil {
			l.logf("job %s was already run; sending its result again.", job.ID)
			l.queue(*e.Result)
		} else {
			l.logf("job %s was already started once; refusing to run it again.", job.ID)
			l.queue(rejected(job.ID, job.Mode, now, "This job was already started once (the agent may have restarted during it), so it isn't run again."))
		}
		return
	}
	seen.Jobs[job.ID] = &seenJob{ExpiresAt: job.ExpiresAt}
	seen.prune(now)
	if err := saveSeen(l.dir(), seen); err != nil {
		l.reject(job, now, "The list of jobs already run can't be written ("+err.Error()+"), so the job didn't run.")
		return
	}

	l.logf("running job %s (%s, %s).", job.ID, job.Mode, job.Trigger)
	s := newSender(l, job.ID)
	res := l.Engine.Run(ctx, job, s.Emit)
	s.Close(ctx, 2*time.Minute)
	seen.Jobs[job.ID].Result = &res
	if err := saveSeen(l.dir(), seen); err != nil {
		l.logf("couldn't record job %s as done: %v", job.ID, err)
	}
	l.logf("job %s: %s. %s", job.ID, res.Outcome, res.Summary)
	l.queue(res)
}

// recordRecovered stores a cut-off run's result with its job, so a
// redelivery of that job resends it instead of replacing it with
// "already started".
func (l *Loop) recordRecovered(res protocol.RunResult) {
	if res.JobID == "" {
		return
	}
	seen, err := loadSeen(l.dir())
	if err != nil {
		return
	}
	e := seen.Jobs[res.JobID]
	if e == nil {
		e = &seenJob{ExpiresAt: l.now().Add(protocol.MaxJobLifetime)}
		seen.Jobs[res.JobID] = e
	}
	e.Result = &res
	if err := saveSeen(l.dir(), seen); err != nil {
		l.logf("couldn't record the cut-off run's result: %v", err)
	}
}

func (l *Loop) reject(peek protocol.Job, now time.Time, reason string) {
	if !cloudclient.JobIDOK(peek.ID) {
		return
	}
	l.queue(rejected(peek.ID, peek.Mode, now, reason))
}

// ---- results outbox (survives restarts) ----

func (l *Loop) outboxPath() string { return l.dir() + "/outbox.json" }

func (l *Loop) queue(res protocol.RunResult) {
	var box []protocol.RunResult
	statefile.ReadJSON(l.outboxPath(), &box)
	for i, r := range box {
		if r.JobID == res.JobID {
			box[i] = res
			res.JobID = ""
		}
	}
	if res.JobID != "" {
		box = append(box, res)
	}
	if len(box) > 50 {
		box = box[len(box)-50:]
	}
	if err := statefile.WriteJSON(l.outboxPath(), box); err != nil {
		l.logf("couldn't save the run result for later: %v", err)
	}
}

// deliver posts every queued result once; failures stay queued.
func (l *Loop) deliver(ctx context.Context) {
	var box []protocol.RunResult
	if ok, _ := statefile.ReadJSON(l.outboxPath(), &box); !ok || len(box) == 0 {
		return
	}
	var keep []protocol.RunResult
	for _, r := range box {
		err := l.Client.PostResult(ctx, r)
		var se *cloudclient.StatusError
		switch {
		case err == nil:
		case errors.As(err, &se) && se.Code >= 400 && se.Code < 500 && se.Code != http.StatusTooManyRequests && se.Code != http.StatusUnauthorized:
			l.logf("the cloud refused the result of job %s (%v); dropping it.", r.JobID, err)
		default:
			keep = append(keep, r)
		}
	}
	if len(keep) == 0 {
		statefile.Remove(l.outboxPath())
		return
	}
	statefile.WriteJSON(l.outboxPath(), keep)
}

// ---- replay store ----

type seenJob struct {
	ExpiresAt time.Time           `json:"expires_at"`
	Result    *protocol.RunResult `json:"result,omitempty"`
}

type seenFile struct {
	Jobs map[string]*seenJob `json:"jobs"`
}

func seenPath(dir string) string { return dir + "/jobs-seen.json" }

func loadSeen(dir string) (seenFile, error) {
	f := seenFile{Jobs: map[string]*seenJob{}}
	if _, err := statefile.ReadJSON(seenPath(dir), &f); err != nil {
		return f, err
	}
	if f.Jobs == nil {
		f.Jobs = map[string]*seenJob{}
	}
	return f, nil
}

func saveSeen(dir string, f seenFile) error { return statefile.WriteJSON(seenPath(dir), f) }

// prune drops jobs past their expiry (a replay of those fails VerifyJob
// anyway), keeping at most 500.
func (f seenFile) prune(now time.Time) {
	for id, j := range f.Jobs {
		if now.Sub(j.ExpiresAt) > protocol.Skew+time.Hour {
			delete(f.Jobs, id)
		}
	}
	if len(f.Jobs) <= 500 {
		return
	}
	ids := make([]string, 0, len(f.Jobs))
	for id := range f.Jobs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return f.Jobs[ids[i]].ExpiresAt.Before(f.Jobs[ids[j]].ExpiresAt) })
	for _, id := range ids[:len(ids)-500] {
		delete(f.Jobs, id)
	}
}

// ---- job key info (for `upkeeper status` and reports) ----

// KeyInfo describes the online key of the last job that verified.
type KeyInfo struct {
	KeyID       string    `json:"key_id"`
	Fingerprint string    `json:"fingerprint"`
	RootID      string    `json:"root_id"`
	NotAfter    time.Time `json:"not_after"`
	SeenAt      time.Time `json:"seen_at"`
}

func keyPath(dir string) string { return dir + "/jobkey.json" }

func saveKeyInfo(dir string, c protocol.KeyCert, now time.Time) {
	statefile.WriteJSON(keyPath(dir), KeyInfo{KeyID: c.KeyID, Fingerprint: protocol.Fingerprint(c.PublicKey), RootID: c.RootID, NotAfter: c.NotAfter, SeenAt: now.UTC()})
}

// LoadKeyInfo returns the last verified job key, if any.
func LoadKeyInfo(dir string) (KeyInfo, bool) {
	var k KeyInfo
	ok, err := statefile.ReadJSON(keyPath(dir), &k)
	return k, ok && err == nil
}

// ---- event sender ----

// maxEvents caps what one run sends.
const maxEvents = 500

type sender struct {
	l     *Loop
	jobID string

	mu      sync.Mutex
	pending []protocol.RunEvent
	sent    int
	wake    chan struct{}
	stop    chan struct{}
	done    chan struct{}
}

func newSender(l *Loop, jobID string) *sender {
	s := &sender{l: l, jobID: jobID, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go s.loop()
	return s
}

func (s *sender) Emit(ev protocol.RunEvent) {
	s.mu.Lock()
	if s.sent+len(s.pending) < maxEvents {
		s.pending = append(s.pending, ev)
	}
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *sender) flush(ctx context.Context) error {
	s.mu.Lock()
	batch := append([]protocol.RunEvent(nil), s.pending...)
	s.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	if err := s.l.Client.PostEvents(ctx, s.jobID, batch); err != nil {
		return err
	}
	s.mu.Lock()
	s.pending = s.pending[len(batch):]
	s.sent += len(batch)
	s.mu.Unlock()
	return nil
}

func (s *sender) loop() {
	defer close(s.done)
	backoff := time.Second
	for {
		select {
		case <-s.stop:
			return
		case <-s.wake:
		}
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := s.flush(ctx)
			cancel()
			if err == nil {
				backoff = time.Second
				break
			}
			select {
			case <-s.stop:
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
		}
	}
}

// Close sends what's left, trying for up to timeout.
func (s *sender) Close(ctx context.Context, timeout time.Duration) {
	close(s.stop)
	<-s.done
	deadline := time.Now().Add(timeout)
	backoff := time.Second
	for time.Now().Before(deadline) {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		err := s.flush(fctx)
		cancel()
		if err == nil {
			return
		}
		time.Sleep(min(backoff, time.Until(deadline)))
		backoff = min(backoff*2, 15*time.Second)
	}
	s.mu.Lock()
	n := len(s.pending)
	s.mu.Unlock()
	s.l.logf("job %s: %d run events couldn't be sent.", s.jobID, n)
}
