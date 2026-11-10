// Package cloudclient talks to the upkeeper.sh control plane. The agent only
// makes outbound HTTPS requests: enroll once, then post reports.
package cloudclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

type Client struct {
	Base      string // https://upkeeper.sh
	Token     string // agent token, after enrollment
	HTTP      *http.Client
	UserAgent string
}

// StatusError is a non-2xx answer from the cloud.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("HTTP %d: %s", e.Code, e.Body)
	}
	return fmt.Sprintf("HTTP %d", e.Code)
}

// Unauthorized reports whether err means the cloud rejected our token.
func Unauthorized(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden)
}

// CheckURL accepts https URLs, and plain http only for loopback (local dev).
func CheckURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid cloud URL %q", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		h := u.Hostname()
		ip := net.ParseIP(h)
		if h != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", fmt.Errorf("cloud URL %q must use https", raw)
		}
	default:
		return "", fmt.Errorf("cloud URL %q must use https", raw)
	}
	return u.String(), nil
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// JobIDOK is the shape of job IDs the agent puts in a URL.
var jobIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// JobIDOK reports whether id is safe to use in a URL path.
func JobIDOK(id string) bool { return jobIDRe.MatchString(id) }

// NextJob long-polls for a job. It returns nil, nil when there is none.
func (c *Client) NextJob(ctx context.Context, wait time.Duration) (*protocol.SignedJob, error) {
	base, err := CheckURL(c.Base)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, wait+20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/v1/jobs?wait=%d", base, int(wait.Seconds())), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	h := c.http()
	if c.HTTP == nil {
		h = &http.Client{} // the context bounds the long poll
	}
	resp, err := h.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNoContent:
		return nil, nil
	case resp.StatusCode != http.StatusOK:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, &StatusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	var sj protocol.SignedJob
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&sj); err != nil {
		return nil, fmt.Errorf("jobs: bad response: %w", err)
	}
	return &sj, nil
}

// PostEvents appends run events (the cloud ignores seqs it already has).
func (c *Client) PostEvents(ctx context.Context, jobID string, evs []protocol.RunEvent) error {
	if !JobIDOK(jobID) {
		return fmt.Errorf("bad job id %q", jobID)
	}
	return c.post(ctx, "/v1/runs/"+jobID+"/events", evs, nil)
}

// PostResult sends a run's final result.
func (c *Client) PostResult(ctx context.Context, res protocol.RunResult) error {
	if !JobIDOK(res.JobID) {
		return fmt.Errorf("bad job id %q", res.JobID)
	}
	return c.post(ctx, "/v1/runs/"+res.JobID+"/result", res, nil)
}

func (c *Client) post(ctx context.Context, path string, in, out any) error {
	base, err := CheckURL(c.Base)
	if err != nil {
		return err
	}
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &StatusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return fmt.Errorf("%s: bad response: %w", path, err)
	}
	return nil
}

func (c *Client) Enroll(ctx context.Context, req protocol.EnrollRequest) (protocol.EnrollResponse, error) {
	var resp protocol.EnrollResponse
	err := c.post(ctx, "/v1/enroll", req, &resp)
	if err == nil && resp.AgentToken == "" {
		err = errors.New("enroll: the server sent no agent token")
	}
	return resp, err
}

func (c *Client) Report(ctx context.Context, r protocol.Report) (protocol.ReportAck, error) {
	var ack protocol.ReportAck
	err := c.post(ctx, "/v1/report", r, &ack)
	if err == nil && !ack.OK {
		err = errors.New("report: the server did not accept it")
	}
	return ack, err
}
