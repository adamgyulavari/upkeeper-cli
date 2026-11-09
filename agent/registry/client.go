// Package registry reads tags and digests from OCI registries (Docker Hub,
// ghcr.io, quay.io, and others that allow anonymous pulls). It only lists
// tags and HEADs manifests; it never pulls an image.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ManifestAccept asks for the index digest first, the one `docker pull` records.
var ManifestAccept = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.docker.distribution.manifest.v2+json",
	"application/vnd.oci.image.manifest.v1+json",
}, ", ")

// ErrUnavailable means the registry is skipped for the rest of this report
// (offline, rate-limited, or it needs credentials).
var ErrUnavailable = errors.New("registry unavailable")

type Client struct {
	HTTP        *http.Client
	Cache       *Cache
	MinInterval time.Duration                // between requests to one host; default 1 s
	Endpoint    func(registry string) string // base URL for a registry
	UserAgent   string
	MaxTagPages int

	mu      sync.Mutex
	last    map[string]time.Time
	tokens  map[string]string
	skipped map[string]error
}

// New returns a client with the A-06 defaults.
func New(cache *Cache, userAgent string) *Client {
	return &Client{
		HTTP:      &http.Client{Timeout: 20 * time.Second},
		Cache:     cache,
		UserAgent: userAgent,
	}
}

// DefaultEndpoint maps docker.io to its API host.
func DefaultEndpoint(registry string) string {
	if registry == "docker.io" {
		return "https://registry-1.docker.io"
	}
	return "https://" + registry
}

func (c *Client) init() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last == nil {
		c.last = map[string]time.Time{}
		c.tokens = map[string]string{}
		c.skipped = map[string]error{}
	}
	if c.Cache == nil {
		c.Cache = OpenCache("", nil)
	}
	if c.Endpoint == nil {
		c.Endpoint = DefaultEndpoint
	}
	if c.MinInterval == 0 {
		c.MinInterval = time.Second
	}
	if c.MaxTagPages == 0 {
		c.MaxTagPages = 20
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 20 * time.Second}
	}
}

// Skipped returns registries skipped during this client's lifetime, with why.
func (c *Client) Skipped() map[string]error {
	c.init()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]error{}
	for k, v := range c.skipped {
		out[k] = v
	}
	return out
}

func (c *Client) skip(registry string, err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.skipped[registry]; !ok {
		c.skipped[registry] = err
	}
	return fmt.Errorf("%w: %s: %v", ErrUnavailable, registry, err)
}

func (c *Client) checkSkipped(registry string) error {
	c.mu.Lock()
	err, ok := c.skipped[registry]
	c.mu.Unlock()
	if ok {
		return fmt.Errorf("%w: %s: %v", ErrUnavailable, registry, err)
	}
	if until, ok := c.Cache.backoffUntil(registry); ok {
		return c.skip(registry, fmt.Errorf("rate limited; waiting until %s", until.UTC().Format(time.RFC3339)))
	}
	return nil
}

// wait enforces MinInterval per host.
func (c *Client) wait(ctx context.Context, hostname string) error {
	c.mu.Lock()
	next := c.last[hostname].Add(c.MinInterval)
	now := time.Now()
	if next.Before(now) {
		next = now
	}
	c.last[hostname] = next
	c.mu.Unlock()
	if d := time.Until(next); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	return nil
}

// Tags lists all tags of ref's repository (cached for TTL).
func (c *Client) Tags(ctx context.Context, ref Ref) ([]string, error) {
	c.init()
	key := "tags " + ref.Name()
	if e, ok := c.Cache.get(key); ok {
		return e.Tags, nil
	}
	if err := c.checkSkipped(ref.Registry); err != nil {
		return nil, err
	}
	var tags []string
	next := c.Endpoint(ref.Registry) + "/v2/" + ref.Repo + "/tags/list?n=1000"
	for page := 0; next != "" && page < c.MaxTagPages; page++ {
		resp, err := c.do(ctx, ref, http.MethodGet, next, "application/json")
		if err != nil {
			return nil, err
		}
		var body struct {
			Tags []string `json:"tags"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&body)
		link := resp.Header.Get("Link")
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: tag list: %w", ref.Name(), err)
		}
		tags = append(tags, body.Tags...)
		next = nextLink(next, link)
	}
	c.Cache.put(key, cacheEntry{Tags: tags})
	return tags, nil
}

// Digest returns the manifest digest a tag currently points to (cached for TTL).
func (c *Client) Digest(ctx context.Context, ref Ref, tag string) (string, error) {
	c.init()
	key := "digest " + ref.Name() + ":" + tag
	if e, ok := c.Cache.get(key); ok {
		return e.Digest, nil
	}
	if err := c.checkSkipped(ref.Registry); err != nil {
		return "", err
	}
	u := c.Endpoint(ref.Registry) + "/v2/" + ref.Repo + "/manifests/" + url.PathEscape(tag)
	// HEAD doesn't count against Docker Hub's pull limit.
	resp, err := c.do(ctx, ref, http.MethodHead, u, ManifestAccept)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	dg := resp.Header.Get("Docker-Content-Digest")
	if dg == "" {
		resp, err = c.do(ctx, ref, http.MethodGet, u, ManifestAccept)
		if err != nil {
			return "", err
		}
		h := sha256.New()
		_, err = io.Copy(h, io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			return "", err
		}
		dg = "sha256:" + hex.EncodeToString(h.Sum(nil))
	}
	c.Cache.put(key, cacheEntry{Digest: dg})
	return dg, nil
}

// do sends one request, handling the anonymous bearer-token challenge.
func (c *Client) do(ctx context.Context, ref Ref, method, rawURL, accept string) (*http.Response, error) {
	scopeKey := ref.Name()
	for attempt := 0; attempt < 2; attempt++ {
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, err
		}
		if err := c.wait(ctx, u.Host); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", accept)
		if c.UserAgent != "" {
			req.Header.Set("User-Agent", c.UserAgent)
		}
		c.mu.Lock()
		tok := c.tokens[scopeKey]
		c.mu.Unlock()
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, c.skip(ref.Registry, err)
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			return resp, nil
		case resp.StatusCode == http.StatusUnauthorized && attempt == 0:
			ch := resp.Header.Get("WWW-Authenticate")
			resp.Body.Close()
			tok, err := c.token(ctx, ref, ch)
			if err != nil {
				return nil, err
			}
			c.mu.Lock()
			c.tokens[scopeKey] = tok
			c.mu.Unlock()
			continue
		case resp.StatusCode == http.StatusTooManyRequests:
			resp.Body.Close()
			wait := time.Hour
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
				wait = time.Duration(s) * time.Second
			}
			c.Cache.setBackoff(ref.Registry, c.Cache.Now().Add(wait))
			return nil, c.skip(ref.Registry, errors.New("rate limited (HTTP 429)"))
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			resp.Body.Close()
			return nil, fmt.Errorf("%s: needs credentials (HTTP %d); skipped", ref.Name(), resp.StatusCode)
		case resp.StatusCode == http.StatusNotFound:
			resp.Body.Close()
			return nil, fmt.Errorf("%s: not found in registry", ref.Name())
		default:
			resp.Body.Close()
			if resp.StatusCode >= 500 {
				return nil, c.skip(ref.Registry, fmt.Errorf("HTTP %d", resp.StatusCode))
			}
			return nil, fmt.Errorf("%s: HTTP %d", ref.Name(), resp.StatusCode)
		}
	}
	return nil, fmt.Errorf("%s: still unauthorized after getting a token", ref.Name())
}

// token fetches an anonymous pull token for the challenge.
func (c *Client) token(ctx context.Context, ref Ref, challenge string) (string, error) {
	scheme, params := ParseChallenge(challenge)
	if !strings.EqualFold(scheme, "bearer") || params["realm"] == "" {
		return "", fmt.Errorf("%s: needs credentials; skipped", ref.Name())
	}
	tu, err := url.Parse(params["realm"])
	if err != nil {
		return "", err
	}
	q := tu.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	scope := params["scope"]
	if scope == "" {
		scope = "repository:" + ref.Repo + ":pull"
	}
	q.Set("scope", scope)
	tu.RawQuery = q.Encode()
	if err := c.wait(ctx, tu.Host); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tu.String(), nil)
	if err != nil {
		return "", err
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", c.skip(ref.Registry, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		c.Cache.setBackoff(ref.Registry, c.Cache.Now().Add(time.Hour))
		return "", c.skip(ref.Registry, errors.New("rate limited (HTTP 429)"))
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: token request: HTTP %d (private image?); skipped", ref.Name(), resp.StatusCode)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", err
	}
	if body.Token == "" {
		body.Token = body.AccessToken
	}
	if body.Token == "" {
		return "", fmt.Errorf("%s: empty token", ref.Name())
	}
	return body.Token, nil
}

// ParseChallenge parses `Bearer realm="…",service="…",scope="…"`.
func ParseChallenge(h string) (scheme string, params map[string]string) {
	params = map[string]string{}
	h = strings.TrimSpace(h)
	scheme, rest, _ := strings.Cut(h, " ")
	for rest != "" {
		rest = strings.TrimLeft(rest, " ,")
		k, after, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		k = strings.ToLower(strings.TrimSpace(k))
		var v string
		if strings.HasPrefix(after, `"`) {
			end := strings.Index(after[1:], `"`)
			if end < 0 {
				v, rest = after[1:], ""
			} else {
				v, rest = after[1:1+end], after[2+end:]
			}
		} else {
			v, rest, _ = strings.Cut(after, ",")
		}
		params[k] = v
	}
	return scheme, params
}

// nextLink resolves a `Link: </v2/…?last=x>; rel="next"` header against cur.
func nextLink(cur, link string) string {
	if link == "" || !strings.Contains(link, `rel="next"`) {
		return ""
	}
	start, end := strings.Index(link, "<"), strings.Index(link, ">")
	if start < 0 || end <= start {
		return ""
	}
	base, err := url.Parse(cur)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(link[start+1 : end])
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}
