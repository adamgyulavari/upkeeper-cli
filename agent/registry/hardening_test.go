package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCheckRealm(t *testing.T) {
	c := &Client{}
	c.init()
	hub := Ref{Registry: "docker.io", Repo: "library/nginx"}
	ghcr := Ref{Registry: "ghcr.io", Repo: "x/y"}
	for _, tt := range []struct {
		ref   Ref
		realm string
		ok    bool
	}{
		{hub, "https://auth.docker.io/token", true},
		{hub, "https://registry-1.docker.io/token", true},
		{hub, "http://auth.docker.io/token", false},
		{hub, "https://169.254.169.254/latest/meta-data", false},
		{ghcr, "https://ghcr.io/token", true},
		{ghcr, "https://auth.docker.io/token", false},
		{ghcr, "http://ghcr.io/token", false},
		{ghcr, "file:///etc/shadow", false},
		{ghcr, "http://127.0.0.1:8080/token", false},
	} {
		u, _ := url.Parse(tt.realm)
		if err := c.checkRealm(tt.ref, u); (err == nil) != tt.ok {
			t.Errorf("%s realm %s: %v, want ok=%v", tt.ref.Registry, tt.realm, err, tt.ok)
		}
	}
}

func TestNextLinkStaysOnHost(t *testing.T) {
	cur := "https://ghcr.io/v2/x/y/tags/list?n=1000"
	if got := nextLink(cur, `</v2/x/y/tags/list?last=a>; rel="next"`); got != "https://ghcr.io/v2/x/y/tags/list?last=a" {
		t.Errorf("relative: %q", got)
	}
	for _, l := range []string{`<https://evil.example/v2/x>; rel="next"`, `<http://ghcr.io/v2/x>; rel="next"`, `<//evil.example/x>; rel="next"`} {
		if got := nextLink(cur, l); got != "" {
			t.Errorf("%s followed: %q", l, got)
		}
	}
}

func TestRedirectPolicy(t *testing.T) {
	mk := func(u string) *http.Request { r, _ := http.NewRequest("GET", u, nil); return r }
	if err := checkRedirect(mk("http://x/a"), []*http.Request{mk("https://x/")}); err == nil {
		t.Error("https → http redirect allowed")
	}
	if err := checkRedirect(mk("https://y/a"), []*http.Request{mk("https://x/")}); err != nil {
		t.Error(err)
	}
	if err := checkRedirect(mk("https://y/a"), []*http.Request{mk("https://x/"), mk("https://x/"), mk("https://x/")}); err == nil {
		t.Error("4th redirect allowed")
	}
}

func TestTagListLimits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("last")
		var tags []string
		for i := 0; i < 3000; i++ {
			tags = append(tags, fmt.Sprintf("1.%s%d", strings.TrimPrefix(page, "p"), i))
		}
		tags = append(tags, "bad tag", strings.Repeat("a", 200), "-x")
		n := len(page) + 1
		w.Header().Set("Link", fmt.Sprintf(`</v2/r/tags/list?last=%s>; rel="next"`, strings.Repeat("p", n)))
		json.NewEncoder(w).Encode(map[string]any{"tags": tags})
	}))
	defer srv.Close()
	c := &Client{Endpoint: func(string) string { return srv.URL }, MinInterval: time.Nanosecond}
	tags, err := c.Tags(context.Background(), Ref{Registry: "example.com", Repo: "r"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != MaxTags {
		t.Errorf("got %d tags, want the cap %d", len(tags), MaxTags)
	}
	for _, tg := range tags {
		if !tagRe.MatchString(tg) {
			t.Errorf("tag %q passed the grammar filter", tg)
		}
	}
}

func TestFirstSeen(t *testing.T) {
	now := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	c := OpenCache(t.TempDir(), func() time.Time { return now })
	first := c.FirstSeen("redis@sha256:a")
	now = now.Add(48 * time.Hour)
	if got := c.FirstSeen("redis@sha256:a"); !got.Equal(first) {
		t.Errorf("first seen moved: %v", got)
	}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	c2 := OpenCache(c.Dir, func() time.Time { return now })
	if got := c2.FirstSeen("redis@sha256:a"); !got.Equal(first) {
		t.Errorf("not persisted: %v", got)
	}
}
