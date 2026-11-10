// Package fakes holds test doubles shared by the agent's tests: a fake
// Docker Engine API, a fake OCI registry with the anonymous token flow, a
// fake cloud, and a fixture filesystem with canned disk usage.
package fakes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"

	"strings"
	"sync"
	"sync/atomic"

	"github.com/adamgyulavari/upkeeper-cli/agent/dockerapi"
	"github.com/adamgyulavari/upkeeper-cli/agent/host"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// FS is a RootFS with canned Statfs answers (mount → total/used MB).
type FS struct {
	host.RootFS
	Disks map[string][2]uint64
}

func (f FS) Statfs(p string) (uint64, uint64, error) {
	d, ok := f.Disks[p]
	if !ok {
		return 0, 0, fmt.Errorf("statfs %s: no such file or directory", p)
	}
	return d[0] << 20, d[1] << 20, nil
}

// DockerAPI serves containers.json, inspect.json, images.json and
// version.json from dir, the way the Engine API would.
func DockerAPI(dir string) *httptest.Server {
	load := func(name string, v any) error {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		return json.Unmarshal(b, v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(dir, "version.json"))
	})
	mux.HandleFunc("GET /containers/json", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("all") != "1" {
			http.Error(w, "test expects all=1", 400)
			return
		}
		http.ServeFile(w, r, filepath.Join(dir, "containers.json"))
	})
	mux.HandleFunc("GET /containers/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]json.RawMessage
		if err := load("inspect.json", &m); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		v, ok := m[r.PathValue("id")]
		if !ok {
			http.Error(w, `{"message":"No such container"}`, 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(v)
	})
	mux.HandleFunc("GET /images/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]json.RawMessage
		if err := load("images.json", &m); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		v, ok := m[r.PathValue("id")]
		if !ok {
			http.Error(w, `{"message":"No such image"}`, 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(v)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Anything else, in particular any non-GET, is a test failure.
		http.Error(w, "fake docker: unexpected "+r.Method+" "+r.URL.Path, http.StatusTeapot)
	})
	return httptest.NewServer(mux)
}

// DockerClient returns a dockerapi.Client pointed at srv.
func DockerClient(srv *httptest.Server) *dockerapi.Client {
	return &dockerapi.Client{HTTP: srv.Client(), Base: srv.URL}
}

// Repo is one repository in the fake registry.
type Repo struct {
	Tags    []string
	Digests map[string]string // tag → digest
}

// Registry is a fake OCI registry that demands an anonymous bearer token,
// paginates tag lists, and can be told to rate-limit.
type Registry struct {
	Srv          *httptest.Server
	Repos        map[string]Repo // "library/nginx"
	PageSize     int
	RateLimit    atomic.Bool
	NoHeadDigest bool // omit Docker-Content-Digest on HEAD

	mu       sync.Mutex
	Requests []string
}

func NewRegistry(repos map[string]Repo) *Registry {
	reg := &Registry{Repos: repos, PageSize: 2}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		reg.log(r)
		if reg.RateLimit.Load() {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		scope := r.URL.Query().Get("scope")
		json.NewEncoder(w).Encode(map[string]string{"token": "anon:" + scope})
	})
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		reg.log(r)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "read-only fake", http.StatusMethodNotAllowed)
			return
		}
		if reg.RateLimit.Load() {
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/v2/")
		var repo, kind, rest string
		if i := strings.Index(path, "/tags/list"); i >= 0 {
			repo, kind = path[:i], "tags"
		} else if i := strings.Index(path, "/manifests/"); i >= 0 {
			repo, kind, rest = path[:i], "manifest", path[i+len("/manifests/"):]
		} else {
			http.NotFound(w, r)
			return
		}
		want := "Bearer anon:repository:" + repo + ":pull"
		if r.Header.Get("Authorization") != want {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="fake-registry",scope="repository:%s:pull"`, reg.Srv.URL, repo))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		rp, ok := reg.Repos[repo]
		if !ok {
			http.Error(w, `{"errors":[{"code":"NAME_UNKNOWN"}]}`, http.StatusNotFound)
			return
		}
		switch kind {
		case "tags":
			tags := append([]string{}, rp.Tags...)
			sort.Strings(tags)
			start := 0
			if last := r.URL.Query().Get("last"); last != "" {
				start = sort.SearchStrings(tags, last) + 1
			}
			end := min(start+reg.PageSize, len(tags))
			if end < len(tags) {
				w.Header().Set("Link", fmt.Sprintf(`</v2/%s/tags/list?last=%s&n=%d>; rel="next"`, repo, tags[end-1], reg.PageSize))
			}
			json.NewEncoder(w).Encode(map[string]any{"name": repo, "tags": tags[start:end]})
		case "manifest":
			dg, ok := rp.Digests[rest]
			if !ok {
				http.Error(w, `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, http.StatusNotFound)
				return
			}
			if !(reg.NoHeadDigest && r.Method == http.MethodHead) {
				w.Header().Set("Docker-Content-Digest", dg)
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			if r.Method == http.MethodGet {
				w.Write([]byte(`{"schemaVersion":2}`))
			}
		}
	})
	reg.Srv = httptest.NewServer(mux)
	return reg
}

func (r *Registry) log(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Requests = append(r.Requests, req.Method+" "+req.URL.Path)
}

// Count returns how many requests the registry has seen.
func (r *Registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.Requests)
}

// Cloud is a fake upkeeper.sh control plane implementing the protocol package.
type Cloud struct {
	Srv         *httptest.Server
	EnrollToken string
	AgentToken  string
	ReportEvery int
	FailNext    atomic.Int32 // answer 503 this many times

	mu      sync.Mutex
	Reports []protocol.Report
	Enrolls []protocol.EnrollRequest

	// Jobs are handed out in order by GET /v1/jobs (each once, unless
	// Redeliver is set). Events and Results are what agents posted.
	Jobs      []protocol.SignedJob
	Redeliver bool
	Events    map[string][]protocol.RunEvent
	Results   map[string][]protocol.RunResult
	FailPosts atomic.Int32 // answer 503 to this many event/result posts
}

func NewCloud() *Cloud {
	c := &Cloud{EnrollToken: "enr_test", AgentToken: "agt_secret", ReportEvery: 60,
		Events: map[string][]protocol.RunEvent{}, Results: map[string][]protocol.RunResult{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var req protocol.EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		c.mu.Lock()
		c.Enrolls = append(c.Enrolls, req)
		ok := req.EnrollToken == c.EnrollToken
		if ok {
			c.EnrollToken = "" // single use
		}
		c.mu.Unlock()
		if !ok {
			http.Error(w, "enroll token unknown or used", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(protocol.EnrollResponse{ServerID: "srv_1", AgentToken: c.AgentToken, ReportEvery: c.ReportEvery})
	})
	mux.HandleFunc("POST /v1/report", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+c.AgentToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if c.FailNext.Load() > 0 {
			c.FailNext.Add(-1)
			http.Error(w, "try later", http.StatusServiceUnavailable)
			return
		}
		var rep protocol.Report
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		c.mu.Lock()
		c.Reports = append(c.Reports, rep)
		c.mu.Unlock()
		json.NewEncoder(w).Encode(protocol.ReportAck{OK: true, ReportEvery: c.ReportEvery})
	})
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+c.AgentToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /v1/jobs", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if len(c.Jobs) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		j := c.Jobs[0]
		if !c.Redeliver {
			c.Jobs = c.Jobs[1:]
		}
		json.NewEncoder(w).Encode(j)
	})
	mux.HandleFunc("POST /v1/runs/{id}/events", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		if c.FailPosts.Load() > 0 {
			c.FailPosts.Add(-1)
			http.Error(w, "try later", http.StatusServiceUnavailable)
			return
		}
		var evs []protocol.RunEvent
		if err := json.NewDecoder(r.Body).Decode(&evs); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		c.mu.Lock()
		have := map[int]bool{}
		for _, e := range c.Events[r.PathValue("id")] {
			have[e.Seq] = true
		}
		for _, e := range evs {
			if !have[e.Seq] {
				c.Events[r.PathValue("id")] = append(c.Events[r.PathValue("id")], e)
			}
		}
		c.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/runs/{id}/result", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		if c.FailPosts.Load() > 0 {
			c.FailPosts.Add(-1)
			http.Error(w, "try later", http.StatusServiceUnavailable)
			return
		}
		var res protocol.RunResult
		if err := json.NewDecoder(r.Body).Decode(&res); err != nil || res.JobID != r.PathValue("id") {
			http.Error(w, "bad result", 400)
			return
		}
		c.mu.Lock()
		c.Results[res.JobID] = append(c.Results[res.JobID], res)
		c.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	c.Srv = httptest.NewServer(mux)
	return c
}

// AddJob queues a signed job.
func (c *Cloud) AddJob(sj protocol.SignedJob) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Jobs = append(c.Jobs, sj)
}

// RunEvents returns the events posted for a job.
func (c *Cloud) RunEvents(id string) []protocol.RunEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]protocol.RunEvent(nil), c.Events[id]...)
}

// RunResults returns the results posted for a job.
func (c *Cloud) RunResults(id string) []protocol.RunResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]protocol.RunResult(nil), c.Results[id]...)
}

func (c *Cloud) ReportCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.Reports)
}

// FixtureRunner answers the standard collector commands from files in dir:
// dpkg-query.txt, apt-get-s-upgrade.txt, apt-mark-showhold.txt, systemctl-failed.txt.
// A missing file makes that command fail as if the tool weren't installed.
func FixtureRunner(dir string, patterns []string) *host.FakeRunner {
	f := &host.FakeRunner{Out: map[string]string{}, Errs: map[string]error{}}
	read := func(name string) (string, bool) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		return string(b), err == nil
	}
	if s, ok := read("dpkg-query.txt"); ok {
		k := host.Key("dpkg-query", append([]string{"-W", host.DpkgQueryFormat}, patterns...)...)
		f.Out[k] = s
	}
	if s, ok := read("apt-get-s-upgrade.txt"); ok {
		f.Out[host.Key("apt-get", host.AptSimulateUpgrade...)] = s
	}
	if s, ok := read("apt-mark-showhold.txt"); ok {
		f.Out[host.Key("apt-mark", "showhold")] = s
	} else {
		f.Out[host.Key("apt-mark", "showhold")] = ""
	}
	if s, ok := read("systemctl-failed.txt"); ok {
		f.Out[host.Key("systemctl", host.SystemctlFailed...)] = s
	}
	return f
}
