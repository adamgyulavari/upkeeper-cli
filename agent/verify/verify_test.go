package verify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// seqSource returns snapshots in order and repeats the last one.
type seqSource struct {
	snaps []Inventory
	n     int
}

func (s *seqSource) Snapshot(context.Context, []string) Inventory {
	i := min(s.n, len(s.snaps)-1)
	s.n++
	return s.snaps[i]
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }
func (c *clock) sleep(_ context.Context, d time.Duration) bool {
	c.t = c.t.Add(d)
	return true
}

func checker(src Source) (*Checker, *clock) {
	c := &clock{t: time.Date(2026, 11, 15, 3, 0, 0, 0, time.UTC)}
	return &Checker{Source: src, Poll: 10 * time.Second, StartCap: time.Minute, Now: c.now, Sleep: c.sleep}, c
}

func web(id, state, health string, restarts int, port protocol.Port) Container {
	return Container{ID: id, Name: "app-web-1", Project: "app", Service: "web", State: state, Health: health, RestartCount: restarts, Ports: []protocol.Port{port}}
}

var (
	http200 = protocol.Port{HostPort: 8080, Proto: "tcp", TCPOpen: true, HTTPStatus: 200}
	http502 = protocol.Port{HostPort: 8080, Proto: "tcp", TCPOpen: true, HTTPStatus: 502}
	closed  = protocol.Port{HostPort: 8080, Proto: "tcp"}
	tcpOnly = protocol.Port{HostPort: 8080, Proto: "tcp", TCPOpen: true}
)

func inv(cs ...Container) Inventory {
	return Inventory{DockerOK: true, UnitsOK: true, Containers: cs, FailedUnits: []string{}}
}

func TestVerify(t *testing.T) {
	before := inv(web("a", "running", "healthy", 0, http200),
		Container{ID: "db", Project: "other", Service: "db", State: "running", Health: "none"})
	tests := []struct {
		name     string
		snaps    []Inventory
		projects []string
		green    bool
		reason   string
	}{
		{"steady", []Inventory{inv(web("b", "running", "healthy", 0, http200))}, []string{"app"}, true, ""},
		{"starting then healthy", []Inventory{inv(web("b", "running", "starting", 0, closed)), inv(web("b", "running", "healthy", 0, http200))}, []string{"app"}, true, ""},
		{"stays starting", []Inventory{inv(web("b", "running", "starting", 0, closed))}, []string{"app"}, false, "still starting"},
		{"unhealthy", []Inventory{inv(web("b", "running", "unhealthy", 0, http200))}, []string{"app"}, false, "app/web reports unhealthy"},
		{"exited", []Inventory{inv(web("b", "exited", "none", 0, closed))}, []string{"app"}, false, "app/web isn't running"},
		{"gone", []Inventory{inv()}, []string{"app"}, false, "isn't running"},
		{"crash loop", []Inventory{inv(web("b", "running", "healthy", 0, http200)), inv(web("b", "running", "healthy", 2, http200))}, []string{"app"}, false, "restarted 2 times"},
		{"port closed", []Inventory{inv(web("b", "running", "healthy", 0, closed))}, []string{"app"}, false, "doesn't accept connections on port 8080"},
		{"http class", []Inventory{inv(web("b", "running", "healthy", 0, http502))}, []string{"app"}, false, "answers HTTP 502 on port 8080; it was 200"},
		{"no http", []Inventory{inv(web("b", "running", "healthy", 0, tcpOnly))}, []string{"app"}, false, "doesn't answer HTTP now"},
		{"slow port recovers", []Inventory{
			inv(web("b", "running", "healthy", 0, http200)), inv(web("b", "running", "healthy", 0, http200)),
			inv(web("b", "running", "healthy", 0, http200)), inv(web("b", "running", "healthy", 0, http200)),
			inv(web("b", "running", "healthy", 0, http200)), inv(web("b", "running", "healthy", 0, http200)),
			inv(web("b", "running", "healthy", 0, http200)), inv(web("b", "running", "healthy", 0, closed)),
			inv(web("b", "running", "healthy", 0, http200)),
		}, []string{"app"}, true, ""},
		{"docker down", []Inventory{{DockerErr: "connection refused"}}, nil, false, "Docker isn't answering"},
		{"other project ignored", []Inventory{inv(web("b", "running", "healthy", 0, http200))}, []string{"app"}, true, ""},
		{"other project counted", []Inventory{inv(web("b", "running", "healthy", 0, http200))}, nil, false, "other/db isn't running"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := checker(&seqSource{snaps: tt.snaps})
			r := c.Verify(context.Background(), before, tt.projects, time.Minute)
			if r.Green != tt.green {
				t.Fatalf("green=%v reasons=%v", r.Green, r.Reasons)
			}
			if tt.reason != "" && !strings.Contains(strings.Join(r.Reasons, " | "), tt.reason) {
				t.Errorf("reasons %v, want %q", r.Reasons, tt.reason)
			}
			for _, s := range r.Reasons {
				if strings.Contains(s, "!") {
					t.Errorf("no exclamation marks: %s", s)
				}
			}
		})
	}
}

func TestVerifyUnhealthyFailsFast(t *testing.T) {
	before := inv(web("a", "running", "healthy", 0, http200))
	c, clk := checker(&seqSource{snaps: []Inventory{inv(web("b", "running", "unhealthy", 0, http200))}})
	start := clk.t
	r := c.Verify(context.Background(), before, nil, 3*time.Minute)
	if r.Green || clk.t.Sub(start) > 0 {
		t.Errorf("should be red at once: %v after %s", r.Reasons, clk.t.Sub(start))
	}
}

func TestVerifyWaitsTheWindow(t *testing.T) {
	before := inv(web("a", "running", "healthy", 0, http200))
	c, clk := checker(&seqSource{snaps: []Inventory{inv(web("b", "running", "healthy", 0, http200))}})
	start := clk.t
	if r := c.Verify(context.Background(), before, nil, 3*time.Minute); !r.Green {
		t.Fatal(r.Reasons)
	}
	if d := clk.t.Sub(start); d < 3*time.Minute {
		t.Errorf("only watched for %s", d)
	}
}

func TestVerifyBaselineProblemsAreNotRegressions(t *testing.T) {
	before := inv(web("a", "running", "unhealthy", 0, closed),
		Container{ID: "w", Project: "app", Service: "worker", State: "restarting", RestartCount: 40},
		Container{ID: "x", Project: "app", Service: "cron", State: "exited"})
	before.FailedUnits = []string{"old.service"}
	now := inv(web("b", "running", "unhealthy", 0, closed),
		Container{ID: "w", Project: "app", Service: "worker", State: "restarting", RestartCount: 44},
		Container{ID: "x", Project: "app", Service: "cron", State: "exited"})
	now.FailedUnits = []string{"old.service"}
	c, _ := checker(&seqSource{snaps: []Inventory{now}})
	if r := c.Verify(context.Background(), before, nil, time.Minute); !r.Green {
		t.Errorf("pre-existing problems made it red: %v", r.Reasons)
	}
}

func TestVerifyFailedUnits(t *testing.T) {
	before := inv()
	now := inv()
	now.FailedUnits = []string{"nginx.service"}
	c, _ := checker(&seqSource{snaps: []Inventory{now}})
	r := c.Verify(context.Background(), before, nil, time.Minute)
	if r.Green || !strings.Contains(r.Reasons[0], "nginx.service failed") {
		t.Errorf("new failed unit: %+v", r)
	}
	c, _ = checker(&seqSource{snaps: []Inventory{now}})
	if r := c.Verify(context.Background(), before, []string{"app"}, time.Minute); !r.Green {
		t.Errorf("project checks don't look at units: %v", r.Reasons)
	}
}

func TestVerifyOOM(t *testing.T) {
	before := inv(web("a", "running", "none", 0, tcpOnly))
	now := web("b", "running", "none", 0, tcpOnly)
	now.OOMKilled = true
	c, _ := checker(&seqSource{snaps: []Inventory{inv(now)}})
	if r := c.Verify(context.Background(), before, nil, time.Minute); r.Green || !strings.Contains(r.Reasons[0], "out of memory") {
		t.Errorf("oom: %+v", r)
	}
}

type noteLogs struct{}

func (noteLogs) Scan(_ context.Context, cs []Container, _ time.Time) []string {
	return []string{ScanLog("app/web", []byte("\x01\x00\x00\x00\x00\x00\x00\x10FATAL: could not open file\nok\n"))}
}

func TestLogNotesNeverDecide(t *testing.T) {
	before := inv(web("a", "running", "healthy", 0, http200))
	c, _ := checker(&seqSource{snaps: []Inventory{inv(web("b", "running", "healthy", 0, http200))}})
	c.Logs = noteLogs{}
	r := c.Verify(context.Background(), before, nil, time.Minute)
	if !r.Green || len(r.Notes) != 1 || !strings.Contains(r.Notes[0], `"FATAL: could not open file"`) {
		t.Errorf("%+v", r)
	}
}

func TestVerifyInterrupted(t *testing.T) {
	before := inv(web("a", "running", "healthy", 0, http200))
	c, _ := checker(&seqSource{snaps: []Inventory{inv(web("b", "running", "healthy", 0, http200))}})
	c.Sleep = func(context.Context, time.Duration) bool { return false }
	if r := c.Verify(context.Background(), before, nil, time.Minute); r.Green {
		t.Error("interrupted check can't be green")
	}
}
