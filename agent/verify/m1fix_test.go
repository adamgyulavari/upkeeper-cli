package verify

import (
	"context"
	"testing"
	"time"
)

type fixed struct{ inv Inventory }

func (s fixed) Snapshot(context.Context, []string) Inventory { return s.inv }

func clockChecker(src Source) (*Checker, *time.Time) {
	now := time.Unix(0, 0)
	return &Checker{Source: src, Now: func() time.Time { return now },
		Sleep: func(ctx context.Context, d time.Duration) bool { now = now.Add(d); return ctx.Err() == nil }}, &now
}

// M-06: a server without Docker isn't red for it.
func TestNoDockerBeforeIsFine(t *testing.T) {
	c, _ := clockChecker(fixed{Inventory{DockerOK: false, DockerErr: "no socket", UnitsOK: true}})
	before := c.Snapshot(context.Background(), nil)
	if res := c.Verify(context.Background(), before, nil, time.Minute); !res.Green {
		t.Fatalf("%+v", res)
	}
	// It is when Docker answered before.
	before.DockerOK = true
	if res := c.Verify(context.Background(), before, nil, time.Minute); res.Green {
		t.Fatalf("%+v", res)
	}
}

// H-05: "starting" is waited for as long as the healthcheck takes.
func TestStartingWaitsForTheHealthcheck(t *testing.T) {
	wait, first := HealthTimes(time.Minute, 10*time.Second, 2*time.Minute, 0, 3)
	if wait != 2*time.Minute+3*70*time.Second+30*time.Second || first != 5*time.Second {
		t.Fatalf("wait %s first %s", wait, first)
	}
	b := Inventory{DockerOK: true, Containers: []Container{{ID: "a", Project: "p", Service: "s", State: "running", Health: "healthy", RestartPolicy: "always"}}}
	a := Inventory{DockerOK: true, Containers: []Container{{ID: "b", Project: "p", Service: "s", State: "running", Health: "starting", RestartPolicy: "always", HealthWait: wait}}}
	c, now := clockChecker(fixed{a})
	res := c.Verify(context.Background(), b, []string{"p"}, 3*time.Minute)
	if res.Green || !res.OnlyStarting {
		t.Fatalf("%+v", res)
	}
	if got := now.Sub(time.Unix(0, 0)); got < wait {
		t.Errorf("gave up after %s, the healthcheck takes %s", got, wait)
	}
	// Never longer than MaxHealthWait.
	a.Containers[0].HealthWait = time.Hour
	c, now = clockChecker(fixed{a})
	c.Verify(context.Background(), b, []string{"p"}, 3*time.Minute)
	if got := now.Sub(time.Unix(0, 0)); got > MaxHealthWait+2*time.Minute {
		t.Errorf("waited %s", got)
	}
}

// H-04: finished jobs vs. services that stopped.
func TestFinishedContainers(t *testing.T) {
	run := Container{ID: "a", Project: "(standalone)", Service: "backup", State: "running", Health: "none"}
	cases := []struct {
		name   string
		before Container
		after  []Container
		green  bool
	}{
		{"exit 0, restart no", withPolicy(run, "no"), []Container{exited(withPolicy(run, "no"), 0)}, true},
		{"exit 0, on-failure", withPolicy(run, "on-failure"), []Container{exited(withPolicy(run, "on-failure"), 0)}, true},
		{"exit 1, restart no", withPolicy(run, "no"), []Container{exited(withPolicy(run, "no"), 1)}, false},
		{"exit 0, unless-stopped", withPolicy(run, "unless-stopped"), []Container{exited(withPolicy(run, "unless-stopped"), 0)}, false},
		{"--rm and gone", rm(withPolicy(run, "no")), nil, true},
		{"gone without --rm", withPolicy(run, "no"), nil, false},
	}
	for _, tc := range cases {
		c, _ := clockChecker(fixed{Inventory{DockerOK: true, Containers: tc.after}})
		res := c.Verify(context.Background(), Inventory{DockerOK: true, Containers: []Container{tc.before}}, nil, time.Minute)
		if res.Green != tc.green {
			t.Errorf("%s: green=%v %v", tc.name, res.Green, res.Reasons)
		}
	}
}

func withPolicy(c Container, p string) Container { c.RestartPolicy = p; return c }
func exited(c Container, code int) Container     { c.State, c.ExitCode = "exited", code; return c }
func rm(c Container) Container                   { c.AutoRemove = true; return c }

func TestInterruptedIsFlagged(t *testing.T) {
	inv := Inventory{DockerOK: true}
	c, _ := clockChecker(fixed{inv})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if res := c.Verify(ctx, inv, nil, time.Minute); !res.Interrupted || res.Green {
		t.Fatalf("%+v", res)
	}
}
