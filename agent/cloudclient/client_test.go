package cloudclient_test

import (
	"context"
	"testing"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/cloudclient"
	"github.com/adamgyulavari/upkeeper-cli/agent/fakes"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

func TestCheckURL(t *testing.T) {
	tests := map[string]bool{
		"https://upkeeper.sh":   true,
		"https://upkeeper.sh/":  true,
		"http://localhost:8080": true,
		"http://127.0.0.1:8080": true,
		"http://[::1]:8080":     true,
		"http://upkeeper.sh":    false,
		"http://10.0.0.1":       false,
		"ftp://upkeeper.sh":     false,
		"upkeeper.sh":           false,
	}
	for in, ok := range tests {
		_, err := cloudclient.CheckURL(in)
		if (err == nil) != ok {
			t.Errorf("CheckURL(%q) = %v, want ok=%v", in, err, ok)
		}
	}
}

func TestEnrollAndReport(t *testing.T) {
	cloud := fakes.NewCloud()
	defer cloud.Srv.Close()
	ctx := context.Background()
	c := &cloudclient.Client{Base: cloud.Srv.URL}

	if _, err := c.Enroll(ctx, protocol.EnrollRequest{EnrollToken: "wrong"}); err == nil {
		t.Fatal("bad enroll token accepted")
	}
	resp, err := c.Enroll(ctx, protocol.EnrollRequest{EnrollToken: "enr_test", Hostname: "web-1", MachineID: "m", AgentVersion: "t"})
	if err != nil || resp.AgentToken != "agt_secret" || resp.ServerID != "srv_1" {
		t.Fatalf("enroll: %+v %v", resp, err)
	}
	// single use
	if _, err := c.Enroll(ctx, protocol.EnrollRequest{EnrollToken: "enr_test"}); err == nil {
		t.Error("enroll token reused")
	}

	if _, err := c.Report(ctx, protocol.Report{}); !cloudclient.Unauthorized(err) {
		t.Errorf("report without token: %v", err)
	}
	c.Token = resp.AgentToken
	ack, err := c.Report(ctx, protocol.Report{ProtocolVersion: protocol.Version, AgentVersion: "t"})
	if err != nil || !ack.OK || ack.ReportEvery != 60 || cloud.ReportCount() != 1 {
		t.Errorf("report: %+v %v", ack, err)
	}
}

func TestLoopBacksOffAndRecovers(t *testing.T) {
	cloud := fakes.NewCloud()
	defer cloud.Srv.Close()
	cloud.FailNext.Store(3)
	cloud.ReportEvery = 120

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var waits []time.Duration
	l := &cloudclient.Loop{
		Client: &cloudclient.Client{Base: cloud.Srv.URL, Token: cloud.AgentToken},
		Collect: func(context.Context) protocol.Report {
			return protocol.Report{ProtocolVersion: protocol.Version}
		},
		Interval:   300 * time.Second,
		Logf:       func(string, ...any) {},
		MinBackoff: 10 * time.Second,
		MaxBackoff: 25 * time.Second,
		Sleep: func(_ context.Context, d time.Duration) bool {
			waits = append(waits, d)
			if len(waits) == 6 {
				cancel()
				return false
			}
			return true
		},
	}
	var newInterval int
	l.OnInterval = func(s int) { newInterval = s }
	l.Run(ctx)

	// 3 failures: 10 s, 20 s, 25 s (capped), then success → server's 120 s.
	within := func(d, want time.Duration) bool { return d >= want*9/10 && d <= want*11/10 }
	wants := []time.Duration{10 * time.Second, 20 * time.Second, 25 * time.Second, 120 * time.Second, 120 * time.Second, 120 * time.Second}
	for i, w := range wants {
		if i >= len(waits) || !within(waits[i], w) {
			t.Fatalf("waits = %v, want ≈ %v", waits, wants)
		}
	}
	if newInterval != 120 {
		t.Errorf("OnInterval = %d", newInterval)
	}
	if cloud.ReportCount() != 3 {
		t.Errorf("reports stored = %d", cloud.ReportCount())
	}
}

func TestLoopUnauthorizedWaitsLong(t *testing.T) {
	cloud := fakes.NewCloud()
	defer cloud.Srv.Close()
	var waits []time.Duration
	var logs []string
	l := &cloudclient.Loop{
		Client:     &cloudclient.Client{Base: cloud.Srv.URL, Token: "revoked"},
		Collect:    func(context.Context) protocol.Report { return protocol.Report{} },
		MaxBackoff: time.Minute,
		Logf:       func(f string, a ...any) { logs = append(logs, f) },
		Sleep: func(_ context.Context, d time.Duration) bool {
			waits = append(waits, d)
			return len(waits) < 2
		},
	}
	l.Run(context.Background())
	if len(waits) != 2 || waits[0] < 54*time.Second {
		t.Errorf("waits %v", waits)
	}
	if len(logs) == 0 {
		t.Error("no log line")
	}
}

func TestJitter(t *testing.T) {
	for i := 0; i < 1000; i++ {
		d := cloudclient.Jitter(300 * time.Second)
		if d < 270*time.Second || d > 330*time.Second {
			t.Fatalf("jitter out of ±10%%: %s", d)
		}
	}
}
