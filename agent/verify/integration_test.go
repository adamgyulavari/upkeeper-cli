//go:build integration

package verify

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/dockerapi"
)

// H-06: a published port whose container doesn't listen is closed, even
// though docker-proxy accepts on the host side.
func TestIntegrationProbeSeesTheContainer(t *testing.T) {
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("no Docker daemon: %v %s", err, out)
	}
	img := os.Getenv("UPK_IT_BASE")
	if img == "" {
		img = "mirror.gcr.io/library/busybox:1.36"
	}
	start := func(name, port string, cmd ...string) {
		exec.Command("docker", "rm", "-f", name).Run()
		args := append([]string{"run", "-d", "--name", name, "-p", "127.0.0.1:" + port + ":8080", img}, cmd...)
		if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
		t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })
	}
	start("upk-it-silent", "18091", "sleep", "300")
	start("upk-it-httpd", "18092", "httpd", "-f", "-p", "8080", "-h", "/")
	src := HostSource{API: dockerapi.NewUnix(dockerapi.DefaultSocket), Prober: collect.Prober{}}
	inv := src.Snapshot(context.Background(), nil)
	found := 0
	for _, c := range inv.Containers {
		if (c.Name != "upk-it-silent" && c.Name != "upk-it-httpd") || len(c.Ports) != 1 {
			continue
		}
		found++
		open := c.Ports[0].TCPOpen
		if c.Name == "upk-it-silent" && open {
			t.Error("a port nothing listens on looks open")
		}
		if c.Name == "upk-it-httpd" && !open {
			t.Error("httpd's port looks closed")
		}
	}
	if found != 2 {
		t.Fatalf("found %d test containers", found)
	}
	// For the record: through the host port, docker-proxy answers anyway.
	open, _ := (collect.Prober{}).Probe(context.Background(), "127.0.0.1:18091")
	t.Logf("host port 18091 through docker-proxy: open=%v", open)
}
