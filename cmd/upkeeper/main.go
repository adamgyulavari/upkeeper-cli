// Command upkeeper is the upkeeper.sh server agent. In M0 it is read-only:
// it collects an inventory of the server, classifies pending updates and
// sends the report to the control plane. It changes nothing on the server.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/cloudclient"
	"github.com/adamgyulavari/upkeeper-cli/agent/config"
	"github.com/adamgyulavari/upkeeper-cli/agent/report"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

const usage = `upkeeper keeps this server up to date. In this version it only reports.

Usage:
  upkeeper version
  upkeeper enroll <token> [--url https://upkeeper.sh]
  upkeeper run                   report every few minutes (what the systemd unit runs)
  upkeeper report [--print]      collect once; --print shows the JSON and sends nothing

Flags for every command:
  --config PATH     default /etc/upkeeper/agent.json (env UPKEEPER_CONFIG)
  --cache-dir DIR   default /var/cache/upkeeper (env UPKEEPER_CACHE_DIR)
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type globals struct {
	config   string
	cacheDir string
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func newFlags(name string, g *globals, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	fs.StringVar(&g.config, "config", envOr("UPKEEPER_CONFIG", config.DefaultPath), "config file")
	fs.StringVar(&g.cacheDir, "cache-dir", envOr("UPKEEPER_CACHE_DIR", config.DefaultCacheDir), "cache directory")
	return fs
}

// parse allows flags before and after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, args := args[0], args[1:]
	var g globals
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "upkeeper %s (protocol %d)\n", version, protocol.Version)
		return 0

	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0

	case "enroll":
		fs := newFlags("enroll", &g, stderr)
		url := fs.String("url", envOr("UPKEEPER_URL", config.DefaultURL), "control plane URL")
		pos, err := parse(fs, args)
		if err != nil {
			return 2
		}
		if len(pos) != 1 {
			fmt.Fprintln(stderr, "usage: upkeeper enroll <token> [--url URL]")
			return 2
		}
		if err := enroll(ctx, g, *url, pos[0], stdout); err != nil {
			fmt.Fprintf(stderr, "upkeeper: enroll failed: %v\n", err)
			return 1
		}
		return 0

	case "report":
		fs := newFlags("report", &g, stderr)
		printOnly := fs.Bool("print", false, "print the report as JSON and send nothing")
		offline := fs.Bool("offline", false, "skip registry and Docker repository lookups")
		if _, err := parse(fs, args); err != nil {
			return 2
		}
		c := report.Default(version, g.cacheDir)
		c.Offline = *offline
		if *printOnly {
			r := c.Collect(ctx)
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			enc.SetEscapeHTML(false)
			if err := enc.Encode(r); err != nil {
				fmt.Fprintf(stderr, "upkeeper: %v\n", err)
				return 1
			}
			return 0
		}
		cfg, err := config.Load(g.config)
		if err != nil {
			fmt.Fprintf(stderr, "upkeeper: %v\n", err)
			return 1
		}
		r := c.Collect(ctx)
		cl := client(cfg)
		ack, err := cl.Report(ctx, r)
		if err != nil {
			fmt.Fprintf(stderr, "upkeeper: report not sent: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Report sent: %d items, %d risks. The server asks for one every %d s.\n", len(r.Items), len(r.Risks), ack.ReportEvery)
		return 0

	case "run":
		fs := newFlags("run", &g, stderr)
		if _, err := parse(fs, args); err != nil {
			return 2
		}
		cfg, err := config.Load(g.config)
		if err != nil {
			fmt.Fprintf(stderr, "upkeeper: %v\n", err)
			return 1
		}
		logger := log.New(stderr, "", 0) // journald adds timestamps
		logger.Printf("upkeeper %s: reporting to %s as server %s, read-only.", version, cfg.URL, cfg.ServerID)
		loop := &cloudclient.Loop{
			Client: client(cfg),
			Collect: func(ctx context.Context) protocol.Report {
				return report.Default(version, g.cacheDir).Collect(ctx)
			},
			Interval: time.Duration(cfg.ReportEvery) * time.Second,
			Logf:     logger.Printf,
			OnInterval: func(s int) {
				cfg.ReportEvery = s
				if err := config.Save(g.config, cfg); err != nil {
					logger.Printf("couldn't save the new report interval: %v", err)
				}
			},
		}
		loop.Run(ctx)
		logger.Printf("stopped.")
		return 0
	}
	fmt.Fprintf(stderr, "upkeeper: unknown command %q\n\n%s", cmd, usage)
	return 2
}

func client(cfg config.Config) *cloudclient.Client {
	return &cloudclient.Client{Base: cfg.URL, Token: cfg.AgentToken, UserAgent: "upkeeper/" + version}
}

func enroll(ctx context.Context, g globals, url, token string, stdout io.Writer) error {
	base, err := cloudclient.CheckURL(url)
	if err != nil {
		return err
	}
	// Tokens are opaque (upk_e_…): sent exactly as given.
	if token == "" {
		return errors.New("empty enroll token")
	}
	hostname, _ := os.Hostname()
	machineID := ""
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		machineID = strings.TrimSpace(string(b))
	}
	cl := &cloudclient.Client{Base: base, UserAgent: "upkeeper/" + version}
	resp, err := cl.Enroll(ctx, protocol.EnrollRequest{
		EnrollToken:  token,
		Hostname:     hostname,
		MachineID:    machineID,
		AgentVersion: version,
	})
	if err != nil {
		return err
	}
	every := resp.ReportEvery
	if every <= 0 {
		every = config.DefaultEvery
	}
	cfg := config.Config{URL: base, ServerID: resp.ServerID, AgentToken: resp.AgentToken, ReportEvery: every}
	if err := config.Save(g.config, cfg); err != nil {
		return fmt.Errorf("enrolled, but couldn't save %s: %w", g.config, err)
	}
	fmt.Fprintf(stdout, "Enrolled as server %s. The agent reports every %d s once it runs (systemctl enable --now upkeeper).\n", resp.ServerID, every)
	return nil
}
