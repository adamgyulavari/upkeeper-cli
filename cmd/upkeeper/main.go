// Command upkeeper is the upkeeper.sh server agent. It reports what's out
// of date and, when the local policy and the dashboard both allow it, runs
// maintenance jobs signed by the control plane.
package main

import (
	"bufio"
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

	"github.com/adamgyulavari/upkeeper-cli/agent/classify"
	"github.com/adamgyulavari/upkeeper-cli/agent/cloudclient"
	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/config"
	"github.com/adamgyulavari/upkeeper-cli/agent/dockerapi"
	"github.com/adamgyulavari/upkeeper-cli/agent/host"
	"github.com/adamgyulavari/upkeeper-cli/agent/jobs"
	"github.com/adamgyulavari/upkeeper-cli/agent/policy"
	"github.com/adamgyulavari/upkeeper-cli/agent/report"
	runengine "github.com/adamgyulavari/upkeeper-cli/agent/run"
	"github.com/adamgyulavari/upkeeper-cli/agent/statefile"
	"github.com/adamgyulavari/upkeeper-cli/agent/verify"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

const usage = `upkeeper keeps this server up to date.

Usage:
  upkeeper version
  upkeeper enroll <token> [--url https://upkeeper.sh]
                                 the token can also come from UPKEEPER_ENROLL_TOKEN,
                                 or from stdin with "-"
  upkeeper run                   report and take signed jobs (what the systemd unit runs)
  upkeeper report [--print]      collect once; --print shows the JSON and sends nothing
  upkeeper status                local policy, freeze state and job keys
  upkeeper policy show
  upkeeper policy set observe|dry-run|auto       (root)
  upkeeper policy window "sun 03:00-05:00"|none  (root)
  upkeeper unfreeze              allow runs again after a stop (root)

Flags for every command:
  --config PATH     default /etc/upkeeper/agent.json (env UPKEEPER_CONFIG)
  --cache-dir DIR   default /var/cache/upkeeper (env UPKEEPER_CACHE_DIR)
  --policy PATH     default /etc/upkeeper/policy.yaml (env UPKEEPER_POLICY)
  --state-dir DIR   default /var/lib/upkeeper (env UPKEEPER_STATE_DIR)
`

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

type globals struct {
	config   string
	cacheDir string
	policy   string
	stateDir string
}

// policyOwner is who must own policy.yaml: root, except in tests.
var policyOwner *int

func (g globals) store() policy.Store {
	return policy.Store{Path: g.policy, StateDir: g.stateDir, OwnerUID: policyOwner}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// isRoot is replaceable in tests.
var isRoot = func() bool { return os.Geteuid() == 0 }

func newFlags(name string, g *globals, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	fs.StringVar(&g.config, "config", envOr("UPKEEPER_CONFIG", config.DefaultPath), "config file")
	fs.StringVar(&g.cacheDir, "cache-dir", envOr("UPKEEPER_CACHE_DIR", config.DefaultCacheDir), "cache directory")
	fs.StringVar(&g.policy, "policy", envOr("UPKEEPER_POLICY", policy.DefaultPath), "policy file")
	fs.StringVar(&g.stateDir, "state-dir", envOr("UPKEEPER_STATE_DIR", policy.DefaultStateDir), "state directory")
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

// run keeps the old name for tests.
func run(args []string, stdout, stderr io.Writer) int {
	return runCLI(args, strings.NewReader(""), stdout, stderr)
}

func runCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
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
		token := os.Getenv("UPKEEPER_ENROLL_TOKEN")
		switch {
		case len(pos) == 1 && pos[0] == "-":
			line, _ := bufio.NewReader(stdin).ReadString('\n')
			token = strings.TrimSpace(line)
		case len(pos) == 1:
			token = pos[0]
		case len(pos) == 0 && token != "":
		default:
			fmt.Fprintln(stderr, "usage: upkeeper enroll <token> [--url URL]  (or UPKEEPER_ENROLL_TOKEN, or - for stdin)")
			return 2
		}
		if err := enroll(ctx, g, *url, token, stdout); err != nil {
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
		c := collector(g)
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
		ack, err := client(cfg).Report(ctx, r)
		if err != nil {
			fmt.Fprintf(stderr, "upkeeper: report not sent: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Report sent: %d items, %d risks. The server asks for one every %d s.\n", len(r.Items), len(r.Risks), cloudclient.ClampInterval(ack.ReportEvery))
		return 0

	case "status":
		fs := newFlags("status", &g, stderr)
		if _, err := parse(fs, args); err != nil {
			return 2
		}
		status(g, stdout)
		return 0

	case "policy":
		fs := newFlags("policy", &g, stderr)
		pos, err := parse(fs, args)
		if err != nil {
			return 2
		}
		return policyCmd(g, pos, stdout, stderr)

	case "unfreeze":
		fs := newFlags("unfreeze", &g, stderr)
		if _, err := parse(fs, args); err != nil {
			return 2
		}
		if !isRoot() {
			fmt.Fprintln(stderr, "upkeeper: unfreeze needs root: sudo upkeeper unfreeze")
			return 1
		}
		s := g.store()
		f := s.Frozen()
		if !f.Frozen {
			fmt.Fprintln(stdout, "This server isn't frozen.")
			return 0
		}
		if err := s.Unfreeze(); err != nil {
			fmt.Fprintf(stderr, "upkeeper: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Unfrozen. It was frozen because: %s\nAutomatic runs can start again in the next window.\n", f.Reason)
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
		daemon(ctx, g, cfg, log.New(stderr, "", 0)) // journald adds timestamps
		return 0
	}
	fmt.Fprintf(stderr, "upkeeper: unknown command %q\n\n%s", cmd, usage)
	return 2
}

func policyCmd(g globals, pos []string, stdout, stderr io.Writer) int {
	s := g.store()
	if len(pos) == 0 || pos[0] == "show" {
		st, err := s.Load()
		if err != nil {
			fmt.Fprintf(stdout, "Mode: observe (the policy file can't be used: %v)\n", err)
		} else {
			fmt.Fprintf(stdout, "Mode: %s (%s)\n", st.Mode, modeText(st.Mode))
		}
		if st.Window != nil {
			fmt.Fprintf(stdout, "Window: %s (server time)\n", st.Window)
		} else {
			fmt.Fprintln(stdout, "Window: none set here; the dashboard's window applies.")
		}
		if f := s.Frozen(); f.Frozen {
			fmt.Fprintf(stdout, "Frozen: yes. %s\n", f.Reason)
		} else {
			fmt.Fprintln(stdout, "Frozen: no")
		}
		return 0
	}
	if !isRoot() {
		fmt.Fprintln(stderr, "upkeeper: changing the policy needs root: sudo upkeeper policy …")
		return 1
	}
	switch {
	case pos[0] == "set" && len(pos) == 2:
		m, err := policy.ParseMode(pos[1])
		if err != nil {
			fmt.Fprintf(stderr, "upkeeper: %v\n", err)
			return 2
		}
		if err := s.SetMode(m); err != nil {
			fmt.Fprintf(stderr, "upkeeper: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Local policy is now %s (%s).\n", m, modeText(m))
		if m == protocol.ModeAuto {
			fmt.Fprintln(stdout, "The next job runs as a dry run first. Automatic runs also need \"Automatic runs\" switched on in the dashboard.")
		}
		return 0
	case pos[0] == "window" && len(pos) == 2:
		var w *policy.Window
		if pos[1] != "none" {
			pw, err := policy.ParseWindow(pos[1])
			if err != nil {
				fmt.Fprintf(stderr, "upkeeper: %v\n", err)
				return 2
			}
			w = &pw
		}
		if err := s.SetWindow(w); err != nil {
			fmt.Fprintf(stderr, "upkeeper: %v\n", err)
			return 1
		}
		if w == nil {
			fmt.Fprintln(stdout, "Local window removed; the dashboard's window applies.")
		} else {
			fmt.Fprintf(stdout, "Runs now start only within %s (server time).\n", w)
		}
		return 0
	}
	fmt.Fprintln(stderr, "usage: upkeeper policy show | set observe|dry-run|auto | window \"<days> HH:MM-HH:MM\"|none")
	return 2
}

func modeText(m protocol.Mode) string {
	switch m {
	case protocol.ModeAuto:
		return "may apply updates that can be undone automatically"
	case protocol.ModeDryRun:
		return "goes through runs but changes nothing"
	}
	return "reports only, changes nothing"
}

func rootIDs() ([]protocol.RootKey, []string) {
	roots, _ := protocol.Roots()
	var ids []string
	for _, r := range roots {
		ids = append(ids, r.ID)
	}
	return roots, ids
}

func status(g globals, w io.Writer) {
	s := g.store()
	policyCmd(g, []string{"show"}, w, w)
	roots, err := protocol.Roots()
	switch {
	case err != nil:
		fmt.Fprintf(w, "Root keys: broken in this build (%v); no jobs are accepted.\n", err)
	case len(roots) == 0:
		fmt.Fprintln(w, "Root keys: none in this build, so it accepts no jobs.")
	}
	for _, r := range roots {
		note := ""
		if r.ID == protocol.TestRootID {
			note = " (TEST key: development builds only, never on a server you care about)"
		}
		fmt.Fprintf(w, "Root key: %s %s%s\n", r.ID, protocol.Fingerprint(r.PublicKey), note)
	}
	if k, ok := jobs.LoadKeyInfo(g.stateDir); ok {
		fmt.Fprintf(w, "Job key: %s %s, certified by %s until %s; last used %s\n", k.KeyID, k.Fingerprint, k.RootID, k.NotAfter.Format(time.RFC3339), k.SeenAt.Format(time.RFC3339))
	} else {
		fmt.Fprintln(w, "Job key: no job has arrived yet.")
	}
	if h, err := s.History(); err == nil {
		if !h.LastFullRun.IsZero() {
			fmt.Fprintf(w, "Last full run: %s\n", h.LastFullRun.Format(time.RFC3339))
		}
		if !h.LastSecurityRun.IsZero() {
			fmt.Fprintf(w, "Last security run: %s\n", h.LastSecurityRun.Format(time.RFC3339))
		}
	}
	var st runengine.State
	if ok, _ := statefile.ReadJSON(g.stateDir+"/run.json", &st); ok {
		fmt.Fprintf(w, "Run in progress: job %s, %s step, since %s\n", st.JobID, st.Step, st.StartedAt.Format(time.RFC3339))
	}
}

// policyReport is Report.Policy: the local policy plus key information.
func policyReport(g globals) *protocol.Policy {
	p := g.store().Report()
	_, p.RootKeyIDs = rootIDs()
	if k, ok := jobs.LoadKeyInfo(g.stateDir); ok {
		p.JobKeyID, p.JobKeyFingerprint = k.KeyID, k.Fingerprint
	}
	return p
}

// minReleaseAge is 3 days. Development builds may lower it with
// UPKEEPER_DEV_MIN_RELEASE_AGE (a Go duration) for test VMs.
func minReleaseAge(logger *log.Logger) time.Duration {
	if v := os.Getenv("UPKEEPER_DEV_MIN_RELEASE_AGE"); v != "" && protocol.DevBuild() {
		if d, err := time.ParseDuration(v); err == nil && d >= 0 {
			if logger != nil {
				logger.Printf("development build: minimum image release age is %s instead of %s.", d, classify.DefaultMinReleaseAge)
			}
			return d
		}
	}
	return classify.DefaultMinReleaseAge
}

func collector(g globals) *report.Collector {
	c := report.Default(version, g.cacheDir)
	c.Settings.MinReleaseAge = minReleaseAge(nil)
	c.Policy = func() *protocol.Policy { return policyReport(g) }
	return c
}

// planner gives every run a fresh collector.
type planner struct{ g globals }

func (p planner) Plan(ctx context.Context) (protocol.Report, classify.Input) {
	return collector(p.g).Plan(ctx)
}

func daemon(ctx context.Context, g globals, cfg config.Config, logger *log.Logger) {
	mode, err := g.store().Mode()
	if err != nil {
		logger.Printf("local policy: %v", err)
	}
	roots, ids := rootIDs()
	rootList := "none, so no jobs are accepted"
	if len(ids) > 0 {
		rootList = strings.Join(ids, ", ")
	}
	logger.Printf("upkeeper %s: reporting to %s as server %s. Local policy: %s. Trusted root keys: %s.", version, cfg.URL, cfg.ServerID, mode, rootList)
	if protocol.TestRootTrusted() {
		logger.Printf("WARNING: this is a development build that trusts the TEST root key. Don't run it on a server you care about.")
	}

	api := dockerapi.NewUnix(dockerapi.DefaultSocket)
	runner := host.ExecRunner{}
	engine := &runengine.Engine{
		Planner: planner{g},
		Runner:  runner,
		Docker:  runengine.NewEngineOps(api),
		Checker: &verify.Checker{
			Source: verify.HostSource{API: api, Run: runner, Prober: collect.Prober{}},
			Logs:   verify.DockerLogs{API: api},
		},
		FS:        host.RootFS{Root: "/"},
		Policy:    g.store(),
		StatePath: g.stateDir + "/run.json",
		Settings:  classify.Settings{MinReleaseAge: minReleaseAge(logger)},
		Logf:      logger.Printf,
	}
	jl := &jobs.Loop{
		Client:   client(cfg),
		ServerID: cfg.ServerID,
		Roots:    roots,
		Engine:   engine,
		StateDir: g.stateDir,
		Logf:     logger.Printf,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		jl.Run(ctx)
	}()
	loop := &cloudclient.Loop{
		Client:   client(cfg),
		Collect:  func(ctx context.Context) protocol.Report { return collector(g).Collect(ctx) },
		Interval: time.Duration(cfg.ReportEvery) * time.Second,
		Logf:     logger.Printf,
	}
	loop.Run(ctx)
	<-done
	logger.Printf("stopped.")
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
	every = cloudclient.ClampInterval(every)
	cfg := config.Config{URL: base, ServerID: resp.ServerID, AgentToken: resp.AgentToken, ReportEvery: every}
	if err := config.Save(g.config, cfg); err != nil {
		return fmt.Errorf("enrolled, but couldn't save %s: %w", g.config, err)
	}
	fmt.Fprintf(stdout, "Enrolled as server %s. The agent reports every %d s once it runs (systemctl enable --now upkeeper).\n", resp.ServerID, every)
	return nil
}
