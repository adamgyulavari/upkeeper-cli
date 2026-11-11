//go:build integration

// Integration tests against a real Docker Engine and Docker Compose:
//
//	go test -tags integration -count=1 -v ./agent/run/
//
// They need a running Docker daemon the current user can use, start a
// throwaway registry on 127.0.0.1:5000 and Compose projects under a temp
// directory, and remove what they created. They never run apt.
package run_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/agent/classify"
	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/discover"
	"github.com/adamgyulavari/upkeeper-cli/agent/dockerapi"
	"github.com/adamgyulavari/upkeeper-cli/agent/host"
	"github.com/adamgyulavari/upkeeper-cli/agent/policy"
	"github.com/adamgyulavari/upkeeper-cli/agent/registry"
	"github.com/adamgyulavari/upkeeper-cli/agent/run"
	"github.com/adamgyulavari/upkeeper-cli/agent/verify"
	"github.com/adamgyulavari/upkeeper-cli/agent/versions"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

const (
	regAddr = "127.0.0.1:5000"
	repo    = "localhost:5000/upk-it/app"
)

// base image for the test images; override with UPK_IT_BASE.
func baseImage() string {
	if b := os.Getenv("UPK_IT_BASE"); b != "" {
		return b
	}
	return "mirror.gcr.io/library/busybox:1.36"
}

func sh(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func shOK(dir string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

var builtDigests = map[string]string{}

// image builds and pushes repo:tag. good images serve HTTP on 8080;
// bad ones exit at once (a crash loop under a restart policy). It returns
// the registry digest and removes the local tag, so a run really pulls.
func image(t *testing.T, tag string, good bool) string {
	t.Helper()
	if d, ok := builtDigests[tag]; ok {
		return d
	}
	dir := t.TempDir()
	cmd := `["httpd","-f","-p","8080","-h","/www"]`
	if !good {
		cmd = `["sh","-c","echo broken release; exit 3"]`
	}
	df := fmt.Sprintf("FROM %s\nRUN mkdir -p /www && echo %s > /www/index.html\nCMD %s\n", baseImage(), tag, cmd)
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(df), 0o644)
	sh(t, dir, "docker", "build", "-q", "-t", repo+":"+tag, ".")
	sh(t, dir, "docker", "push", "-q", repo+":"+tag)
	var digests []string
	json.Unmarshal([]byte(sh(t, dir, "docker", "image", "inspect", "-f", "{{json .RepoDigests}}", repo+":"+tag)), &digests)
	dg := ""
	for _, d := range digests {
		if strings.HasPrefix(d, repo+"@") {
			dg = strings.TrimPrefix(d, repo+"@")
		}
	}
	if dg == "" {
		t.Fatalf("no registry digest for %s: %v", tag, digests)
	}
	builtDigests[tag] = dg
	return dg
}

func dropLocal(t *testing.T, tags ...string) {
	for _, tag := range tags {
		shOK("", "docker", "image", "rm", repo+":"+tag)
	}
}

func startRegistry(t *testing.T) {
	if out, err := shOK("", "docker", "info"); err != nil {
		t.Skipf("no Docker daemon: %v %s", err, out)
	}
	if _, err := shOK("", "docker", "inspect", "upk-it-registry"); err == nil {
		return
	}
	reg := os.Getenv("UPK_IT_REGISTRY_IMAGE")
	if reg == "" {
		reg = "mirror.gcr.io/library/registry:2"
	}
	sh(t, "", "docker", "run", "-d", "--name", "upk-it-registry", "-p", regAddr+":5000", reg)
	for i := 0; i < 30; i++ {
		if _, err := shOK("", "docker", "exec", "upk-it-registry", "wget", "-q", "-O-", "http://127.0.0.1:5000/v2/"); err == nil {
			return
		}
		time.Sleep(time.Second)
	}
}

// itPlanner plans exactly the given image updates for the live projects.
type itPlanner struct {
	api     *dockerapi.Client
	compose string
	updates []discover.ImageUpdate
}

func (p *itPlanner) Plan(ctx context.Context) (protocol.Report, classify.Input) {
	sys := protocol.System{OSID: "ubuntu", OSVersion: "24.04", OSCodename: "noble", Supported: true}
	in := classify.Input{System: sys,
		Docker:      protocol.Docker{Installed: true, Family: "docker-ce", EngineVersion: "29", ComposeVersion: p.compose},
		DockerFacts: collect.DockerFacts{Reachable: true, Services: map[string]collect.ServiceFacts{}}}
	list, _ := p.api.Containers(ctx)
	byProject := map[string]*protocol.Project{}
	for _, c := range list {
		ci, err := p.api.Inspect(ctx, c.ID)
		if err != nil {
			continue
		}
		l := ci.Config.Labels
		name := l["com.docker.compose.project"]
		if !strings.HasPrefix(name, "upkit") {
			continue
		}
		pr := byProject[name]
		if pr == nil {
			pr = &protocol.Project{Name: name, WorkDir: l["com.docker.compose.project.working_dir"]}
			byProject[name] = pr
		}
		var mounts []string
		for _, m := range ci.Mounts {
			if m.RW {
				mounts = append(mounts, m.Source)
			}
		}
		svc := l["com.docker.compose.service"]
		pr.Services = append(pr.Services, protocol.Service{Name: svc, Image: ci.Config.Image, State: ci.State.Status, Health: "none", RestartPolicy: ci.HostConfig.RestartPolicy.Name, HostPathMounts: mounts})
		ref, err := registry.ParseRef(ci.Config.Image)
		in.DockerFacts.Services[name+"/"+svc] = collect.ServiceFacts{Ref: ref, RefErr: err}
	}
	for _, pr := range byProject {
		in.Projects = append(in.Projects, *pr)
	}
	in.Images = p.updates
	r := protocol.Report{ProtocolVersion: protocol.Version, System: sys, Docker: in.Docker, Projects: in.Projects}
	r.Items = classify.Items(in)
	return r, in
}

type itEnv struct {
	t       *testing.T
	root    string
	dir     string
	project string
	api     *dockerapi.Client
	planner *itPlanner
	n       int
}

func newIT(t *testing.T, project, composeYAML string) *itEnv {
	startRegistry(t)
	root := t.TempDir()
	dir := filepath.Join(root, project)
	os.Mkdir(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "compose.yml"), []byte(composeYAML), 0o644)
	t.Cleanup(func() {
		shOK(dir, "docker", "compose", "-p", project, "-f", filepath.Join(dir, "compose.yml"), "down", "-v", "--remove-orphans")
	})
	sh(t, dir, "docker", "compose", "-p", project, "-f", filepath.Join(dir, "compose.yml"), "up", "-d", "--wait")
	api := dockerapi.NewUnix(dockerapi.DefaultSocket)
	cv := sh(t, "", "docker", "compose", "version", "--short")
	return &itEnv{t: t, root: root, dir: dir, project: project, api: api, planner: &itPlanner{api: api, compose: cv}}
}

func (e *itEnv) engine() *run.Engine {
	uid := os.Getuid()
	e.n++
	state := filepath.Join(e.root, fmt.Sprintf("state%d", e.n))
	pol := policy.Store{Path: filepath.Join(e.root, fmt.Sprintf("policy%d.yaml", e.n)), StateDir: state, OwnerUID: &uid}
	if err := pol.SetMode(protocol.ModeAuto); err != nil {
		e.t.Fatal(err)
	}
	pol.RecordDryRun(time.Now().Add(time.Second))
	runner := host.ExecRunner{}
	return &run.Engine{
		Planner: e.planner, Runner: runner, Docker: run.NewEngineOps(e.api),
		Checker:       &verify.Checker{Source: verify.HostSource{API: e.api, Run: runner, Prober: collect.Prober{}}, Poll: 2 * time.Second},
		FS:            host.RootFS{Root: "/"},
		Locked:        func() (string, bool, error) { return "", false, nil },
		Policy:        pol,
		Trust:         run.PathChecker{OwnerUID: uid, Root: e.root},
		StatePath:     filepath.Join(state, "run.json"),
		Memory:        &run.Memory{Dir: filepath.Join(e.root, "memory")},
		ProjectVerify: 25 * time.Second, FinalVerify: 5 * time.Second, OSVerify: 5 * time.Second,
		MinFreeBytes: 1,
		Logf:         e.t.Logf,
	}
}

func (e *itEnv) run(ups ...discover.ImageUpdate) protocol.RunResult {
	e.planner.updates = ups
	var keys []string
	for _, u := range ups {
		keys = append(keys, protocol.ItemKey(protocol.Item{Layer: protocol.LayerImage, Subject: u.Project + "/" + u.Service, To: classify.ImageTo(u)}))
	}
	now := time.Now().Add(2 * time.Second)
	job := protocol.Job{ID: fmt.Sprintf("it_%d", time.Now().UnixNano()), ServerID: "srv", Kind: protocol.KindRun, Mode: protocol.ModeAuto,
		Trigger: protocol.TriggerManual, Approved: keys, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Hour), WindowEnd: now.Add(time.Hour)}
	res := e.engine().Run(context.Background(), job, func(ev protocol.RunEvent) { e.t.Logf("  %s %s: %s", ev.Step, ev.Status, ev.Message) })
	e.t.Logf("result: %s; %s", res.Outcome, res.Summary)
	return res
}

func (e *itEnv) inspect(service string) dockerapi.ContainerInspect {
	id := sh(e.t, e.dir, "docker", "compose", "-p", e.project, "-f", filepath.Join(e.dir, "compose.yml"), "ps", "-a", "-q", service)
	ci, err := e.api.Inspect(context.Background(), strings.Fields(id)[0])
	if err != nil {
		e.t.Fatal(err)
	}
	return ci
}

func (e *itEnv) imageID(ref string) string {
	return sh(e.t, "", "docker", "image", "inspect", "-f", "{{.Id}}", ref)
}

func version(project, service, from, to, digest string) discover.ImageUpdate {
	return discover.ImageUpdate{Project: project, Service: service, Image: repo + ":" + from, FromTag: from, ToTag: to, Change: versions.Patch, ToDigest: digest}
}

const webService = `
  web:
    image: ` + repo + `:1.0.0
    restart: unless-stopped
    ports: ["127.0.0.1:18080:8080"]
`

// Version update, then a crash-looping release that is undone (L1), with
// the override written and put back, and pulls by digest.
func TestIntegrationUpdateAndUndo(t *testing.T) {
	startRegistry(t)
	image(t, "1.0.0", true)
	d1 := image(t, "1.0.1", true)
	d2 := image(t, "1.0.2", false)
	dropLocal(t, "1.0.1", "1.0.2")
	e := newIT(t, "upkit1", "services:"+webService)
	before := e.inspect("web")

	res := e.run(version("upkit1", "web", "1.0.0", "1.0.1", d1))
	if res.Outcome != protocol.OutcomeDone || len(res.Applied) != 1 {
		t.Fatalf("update: %+v", res)
	}
	after := e.inspect("web")
	if after.Image != e.imageID(repo+"@"+d1) {
		t.Errorf("web runs %s, want the image pulled by digest %s", after.Image, d1)
	}
	ov, _, err := run.ReadOverride(filepath.Join(e.dir, run.OverrideName))
	if err != nil || ov["web"] != repo+":1.0.1" {
		t.Errorf("override %v %v", ov, err)
	}
	if after.Config.Labels["com.docker.compose.config-hash"] == before.Config.Labels["com.docker.compose.config-hash"] {
		t.Error("config hash didn't change with the new tag")
	}

	res = e.run(version("upkit1", "web", "1.0.1", "1.0.2", d2))
	if res.Outcome != protocol.OutcomeUndone || res.Frozen {
		t.Fatalf("crash loop: %+v", res)
	}
	back := e.inspect("web")
	if back.Image != after.Image || back.State.Status != "running" {
		t.Errorf("after undo web runs %s (%s), want %s", back.Image, back.State.Status, after.Image)
	}
	if back.Config.Labels["com.docker.compose.config-hash"] != after.Config.Labels["com.docker.compose.config-hash"] {
		t.Error("undo didn't restore the exact config")
	}
	if ov, _, _ := run.ReadOverride(filepath.Join(e.dir, run.OverrideName)); ov["web"] != repo+":1.0.1" {
		t.Errorf("override after undo %v", ov)
	}
}

// Compose files edited without `up`: the project is skipped, nothing pulled.
func TestIntegrationConfigHashMismatch(t *testing.T) {
	startRegistry(t)
	image(t, "1.0.0", true)
	d1 := image(t, "1.0.1", true)
	dropLocal(t, "1.0.1")
	e := newIT(t, "upkit2", "services:"+webService)
	before := e.inspect("web")
	f := filepath.Join(e.dir, "compose.yml")
	b, _ := os.ReadFile(f)
	os.WriteFile(f, append(b, []byte("    environment:\n      NEW_SETTING: \"1\"\n")...), 0o644)

	res := e.run(version("upkit2", "web", "1.0.0", "1.0.1", d1))
	if len(res.Applied) != 0 || len(res.Skipped) != 1 || res.Skipped[0].Code != run.RiskComposeMismatch {
		t.Fatalf("%+v", res)
	}
	if e.inspect("web").ID != before.ID {
		t.Error("web was recreated")
	}
	if _, err := shOK("", "docker", "image", "inspect", repo+"@"+d1); err == nil {
		t.Error("the new image was pulled")
	}
}

// Variables from the shell that started the project: skipped.
func TestIntegrationShellVariables(t *testing.T) {
	startRegistry(t)
	image(t, "1.0.0", true)
	d1 := image(t, "1.0.1", true)
	os.Setenv("UPKIT_GREETING", "hello")
	defer os.Unsetenv("UPKIT_GREETING")
	e := newIT(t, "upkit5", "services:"+webService+"    environment:\n      GREETING: ${UPKIT_GREETING}\n")
	os.Unsetenv("UPKIT_GREETING")
	res := e.run(version("upkit5", "web", "1.0.0", "1.0.1", d1))
	if len(res.Applied) != 0 || len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0].Reason, "UPKIT_GREETING") {
		t.Fatalf("%+v", res)
	}
}

// A stopped service with an update is left stopped.
func TestIntegrationStoppedServiceLeftAlone(t *testing.T) {
	startRegistry(t)
	image(t, "1.0.0", true)
	d1 := image(t, "1.0.1", true)
	e := newIT(t, "upkit3", "services:"+webService+strings.ReplaceAll(strings.ReplaceAll(webService, "web:", "job:"), "18080", "18081"))
	sh(t, e.dir, "docker", "compose", "-p", "upkit3", "-f", filepath.Join(e.dir, "compose.yml"), "stop", "job")
	res := e.run(version("upkit3", "job", "1.0.0", "1.0.1", d1))
	if len(res.Applied) != 0 || !strings.Contains(res.Skipped[0].Reason, "wasn't running") {
		t.Fatalf("%+v", res)
	}
	if st := e.inspect("job").State.Status; st != "exited" {
		t.Errorf("job is %s", st)
	}
}

// Data in an anonymous volume survives the recreate.
func TestIntegrationAnonymousVolumeKept(t *testing.T) {
	startRegistry(t)
	image(t, "1.0.0", true)
	d1 := image(t, "1.0.1", true)
	dropLocal(t, "1.0.1")
	e := newIT(t, "upkit4", "services:"+webService+"    volumes: [\"/data\"]\n")
	id := e.inspect("web").ID
	sh(t, "", "docker", "exec", id, "sh", "-c", "echo kept > /data/row")
	res := e.run(version("upkit4", "web", "1.0.0", "1.0.1", d1))
	if res.Outcome != protocol.OutcomeDone {
		t.Fatalf("%+v", res)
	}
	nid := e.inspect("web").ID
	if nid == id {
		t.Fatal("not recreated")
	}
	if out := sh(t, "", "docker", "exec", nid, "cat", "/data/row"); out != "kept" {
		t.Errorf("anonymous volume lost: %q", out)
	}
}
