package run_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adamgyulavari/upkeeper-cli/agent/dockerapi"
	"github.com/adamgyulavari/upkeeper-cli/agent/run"
)

func engineAPI(t *testing.T, containers map[string]string, imageStatus int) *run.EngineOps {
	mux := http.NewServeMux()
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		var ids []string
		for id := range containers {
			ids = append(ids, `{"Id":"`+id+`"}`)
		}
		w.Write([]byte("[" + strings.Join(ids, ",") + "]"))
	})
	for id, body := range containers {
		mux.HandleFunc("/containers/"+id+"/json", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })
	}
	mux.HandleFunc("/images/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(imageStatus)
		w.Write([]byte(`{"Id":"sha256:img"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return run.NewEngineOps(&dockerapi.Client{HTTP: srv.Client(), Base: srv.URL})
}

func inspect(svc, files, hash, state string) string {
	return `{"Id":"x","Image":"sha256:img","State":{"Status":"` + state + `"},"Config":{"Image":"redis:7","Labels":{` +
		`"com.docker.compose.project":"app","com.docker.compose.service":"` + svc + `",` +
		`"com.docker.compose.project.working_dir":"/opt/app","com.docker.compose.config-hash":"` + hash + `",` +
		`"com.docker.compose.project.config_files":"` + files + `"}}}`
}

// H-02: the override in one container's labels doesn't make the project inconsistent.
func TestProjectLabelsWithOverride(t *testing.T) {
	ops := engineAPI(t, map[string]string{
		"a": inspect("redis", "/opt/app/compose.yml,/opt/app/compose.override.upkeeper.yml", "h1", "running"),
		"b": inspect("web", "/opt/app/compose.yml", "h2", "exited"),
	}, 200)
	pi, err := ops.Project(context.Background(), "app")
	if err != nil || pi.Inconsistent != "" {
		t.Fatalf("%v %q", err, pi.Inconsistent)
	}
	if len(pi.ConfigFiles) != 1 || pi.ConfigFiles[0] != "/opt/app/compose.yml" || pi.Override != "/opt/app/"+run.OverrideName {
		t.Errorf("files %v override %s", pi.ConfigFiles, pi.Override)
	}
	if h, ok := pi.Services["redis"].ConfigHash(); !ok || h != "h1" || pi.Services["web"].Running != 0 || pi.Services["web"].Containers != 1 {
		t.Errorf("services %+v", pi.Services)
	}
}

// M-02: a file named like the override elsewhere is the user's and stays.
func TestUserFilesKeepsForeignOverrideName(t *testing.T) {
	user, ov := run.UserFiles([]string{"/opt/app/compose.yml", "/opt/other/" + run.OverrideName, "/opt/app/" + run.OverrideName})
	if len(user) != 2 || user[1] != "/opt/other/"+run.OverrideName || ov != "/opt/app/"+run.OverrideName {
		t.Errorf("%v %s", user, ov)
	}
}

// M-02: an image that can't be inspected fails closed.
func TestProjectFailsClosedOnImageInspect(t *testing.T) {
	ops := engineAPI(t, map[string]string{"a": inspect("redis", "/opt/app/compose.yml", "h1", "running")}, 500)
	if _, err := ops.Project(context.Background(), "app"); err == nil {
		t.Fatal("no error")
	}
}
