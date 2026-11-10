package run

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/adamgyulavari/upkeeper-cli/agent/dockerapi"
)

// ProjectInfo is what's needed to run `docker compose up` for a project
// exactly the way it was started: from its containers' Compose labels.
type ProjectInfo struct {
	Name         string
	WorkDir      string
	ConfigFiles  []string
	EnvFileLabel string            // com.docker.compose.project.environment_file, if set
	ImageIDs     map[string]string // service → image ID of its running container
	// MountSources are host paths every container on the server can write
	// to (all containers, not only this project's).
	MountSources []string
	// ImageLabels lists com.docker.compose.* labels set by an image of the
	// project (ImageLabelsFrom names the service); then labels can't be trusted.
	ImageLabels     []string
	ImageLabelsFrom string
	// Inconsistent explains labels that disagree between containers.
	Inconsistent string
	// Hashes of the compose files and .env, set by PathChecker.CheckProject.
	Hashes map[string]string
}

// DockerOps is the agent's door to Docker for a run: reads, plus the two
// Engine API writes M1 needs (pull and tag).
type DockerOps interface {
	Project(ctx context.Context, name string) (ProjectInfo, error)
	// Pull downloads image ("name:tag" or "name@sha256:…").
	Pull(ctx context.Context, image string) error
	// ImageID returns the local image ID of a reference.
	ImageID(ctx context.Context, image string) (string, error)
	// Tag points repo:tag at imageID.
	Tag(ctx context.Context, imageID, repo, tag string) error
}

// EngineOps implements DockerOps with the Engine API on the unix socket.
type EngineOps struct {
	API  *dockerapi.Client // reads
	HTTP *http.Client      // writes; no overall timeout (pulls take a while), ctx bounds it
	Base string
}

// NewEngineOps returns EngineOps for the default socket.
func NewEngineOps(api *dockerapi.Client) *EngineOps {
	h := *api.HTTP
	h.Timeout = 0
	return &EngineOps{API: api, HTTP: &h, Base: api.Base}
}

var refRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:@-]*$`)

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (e *EngineOps) Project(ctx context.Context, name string) (ProjectInfo, error) {
	pi := ProjectInfo{Name: name, ImageIDs: map[string]string{}}
	list, err := e.API.Containers(ctx)
	if err != nil {
		return pi, err
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	first := true
	for _, c := range list {
		ci, err := e.API.Inspect(ctx, c.ID)
		if err != nil {
			return pi, err
		}
		for _, m := range ci.Mounts {
			if m.RW && m.Source != "" {
				pi.MountSources = append(pi.MountSources, m.Source)
			}
		}
		l := ci.Config.Labels
		if l["com.docker.compose.project"] != name || l["com.docker.compose.oneoff"] == "True" {
			continue
		}
		svc := l["com.docker.compose.service"]
		if im, err := e.API.Image(ctx, ci.Image); err == nil && len(pi.ImageLabels) == 0 {
			for k := range im.Config.Labels {
				if strings.HasPrefix(k, "com.docker.compose.") {
					pi.ImageLabels = append(pi.ImageLabels, k)
					pi.ImageLabelsFrom = svc
				}
			}
			sort.Strings(pi.ImageLabels)
		}
		wd := l["com.docker.compose.project.working_dir"]
		files := splitList(l["com.docker.compose.project.config_files"])
		env := l["com.docker.compose.project.environment_file"]
		if first {
			pi.WorkDir, pi.ConfigFiles, pi.EnvFileLabel, first = wd, files, env, false
		} else if wd != pi.WorkDir || strings.Join(files, ",") != strings.Join(pi.ConfigFiles, ",") || env != pi.EnvFileLabel {
			pi.Inconsistent = "its containers disagree about the project's directory or compose files"
		}
		if _, ok := pi.ImageIDs[svc]; !ok || ci.State.Status == "running" {
			pi.ImageIDs[svc] = ci.Image
		}
	}
	if pi.WorkDir == "" || len(pi.ConfigFiles) == 0 {
		return pi, fmt.Errorf("no Compose labels with the project's directory and files on its containers")
	}
	return pi, nil
}

func splitRef(image string) (name, tagOrDigest string) {
	if i := strings.Index(image, "@"); i >= 0 {
		return image[:i], image[i+1:]
	}
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		return image[:i], image[i+1:]
	}
	return image, "latest"
}

func (e *EngineOps) do(ctx context.Context, method, path string, q url.Values) (*http.Response, error) {
	u := e.Base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	return e.HTTP.Do(req)
}

func (e *EngineOps) Pull(ctx context.Context, image string) error {
	if !refRe.MatchString(image) {
		return fmt.Errorf("refusing to pull %q", image)
	}
	name, tag := splitRef(image)
	resp, err := e.do(ctx, http.MethodPost, "/images/create", url.Values{"fromImage": {name}, "tag": {tag}})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("pull %s: %s: %s", image, resp.Status, strings.TrimSpace(string(b)))
	}
	// The answer is a stream of progress messages; an error can come at the end.
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var m struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(sc.Bytes(), &m) == nil && m.Error != "" {
			return fmt.Errorf("pull %s: %s", image, m.Error)
		}
	}
	return sc.Err()
}

func (e *EngineOps) ImageID(ctx context.Context, image string) (string, error) {
	if !refRe.MatchString(image) {
		return "", fmt.Errorf("bad image reference %q", image)
	}
	resp, err := e.do(ctx, http.MethodGet, "/images/"+image+"/json", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("image %s: %s", image, resp.Status)
	}
	var im dockerapi.Image
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&im); err != nil {
		return "", err
	}
	return im.ID, nil
}

func (e *EngineOps) Tag(ctx context.Context, imageID, repo, tag string) error {
	if !refRe.MatchString(imageID) || !refRe.MatchString(repo) || !refRe.MatchString(tag) || strings.Contains(tag, "/") {
		return fmt.Errorf("refusing to tag %q as %s:%s", imageID, repo, tag)
	}
	resp, err := e.do(ctx, http.MethodPost, "/images/"+imageID+"/tag", url.Values{"repo": {repo}, "tag": {tag}})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("tag %s:%s: %s: %s", repo, tag, resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}
