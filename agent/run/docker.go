package run

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/adamgyulavari/upkeeper-cli/agent/dockerapi"
)

// ProjectInfo is what's needed to run `docker compose up` for a project
// exactly the way it was started: from its containers' Compose labels.
type ProjectInfo struct {
	Name    string
	WorkDir string
	// ConfigFiles are the user's compose files from the
	// com.docker.compose.project.config_files label, without the agent's
	// own override (Override), which Compose lists there too once the
	// agent has recreated a service with it.
	ConfigFiles  []string
	Override     string            // path of the agent's override file for this project
	EnvFileLabel string            // com.docker.compose.project.environment_file, if set
	ImageIDs     map[string]string // service → image ID of its running container
	// Services holds what each service's containers say about themselves.
	Services map[string]ServiceInfo
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

// ServiceInfo is one Compose service as its containers describe it.
type ServiceInfo struct {
	Containers int      // containers of the service (not one-off runs), in any state
	Running    int      // of those, running
	Hashes     []string // distinct com.docker.compose.config-hash labels, sorted
	Image      string   // the image as the container was created with (Config.Image)
	ImageID    string
}

// ConfigHash is the service's config hash when all its containers agree.
func (s ServiceInfo) ConfigHash() (string, bool) {
	if len(s.Hashes) != 1 || s.Hashes[0] == "" {
		return "", false
	}
	return s.Hashes[0], true
}

// OverridePath is where the agent keeps its override for a project whose
// first compose file is first.
func OverridePath(first string) string {
	return filepath.Join(filepath.Dir(first), OverrideName)
}

// UserFiles drops the agent's override from a config_files label list. The
// override is the file named OverrideName next to the first other file;
// a file with that name anywhere else is the user's and stays.
func UserFiles(files []string) (user []string, override string) {
	for _, f := range files {
		if override == "" && filepath.Base(f) != OverrideName {
			override = OverridePath(f)
		}
	}
	for _, f := range files {
		if f != override && !slices.Contains(user, f) {
			user = append(user, f)
		}
	}
	return user, override
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

// Label names Compose writes on containers.
const (
	LabelProject     = "com.docker.compose.project"
	LabelService     = "com.docker.compose.service"
	LabelWorkingDir  = "com.docker.compose.project.working_dir"
	LabelConfigFiles = "com.docker.compose.project.config_files"
	LabelEnvFile     = "com.docker.compose.project.environment_file"
	LabelConfigHash  = "com.docker.compose.config-hash"
	LabelOneoff      = "com.docker.compose.oneoff"
)

func (e *EngineOps) Project(ctx context.Context, name string) (ProjectInfo, error) {
	pi := ProjectInfo{Name: name, ImageIDs: map[string]string{}, Services: map[string]ServiceInfo{}}
	list, err := e.API.Containers(ctx)
	if err != nil {
		return pi, err
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	first := true
	images := map[string]bool{}
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
		if l[LabelProject] != name || l[LabelOneoff] == "True" {
			continue
		}
		svc := l[LabelService]
		if !images[ci.Image] {
			images[ci.Image] = true
			im, err := e.API.Image(ctx, ci.Image)
			if err != nil {
				// Without the image's labels the container's can't be trusted.
				return pi, fmt.Errorf("can't read the image of %s: %w", svc, err)
			}
			var set []string
			for k := range im.Config.Labels {
				if strings.HasPrefix(k, "com.docker.compose.") {
					set = append(set, k)
				}
			}
			if len(set) > 0 && len(pi.ImageLabels) == 0 {
				sort.Strings(set)
				pi.ImageLabels, pi.ImageLabelsFrom = set, svc
			}
		}
		wd := l[LabelWorkingDir]
		files, override := UserFiles(splitList(l[LabelConfigFiles]))
		env := l[LabelEnvFile]
		if first {
			pi.WorkDir, pi.ConfigFiles, pi.Override, pi.EnvFileLabel, first = wd, files, override, env, false
		} else if wd != pi.WorkDir || strings.Join(files, ",") != strings.Join(pi.ConfigFiles, ",") || env != pi.EnvFileLabel {
			pi.Inconsistent = "its containers disagree about the project's directory or compose files"
		}
		si := pi.Services[svc]
		si.Containers++
		if ci.State.Status == "running" {
			si.Running++
		}
		if h := l[LabelConfigHash]; !slices.Contains(si.Hashes, h) {
			si.Hashes = append(si.Hashes, h)
			sort.Strings(si.Hashes)
		}
		if si.ImageID == "" || ci.State.Status == "running" {
			si.ImageID, si.Image = ci.Image, ci.Config.Image
		}
		pi.Services[svc] = si
		pi.ImageIDs[svc] = si.ImageID
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
