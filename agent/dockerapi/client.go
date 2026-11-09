// Package dockerapi is a minimal, read-only Docker Engine API client over the
// unix socket. It only issues GET requests.
package dockerapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

const DefaultSocket = "/var/run/docker.sock"

type Client struct {
	HTTP *http.Client
	Base string // "http://docker" for the socket, or an httptest URL
}

// NewUnix returns a client for the Engine API on a unix socket.
func NewUnix(socket string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:    2,
		IdleConnTimeout: 10 * time.Second,
	}
	return &Client{HTTP: &http.Client{Transport: tr, Timeout: 15 * time.Second}, Base: "http://docker"}
}

func (c *Client) get(ctx context.Context, path string, q url.Values, v any) error {
	u := c.Base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET %s: %s: %s", path, resp.Status, string(b))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(v)
}

type Version struct {
	Version    string `json:"Version"`
	APIVersion string `json:"ApiVersion"`
	Os         string `json:"Os"`
	Arch       string `json:"Arch"`
	Components []struct {
		Name    string `json:"Name"`
		Version string `json:"Version"`
	} `json:"Components"`
}

func (c *Client) Version(ctx context.Context) (Version, error) {
	var v Version
	err := c.get(ctx, "/version", nil, &v)
	return v, err
}

type PortSummary struct {
	IP          string `json:"IP"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
}

type ContainerSummary struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`
	Labels map[string]string `json:"Labels"`
	Ports  []PortSummary     `json:"Ports"`
}

func (c *Client) Containers(ctx context.Context) ([]ContainerSummary, error) {
	var cs []ContainerSummary
	err := c.get(ctx, "/containers/json", url.Values{"all": {"1"}}, &cs)
	return cs, err
}

type Mount struct {
	Type        string `json:"Type"`
	Name        string `json:"Name"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

type ContainerInspect struct {
	ID           string `json:"Id"`
	Name         string `json:"Name"`
	Image        string `json:"Image"` // image ID
	RestartCount int    `json:"RestartCount"`
	State        struct {
		Status    string `json:"Status"`
		OOMKilled bool   `json:"OOMKilled"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	Mounts []Mount `json:"Mounts"`
}

func (c *Client) Inspect(ctx context.Context, id string) (ContainerInspect, error) {
	var ci ContainerInspect
	err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/json", nil, &ci)
	return ci, err
}

type Image struct {
	ID          string   `json:"Id"`
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
}

func (c *Client) Image(ctx context.Context, id string) (Image, error) {
	var im Image
	err := c.get(ctx, "/images/"+url.PathEscape(id)+"/json", nil, &im)
	return im, err
}
