// Package config stores the agent's enrollment in /etc/upkeeper/agent.json (0600).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	DefaultPath     = "/etc/upkeeper/agent.json"
	DefaultCacheDir = "/var/cache/upkeeper"
	DefaultURL      = "https://upkeeper.sh"
	DefaultEvery    = 300
)

type Config struct {
	URL         string `json:"url"`
	ServerID    string `json:"server_id"`
	AgentToken  string `json:"agent_token"`
	ReportEvery int    `json:"report_every_seconds"`
}

// ErrNotEnrolled means there is no config file yet.
var ErrNotEnrolled = errors.New("not enrolled yet: run `upkeeper enroll <token>` first")

func Load(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, ErrNotEnrolled
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	if c.AgentToken == "" || c.URL == "" {
		return c, fmt.Errorf("%s: missing url or agent_token; enroll again", path)
	}
	if c.ReportEvery <= 0 {
		c.ReportEvery = DefaultEvery
	}
	return c, nil
}

// Save writes the config atomically with mode 0600 (the directory 0700).
func Save(path string, c Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".agent-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
