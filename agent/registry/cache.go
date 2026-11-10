package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TTL is how long registry answers are reused (A-06: 6 h).
const TTL = 6 * time.Hour

type cacheEntry struct {
	Tags    []string  `json:"tags,omitempty"`
	Digest  string    `json:"digest,omitempty"`
	Fetched time.Time `json:"fetched"`
}

type cacheFile struct {
	Entries map[string]cacheEntry `json:"entries"`
	// Backoff holds registries that rate-limited us, until the given time.
	Backoff map[string]time.Time `json:"backoff,omitempty"`
	// Seen holds when this agent first saw an image digest or tag.
	Seen map[string]time.Time `json:"seen,omitempty"`
}

// SeenTTL is how long first-seen times are kept.
const SeenTTL = 60 * 24 * time.Hour

// maxSeen caps the first-seen table.
const maxSeen = 5000

// Cache is a small JSON file in the agent's cache dir. A Cache with an empty
// Dir lives in memory only.
type Cache struct {
	Dir string
	Now func() time.Time

	mu    sync.Mutex
	data  cacheFile
	dirty bool
}

const cacheFileName = "registry-cache.json"

// OpenCache loads the cache from dir. A missing or corrupt file starts empty.
func OpenCache(dir string, now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	c := &Cache{Dir: dir, Now: now}
	c.data = cacheFile{Entries: map[string]cacheEntry{}, Backoff: map[string]time.Time{}, Seen: map[string]time.Time{}}
	if dir != "" {
		if b, err := os.ReadFile(filepath.Join(dir, cacheFileName)); err == nil {
			var f cacheFile
			if json.Unmarshal(b, &f) == nil && f.Entries != nil {
				if f.Backoff == nil {
					f.Backoff = map[string]time.Time{}
				}
				if f.Seen == nil {
					f.Seen = map[string]time.Time{}
				}
				c.data = f
			}
		}
	}
	return c
}

func (c *Cache) get(key string) (cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.data.Entries[key]
	if !ok || c.Now().Sub(e.Fetched) > TTL || e.Fetched.After(c.Now().Add(time.Minute)) {
		return cacheEntry{}, false
	}
	return e, true
}

func (c *Cache) put(key string, e cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.Fetched = c.Now()
	c.data.Entries[key] = e
	c.dirty = true
}

// FirstSeen returns when key was first seen, recording now if it's new.
func (c *Cache) FirstSeen(key string) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.Now()
	if t, ok := c.data.Seen[key]; ok && !t.After(now.Add(time.Minute)) {
		return t
	}
	if len(c.data.Seen) >= maxSeen {
		return now // full: everything counts as new, which only delays updates
	}
	c.data.Seen[key] = now
	c.dirty = true
	return now
}

func (c *Cache) backoffUntil(registry string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.data.Backoff[registry]
	return t, ok && c.Now().Before(t)
}

func (c *Cache) setBackoff(registry string, until time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data.Backoff[registry] = until
	c.dirty = true
}

// Save writes the cache atomically, dropping expired entries.
func (c *Cache) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Dir == "" || !c.dirty {
		return nil
	}
	now := c.Now()
	for k, e := range c.data.Entries {
		if now.Sub(e.Fetched) > TTL {
			delete(c.data.Entries, k)
		}
	}
	for k, t := range c.data.Backoff {
		if now.After(t) {
			delete(c.data.Backoff, k)
		}
	}
	for k, t := range c.data.Seen {
		if now.Sub(t) > SeenTTL {
			delete(c.data.Seen, k)
		}
	}
	b, err := json.Marshal(c.data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.Dir, ".registry-cache-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(c.Dir, cacheFileName)); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	c.dirty = false
	return nil
}

// GetList returns a cached list of strings (used for apt metadata too).
func (c *Cache) GetList(key string) ([]string, bool) {
	e, ok := c.get(key)
	return e.Tags, ok
}

// PutList stores a list of strings under key for TTL.
func (c *Cache) PutList(key string, vals []string) { c.put(key, cacheEntry{Tags: vals}) }
