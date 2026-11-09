// Package host is the agent's only door to the machine it runs on: reading
// files (FS) and running a fixed, read-only set of commands (Runner).
// Collectors take these interfaces so tests can point them at fixtures.
package host

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// FS reads the host filesystem. Paths are absolute host paths ("/etc/os-release");
// implementations may serve them from a different root.
type FS interface {
	ReadFile(path string) ([]byte, error)
	Stat(path string) (fs.FileInfo, error)
	ReadDir(path string) ([]fs.DirEntry, error)
	Glob(pattern string) ([]string, error)
	// Statfs returns total and used bytes of the filesystem holding path.
	Statfs(path string) (total, used uint64, err error)
}

// RootFS reads files below Root. Root "/" (or "") is the real host.
type RootFS struct {
	Root string
}

func (r RootFS) path(p string) string {
	root := r.Root
	if root == "" {
		root = "/"
	}
	return filepath.Join(root, filepath.Clean("/"+p))
}

func (r RootFS) ReadFile(p string) ([]byte, error)       { return os.ReadFile(r.path(p)) }
func (r RootFS) Stat(p string) (fs.FileInfo, error)      { return os.Stat(r.path(p)) }
func (r RootFS) ReadDir(p string) ([]fs.DirEntry, error) { return os.ReadDir(r.path(p)) }

// Glob matches pattern below Root and returns host paths (Root stripped).
func (r RootFS) Glob(pattern string) ([]string, error) {
	matches, err := filepath.Glob(r.path(pattern))
	if err != nil {
		return nil, err
	}
	root := filepath.Clean(r.path("/"))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if root != "/" {
			m = "/" + strings.TrimPrefix(strings.TrimPrefix(m, root), "/")
		}
		out = append(out, m)
	}
	return out, nil
}

func (r RootFS) Statfs(p string) (uint64, uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(r.path(p), &st); err != nil {
		return 0, 0, err
	}
	bs := uint64(st.Bsize)
	total := st.Blocks * bs
	free := st.Bfree * bs
	return total, total - free, nil
}
