package host

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// DpkgLockFiles are the locks apt and dpkg take while they work.
var DpkgLockFiles = []string{
	"/var/lib/dpkg/lock-frontend",
	"/var/lib/dpkg/lock",
	"/var/lib/apt/lists/lock",
	"/var/cache/apt/archives/lock",
}

// Locked reports whether another process holds a write lock (fcntl, the
// kind dpkg and apt take) on any of paths. It opens the files read-only and
// only asks (F_GETLK); it never takes a lock. Missing files are unlocked.
func Locked(paths []string) (string, bool, error) {
	for _, p := range paths {
		f, err := os.Open(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return p, false, err
		}
		lk := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: 0, Len: 0}
		err = syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lk)
		f.Close()
		if err != nil {
			return p, false, err
		}
		if lk.Type != syscall.F_UNLCK {
			return p, true, nil
		}
	}
	return "", false, nil
}
