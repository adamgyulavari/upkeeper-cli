// Package versions compares Debian package versions and semver-like tags.
package versions

import (
	"strings"
)

// CompareDebian compares two Debian versions ([epoch:]upstream[-revision])
// with dpkg's algorithm. It returns -1, 0 or 1.
func CompareDebian(a, b string) int {
	ea, ua, ra := splitDebian(a)
	eb, ub, rb := splitDebian(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

func splitDebian(v string) (epoch int, upstream, revision string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		for _, c := range v[:i] {
			if c < '0' || c > '9' {
				break
			}
			epoch = epoch*10 + int(c-'0')
		}
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// UpstreamDebian strips the epoch and Debian revision:
// "5:28.3.2-1~ubuntu.24.04~noble" → "28.3.2", "27.5.1-0ubuntu3~24.04.2" → "27.5.1".
func UpstreamDebian(v string) string {
	_, u, _ := splitDebian(v)
	// Distros append repack markers ("+dfsg1", "~ds1"); drop them. Any other
	// "~" marks a pre-release ("29.0.0~rc.1"), kept as "29.0.0-rc.1".
	if i := strings.IndexByte(u, '+'); i > 0 {
		u = u[:i]
	}
	if i := strings.IndexByte(u, '~'); i > 0 {
		rest := u[i+1:]
		if strings.HasPrefix(rest, "ds") || strings.HasPrefix(rest, "dfsg") {
			u = u[:i]
		} else {
			u = u[:i] + "-" + rest
		}
	}
	return u
}

func order(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	case c == '~':
		return -1
	case c == 0:
		return 0
	default:
		return int(c) + 256
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// verrevcmp is dpkg's lib/dpkg/version.c verrevcmp.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	at := func(s string, k int) byte {
		if k < len(s) {
			return s[k]
		}
		return 0
	}
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := order(at(a, i)), order(at(b, j))
			if ac != bc {
				if ac < bc {
					return -1
				}
				return 1
			}
			i++
			j++
		}
		for at(a, i) == '0' {
			i++
		}
		for at(b, j) == '0' {
			j++
		}
		for isDigit(at(a, i)) && isDigit(at(b, j)) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if isDigit(at(a, i)) {
			return 1
		}
		if isDigit(at(b, j)) {
			return -1
		}
		if firstDiff != 0 {
			if firstDiff < 0 {
				return -1
			}
			return 1
		}
	}
	return 0
}

// CompareKernel compares kernel release strings ("6.8.0-49-generic",
// "6.1.0-28-amd64") segment by segment, numbers numerically.
func CompareKernel(a, b string) int { return verrevcmp(a, b) }
