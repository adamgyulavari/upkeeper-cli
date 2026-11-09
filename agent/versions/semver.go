package versions

import (
	"regexp"
	"strconv"
	"strings"
)

// Tag is a version-like image tag or upstream version: "v1.2.3",
// "16.4-alpine3.20", "28.3.2".
type Tag struct {
	Raw     string
	Prefix  string // "v" or ""
	Nums    []int  // 1 to 4 numeric components
	Suffix  string // "-alpine3.20", "" …
	Variant string // Suffix with digits and dots removed: "-alpine"
}

var tagRe = regexp.MustCompile(`^(v?)(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?([-_+].*)?$`)

var prereleaseRe = regexp.MustCompile(`(?i)(rc|alpha|beta|dev|pre|preview|nightly|test|snapshot|canary|next|edge|unstable)`)

var variantStripRe = regexp.MustCompile(`[0-9.]+`)

// ParseTag parses s as a version tag. ok is false for words like "latest".
func ParseTag(s string) (Tag, bool) {
	m := tagRe.FindStringSubmatch(s)
	if m == nil {
		return Tag{}, false
	}
	t := Tag{Raw: s, Prefix: m[1], Suffix: m[6]}
	for _, p := range m[2:6] {
		if p == "" {
			break
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return Tag{}, false
		}
		t.Nums = append(t.Nums, n)
	}
	t.Variant = variantStripRe.ReplaceAllString(t.Suffix, "")
	return t, true
}

// Prerelease reports whether the tag looks like an rc/beta/nightly build.
func (t Tag) Prerelease() bool { return prereleaseRe.MatchString(t.Suffix) }

// Precise reports whether the tag names an exact release (three or more
// components). "16" or "1.2" usually float over patch releases.
func (t Tag) Precise() bool { return len(t.Nums) >= 3 }

// Compatible reports whether u is the same kind of tag as t: same "v"
// prefix, same number of components, same variant (-alpine, -bookworm).
func (t Tag) Compatible(u Tag) bool {
	return t.Prefix == u.Prefix && len(t.Nums) == len(u.Nums) && t.Variant == u.Variant
}

// Compare compares numeric components, then the raw suffix.
func Compare(a, b Tag) int {
	for i := 0; i < len(a.Nums) || i < len(b.Nums); i++ {
		var x, y int
		if i < len(a.Nums) {
			x = a.Nums[i]
		}
		if i < len(b.Nums) {
			y = b.Nums[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return strings.Compare(a.Suffix, b.Suffix)
}

// Change describes how far apart two versions are.
type Change int

const (
	Same Change = iota
	Patch
	Minor
	Major
)

func (c Change) String() string {
	return [...]string{"same", "patch", "minor", "major"}[c]
}

// Diff returns the size of the step from a to b (b assumed newer). Below 1.0,
// a minor bump counts as major: by semver convention 0.x minors may break.
func Diff(a, b Tag) Change {
	get := func(t Tag, i int) int {
		if i < len(t.Nums) {
			return t.Nums[i]
		}
		return 0
	}
	switch {
	case get(a, 0) != get(b, 0):
		return Major
	case get(a, 1) != get(b, 1):
		if get(a, 0) == 0 {
			return Major
		}
		return Minor
	case Compare(a, b) != 0:
		return Patch
	}
	return Same
}

// ParseVersion parses a plain upstream version like "28.3.2".
func ParseVersion(s string) (Tag, bool) {
	return ParseTag(strings.TrimPrefix(strings.TrimSpace(s), "v"))
}

// SameMinor reports whether a and b share major.minor.
func SameMinor(a, b Tag) bool {
	return len(a.Nums) >= 2 && len(b.Nums) >= 2 && a.Nums[0] == b.Nums[0] && a.Nums[1] == b.Nums[1]
}
