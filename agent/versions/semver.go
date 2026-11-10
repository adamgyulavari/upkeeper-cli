package versions

import (
	"fmt"
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
	// Family is Suffix with every embedded version cut to its major:
	// "-pg16" stays "-pg16", "-alpine3.20" becomes "-alpine3",
	// "-jdk17-alpine3.19" becomes "-jdk17-alpine3". Build counters
	// ("-r1", "-ls45", "-1") are dropped. Tags of one family are one
	// release line; a different family (pg16 → pg17) changes something
	// bundled in the image by a major version.
	Family string
	// Embedded lists the versioned parts of the suffix with their majors.
	Embedded []Embedded
}

// Embedded is a version inside a tag suffix: "pg16" → {pg, 16}.
type Embedded struct {
	Word  string
	Major int
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
	t.Family, t.Embedded = family(t.Suffix)
	return t, true
}

// embeddedRe finds word+version parts of a suffix: "pg16", "alpine3.20", "jdk17".
var bareNumRe = regexp.MustCompile(`[-_.+]?\b\d+(?:\.\d+)*\b`)

var embeddedRe = regexp.MustCompile(`([A-Za-z]+)(\d+)((?:\.\d+)*)`)

// buildWords are suffix words followed by a build counter, not a version.
var buildWords = map[string]bool{"r": true, "ls": true, "build": true, "b": true, "rev": true, "p": true, "patch": true, "rel": true, "release": true}

func family(suffix string) (string, []Embedded) {
	var emb []Embedded
	fam := embeddedRe.ReplaceAllStringFunc(suffix, func(m string) string {
		sm := embeddedRe.FindStringSubmatch(m)
		word := strings.ToLower(sm[1])
		if buildWords[word] {
			return sm[1]
		}
		major, _ := strconv.Atoi(sm[2])
		emb = append(emb, Embedded{Word: word, Major: major})
		return sm[1] + sm[2]
	})
	// Remaining bare numbers (".1", "-2") are build counters.
	return bareNumRe.ReplaceAllString(fam, ""), emb
}

// SameKind reports whether u looks like t apart from versions inside the
// suffix: same "v" prefix, same number of components, same variant words.
// pg16 and pg17 are the same kind, but not the same family.
func (t Tag) SameKind(u Tag) bool {
	return t.Prefix == u.Prefix && len(t.Nums) == len(u.Nums) && t.Variant == u.Variant
}

// FamilyChange describes how the versioned parts of the suffix differ from
// t to u ("pg 16 → 17"), or "" if they don't.
func FamilyChange(t, u Tag) string {
	if t.Family == u.Family || len(t.Embedded) != len(u.Embedded) {
		if t.Family == u.Family {
			return ""
		}
		return strings.TrimLeft(t.Suffix, "-_+") + " → " + strings.TrimLeft(u.Suffix, "-_+")
	}
	var parts []string
	for i := range t.Embedded {
		a, b := t.Embedded[i], u.Embedded[i]
		if a.Major != b.Major {
			parts = append(parts, fmt.Sprintf("%s %d → %d", a.Word, a.Major, b.Major))
		}
	}
	return strings.Join(parts, ", ")
}

// FamilyNewer reports whether every versioned part of u's suffix is at
// least t's, and one is higher (pg16 → pg17, not pg16 → pg15).
func FamilyNewer(t, u Tag) bool {
	if len(t.Embedded) != len(u.Embedded) || len(t.Embedded) == 0 {
		return false
	}
	higher := false
	for i := range t.Embedded {
		a, b := t.Embedded[i], u.Embedded[i]
		if a.Word != b.Word || b.Major < a.Major {
			return false
		}
		if b.Major > a.Major {
			higher = true
		}
	}
	return higher
}

// Prerelease reports whether the tag looks like an rc/beta/nightly build.
func (t Tag) Prerelease() bool { return prereleaseRe.MatchString(t.Suffix) }

// Precise reports whether the tag names an exact release (three or more
// components). "16" or "1.2" usually float over patch releases.
func (t Tag) Precise() bool { return len(t.Nums) >= 3 }

// Compatible reports whether u is on the same release line as t: same "v"
// prefix, same number of components, same suffix family (-alpine3,
// -bookworm, -pg16). 0.7.2-pg16 and 0.7.4-pg17 are not compatible.
func (t Tag) Compatible(u Tag) bool {
	return t.SameKind(u) && t.Family == u.Family
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
	return naturalCompare(a.Suffix, b.Suffix)
}

// naturalCompare compares strings with digit runs compared as numbers, so
// "-alpine3.9" < "-alpine3.10".
func naturalCompare(a, b string) int {
	for a != "" && b != "" {
		da, db := digitRun(a), digitRun(b)
		if da > 0 && db > 0 {
			x, _ := strconv.Atoi(a[:da])
			y, _ := strconv.Atoi(b[:db])
			if x != y {
				if x < y {
					return -1
				}
				return 1
			}
			a, b = a[da:], b[db:]
			continue
		}
		if a[0] != b[0] {
			if a[0] < b[0] {
				return -1
			}
			return 1
		}
		a, b = a[1:], b[1:]
	}
	return strings.Compare(a, b)
}

func digitRun(s string) int {
	n := 0
	for n < len(s) && n < 9 && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	return n
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
