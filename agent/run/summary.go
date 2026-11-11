package run

import (
	"fmt"
	"strings"

	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// changesPhrase is "9 packages and 1 image", "a new kernel", "" for nothing.
func changesPhrase(items []protocol.Item) string {
	pk, img, kernel := 0, 0, false
	for _, it := range items {
		switch it.Layer {
		case protocol.LayerOS:
			pk++
		case protocol.LayerKernel:
			kernel = true
		case protocol.LayerImage:
			img++
		}
	}
	var parts []string
	if pk > 0 {
		parts = append(parts, plural(pk, "package", "packages"))
	}
	if kernel {
		parts = append(parts, "the kernel")
	}
	if img > 0 {
		parts = append(parts, plural(img, "image", "images"))
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i+1]
	}
	return s
}

func shortService(subject string) string {
	if i := strings.LastIndex(subject, "/"); i >= 0 {
		return subject[i+1:]
	}
	return subject
}

func shortVersion(v string) string {
	if tag, _, ok := strings.Cut(v, "@"); ok {
		return tag
	}
	return v
}

// summary is the one plain sentence (or two) for the run record and emails.
func (r *runner) summary() string {
	res := r.res
	healthy := fmt.Sprintf("All %s healthy.", plural(r.lastRunning, "container", "containers"))
	if r.lastRunning == 0 {
		healthy = ""
	}
	join := func(ss ...string) string {
		var out []string
		for _, s := range ss {
			if s != "" {
				out = append(out, s)
			}
		}
		return strings.Join(out, " ")
	}
	kernel := ""
	if r.kernel && !r.dry && len(res.Applied) > 0 {
		kernel = "The new kernel takes effect after the next reboot."
	}
	switch {
	case r.stopped && r.dry:
		return "Dry run stopped: " + lowerFirst(firstSentence(res.FrozenReason)) + " Nothing was changed."
	case r.stopped:
		return "Stopped: " + lowerFirst(firstSentence(res.FrozenReason)) + " The server is frozen until you unfreeze it."
	case r.dry:
		if c := changesPhrase(res.Applied); c != "" {
			return "Dry run: would update " + c + ". Nothing was changed."
		}
		return "Dry run: nothing to update. Nothing was changed."
	case len(r.undone) > 0:
		var parts []string
		for _, u := range r.undone {
			from := shortVersion(u.from)
			to := shortVersion(u.to)
			if from == to || from == "" {
				parts = append(parts, fmt.Sprintf("The new %s image (%s) didn't come back healthy, so the previous one is running again.", u.name, to))
			} else {
				parts = append(parts, fmt.Sprintf("%s %s didn't come back healthy, so %s is running again.", u.name, to, from))
			}
			if u.data {
				parts = append(parts, fmt.Sprintf("The new version ran on %s's data for a few minutes; any changes it made to that data stay.", u.name))
			}
		}
		rest := "Nothing else changed."
		if c := changesPhrase(res.Applied); c != "" {
			rest = "Updated " + c + "."
		}
		return join(strings.Join(parts, " "), rest, kernel)
	}
	c := changesPhrase(res.Applied)
	if c == "" {
		if r.approvedSkipped > 0 {
			return join(fmt.Sprintf("Nothing was updated; %s skipped (see the run record).", plural(r.approvedSkipped, "approved update was", "approved updates were")), healthy)
		}
		return join("Nothing to update.", healthy)
	}
	out := join("Updated "+c+".", healthy, kernel)
	if r.approvedSkipped > 0 {
		out = join(out, fmt.Sprintf("%s skipped; see the run record.", plural(r.approvedSkipped, "approved update was", "approved updates were")))
	}
	return out
}
