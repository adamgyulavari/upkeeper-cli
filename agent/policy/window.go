package policy

import (
	"fmt"
	"strings"
	"time"
)

// Window is a weekly maintenance window in the server's local time.
type Window struct {
	Days          [7]bool // indexed by time.Weekday; the day the window starts
	Start, Length time.Duration
	Loc           *time.Location // default time.Local
}

var dayNames = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

// ParseWindow parses "sun 03:00-05:00", "mon,thu 02:00-04:00" or
// "daily 23:00-01:00" (an end before the start runs past midnight).
func ParseWindow(s string) (Window, error) {
	var w Window
	f := strings.Fields(strings.ToLower(s))
	if len(f) != 2 {
		return w, fmt.Errorf("window %q: want \"<days> HH:MM-HH:MM\", for example \"sun 03:00-05:00\"", s)
	}
	if f[0] == "daily" {
		for i := range w.Days {
			w.Days[i] = true
		}
	} else {
		for _, d := range strings.Split(f[0], ",") {
			found := false
			for i, n := range dayNames {
				if d == n {
					w.Days[i], found = true, true
				}
			}
			if !found {
				return w, fmt.Errorf("window %q: unknown day %q (use sun, mon, … or daily)", s, d)
			}
		}
	}
	a, b, ok := strings.Cut(f[1], "-")
	if !ok {
		return w, fmt.Errorf("window %q: want HH:MM-HH:MM", s)
	}
	start, err1 := clock(a)
	end, err2 := clock(b)
	if err1 != nil || err2 != nil {
		return w, fmt.Errorf("window %q: times must be HH:MM", s)
	}
	if end <= start {
		end += 24 * time.Hour
	}
	w.Start, w.Length = start, end-start
	if w.Length > 12*time.Hour {
		return w, fmt.Errorf("window %q: at most 12 hours", s)
	}
	return w, nil
}

func clock(s string) (time.Duration, error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, err
	}
	return time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute, nil
}

func (w Window) loc() *time.Location {
	if w.Loc != nil {
		return w.Loc
	}
	return time.Local
}

// String is the policy.yaml form.
func (w Window) String() string {
	var days []string
	all := true
	for i, on := range w.Days {
		if on {
			days = append(days, dayNames[i])
		} else {
			all = false
		}
	}
	d := strings.Join(days, ",")
	if all {
		d = "daily"
	}
	end := (w.Start + w.Length) % (24 * time.Hour)
	return fmt.Sprintf("%s %s-%s", d, hm(w.Start), hm(end))
}

func hm(d time.Duration) string {
	return fmt.Sprintf("%02d:%02d", int(d.Hours()), int(d.Minutes())%60)
}

// End returns when the window that contains t ends, and false if t is
// outside every window.
func (w Window) End(t time.Time) (time.Time, bool) {
	lt := t.In(w.loc())
	for back := 0; back <= 1; back++ {
		day := time.Date(lt.Year(), lt.Month(), lt.Day()-back, 0, 0, 0, 0, w.loc())
		if !w.Days[day.Weekday()] {
			continue
		}
		start := day.Add(w.Start)
		end := start.Add(w.Length)
		if !lt.Before(start) && lt.Before(end) {
			return end, true
		}
	}
	return time.Time{}, false
}
