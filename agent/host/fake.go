package host

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// FakeRunner returns canned output keyed by the full command line
// ("apt-mark showhold"). It enforces the same allowlist as ExecRunner, so a
// collector test fails if the collector asks for a command we don't allow.
type FakeRunner struct {
	Out  map[string]string
	Errs map[string]error
	Seen []string
}

func Key(name string, args ...string) string {
	return strings.TrimSpace(name + " " + strings.Join(args, " "))
}

func (f *FakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if err := Allowed(name, args); err != nil {
		return nil, err
	}
	k := Key(name, args...)
	f.Seen = append(f.Seen, k)
	out, ok := f.Out[k]
	err := f.Errs[k]
	if !ok && err == nil {
		return nil, fmt.Errorf("%s: %w", name, errors.New("executable file not found in $PATH"))
	}
	return []byte(out), err
}
