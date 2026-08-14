package wireguard

import (
	"errors"
	"strings"
	"sync"
)

// FakeRunner is a Runner that records commands instead of executing them, for
// use with SetRunnerForTest.
//
// It lives in the production package rather than a _test.go file so that
// cmd/agent's tests can use it too — Go test files are not importable across
// packages, and duplicating the recorder in every consumer is worse than the
// handful of unused bytes this adds to the binary.
type FakeRunner struct {
	mu    sync.Mutex
	calls []Command

	// FailAt is 1-indexed; 0 means never fail.
	FailAt int
	// FailErr is returned at FailAt. A generic error is used when nil.
	FailErr error

	// Outputs maps a command key (see CmdKey) to the stdout that command
	// should return. Commands with no entry return empty output.
	Outputs map[string]string
}

// NewFakeRunner returns a FakeRunner with its Outputs map ready to use.
func NewFakeRunner() *FakeRunner {
	return &FakeRunner{Outputs: map[string]string{}}
}

// CmdKey renders a command as "name arg1 arg2", the key format used by
// FakeRunner.Outputs and returned by Calls.
func CmdKey(name string, args ...string) string {
	if len(args) == 0 {
		return name
	}
	return name + " " + strings.Join(args, " ")
}

// Run records the command and returns its programmed output, or the injected
// failure when this call is the FailAt-th.
func (f *FakeRunner) Run(c Command) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, c)
	if f.FailAt > 0 && len(f.calls) == f.FailAt {
		err := f.FailErr
		if err == nil {
			err = errors.New("fake runner: injected failure")
		}
		return []byte("injected failure output"), err
	}
	return []byte(f.Outputs[CmdKey(c.Name, c.Args...)]), nil
}

// Calls returns each recorded command rendered as "name arg1 arg2", in order.
func (f *FakeRunner) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]string, len(f.calls))
	for i, c := range f.calls {
		out[i] = CmdKey(c.Name, c.Args...)
	}
	return out
}

// Commands returns the recorded commands in full, for assertions that need
// more than the rendered string — stdin contents or the Combine flag.
func (f *FakeRunner) Commands() []Command {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]Command, len(f.calls))
	copy(out, f.calls)
	return out
}

// Reset clears recorded calls, keeping the programmed outputs and failure.
func (f *FakeRunner) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}
