package wireguard

import (
	"os/exec"
	"strings"
)

// Command describes a single external command execution.
type Command struct {
	Name    string
	Args    []string
	Stdin   string // fed to the command's stdin when non-empty
	Combine bool   // capture stdout+stderr instead of stdout alone
}

// Runner executes external commands. The package uses a single implementation
// in production; tests swap in a fake to assert which commands ran, in what
// order, with what arguments.
type Runner interface {
	Run(Command) ([]byte, error)
}

// execRunner is the production Runner: it shells out for real.
type execRunner struct{}

func (execRunner) Run(c Command) ([]byte, error) {
	cmd := exec.Command(c.Name, c.Args...)
	if c.Stdin != "" {
		cmd.Stdin = strings.NewReader(c.Stdin)
	}
	if c.Combine {
		return cmd.CombinedOutput()
	}
	return cmd.Output()
}

var defaultRunner Runner = execRunner{}

// SetRunnerForTest swaps the package runner and returns a function that
// restores the previous one.
//
// This is the injection point for tests in any package: cmd/agent's handler
// and manager tests drive real code paths through a FakeRunner rather than
// shelling out, which is what makes them runnable without root or Linux.
//
// defaultRunner is package state, so tests that call this must not use
// t.Parallel().
func SetRunnerForTest(r Runner) (restore func()) {
	prev := defaultRunner
	defaultRunner = r
	return func() { defaultRunner = prev }
}

// output runs a command and returns its stdout. Use for commands whose output
// is parsed — stderr must stay out of the way.
func output(name string, args ...string) ([]byte, error) {
	return defaultRunner.Run(Command{Name: name, Args: args})
}

// outputStdin runs a command with stdin attached and returns its stdout.
func outputStdin(stdin, name string, args ...string) ([]byte, error) {
	return defaultRunner.Run(Command{Name: name, Args: args, Stdin: stdin})
}

// combined runs a command and returns stdout+stderr. Use where the output is
// only ever embedded in an error message.
func combined(name string, args ...string) ([]byte, error) {
	return defaultRunner.Run(Command{Name: name, Args: args, Combine: true})
}

// quiet runs a command and discards its output, returning only the error. Use
// for best-effort calls whose failure the caller intends to ignore.
func quiet(name string, args ...string) error {
	_, err := defaultRunner.Run(Command{Name: name, Args: args})
	return err
}
