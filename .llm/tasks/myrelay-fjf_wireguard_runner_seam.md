# myrelay-fjf — Add command runner seam to pkg/wireguard

Issue: myrelay-fjf (P1, task) · Parent: myrelay-d73 · Blocks: myrelay-5uw
Plan: `docs/plans/testing-auth-teardown.md` (phase 0.1)

## Goal

Make every external command in `pkg/wireguard` injectable, so create/destroy
ordering, rollback behaviour, and exact command arguments can be asserted
without root and without Linux.

## Background

`pkg/wireguard/wireguard.go` calls `exec.Command` at 23 sites. Nothing in the
package can be tested off a privileged Linux host, which is why
`pkg/wireguard` sits at 23% coverage (only `split.go`, which shells out to
nothing) and why `myrelay-5uw` — the teardown and rollback tests — is blocked.

This task builds the seam and proves it works. It asserts no production
behaviour; that is `myrelay-5uw`'s job.

### Call-site inventory

The 23 sites use four distinct invocation styles, and the differences matter:

| Style | Count | Sites | Why it differs |
|---|---|---|---|
| `.Output()` | 6 | `wireguard.go:48` (genkey), `:244` (ListInterfaces), `:269` (ShowPeers), `:331` (ReadServerPublicKey), `:346`, `:357` | stdout **only** — these outputs are parsed |
| `.Output()` + `Stdin` | 1 | `:55` (`wg pubkey`, fed the private key) | needs stdin plumbing |
| `.CombinedOutput()` | 8 | `:173`, `:194`, `:200`, `:206`, `:236`, `:319`, `:384`, `:394` | stderr is embedded in the returned error |
| `.Run()` | 8 | `:181`, `:188`, `:195`, `:201`, `:207` (rollback), `:214`, `:233` (iptables), `:315` (wg-quick down) | output discarded, error deliberately ignored |

Collapsing stdout-only and combined into one method would be wrong:
`ShowPeers` and `ReadServerPublicKey` parse their output, and folding stderr in
would corrupt the parse the first time `wg` writes a warning.

## Prior Art & Reuse

Searched: `exec.Command` across the repo, plus `var execCommand`, `Runner`,
`CommandContext`, and any existing fake/stub/mock. Findings:

- **No indirection exists anywhere.** Every caller shells out directly. This
  task introduces the first seam of its kind in the codebase, so there is no
  in-repo pattern to mirror and the shape chosen here becomes the precedent.
- `pkg/wireguard/split_test.go` and `internal/config/config_test.go` set the
  test idiom to match: stdlib `testing` only, no testify, `t.Fatalf`.
- `wgMu` (`wireguard.go:20`) already serializes command execution. The seam
  sits underneath it and changes nothing about locking.
- Deliberately **not** reused: the `os/exec` `TestHelperProcess` trick (a
  package-level `var execCommand = exec.Command` swapped for a function that
  re-execs the test binary). It is a one-token edit per call site, but the fake
  is awkward, ordered-command recording needs package globals, and injecting a
  failure at the Nth call means encoding state in environment variables.
  `myrelay-5uw` needs both of those to be ergonomic.

**Out of scope, recorded so the next session doesn't re-derive it:** the same
pattern exists at `pkg/bandwidth/monitor.go:168` (1 site) and
`pkg/security/status.go` (8 sites). Neither is needed by the auth/teardown
tests. `pkg/security` is the better follow-up candidate — it is pure
command-output parsing and would test well.

## Requirements & Acceptance Criteria

In scope:

1. Every `exec.Command` in `pkg/wireguard` routes through an injectable runner.
2. The runner distinguishes stdout-only from combined output, and supports
   stdin.
3. A test fake records commands in order and can fail on the Nth call.
4. Production behaviour is byte-for-byte unchanged: same binaries, same
   argument vectors, same error wrapping, same ignored errors.
5. `make test` (`-race`) and `make lint` pass; `staticcheck` reports nothing
   new (`cmd/tui/main.go:765` S1039 is pre-existing).

Out of scope:

- Behavioural assertions on `CreateInterface`/`DestroyInterface` — that is
  **myrelay-5uw**, which this unblocks.
- The `0.0.0.0/0` NAT bug (**myrelay-3bj**) and the hardcoded `eth0`
  (**myrelay-nih**). Both live in the lines this task edits. Resist fixing them
  here — a seam commit that also changes behaviour is unreviewable.
- `pkg/bandwidth` and `pkg/security` exec sites.

## Next Actions

### 1. New file `pkg/wireguard/runner.go`

A one-method interface, so the fake stays trivial:

```go
// Command describes an external command to execute.
type Command struct {
    Name    string
    Args    []string
    Stdin   string // optional
    Combine bool   // merge stderr into the returned output
}

// Runner executes external commands. Swapped out in tests.
type Runner interface {
    Run(Command) ([]byte, error)
}

var defaultRunner Runner = execRunner{}
```

Four unexported helpers keep the call sites as short as they are today:

```go
func output(name string, args ...string) ([]byte, error)             // stdout only
func combined(name string, args ...string) ([]byte, error)           // stdout+stderr
func quiet(name string, args ...string) error                        // discard output
func outputStdin(stdin, name string, args ...string) ([]byte, error) // stdout, with stdin
```

`execRunner.Run` maps `Command` onto `exec.Command`, selecting `Output()` or
`CombinedOutput()` on `Combine` and setting `cmd.Stdin` when `Stdin != ""`.

Test hook, unexported — nothing outside the package needs to inject:

```go
func setRunner(r Runner) (restore func())
```

### 2. `pkg/wireguard/wireguard.go` — 23 mechanical edits

`exec.Command(...).CombinedOutput()` → `combined(...)`, `.Output()` →
`output(...)`, `_ = exec.Command(...).Run()` → `_ = quiet(...)`, and
`GenerateKeyPair`'s piped call → `outputStdin(privateKey, "wg", "pubkey")`.
Drop the now-unused `os/exec` import.

Nothing else moves. Every argument vector, error string, and ignored error
stays exactly as it is.

### 3. New file `pkg/wireguard/runner_test.go`

The fake `myrelay-5uw` will build on:

```go
type fakeRunner struct {
    calls   []Command
    failAt  int   // 1-indexed; 0 = never fail
    failErr error
    outputs map[string]string // keyed by "name arg1 arg2"; "" if absent
}
```

Tests for the seam itself — enough to prove the fake is trustworthy before
another issue depends on it:

- calls are recorded in order, with the full argument vector
- `failAt` fails exactly the Nth call and lets the others through
- `Combine` selects combined vs stdout-only
- stdin reaches the command
- `setRunner`'s restore actually restores
- a smoke test that one real function (`DestroyInterface` with a valid subnet)
  drives the expected two commands, proving the wiring end to end

Tests must not call `t.Parallel()` — `defaultRunner` is a package global.
Document that on `setRunner`.

## References

- `pkg/wireguard/wireguard.go` — all 23 call sites, inventory above
- `pkg/wireguard/wireguard.go:20` — `wgMu`, unaffected
- `pkg/wireguard/split_test.go` — test idiom
- `docs/plans/testing-auth-teardown.md` — phase 0.1; blocked work in phase 2.1
- Conventions: `CLAUDE.md`
