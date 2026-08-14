# myrelay-su8 — Fix: Monitor.Stop panics on double call

Issue: myrelay-su8 (P0, bug) · Parent: myrelay-d73 · Blocks: myrelay-eh0
Plan: `docs/plans/testing-auth-teardown.md` (phase 0.3, fix #1 and #2)

## Goal

`bandwidth.Monitor.Stop()` must be safe to call more than once, and
`InterfaceManager.DestroyInterface` must stop the monitor only after the
WireGuard teardown actually succeeded.

## Background

`Monitor.Stop()` (`pkg/bandwidth/monitor.go:52-54`) is a bare
`close(m.stopCh)` with no guard.

`InterfaceManager.DestroyInterface` (`cmd/agent/manager.go:100-126`) calls
`info.Monitor.Stop()` at line 109, *before* `wireguard.DestroyInterface` at
line 117. When the wg teardown fails, the function returns an error at line 118
without touching the maps — so the interface stays registered with a monitor
whose channel is already closed.

Failure path in production:

1. `DELETE /interfaces/wg-a` → `ip link delete` fails (device busy, wg binary
   missing, permission loss after a capability change).
2. Handler logs and returns 500 (`cmd/agent/main.go:465-475`). `wg-a` is still
   in `m.interfaces`, monitor stopped.
3. Operator or control plane retries `DELETE /interfaces/wg-a`.
4. `Stop()` runs again → `close of closed channel` → **unrecovered panic in the
   HTTP handler goroutine**.

Go's `net/http` recovers panics per connection, so this does not always kill
the process — but `close of closed channel` inside `DestroyInterface` happens
while `m.mu` is held (`manager.go:101`). The deferred `Unlock` does run during
the panic, so the mutex is released, but the manager is left mid-mutation and
the connection is torn down. Under the systemd unit in `scripts/setup-node.sh`
a repeated panic is an availability problem on a node serving live VPN peers.

The second half of the fix (ordering) is what makes the first half sufficient:
if the monitor is only stopped on success, a failed destroy leaves a *live*
monitor and the interface remains fully functional until the retry succeeds.
Today a failed destroy silently blinds bandwidth reporting for that interface
even though the interface is still passing traffic.

## Prior Art & Reuse

Searched: `grep -rn "sync.Once\|NumGoroutine\|goleak"` across the repo — no
hits. There is no existing idempotent-shutdown idiom to mirror, and no
goroutine-leak test helper; this task establishes both.

- `pkg/bandwidth/` has **no test file at all** — `monitor_test.go` is new.
- Test style to mirror: `pkg/wireguard/split_test.go` and
  `internal/config/config_test.go` — stdlib `testing` only, no testify, one
  behavior per named `TestXxx_Case` func, `t.Fatalf` for assertions.
- `Monitor.loop()` (`monitor.go:82-97`) already has the right shape for a
  deterministic exit signal; it needs a `defer close(m.done)` and nothing else.
- Deliberately **not** reused: no `context.Context` plumbing. The monitor's
  lifetime is owned by `InterfaceInfo`, not by a request, and converting it
  would touch `NewMonitor`'s signature and every call site in
  `cmd/agent/manager.go` for no benefit at this size.

## Requirements & Acceptance Criteria

In scope:

1. `Monitor.Stop()` is idempotent — N calls, sequential or concurrent, never
   panic and never block.
2. `Monitor.Stop()` before `Start()` does not panic, and a subsequent `Start()`
   exits immediately rather than polling forever.
3. `Monitor.loop()` signals its own exit so tests can assert the goroutine is
   actually gone, not just that `Stop()` returned.
4. `DestroyInterface` stops the monitor only after `wireguard.DestroyInterface`
   returns nil.
5. A failed `DestroyInterface` leaves the monitor running and the interface
   registered, and a retry behaves identically to a first call.
6. `make test` (`-race`) and `make lint` pass.

Out of scope:

- Guarding `Start()` against double-Start. With fix #4 the monitor is never
  stopped-then-restarted, so there is no path that needs it. Noted in
  `docs/plans/testing-auth-teardown.md` if it ever becomes reachable.
- The `InterfaceManager`-level test for requirement 5. It needs the injectable
  wireguard seam from **myrelay-nhp**, which is not built yet; that assertion
  is already scoped in **myrelay-eh0** ("destroy fails, then retry must not
  panic"). This task makes eh0's test possible rather than pre-empting it.
- The `0.0.0.0/0` NAT subnet bug on the adjacent line (`manager.go:112`) —
  that is **myrelay-3bj**.

## Next Actions

### 1. `pkg/bandwidth/monitor.go`

Add to the `Monitor` struct:

```go
stopCh   chan struct{}
stopOnce sync.Once
done     chan struct{} // closed when loop() exits
```

`NewMonitor` initialises `done`. `Stop` becomes:

```go
// Stop signals the polling loop to exit. Safe to call multiple times.
func (m *Monitor) Stop() {
    m.stopOnce.Do(func() { close(m.stopCh) })
}
```

`loop()` gains `defer close(m.done)` as its first statement, and checks
`m.stopCh` once before the initial `m.poll()` so a Stop-before-Start monitor
never shells out to `wg`.

`done` stays unexported — `monitor_test.go` is in package `bandwidth` and reads
it directly. No public API change.

### 2. `cmd/agent/manager.go`

Move `info.Monitor.Stop()` from line 109 to after the `wireguard.DestroyInterface`
error check (currently line 119), so the order is: compute subnet → destroy
interface → **stop monitor** → delete from maps → save state.

Add a comment recording why the order matters, since the line looks arbitrary
otherwise.

### 3. `pkg/bandwidth/monitor_test.go` (new)

- `TestMonitorStop_Idempotent` — Start, Stop ×3, no panic; `done` closes within
  a timeout.
- `TestMonitorStop_Concurrent` — Start, then 50 goroutines calling Stop, all
  join, no panic. Real coverage comes from `-race` in `make test`.
- `TestMonitorStop_BeforeStart` — Stop then Start; `done` closes promptly and
  no poll is attempted.
- `TestMonitorStop_LoopExits` — the goroutine-exit assertion the other tests
  lean on: select on `m.done` with a timeout, `t.Fatal` on timeout.
- `TestMonitorGetAllPeers_AfterStop` — reading a stopped monitor returns an
  empty slice, not nil and not a panic.

Tests use a long poll interval (e.g. `time.Hour`) so only the initial poll can
fire, and redirect `log.SetOutput` to `io.Discard` — `readTransfer` shells out
to `wg`, which is absent on darwin, and the resulting error log is noise, not a
failure.

## References

- `pkg/bandwidth/monitor.go:25-54` — struct, `Start`, `Stop`
- `pkg/bandwidth/monitor.go:82-97` — `loop`
- `cmd/agent/manager.go:100-126` — `DestroyInterface`
- `cmd/agent/main.go:465-475` — `handleDestroyInterface` (the 500 path)
- `scripts/setup-node.sh:104-131` — systemd unit
- `docs/plans/testing-auth-teardown.md` — phases 0.3, 2.2; fixes 1 and 2
- Conventions: `CLAUDE.md`
