# Test Plan: Auth and Teardown

Status: proposed
Scope: authentication/authorization on the agent HTTP surface, and interface
teardown (destroy + NAT/state/monitor cleanup).

## Why

The repo has two test files (`internal/config/config_test.go`,
`pkg/wireguard/split_test.go`). Neither auth nor teardown is covered. Both are
the paths where a defect is silent and expensive: an auth defect leaks one
customer's VPN to another, and a teardown defect either strands resources on a
node or takes down every peer on that node.

## Blockers to testing today

Nothing in `pkg/wireguard` is injectable — `CreateInterface`/`DestroyInterface`
call `exec.Command("ip"|"wg"|"iptables", ...)` directly, so they can only run as
root on Linux. `InterfaceManager` calls those package functions directly, so it
inherits the same constraint. Fixing that seam is phase 0 and gates everything
else.

## Phase 0 — Testability seams

### 0.1 Command runner seam in `pkg/wireguard`

Introduce an injectable runner rather than calling `exec.Command` inline:

```go
// runner.go
type Runner interface {
    Run(name string, args ...string) ([]byte, error)
}

var defaultRunner Runner = execRunner{}

// SetRunner swaps the runner; test-only, returns a restore func.
func SetRunner(r Runner) (restore func())
```

Replace every `exec.Command(...)` in `wireguard.go` with `defaultRunner.Run(...)`.
The fake runner records an ordered `[]struct{Name string; Args []string}` and is
programmable to fail on the Nth call — that is what makes rollback ordering and
NAT-argument assertions testable without root.

### 0.2 Manager seam in `cmd/agent`

`InterfaceManager` should hold function values (or a small interface) for
`createIface`, `destroyIface`, `listIfaces`, `readPubKey`, defaulting to the
`wireguard` package. Lets manager tests run on darwin with no privileges.

### 0.3 Monitor lifecycle fix (prerequisite, not just a test)

`Monitor.Stop()` is `close(m.stopCh)` with no guard. Make it `sync.Once` (or a
closed flag) so double-Stop is a no-op, then test it. Without this, the teardown
retry test panics the test binary rather than failing an assertion.

### 0.4 CI

Add `.github/workflows/test.yml`: `make lint` + `make test` on ubuntu-latest,
and a second job with `sudo` + `wireguard-tools` running the `integration` tag.
Add `make test-integration` and a coverage target.

## Phase 1 — Auth unit tests (`cmd/agent/auth_test.go`)

Both server constructors already return `*http.Server`, so tests drive
`srv.Handler` through `httptest.NewServer` / `httptest.NewRecorder` with a fake
manager. No root, no wg.

### 1.1 Standalone `requireToken` (`main.go:206`)

Table over every protected route (`/peers`, `/bandwidth`, `/security`,
`/status`):

| case | header | expect |
|---|---|---|
| valid | `Bearer <tok>` | 200 |
| missing header | — | 401 |
| empty bearer | `Bearer ` | 401 |
| wrong token | `Bearer nope` | 401 |
| right token, wrong case scheme | `bearer <tok>` | pin current behavior (401) |
| bare token, no scheme | `<tok>` | pin current behavior (200 — decide if intended) |
| prefix of token | `Bearer <tok[:len-1]>` | 401 |
| token + suffix | `Bearer <tok>x` | 401 |
| extra space | `Bearer  <tok>` | 401 |
| other scheme | `Basic <b64>` | 401 |
| duplicate Authorization headers | two values | 401 |

Plus: `/health` is reachable with no auth and its body contains no token,
interface names, or peer keys.

### 1.2 `Authorize` (`manager.go:163`)

- admin token → `("admin", "", true)`
- user token → `("user", <its iface>, true)`
- unknown → `("", "", false)`
- **empty token against empty adminToken** → must be `false`. Currently true.
  This test drives a guard in `NewInterfaceManager` (reject empty admin token)
  and in `Authorize` (reject empty input).
- admin comparison must use `subtle.ConstantTimeCompare` — assert by code, and
  keep the behavioral cases green after the change.
- concurrent `Authorize` during `CreateInterface`/`DestroyInterface` under
  `-race` (100 goroutines each way).

### 1.3 `requireAdmin` vs `requireAccess` (`main.go:335`, `:348`)

Fixture: admin token, iface `wg-a` with token `tok-a`, iface `wg-b` with `tok-b`.

Admin-only routes — `POST /interfaces`, `DELETE /interfaces/{iface}`,
`GET /interfaces`, `GET /security`, `GET /status`:
- admin → allowed
- `tok-a` → 401 (not 403 — `requireAdmin` doesn't consult the manager; pin it)
- no header → 401

Per-interface routes — `POST /interfaces/{iface}/peers`,
`POST /interfaces/{iface}/peers/remove`, `GET /interfaces/{iface}/peers`:
- admin + any iface → allowed
- `tok-a` + `wg-a` → allowed
- **`tok-a` + `wg-b` → 403** (cross-tenant; the single most important assertion
  in this file — run it against every per-interface route, no exceptions)
- `tok-a` + nonexistent iface `wg-zzz` → 403
- unknown token + `wg-a` → 401
- admin + nonexistent iface → passes auth, handler returns 404

Path-shape probes against the cross-tenant check (Go 1.22 mux with `{iface}`):
`/interfaces/wg-a/../wg-b/peers`, `/interfaces/wg%2Da/peers`,
`/interfaces/WG-A/peers`, trailing slash, `//interfaces/wg-a/peers`. Each must
resolve to a 403 or 404 — never to `wg-b`'s peer list under `tok-a`.

### 1.4 Token lifecycle

- `CreateInterface` twice with the same user token → error (`manager.go:71`),
  and the second iface was not created (fake runner recorded no `ip link add`).
- Create `wg-a`/`tok-a`, destroy `wg-a`, re-create `wg-b` with `tok-a` → allowed,
  and `tok-a` now authorizes `wg-b` only.
- After destroy, `Authorize("tok-a")` → false (revocation is immediate).
- Failed destroy must not revoke: if wg destroy errors, `tok-a` still maps to
  `wg-a` (asserts the delete-after-success ordering in `manager.go:117-122`).
- Empty user token to `CreateInterface` → error (handler rejects at
  `main.go:429`, manager currently does not; add the manager-level guard).

### 1.5 Secret hygiene

- Capture `log.SetOutput` across create/destroy/authorize-fail/report cycles and
  assert no admin or user token substring appears.
- `GET /interfaces` response body must not contain `user_token`
  (`ifaceResponse` omits it — regression-lock it, since `InterfaceInfo` has the
  field with a JSON tag and is one careless `json.Encode(info)` away from leaking).
- State file written by `saveStateLocked` is mode 0600 and its dir 0700.

### 1.6 Fuzz

`FuzzAuthHeader` — arbitrary `Authorization` values against `requireAccess`;
invariant: response is 401/403 unless the header parses to exactly a known token.
`FuzzInterfaceName`, `FuzzCIDR` in `pkg/validate` — no panic, and anything
accepted by `InterfaceName` contains no shell/iptables metacharacters.

## Phase 2 — Teardown unit tests

### 2.1 `pkg/wireguard/wireguard_test.go` (fake runner)

`DestroyInterface`:
- happy path issues exactly, in order: `iptables -t nat -D POSTROUTING -s <subnet> -o eth0 -j MASQUERADE`, then `ip link delete <name>`.
- invalid name → error, **zero commands run** (no iptables call escapes validation).
- invalid subnet → error, zero commands run.
- iptables delete fails → still deletes the link, returns nil (best-effort is intended; lock it).
- `ip link delete` fails → error wraps combined output.
- `subnet == "0.0.0.0/0"` → **must not issue the iptables delete**. Guard the
  wildcard: today it removes the node-wide MASQUERADE from `setup-node.sh:47`
  and kills egress for every peer. Test drives the fix.
- egress interface is configurable (env/flag, default eth0) and Create/Destroy
  use the same value — a symmetry test that fails today's hardcoded `eth0`.

`CreateInterface` rollback — for each failure injection point (keygen, temp key
write, `wg set`, `ip addr add`, `ip link set up`), assert:
- an `ip link delete <name>` was issued,
- no `iptables -A POSTROUTING` was issued,
- `/tmp/wg-privkey-<name>` does not exist afterward,
- the returned error names the failing step.

Also: temp key file is 0600 while it exists; creating with a name containing
`;`, `$(...)`, `../`, a 16+ char name, or a leading `-` is rejected by
`validate.InterfaceName` before any exec.

### 2.2 `cmd/agent/manager_test.go`

- `DestroyInterface` happy path: monitor stopped, removed from `interfaces` and
  `tokenToIface`, state file rewritten without it.
- Unknown name → error, no wg commands issued.
- **Destroy fails, then retry** → second call must not panic (this is bug #1) and
  must return the same error; state unchanged both times.
- Destroy fails → monitor must still be running, or restartable. Decide the
  contract: move `info.Monitor.Stop()` after a successful wg destroy. Test it.
- Address unparseable (`""`, `"garbage"`, bare IP with no mask) → destroy must
  not pass a wildcard subnet down.
- Concurrent destroy of the same interface from N goroutines → exactly one
  success, N-1 "not found", no panic, `-race` clean.
- Concurrent destroy of different interfaces → all succeed.
- `GetAllBandwidth` racing a destroy → no nil-map or use-after-stop.

### 2.3 State persistence and re-adoption (`loadState`)

- Round-trip: create two ifaces → new manager over the same path with all
  interfaces reported running → both re-adopted, `tokenToIface` rebuilt.
- Entry not in `ListInterfaces()` → skipped, no monitor started, and it is
  dropped from the file on the next save (no zombie tokens authorizing).
- `ReadServerPublicKey` fails → skipped, not fatal.
- Corrupt/truncated JSON → manager starts empty, does not panic.
- State file with `user_token: ""` → not inserted into `tokenToIface`
  (`manager.go:257` already guards; regression-lock).
- Two entries sharing a user token (hand-crafted file) → last-writer wins is the
  current behavior; assert it and log a warning.
- Missing file / unreadable file (0000) → starts empty, logs.
- Simulated crash between wg destroy and save → next boot self-heals via the
  not-running skip.

### 2.4 Handler-level teardown (`main.go:465`)

- `DELETE /interfaces/wg-a` as admin → 204, body empty.
- Same request twice → second is **404** (change from today's blanket 500).
- Real failure → 500, and the response body leaks no interface path or error
  internals (currently a fixed string; lock it).
- `DELETE` with a user token → 401.

## Phase 3 — Integration tests (`//go:build linux && integration`)

Real `wg`/`ip`/`iptables`, run inside a fresh network namespace per test so the
host is never touched. Root required; CI-only, guarded by the build tag.

- Full lifecycle: create → peer add → traffic → destroy → `wg show interfaces`
  no longer lists it, `ip link show` gone, `iptables -t nat -S POSTROUTING`
  back to its pre-test rule set (byte-for-byte diff — this is the orphan-rule
  detector).
- Create/destroy the same iface 50× → no fd leak, no rule accumulation, no
  address leak.
- Agent SIGTERM mid-teardown → restart re-adopts consistent state.
- Two interfaces, destroy one → the other's NAT rule and connectivity survive
  (the direct regression test for the wildcard-subnet bug).
- Destroy while a peer is actively transferring → no hang, monitor goroutine
  exits (verified by goroutine count).

## Phase 4 — TLS/transport auth

`pkg/tlsutil/tlsutil_test.go`:
- `GenerateServerCert` → SANs contain the requested IPs and nothing else;
  expiry and key usage as intended.
- `ClientTLSConfig` with a real CA → handshake to a matching server succeeds;
  to a server signed by a different CA → fails; to a cert with a mismatched IP →
  fails; expired cert → fails.
- `ServerTLSConfig` rejects TLS 1.1.

`cmd/ctl` / `cmd/tui`: both fall back to `InsecureSkipVerify: true` when
`TLS_CA_CERT` is unset (`ctl/main.go:45`, `tui/main.go:182`). Test that with
`TLS_CA_CERT` set, a bad cert *is* rejected, and that the insecure fallback
prints its warning to stderr. Follow-up issue: make insecure opt-in via an
explicit flag rather than the default.

Agent→control-plane calls (`activateNode`, `reportBandwidthMulti`): assert the
`Authorization: Bearer` header is present against an `httptest.TLSServer`, that
a 401 response is surfaced (not swallowed), and that `activateWithRetry` backs
off 5s→10s→…→5m capped, with an injectable sleep so the test is instant.

## Phase 5 — Coverage gate

Once the above lands, enforce in CI: `cmd/agent` ≥ 70%, `pkg/wireguard` ≥ 70%,
`pkg/validate` and `pkg/tlsutil` ≥ 85%. Fail the build on regression.

## Sequencing

Phase 0 gates everything. Phases 1 and 2 are parallel after that. Phase 3
requires CI with root. Phase 4 is independent of all of them and can start any
time. Phase 5 is last.

## Fixes this plan forces

These are production changes the tests require, not test-only work:

1. `Monitor.Stop()` idempotent (`sync.Once`).
2. Stop the monitor only after wg teardown succeeds (`manager.go:109`).
3. Never pass `0.0.0.0/0` as the NAT subnet on destroy (`manager.go:112`).
4. Configurable egress interface, shared by create and destroy (`wireguard.go:214,233`).
5. `Authorize` uses `subtle.ConstantTimeCompare` and rejects empty tokens
   (`manager.go:164`).
6. `NewInterfaceManager` rejects an empty admin token.
7. Destroy of an unknown interface returns 404 (`main.go:468`).
8. Decide and enforce whether a bare token with no `Bearer` scheme is accepted
   (`main.go:209,338,351`).
9. Temp private-key path moves to `os.CreateTemp` in a 0700 dir, not a
   predictable `/tmp` name (`wireguard.go:186`).
