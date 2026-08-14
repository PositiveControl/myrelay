package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/PositiveControl/myrelay/pkg/wireguard"
)

// These tests prove the seam works end to end: real handler and manager code
// paths run against a fake command runner, with no root and no WireGuard
// installed. The auth and teardown suites built on this are myrelay-v0d,
// myrelay-snk, myrelay-sst, myrelay-xfo, myrelay-eh0, and myrelay-cn2.

// newTestManager returns a manager wired to a fake runner, with state in a
// temp dir and a poll interval long enough that no bandwidth poll fires.
func newTestManager(t *testing.T, adminToken string) (*InterfaceManager, *wireguard.FakeRunner) {
	t.Helper()

	prev := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prev) })

	f := wireguard.NewFakeRunner()
	f.Outputs[wireguard.CmdKey("wg", "genkey")] = "cHJpdmF0ZS1rZXktZm9yLXRlc3RpbmctcHVycG9zZXM="
	f.Outputs[wireguard.CmdKey("wg", "pubkey")] = "cHVibGljLWtleS1mb3ItdGVzdGluZy1wdXJwb3Nlcy0="
	t.Cleanup(wireguard.SetRunnerForTest(f))

	statePath := filepath.Join(t.TempDir(), "interfaces.json")
	return NewInterfaceManager(adminToken, time.Hour, statePath), f
}

func TestSeam_ManagerCreateAndDestroyWithoutRoot(t *testing.T) {
	mgr, f := newTestManager(t, "admin-token")

	info, err := mgr.CreateInterface("wg-a", 51820, "10.0.0.1/24", "user-token-a")
	if err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	if info.PublicKey == "" {
		t.Fatal("expected the public key read back from the fake wg pubkey")
	}

	calls := f.Calls()
	if len(calls) == 0 || calls[0] != "ip link add wg-a type wireguard" {
		t.Fatalf("first command was %v, want the link add", calls)
	}

	f.Reset()
	if err := mgr.DestroyInterface("wg-a"); err != nil {
		t.Fatalf("DestroyInterface: %v", err)
	}

	want := []string{
		"iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE",
		"ip link delete wg-a",
	}
	got := f.Calls()
	if len(got) != len(want) {
		t.Fatalf("teardown ran %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("command %d = %q, want %q", i, got[i], want[i])
		}
	}

	if _, _, ok := mgr.Authorize("user-token-a"); ok {
		t.Error("destroying an interface must revoke its user token")
	}
}

// TestSeam_FailureInjectionReachesTheManager is what myrelay-eh0 needs: a
// teardown that fails partway, driven without touching a real interface.
func TestSeam_FailureInjectionReachesTheManager(t *testing.T) {
	mgr, f := newTestManager(t, "admin-token")

	if _, err := mgr.CreateInterface("wg-a", 51820, "10.0.0.1/24", "user-token-a"); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}

	f.Reset()
	f.FailAt = 2 // the `ip link delete`, after the iptables cleanup

	if err := mgr.DestroyInterface("wg-a"); err == nil {
		t.Fatal("expected DestroyInterface to fail")
	}

	// The interface must still be registered, and its token still valid,
	// because the teardown did not actually happen.
	if _, ok := mgr.Get("wg-a"); !ok {
		t.Error("failed teardown dropped the interface from the manager")
	}
	if _, _, ok := mgr.Authorize("user-token-a"); !ok {
		t.Error("failed teardown revoked the user token")
	}
}

// TestSeam_HandlersRunAgainstFakeRunner is the property the auth tests depend
// on: an authorized request reaches its handler and returns a real status code
// rather than a 500 from shelling out to a wg binary that isn't there.
func TestSeam_HandlersRunAgainstFakeRunner(t *testing.T) {
	mgr, _ := newTestManager(t, "admin-token")

	if _, err := mgr.CreateInterface("wg-a", 51820, "10.0.0.1/24", "user-token-a"); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	if _, err := mgr.CreateInterface("wg-b", 51821, "10.0.1.1/24", "user-token-b"); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}

	srv := newManagedServer(":0", "admin-token", "", mgr)

	tests := []struct {
		name  string
		token string
		path  string
		want  int
	}{
		{"admin lists any interface's peers", "admin-token", "/interfaces/wg-a/peers", http.StatusOK},
		{"user lists its own interface", "user-token-a", "/interfaces/wg-a/peers", http.StatusOK},
		{"user cannot reach another interface", "user-token-a", "/interfaces/wg-b/peers", http.StatusForbidden},
		{"unknown token is rejected", "nope", "/interfaces/wg-a/peers", http.StatusUnauthorized},
		{"user token cannot list interfaces", "user-token-a", "/interfaces", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			rec := httptest.NewRecorder()

			srv.Handler.ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("%s %s = %d, want %d (body %q)",
					req.Method, tt.path, rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}
