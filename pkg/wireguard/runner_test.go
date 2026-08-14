package wireguard

import (
	"errors"
	"strings"
	"testing"
)

func newFake(t *testing.T) *FakeRunner {
	t.Helper()
	f := NewFakeRunner()
	t.Cleanup(SetRunnerForTest(f))
	return f
}

func TestFakeRunner_RecordsCallsInOrder(t *testing.T) {
	f := newFake(t)

	_, _ = combined("ip", "link", "add", "wg-a", "type", "wireguard")
	_ = quiet("ip", "link", "delete", "wg-a")
	_, _ = output("wg", "show", "interfaces")

	want := []string{
		"ip link add wg-a type wireguard",
		"ip link delete wg-a",
		"wg show interfaces",
	}
	got := f.Calls()
	if len(got) != len(want) {
		t.Fatalf("recorded %d calls, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("call %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestFakeRunner_FailsOnlyAtNthCall(t *testing.T) {
	f := newFake(t)
	f.FailAt = 2

	if _, err := output("wg", "genkey"); err != nil {
		t.Fatalf("call 1 should have succeeded, got %v", err)
	}
	if _, err := output("wg", "pubkey"); err == nil {
		t.Fatal("call 2 should have failed")
	}
	if _, err := output("wg", "show", "interfaces"); err != nil {
		t.Fatalf("call 3 should have succeeded, got %v", err)
	}
	if len(f.Commands()) != 3 {
		t.Fatalf("recorded %d calls, want 3", len(f.Commands()))
	}
}

func TestFakeRunner_InjectedErrorIsReturned(t *testing.T) {
	f := newFake(t)
	sentinel := errors.New("device busy")
	f.FailAt = 1
	f.FailErr = sentinel

	_, err := combined("ip", "link", "delete", "wg-a")
	if !errors.Is(err, sentinel) {
		t.Fatalf("got %v, want the injected error", err)
	}
}

func TestHelpers_SetCombineFlag(t *testing.T) {
	f := newFake(t)

	_, _ = output("wg", "show", "interfaces")
	_, _ = combined("ip", "link", "delete", "wg-a")
	_ = quiet("iptables", "-t", "nat", "-D", "POSTROUTING")

	if f.Commands()[0].Combine {
		t.Error("output() must request stdout only — parsed output would be corrupted by stderr")
	}
	if !f.Commands()[1].Combine {
		t.Error("combined() must request stdout+stderr; its output is embedded in errors")
	}
	if f.Commands()[2].Combine {
		t.Error("quiet() must not request combined output")
	}
}

func TestOutputStdin_PassesStdin(t *testing.T) {
	f := newFake(t)
	f.Outputs[CmdKey("wg", "pubkey")] = "public-key-here\n"

	got, err := outputStdin("private-key-here", "wg", "pubkey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(string(got)) != "public-key-here" {
		t.Fatalf("got output %q, want the programmed stdout", got)
	}
	if f.Commands()[0].Stdin != "private-key-here" {
		t.Fatalf("stdin = %q, want the private key", f.Commands()[0].Stdin)
	}
}

func TestOutput_ReturnsProgrammedStdout(t *testing.T) {
	f := newFake(t)
	f.Outputs[CmdKey("wg", "show", "interfaces")] = "wg0 wg1\n"

	got, err := output("wg", "show", "interfaces")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(string(got)) != "wg0 wg1" {
		t.Fatalf("got %q, want the programmed stdout", got)
	}
}

func TestSetRunner_RestoresPrevious(t *testing.T) {
	before := defaultRunner

	restore := SetRunnerForTest(NewFakeRunner())
	if defaultRunner == before {
		t.Fatal("SetRunnerForTest did not swap the runner")
	}

	restore()
	if defaultRunner != before {
		t.Fatal("restore did not put the previous runner back")
	}
}

// TestDestroyInterface_DrivesExpectedCommands is the end-to-end check that the
// seam is wired to real code, not just to the helpers. The behavioural
// assertions on teardown live in myrelay-5uw.
func TestDestroyInterface_DrivesExpectedCommands(t *testing.T) {
	f := newFake(t)

	if err := DestroyInterface("wg-a", "10.0.0.0/24"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{
		"iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE",
		"ip link delete wg-a",
	}
	got := f.Calls()
	if len(got) != len(want) {
		t.Fatalf("ran %d commands, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("command %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestDestroyInterface_ValidationRunsNoCommands guards the property the
// teardown tests depend on: bad input never reaches iptables.
func TestDestroyInterface_ValidationRunsNoCommands(t *testing.T) {
	f := newFake(t)

	if err := DestroyInterface("wg-a; rm -rf /", "10.0.0.0/24"); err == nil {
		t.Fatal("expected an error for an invalid interface name")
	}
	if len(f.Commands()) != 0 {
		t.Fatalf("validation failure still ran %d commands: %v", len(f.Commands()), f.Calls())
	}
}

// TestDestroyInterface_SkipsNATCleanupWhenSubnetUnknown pins the guard added
// for myrelay-3bj: with no usable subnet, teardown must remove the interface
// and leave iptables untouched.
func TestDestroyInterface_SkipsNATCleanupWhenSubnetUnknown(t *testing.T) {
	f := newFake(t)

	if err := DestroyInterface("wg-a", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := f.Calls()
	if len(got) != 1 || got[0] != "ip link delete wg-a" {
		t.Fatalf("ran %v, want only the link delete", got)
	}
}

// TestDestroyInterface_IgnoresWildcardSubnet is the regression test for the
// bug itself. A catch-all subnet matches the node-wide MASQUERADE rule from
// scripts/setup-node.sh, so honouring it would cut egress for every peer on
// the host.
func TestDestroyInterface_IgnoresWildcardSubnet(t *testing.T) {
	for _, subnet := range []string{"0.0.0.0/0", "1.2.3.4/0", "::/0"} {
		t.Run(subnet, func(t *testing.T) {
			f := newFake(t)

			if err := DestroyInterface("wg-a", subnet); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, c := range f.Calls() {
				if strings.HasPrefix(c, "iptables") {
					t.Fatalf("wildcard subnet %q reached iptables: %q", subnet, c)
				}
			}
			if len(f.Calls()) != 1 {
				t.Fatalf("ran %v, want only the link delete", f.Calls())
			}
		})
	}
}

// TestDestroyInterface_RejectsInvalidSubnet keeps the existing validation:
// garbage is an error, not a silently skipped cleanup, and runs no commands.
func TestDestroyInterface_RejectsInvalidSubnet(t *testing.T) {
	f := newFake(t)

	if err := DestroyInterface("wg-a", "not-a-cidr"); err == nil {
		t.Fatal("expected an error for an invalid subnet")
	}
	if len(f.Commands()) != 0 {
		t.Fatalf("validation failure still ran %d commands: %v", len(f.Commands()), f.Calls())
	}
}
