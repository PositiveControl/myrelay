package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadNonExistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load non-existent: %v", err)
	}
	if cfg.NextIP != 2 {
		t.Errorf("expected NextIP=2, got %d", cfg.NextIP)
	}
	if cfg.Server.Interface != "wg0" {
		t.Errorf("expected default interface wg0, got %s", cfg.Server.Interface)
	}
	if len(cfg.Peers) != 0 {
		t.Errorf("expected 0 peers, got %d", len(cfg.Peers))
	}
}

func TestSaveAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	cfg, _ := Load(path)
	cfg.Server.PublicKey = "testkey123"
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	cfg2, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg2.Server.PublicKey != "testkey123" {
		t.Errorf("expected PublicKey=testkey123, got %s", cfg2.Server.PublicKey)
	}
}

func TestAddPeer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	cfg, _ := Load(path)

	peer, addr, err := cfg.AddPeer("alice", "pubkey-alice-1234567890abcdef")
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if peer.Name != "alice" {
		t.Errorf("expected name=alice, got %s", peer.Name)
	}
	if addr != "10.0.0.2/32" {
		t.Errorf("expected addr=10.0.0.2/32, got %s", addr)
	}
	if cfg.NextIP != 3 {
		t.Errorf("expected NextIP=3, got %d", cfg.NextIP)
	}

	// File should exist now.
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("config file should exist after AddPeer")
	}

	// Second peer.
	_, addr2, err := cfg.AddPeer("bob", "pubkey-bob-1234567890abcdef0")
	if err != nil {
		t.Fatalf("AddPeer bob: %v", err)
	}
	if addr2 != "10.0.0.3/32" {
		t.Errorf("expected addr=10.0.0.3/32, got %s", addr2)
	}
}

func TestAddPeerDuplicateName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	cfg, _ := Load(path)

	cfg.AddPeer("alice", "pubkey-1")
	_, _, err := cfg.AddPeer("alice", "pubkey-2")
	if err == nil {
		t.Error("expected error for duplicate name")
	}
}

func TestAddPeerDuplicateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	cfg, _ := Load(path)

	cfg.AddPeer("alice", "pubkey-same")
	_, _, err := cfg.AddPeer("bob", "pubkey-same")
	if err == nil {
		t.Error("expected error for duplicate public key")
	}
}

func TestRemovePeer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	cfg, _ := Load(path)

	cfg.AddPeer("alice", "pubkey-alice")
	cfg.AddPeer("bob", "pubkey-bob")

	removed, err := cfg.RemovePeer("alice")
	if err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if removed.Name != "alice" {
		t.Errorf("expected removed=alice, got %s", removed.Name)
	}

	peers := cfg.ListPeers()
	if len(peers) != 1 {
		t.Errorf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].Name != "bob" {
		t.Errorf("expected remaining=bob, got %s", peers[0].Name)
	}
}

func TestRemovePeerNotFound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	cfg, _ := Load(path)

	_, err := cfg.RemovePeer("ghost")
	if err == nil {
		t.Error("expected error for non-existent peer")
	}
}

func TestGetPeer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	cfg, _ := Load(path)

	cfg.AddPeer("alice", "pubkey-alice")

	p := cfg.GetPeer("alice")
	if p == nil {
		t.Fatal("expected non-nil peer")
	}
	if p.Name != "alice" {
		t.Errorf("expected name=alice, got %s", p.Name)
	}

	p2 := cfg.GetPeer("ghost")
	if p2 != nil {
		t.Error("expected nil for non-existent peer")
	}
}

func TestReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	cfg, _ := Load(path)
	cfg.AddPeer("alice", "pubkey-alice")

	// Modify file externally.
	cfg2, _ := Load(path)
	cfg2.AddPeer("bob", "pubkey-bob")

	changed, err := cfg.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !changed {
		t.Error("expected changed=true after adding a peer externally")
	}
	if len(cfg.Peers) != 2 {
		t.Errorf("expected 2 peers after reload, got %d", len(cfg.Peers))
	}
}

func TestReloadNoChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	cfg, _ := Load(path)
	cfg.AddPeer("alice", "pubkey-alice")

	changed, err := cfg.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if changed {
		t.Error("expected changed=false when nothing changed")
	}
}
