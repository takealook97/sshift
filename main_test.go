package main

import (
	"testing"
)

func TestServerManager(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	sm := NewServerManager(tempDir)
	jm := NewJumpManager(tempDir)

	// Test server addition
	server := Server{
		Host: "192.168.1.100",
		User: "admin",
		Name: "Test Server",
	}
	sm.Add(server)

	if len(sm.Servers) != 1 {
		t.Errorf("Expected 1 server, got %d", len(sm.Servers))
	}

	if sm.Servers[0].ID != 1 {
		t.Errorf("Expected ID 1, got %d", sm.Servers[0].ID)
	}

	// Test server retrieval
	found, exists := sm.GetByID(1)
	if !exists {
		t.Error("Server should exist")
	}
	if found.Host != "192.168.1.100" {
		t.Errorf("Expected host 192.168.1.100, got %s", found.Host)
	}

	// Test server deletion
	if !sm.DeleteByID(1, jm) {
		t.Error("Server deletion should succeed")
	}
	if len(sm.Servers) != 0 {
		t.Errorf("Expected 0 servers after deletion, got %d", len(sm.Servers))
	}
}

func TestJumpManager(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	jm := NewJumpManager(tempDir)

	// Test jump relation addition
	jm.Add(1, 2)

	if len(jm.Relations) != 1 {
		t.Errorf("Expected 1 relation, got %d", len(jm.Relations))
	}

	// Test jump target retrieval
	target, exists := jm.GetJumpTarget(1)
	if !exists {
		t.Error("Jump target should exist")
	}
	if target != 2 {
		t.Errorf("Expected target 2, got %d", target)
	}

	// Test jump relation deletion
	jm.Delete(1)
	if len(jm.Relations) != 0 {
		t.Errorf("Expected 0 relations after deletion, got %d", len(jm.Relations))
	}
}

func TestNextID(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewServerManager(tempDir)
	jm := NewJumpManager(tempDir)

	// First server
	server1 := Server{Host: "192.168.1.1", User: "user1", Name: "Server 1"}
	sm.Add(server1)
	if sm.Servers[0].ID != 1 {
		t.Errorf("Expected ID 1, got %d", sm.Servers[0].ID)
	}

	// Second server
	server2 := Server{Host: "192.168.1.2", User: "user2", Name: "Server 2"}
	sm.Add(server2)
	if sm.Servers[1].ID != 2 {
		t.Errorf("Expected ID 2, got %d", sm.Servers[1].ID)
	}

	// Delete first server and add new server
	sm.DeleteByID(1, jm)
	server3 := Server{Host: "192.168.1.3", User: "user3", Name: "Server 3"}
	sm.Add(server3)
	if sm.Servers[1].ID != 3 {
		t.Errorf("Expected ID 3, got %d", sm.Servers[1].ID)
	}
}

func TestFileOperations(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewServerManager(tempDir)

	// Add server
	server := Server{Host: "192.168.1.100", User: "admin", Name: "Test Server"}
	sm.Add(server)

	// Load with new instance
	sm2 := NewServerManager(tempDir)
	if len(sm2.Servers) != 1 {
		t.Errorf("Expected 1 server after reload, got %d", len(sm2.Servers))
	}

	if sm2.Servers[0].Host != "192.168.1.100" {
		t.Errorf("Expected host 192.168.1.100, got %s", sm2.Servers[0].Host)
	}
}

func TestJumpRelationUpdate(t *testing.T) {
	tempDir := t.TempDir()
	jm := NewJumpManager(tempDir)

	// Add first relation
	jm.Add(1, 2)
	if len(jm.Relations) != 1 {
		t.Errorf("Expected 1 relation, got %d", len(jm.Relations))
	}

	// Add different toID with same fromID (update)
	jm.Add(1, 3)
	if len(jm.Relations) != 1 {
		t.Errorf("Expected 1 relation after update, got %d", len(jm.Relations))
	}

	target, exists := jm.GetJumpTarget(1)
	if !exists {
		t.Error("Jump target should exist")
	}
	if target != 3 {
		t.Errorf("Expected target 3 after update, got %d", target)
	}
}

func TestSortServers(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewServerManager(tempDir)
	jm := NewJumpManager(tempDir)

	// Add servers (ID 1, 2, 3, 4)
	servers := []Server{
		{Host: "192.168.1.1", User: "user1", Name: "Server 1"},
		{Host: "192.168.1.2", User: "user2", Name: "Server 2"},
		{Host: "192.168.1.3", User: "user3", Name: "Server 3"},
		{Host: "192.168.1.4", User: "user4", Name: "Server 4"},
	}

	for _, server := range servers {
		sm.Add(server)
	}

	// Add jump relation (2 → 4)
	jm.Add(2, 4)

	// Delete server 1 (ID 1 is deleted)
	sm.DeleteByID(1, jm)

	// Check state before sorting
	if len(sm.Servers) != 3 {
		t.Errorf("Expected 3 servers after deletion, got %d", len(sm.Servers))
	}

	// Execute sorting
	SortServers(sm, jm)

	// Check state after sorting
	if len(sm.Servers) != 3 {
		t.Errorf("Expected 3 servers after sort, got %d", len(sm.Servers))
	}

	// Verify IDs are reordered to 1, 2, 3
	expectedIDs := []int{1, 2, 3}
	for i, server := range sm.Servers {
		if server.ID != expectedIDs[i] {
			t.Errorf("Expected ID %d at position %d, got %d", expectedIDs[i], i, server.ID)
		}
	}

	// Verify jump relation is updated to 1 → 3
	target, exists := jm.GetJumpTarget(1)
	if !exists {
		t.Error("Jump target should exist after sort")
	}
	if target != 3 {
		t.Errorf("Expected jump target 3, got %d", target)
	}
} 