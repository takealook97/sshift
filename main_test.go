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
		Host:     "192.168.1.100",
		User:     "admin",
		Name:     "Test Server",
		Password: "testpassword123",
	}
	if err := sm.Add(server); err != nil {
		t.Errorf("Failed to add server: %v", err)
	}

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
	err := sm.DeleteByID(1, jm)
	if err != nil {
		t.Errorf("Server deletion should succeed: %v", err)
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
	if err := jm.Add(1, 2); err != nil {
		t.Errorf("Failed to add jump relation: %v", err)
	}

	if jm.GetJumpCount() != 1 {
		t.Errorf("Expected 1 relation, got %d", jm.GetJumpCount())
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
	if jm.GetJumpCount() != 0 {
		t.Errorf("Expected 0 relations after deletion, got %d", jm.GetJumpCount())
	}
}

func TestNextID(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewServerManager(tempDir)
	jm := NewJumpManager(tempDir)

	// First server
	server1 := Server{Host: "192.168.1.1", User: "user1", Name: "Server 1", Password: "password1"}
	sm.Add(server1)
	if sm.Servers[0].ID != 1 {
		t.Errorf("Expected ID 1, got %d", sm.Servers[0].ID)
	}

	// Second server
	server2 := Server{Host: "192.168.1.2", User: "user2", Name: "Server 2", Password: "password2"}
	sm.Add(server2)
	if sm.Servers[1].ID != 2 {
		t.Errorf("Expected ID 2, got %d", sm.Servers[1].ID)
	}

	// Delete first server and add new server
	sm.DeleteByID(1, jm)
	server3 := Server{Host: "192.168.1.3", User: "user3", Name: "Server 3", Password: "password3"}
	sm.Add(server3)
	// After deletion and re-addition, the new server should get the next available ID (1, since it was freed)
	if sm.Servers[1].ID != 1 {
		t.Errorf("Expected ID 1 (reused from deleted server), got %d", sm.Servers[1].ID)
	}
}

func TestFileOperations(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewServerManager(tempDir)

	// Add server
	server := Server{Host: "192.168.1.100", User: "admin", Name: "Test Server", Password: "testpassword123"}
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
	err := jm.Add(1, 2)
	if err != nil {
		t.Errorf("Failed to add first relation: %v", err)
	}
	if jm.GetJumpCount() != 1 {
		t.Errorf("Expected 1 relation, got %d", jm.GetJumpCount())
	}

	// Add different toID with same fromID (this should create a new relation, not update)
	err = jm.Add(1, 3)
	if err != nil {
		t.Errorf("Failed to add second relation: %v", err)
	}
	if jm.GetJumpCount() != 2 {
		t.Errorf("Expected 2 relations after adding second relation, got %d", jm.GetJumpCount())
	}

	// Check that both relations exist
	targets := jm.GetJumpTargets(1)
	if len(targets) != 2 {
		t.Errorf("Expected 2 targets for server 1, got %d", len(targets))
	}
	
	// Check that both targets are present
	hasTarget2 := false
	hasTarget3 := false
	for _, target := range targets {
		if target == 2 {
			hasTarget2 = true
		}
		if target == 3 {
			hasTarget3 = true
		}
	}
	if !hasTarget2 {
		t.Error("Target 2 should exist")
	}
	if !hasTarget3 {
		t.Error("Target 3 should exist")
	}
}

func TestSortServers(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewServerManager(tempDir)
	jm := NewJumpManager(tempDir)

	// Add servers (ID 1, 2, 3, 4)
	servers := []Server{
		{Host: "192.168.1.1", User: "user1", Name: "Server 1", Password: "password1"},
		{Host: "192.168.1.2", User: "user2", Name: "Server 2", Password: "password2"},
		{Host: "192.168.1.3", User: "user3", Name: "Server 3", Password: "password3"},
		{Host: "192.168.1.4", User: "user4", Name: "Server 4", Password: "password4"},
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

// Performance benchmarks
func BenchmarkServerManagerAdd(b *testing.B) {
	tempDir := b.TempDir()
	sm := NewServerManager(tempDir)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server := Server{
			Host:     "192.168.1.100",
			User:     "admin",
			Name:     "Test Server",
			Password: "testpassword123",
		}
		sm.Add(server)
	}
}

func BenchmarkJumpManagerAdd(b *testing.B) {
	tempDir := b.TempDir()
	jm := NewJumpManager(tempDir)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jm.Add(i, i+1)
	}
}

func BenchmarkEncryption(b *testing.B) {
	password := "test-password-123"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := EncryptPassword(password)
		if err != nil {
			b.Fatal(err)
		}
		_, err = DecryptPassword(encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMemory(b *testing.B) {
	tempDir := b.TempDir()
	sm := NewServerManager(tempDir)
	jm := NewJumpManager(tempDir)
	
	// Pre-allocate servers
	servers := make([]Server, 100)
	for i := range servers {
		servers[i] = Server{
			Host:     "192.168.1.100",
			User:     "admin",
			Name:     "Test Server",
			Password: "testpassword123",
		}
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Add servers
		for _, server := range servers {
			sm.Add(server)
		}
		
		// Add jump relations
		for j := 0; j < len(servers)-1; j++ {
			jm.Add(j+1, j+2)
		}
		
		// Clear for next iteration
		sm.Servers = sm.Servers[:0]
		jm.Graph.AdjacencyList = make(map[int][]int)
		jm.Graph.ReverseList = make(map[int][]int)
	}
} 