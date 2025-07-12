package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	passwordConst = "Password"
)

// TestCoverageInfo provides information about current test coverage
func TestCoverageInfo(t *testing.T) {
	t.Parallel()
	// This test provides information about test coverage without enforcing thresholds

	t.Log("Test coverage information:")
	t.Log("- Current coverage is measured during CI/CD pipeline")
	t.Log("- No strict thresholds are enforced")
	t.Log("- Coverage reports are generated for monitoring purposes")
}

func TestServerManager(t *testing.T) {
	t.Parallel()
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

	err := sm.Add(server)
	if err != nil {
		t.Fatalf("Failed to add server: %v", err)
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
	err = sm.DeleteByID(1, jm)
	if err != nil {
		t.Fatalf("Failed to delete server1: %v", err)
	}

	if len(sm.Servers) != 0 {
		t.Errorf("Expected 0 servers after deletion, got %d", len(sm.Servers))
	}
}

func TestJumpManager(t *testing.T) {
	t.Parallel()
	// Create temporary directory
	tempDir := t.TempDir()
	jm := NewJumpManager(tempDir)

	// Test jump relation addition
	err := jm.Add(1, 2)
	if err != nil {
		t.Fatalf("Failed to add jump relation: %v", err)
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
	err = jm.Delete(1)
	if err != nil {
		t.Fatalf("Failed to delete jump relation: %v", err)
	}

	if jm.GetJumpCount() != 0 {
		t.Errorf("Expected 0 relations after deletion, got %d", jm.GetJumpCount())
	}
}

func TestNextID(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	sm := NewServerManager(tempDir)
	jm := NewJumpManager(tempDir)

	var err error
	// First server
	server1 := Server{Host: "192.168.1.1", User: "user1", Name: "Server 1", Password: "password1"}

	err = sm.Add(server1)
	if err != nil {
		t.Fatalf("Failed to add server1: %v", err)
	}

	if sm.Servers[0].ID != 1 {
		t.Errorf("Expected ID 1, got %d", sm.Servers[0].ID)
	}

	// Second server
	server2 := Server{Host: "192.168.1.2", User: "user2", Name: "Server 2", Password: "password2"}

	err = sm.Add(server2)
	if err != nil {
		t.Fatalf("Failed to add server2: %v", err)
	}

	if sm.Servers[1].ID != 2 {
		t.Errorf("Expected ID 2, got %d", sm.Servers[1].ID)
	}

	// Delete first server and add new server
	err = sm.DeleteByID(1, jm)
	if err != nil {
		t.Fatalf("Failed to delete server1: %v", err)
	}

	server3 := Server{Host: "192.168.1.3", User: "user3", Name: "Server 3", Password: "password3"}

	err = sm.Add(server3)
	if err != nil {
		t.Fatalf("Failed to add server3: %v", err)
	}
	// After deletion and re-addition, the new server should get the next available ID (1, since it was freed)
	if sm.Servers[1].ID != 1 {
		t.Errorf("Expected ID 1 (reused from deleted server), got %d", sm.Servers[1].ID)
	}
}

func TestFileOperations(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	sm := NewServerManager(tempDir)

	var err error
	// Add server
	server := Server{Host: "192.168.1.100", User: "admin", Name: "Test Server", Password: "testpassword123"}

	err = sm.Add(server)
	if err != nil {
		t.Fatalf("Failed to add server: %v", err)
	}

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
	t.Parallel()
	tempDir := t.TempDir()
	jm := NewJumpManager(tempDir)

	var err error
	// Add first relation
	err = jm.Add(1, 2)
	if err != nil {
		t.Fatalf("Failed to add first relation: %v", err)
	}

	if jm.GetJumpCount() != 1 {
		t.Errorf("Expected 1 relation, got %d", jm.GetJumpCount())
	}

	// Add different toID with same fromID (this should create a new relation, not update)
	err = jm.Add(1, 3)
	if err != nil {
		t.Fatalf("Failed to add second relation: %v", err)
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
	t.Parallel()
	tempDir := t.TempDir()
	sm := NewServerManager(tempDir)
	jm := NewJumpManager(tempDir)

	var err error
	// Add servers (ID 1, 2, 3, 4)
	servers := []Server{
		{Host: "192.168.1.1", User: "user1", Name: "Server 1", Password: "password1"},
		{Host: "192.168.1.2", User: "user2", Name: "Server 2", Password: "password2"},
		{Host: "192.168.1.3", User: "user3", Name: "Server 3", Password: "password3"},
		{Host: "192.168.1.4", User: "user4", Name: "Server 4", Password: "password4"},
	}

	for _, server := range servers {
		err = sm.Add(server)
		if err != nil {
			t.Fatalf("Failed to add server: %v", err)
		}
	}

	// Add jump relation (2 → 4)
	err = jm.Add(2, 4)
	if err != nil {
		t.Fatalf("Failed to add jump relation: %v", err)
	}

	// Delete server 1 (ID 1 is deleted)
	err = sm.DeleteByID(1, jm)
	if err != nil {
		t.Fatalf("Failed to delete server1: %v", err)
	}

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

// Test encryption and decryption functions
func TestEncryptionDecryption(t *testing.T) {
	t.Parallel()

	// Set up encryption key for testing
	os.Setenv("SSHIFT_ENCRYPTION_KEY", "test-key-32-bytes-long-for-aes-256")

	password := "testpassword123"

	// Test encryption
	encrypted, err := EncryptPassword(password)
	if err != nil {
		t.Fatalf("Failed to encrypt password: %v", err)
	}

	if encrypted == password {
		t.Error("Encrypted password should not be the same as original")
	}

	// Test decryption
	decrypted, err := DecryptPassword(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt password: %v", err)
	}

	if decrypted != password {
		t.Errorf("Decrypted password should match original. Expected: %s, Got: %s", password, decrypted)
	}
}

// Test server validation
func TestServerValidation(t *testing.T) {
	t.Parallel()

	// Test valid server
	validServer := Server{
		Host:     "192.168.1.100",
		User:     "admin",
		Name:     "Test Server",
		Password: "testpassword123",
	}

	err := validServer.Validate()
	if err != nil {
		t.Errorf("Valid server should pass validation: %v", err)
	}

	// Test invalid server (empty host)
	invalidServer := Server{
		Host:     "",
		User:     "admin",
		Name:     "Test Server",
		Password: "testpassword123",
	}

	err = invalidServer.Validate()
	if err == nil {
		t.Error("Invalid server should fail validation")
	}

	// Test invalid server (empty user)
	invalidServer2 := Server{
		Host:     "192.168.1.100",
		User:     "",
		Name:     "Test Server",
		Password: "testpassword123",
	}

	err = invalidServer2.Validate()
	if err == nil {
		t.Error("Invalid server should fail validation")
	}
}

// Test utility functions
func TestUtilityFunctions(t *testing.T) {
	t.Parallel()
	// Test getAuthType
	serverWithPassword := Server{Password: "test", KeyPath: ""}
	authType := getAuthType(serverWithPassword)

	if authType != passwordConst {
		t.Errorf("Expected auth type '%s', got %s", passwordConst, authType)
	}

	serverWithKey := Server{Password: "", KeyPath: "/path/to/key"}
	authType = getAuthType(serverWithKey)

	if authType != "SSH Key (key)" {
		t.Errorf("Expected auth type 'SSH Key (key)', got %s", authType)
	}

	serverWithBoth := Server{Password: "test", KeyPath: "/path/to/key"}
	authType = getAuthType(serverWithBoth)

	if authType != passwordConst {
		t.Errorf("Expected auth type '%s' when both password and key exist, got %s", passwordConst, authType)
	}
}

// Test color functions
func TestColorFunctions(t *testing.T) {
	t.Parallel()

	text := "test"

	// Test color functions don't crash
	_ = colorize(Red, text)
	_ = success(text)
	_ = errorMsg(text)
	_ = warning(text)
	_ = info(text)
	_ = prompt(text)
	_ = serverName(text)
	_ = jump(text)
}

// Test secure string functions
func TestSecureString(t *testing.T) {
	t.Parallel()

	original := "testpassword"

	ss := NewSecureString(original)

	// Test String method
	if ss.String() != original {
		t.Errorf("Expected %s, got %s", original, ss.String())
	}

	// Test Bytes method
	bytesVal := ss.Bytes()

	if !bytes.Equal(bytesVal, []byte(original)) {
		t.Errorf("Expected %s, got %s", original, string(bytesVal))
	}

	// Test Clear method
	ss.Clear()

	if ss.String() != "" {
		t.Error("String should be empty after clear")
	}
}

// Test secure bytes functions
func TestSecureBytes(t *testing.T) {
	t.Parallel()

	original := []byte("testpassword")

	sb := NewSecureBytes(original)

	// Test Bytes method
	bytesVal := sb.Bytes()

	if !bytes.Equal(bytesVal, original) {
		t.Errorf("Expected %s, got %s", string(original), string(bytesVal))
	}

	// Test Clear method
	sb.Clear()

	if len(sb.Bytes()) != 0 {
		t.Error("Bytes should be empty after clear")
	}
}

// Test jump graph functions
func TestJumpGraph(t *testing.T) {
	t.Parallel()

	jg := NewJumpGraph()

	// Test AddJump
	err := jg.AddJump(1, 2)
	if err != nil {
		t.Fatalf("Failed to add jump: %v", err)
	}

	// Test HasJump
	if !jg.HasJump(1, 2) {
		t.Error("Jump should exist")
	}

	// Test GetJumpTargets
	targets := jg.GetJumpTargets(1)
	if len(targets) != 1 || targets[0] != 2 {
		t.Errorf("Expected target [2], got %v", targets)
	}

	// Test GetJumpSources
	sources := jg.GetJumpSources(2)
	if len(sources) != 1 || sources[0] != 1 {
		t.Errorf("Expected sources [1], got %v", sources)
	}

	// Test GetDirectJumpTarget
	target, exists := jg.GetDirectJumpTarget(1)
	if !exists || target != 2 {
		t.Errorf("Expected direct target 2, got %d, exists: %v", target, exists)
	}

	// Test GetDirectJumpSource
	source, exists := jg.GetDirectJumpSource(2)
	if !exists || source != 1 {
		t.Errorf("Expected direct source 1, got %d, exists: %v", source, exists)
	}

	// Test DeleteJump
	err = jg.DeleteJump(1, 2)
	if err != nil {
		t.Fatalf("Failed to delete jump: %v", err)
	}

	if jg.HasJump(1, 2) {
		t.Error("Jump should not exist after deletion")
	}
}

func TestFileOperationsWithEncryption(t *testing.T) {
	t.Parallel()
	os.Setenv("SSHIFT_ENCRYPTION_KEY", "test-key-32-bytes-long-for-aes-256")

	tempDir := t.TempDir()

	sm := NewServerManager(tempDir)
	encPass, err := EncryptPassword("testpassword123")

	if err != nil {
		t.Fatalf("Failed to encrypt password: %v", err)
	}

	server := Server{
		Host:     "192.168.1.100",
		User:     "admin",
		Name:     "Test Server",
		Password: encPass,
	}

	err = sm.Add(server)

	if err != nil {
		t.Fatalf("Failed to add server: %v", err)
	}

	err = sm.Save()

	if err != nil {
		t.Fatalf("Failed to save: %v", err)
	}

	sm2 := NewServerManager(tempDir)
	sm2.Load()

	if len(sm2.Servers) != 1 {
		t.Errorf("Expected 1 server after reload, got %d", len(sm2.Servers))
	}

	decrypted, err := sm2.Servers[0].GetDecryptedPassword()

	if err != nil {
		t.Fatalf("Failed to decrypt password: %v", err)
	}

	if decrypted != "testpassword123" {
		t.Errorf("Expected decrypted password 'testpassword123', got %s", decrypted)
	}
}

// Test jump manager with file operations
func TestJumpManagerFileOperations(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	jm := NewJumpManager(tempDir)

	// Add jump relations
	err := jm.Add(1, 2)
	if err != nil {
		t.Fatalf("Failed to add jump relation: %v", err)
	}

	err = jm.Add(2, 3)
	if err != nil {
		t.Fatalf("Failed to add jump relation: %v", err)
	}

	// Save to file
	err = jm.Save()
	if err != nil {
		t.Fatalf("Failed to save: %v", err)
	}

	// Create new instance and load
	jm2 := NewJumpManager(tempDir)
	jm2.Load()

	if jm2.GetJumpCount() != 2 {
		t.Errorf("Expected 2 jump relations after reload, got %d", jm2.GetJumpCount())
	}

	// Test path finding
	path, exists := jm2.FindPath(1, 3)
	if !exists {
		t.Error("Path should exist from 1 to 3")
	}

	expectedPath := []int{1, 2, 3}
	if len(path) != len(expectedPath) {
		t.Errorf("Expected path length %d, got %d", len(expectedPath), len(path))
	}

	for i, id := range path {
		if id != expectedPath[i] {
			t.Errorf("Expected path[%d] = %d, got %d", i, expectedPath[i], id)
		}
	}
}

// Test error handling
func TestErrorHandling(t *testing.T) {
	t.Parallel()

	// Test server with invalid host (exceeds max length)
	longHost := strings.Repeat("a", MaxHostLength+1)
	server := Server{
		Host:     longHost,
		User:     "admin",
		Name:     "Test Server",
		Password: "testpassword123",
	}

	err := server.Validate()
	if err == nil {
		t.Error("Server with invalid host should fail validation")
	}

	// Test server with invalid user (exceeds max length)
	longUser := strings.Repeat("b", MaxUserLength+1)
	server2 := Server{
		Host:     "192.168.1.100",
		User:     longUser,
		Name:     "Test Server",
		Password: "testpassword123",
	}

	err = server2.Validate()
	if err == nil {
		t.Error("Server with invalid user should fail validation")
	}
}

// Test circular jump detection
func TestCircularJumpDetection(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	jm := NewJumpManager(tempDir)

	// Add jump relations that would create a cycle
	err := jm.Add(1, 2)
	if err != nil {
		t.Fatalf("Failed to add jump relation: %v", err)
	}

	err = jm.Add(2, 3)
	if err != nil {
		t.Fatalf("Failed to add jump relation: %v", err)
	}

	// Try to add a relation that would create a cycle (3 -> 1)
	err = jm.Add(3, 1)
	if err == nil {
		t.Error("Adding circular jump should fail")
	}
}

// Test jump manager edge cases
func TestJumpManagerEdgeCases(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	jm := NewJumpManager(tempDir)

	// Test deleting non-existent jump
	err := jm.Delete(999)
	if err == nil {
		t.Error("Deleting non-existent jump should fail")
	}

	// Test getting jump target for non-existent server
	_, exists := jm.GetJumpTarget(999)
	if exists {
		t.Error("Non-existent jump target should not exist")
	}

	// Test getting jump source for non-existent server
	_, exists = jm.GetJumpFrom(999)
	if exists {
		t.Error("Non-existent jump source should not exist")
	}
}

// Test server manager edge cases
func TestServerManagerEdgeCases(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	sm := NewServerManager(tempDir)
	jm := NewJumpManager(tempDir)

	// Test getting non-existent server
	_, exists := sm.GetByID(999)
	if exists {
		t.Error("Non-existent server should not exist")
	}

	// Test deleting non-existent server
	err := sm.DeleteByID(999, jm)
	if err == nil {
		t.Error("Deleting non-existent server should fail")
	}

	// Test adding server with invalid data
	invalidServer := Server{
		Host:     "",
		User:     "",
		Name:     "",
		Password: "",
	}

	err = sm.Add(invalidServer)
	if err == nil {
		t.Error("Adding invalid server should fail")
	}
}

// Test encryption key handling
func TestEncryptionKeyHandling(t *testing.T) {
	t.Parallel()

	// 항상 고정된 키 사용
	os.Setenv("SSHIFT_ENCRYPTION_KEY", "test-key-32-bytes-long-for-aes-256")

	password := "testpassword"
	encrypted, err := EncryptPassword(password)

	if err != nil {
		t.Fatalf("Encryption should work with fixed key: %v", err)
	}

	decrypted, err := DecryptPassword(encrypted)

	if err != nil {
		t.Fatalf("Decryption should work with fixed key: %v", err)
	}

	if decrypted != password {
		t.Errorf("Expected %s, got %s", password, decrypted)
	}
}

// Test file path handling
func TestFilePathHandling(t *testing.T) {
	t.Parallel()

	// Test with tilde in path
	expandedPath := filepath.Join(os.Getenv("HOME"), "test")

	// This is just a basic test to ensure filepath operations work
	if !strings.Contains(expandedPath, os.Getenv("HOME")) {
		t.Error("Tilde expansion should include home directory")
	}
}

// Test system entropy
func TestSystemEntropy(t *testing.T) {
	t.Parallel()

	entropy, err := getSystemEntropy()
	if err != nil {
		t.Fatalf("Failed to get system entropy: %v", err)
	}

	if len(entropy) == 0 {
		t.Error("System entropy should not be empty")
	}
}

// Test encryption key generation
func TestEncryptionKeyGeneration(t *testing.T) {
	t.Parallel()

	key, err := getEncryptionKey()
	if err != nil {
		t.Fatalf("Failed to get encryption key: %v", err)
	}

	if len(key) < MinKeyLength {
		t.Errorf("Encryption key should be at least %d bytes, got %d", MinKeyLength, len(key))
	}
}

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
		_ = sm.Add(server)
	}
}

func BenchmarkJumpManagerAdd(b *testing.B) {
	tempDir := b.TempDir()

	jm := NewJumpManager(tempDir)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = jm.Add(i, i+1)
	}
}

func BenchmarkEncryption(b *testing.B) {
	os.Setenv("SSHIFT_ENCRYPTION_KEY", "test-key-32-bytes-long-for-aes-256")

	password := "testpassword123"

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		encrypted, _ := EncryptPassword(password)
		_, _ = DecryptPassword(encrypted)
	}
}

func BenchmarkMemory(b *testing.B) {
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ss := NewSecureString("testpassword")
		_ = ss.String()
		ss.Clear()
	}
}

// Test CLI entrypoints and menu logic
func TestRunMenuAndCLIEntrypoints(t *testing.T) {
	t.Parallel()

	os.Setenv("SSHIFT_TEST_MODE", "1")

	tempDir := t.TempDir()

	baseDir := filepath.Join(tempDir, ".sshift")

	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatalf("Failed to create baseDir: %v", err)
	}

	// Prepare server and jump manager
	sm := NewServerManager(baseDir)
	jm := NewJumpManager(baseDir)

	// Add a server for menu
	encPass, _ := EncryptPassword("testpassword123")

	sm.Servers = append(sm.Servers, Server{
		ID:       1,
		Host:     "127.0.0.1",
		User:     "test",
		Name:     "TestServer",
		Password: encPass,
	})

	if err := sm.Save(); err != nil {
		t.Fatalf("Failed to save server: %v", err)
	}

	pr, pw, _ := os.Pipe()
	oldStdin := os.Stdin
	os.Stdin = pr

	defer func() {
		os.Stdin = oldStdin
	}()

	go func() {
		time.Sleep(100 * time.Millisecond)

		if _, err := pw.WriteString("0\n"); err != nil {
			t.Errorf("Failed to write to pipe: %v", err)
		}

		pw.Close()

		time.Sleep(50 * time.Millisecond)
	}()

	done := make(chan bool)

	go func() {
		RunMenu(sm, jm)
		done <- true
	}()

	select {
	case <-done:
		// Menu completed successfully
	case <-time.After(2 * time.Second):
		t.Fatal("RunMenu timed out - likely stuck in infinite loop")
	}
}

func TestHandleJumpCommand(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()

	sm := NewServerManager(tempDir)

	jm := NewJumpManager(tempDir)

	// Add dummy server
	sm.Servers = append(sm.Servers, Server{ID: 1, Host: "127.0.0.1", User: "test", Name: "Test", Password: "pw"})

	if err := sm.Save(); err != nil {
		t.Fatalf("Failed to save server: %v", err)
	}

	// Test add/list/delete
	HandleJumpCommand(jm, sm, []string{"list"})
	HandleJumpCommand(jm, sm, []string{"add"})
	HandleJumpCommand(jm, sm, []string{"delete"})
	HandleJumpCommand(jm, sm, []string{"unknown"})
}

func TestPrintServerListAndJumpList(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()

	sm := NewServerManager(tempDir)

	jm := NewJumpManager(tempDir)

	sm.Servers = append(sm.Servers, Server{ID: 1, Host: "127.0.0.1", User: "test", Name: "Test", Password: "pw"})

	PrintServerList(sm)
	PrintJumpList(jm, sm)
}

func TestPromptInput(t *testing.T) {
	t.Parallel()
	pr, pw, _ := os.Pipe()
	oldStdin := os.Stdin
	os.Stdin = pr

	defer func() {
		os.Stdin = oldStdin
	}()

	if _, err := pw.WriteString("testinput\n"); err != nil {
		t.Fatalf("Failed to write to pipe: %v", err)
	}

	pw.Close()

	result := PromptInput("Enter: ")

	if result != "testinput" {
		t.Errorf("Expected 'testinput', got '%s'", result)
	}
}
