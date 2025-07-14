package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

// Version information (injected during build)
var Version = "1.3.7"

// SSHift ASCII Art Logo
const SSHiftLogo = `
              __    _ ______
   __________/ /_  (_) __/ /_______________________
  / ___/ ___/ __ \/ / /_/ __/________________
 (__  |__  ) / / / / __/ /_____________
/____/____/_/ /_/_/_/  \__/______
`

// ANSI color codes
const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
)

// Security constants
const (
	MinKeyLength      = 32
	MaxKeyLength      = 64
	SaltLength        = 32
	Iterations        = 100000 // PBKDF2 iterations
	MinPasswordLength = 1      // Allow any non-empty password for existing server accounts
	MaxPasswordLength = 128
	MaxHostLength     = 255
	MaxUserLength     = 64
	MaxNameLength     = 100
	YesResponse       = "y"
	YesResponseFull   = "yes"
)

// File permission constants
const (
	FilePermOwnerOnly   = 0600
	SSHKeyPermOwnerOnly = 0400 // Allow 400 (read-only) for SSH keys
	DirPermOwnerOnly    = 0700
	DirPermStandard     = 0755
)

// SSH and terminal constants
const (
	SSHTimeoutSeconds = 30
	TTYISpeed         = 14400
	TTYOSpeed         = 14400
	TTYRows           = 40
	TTYCols           = 80
	MinServersForJump = 2
)

// SecureString provides secure string handling with automatic memory clearing
type SecureString struct {
	data []byte
}

// NewSecureString creates a new secure string
func NewSecureString(s string) *SecureString {
	return &SecureString{data: []byte(s)}
}

// String returns the string value (use with caution)
func (ss *SecureString) String() string {
	return string(ss.data)
}

// Bytes returns a copy of the underlying bytes
func (ss *SecureString) Bytes() []byte {
	result := make([]byte, len(ss.data))
	copy(result, ss.data)

	return result
}

// Clear securely clears the string from memory
func (ss *SecureString) Clear() {
	if ss.data != nil {
		// Use runtime.memclr for secure clearing
		for i := range ss.data {
			ss.data[i] = 0
		}

		ss.data = nil
	}
}

// SecureBytes provides secure byte slice handling
type SecureBytes struct {
	data []byte
}

// NewSecureBytes creates a new secure byte slice
func NewSecureBytes(b []byte) *SecureBytes {
	result := make([]byte, len(b))
	copy(result, b)

	return &SecureBytes{data: result}
}

// Bytes returns a copy of the underlying bytes
func (sb *SecureBytes) Bytes() []byte {
	result := make([]byte, len(sb.data))
	copy(result, sb.data)

	return result
}

// Clear securely clears the bytes from memory
func (sb *SecureBytes) Clear() {
	if sb.data != nil {
		for i := range sb.data {
			sb.data[i] = 0
		}

		sb.data = nil
	}
}

// Color functions
func colorize(color, text string) string {
	return color + text + Reset
}

func success(text string) string {
	return colorize(Green+Bold, "✅  "+text)
}

func errorMsg(text string) string {
	return colorize(Red+Bold, "❌  "+text)
}

func warning(text string) string {
	return colorize(Yellow+Bold, "⚠️  "+text)
}

func info(text string) string {
	return colorize(Cyan+Bold, "ℹ️  "+text)
}

func prompt(text string) string {
	return colorize(Blue+Bold, "🔍  "+text)
}

func serverName(text string) string {
	return colorize(Magenta, text)
}

func jump(text string) string {
	return colorize(Yellow, text)
}

// getSystemEntropy generates system-specific entropy for key generation
func getSystemEntropy() ([]byte, error) {
	var entropy []byte

	// Get home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	entropy = append(entropy, []byte(homeDir)...)

	// Get current user
	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %w", err)
	}

	entropy = append(entropy, []byte(currentUser.Username)...)
	entropy = append(entropy, []byte(currentUser.Uid)...)

	// Get environment variables
	entropy = append(entropy, []byte(os.Getenv("USER"))...)
	entropy = append(entropy, []byte(os.Getenv("HOME"))...)
	entropy = append(entropy, []byte(os.Getenv("HOSTNAME"))...)

	// Get system information
	entropy = append(entropy, []byte(runtime.GOOS)...)
	entropy = append(entropy, []byte(runtime.GOARCH)...)

	// Use fixed salt for consistent key generation on same system
	// This ensures the same key is generated every time on the same system
	fixedSalt := []byte("SSHift-System-Key-Salt-v1")
	entropy = append(entropy, fixedSalt...)

	return entropy, nil
}

// getEncryptionKey returns the encryption key from environment or generates a secure system-specific key
func getEncryptionKey() ([]byte, error) {
	// Check for custom encryption key in environment
	envKey := os.Getenv("SSHIFT_ENCRYPTION_KEY")
	if envKey != "" {
		if len(envKey) < MinKeyLength {
			return nil, fmt.Errorf("environment key too short, minimum %d characters required", MinKeyLength)
		}

		if len(envKey) > MaxKeyLength {
			return nil, fmt.Errorf("environment key too long, maximum %d characters allowed", MaxKeyLength)
		}
		// Use SHA-256 to ensure consistent 32-byte key
		hash := sha256.Sum256([]byte(envKey))

		return hash[:], nil
	}

	// Generate system-specific key with high entropy
	entropy, err := getSystemEntropy()
	if err != nil {
		return nil, fmt.Errorf("failed to generate system entropy: %w", err)
	}

	// Use SHA-256 to generate a proper 32-byte key
	hash := sha256.Sum256(entropy)

	// Clear sensitive data from memory
	for i := range entropy {
		entropy[i] = 0
	}

	return hash[:], nil
}

// EncryptPassword encrypts a password using AES with secure memory handling
func EncryptPassword(password string) (string, error) {
	// Create secure string wrapper
	securePass := NewSecureString(password)
	defer securePass.Clear()

	// Get encryption key
	key, err := getEncryptionKey()
	if err != nil {
		return "", fmt.Errorf("failed to get encryption key: %w", err)
	}

	defer func() {
		// Clear key from memory
		for i := range key {
			key[i] = 0
		}
	}()

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Prepare ciphertext with IV
	plaintext := securePass.Bytes()
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	// Generate random IV
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %w", err)
	}

	// Encrypt
	// SECURITY: Using CTR mode (more secure than deprecated CFB)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// Encode to base64
	result := base64.URLEncoding.EncodeToString(ciphertext)

	// Clear sensitive data
	for i := range plaintext {
		plaintext[i] = 0
	}

	for i := range ciphertext {
		ciphertext[i] = 0
	}

	return result, nil
}

// DecryptPassword decrypts an encrypted password with secure memory handling
func DecryptPassword(encryptedPassword string) (string, error) {
	// Get encryption key
	key, err := getEncryptionKey()
	if err != nil {
		return "", fmt.Errorf("failed to get encryption key: %w", err)
	}

	defer func() {
		// Clear key from memory
		for i := range key {
			key[i] = 0
		}
	}()

	// Decode from base64
	ciphertext, err := base64.URLEncoding.DecodeString(encryptedPassword)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	defer func() {
		// Clear ciphertext from memory
		for i := range ciphertext {
			ciphertext[i] = 0
		}
	}()

	// Validate ciphertext length
	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Extract IV and ciphertext
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// Decrypt
	// SECURITY: Using CTR mode (more secure than deprecated CFB)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	// Convert to string
	result := string(ciphertext)

	return result, nil
}

type Server struct {
	ID       int    `json:"id"`
	Host     string `json:"host"`
	User     string `json:"user"`
	Name     string `json:"name"`
	Password string `json:"password,omitempty"`
	KeyPath  string `json:"key_path,omitempty"`
}

// ValidateServer validates server configuration
func (s *Server) Validate() error {
	// Validate host
	if s.Host == "" {
		return fmt.Errorf("host cannot be empty")
	}

	if len(s.Host) > MaxHostLength {
		return fmt.Errorf("host too long, maximum %d characters allowed", MaxHostLength)
	}

	// Basic host format validation
	if strings.Contains(s.Host, "://") {
		return fmt.Errorf("host should not include protocol (e.g., ssh://)")
	}

	// Validate user
	if s.User == "" {
		return fmt.Errorf("user cannot be empty")
	}

	if len(s.User) > MaxUserLength {
		return fmt.Errorf("user too long, maximum %d characters allowed", MaxUserLength)
	}

	// Validate user format (basic)
	if strings.ContainsAny(s.User, ":/\\") {
		return fmt.Errorf("user contains invalid characters")
	}

	// Validate name
	if s.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	if len(s.Name) > MaxNameLength {
		return fmt.Errorf("name too long, maximum %d characters allowed", MaxNameLength)
	}

	// Validate authentication
	if s.Password == "" && s.KeyPath == "" {
		return fmt.Errorf("either password or key_path must be provided")
	}

	// Validate password if provided
	if s.Password != "" {
		// Note: Password is encrypted, so we can't validate length here
		// Length validation should be done during input
		// This block intentionally left empty as validation is done during input
		_ = s.Password // Use the variable to avoid unused variable warning
	}

	// Validate key path if provided
	if s.KeyPath != "" {
		if _, err := os.Stat(s.KeyPath); os.IsNotExist(err) {
			return fmt.Errorf("SSH key file does not exist: %s", s.KeyPath)
		}

		// Check file permissions
		if info, err := os.Stat(s.KeyPath); err == nil {
			mode := info.Mode()
			if mode.Perm() != SSHKeyPermOwnerOnly {
				return fmt.Errorf("SSH key file has loose permissions (%s), should be 400", mode.String())
			}
		}
	}

	return nil
}

// findSSHKeys finds all available SSH private keys in the given directory
func findSSHKeys(sshDir string) ([]string, error) {
	var keys []string

	// Validate SSH directory
	if sshDir == "" {
		return nil, fmt.Errorf("SSH directory path is empty")
	}

	// Check if directory exists
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("SSH directory does not exist: %s", sshDir)
	}

	// Common SSH key filenames (private keys only)
	keyNames := []string{"id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"}

	for _, keyName := range keyNames {
		keyPath := filepath.Join(sshDir, keyName)
		if _, err := os.Stat(keyPath); err == nil {
			// Validate file permissions (should be 400 or 600)
			if info, err := os.Stat(keyPath); err == nil {
				mode := info.Mode()
				if mode.Perm() != SSHKeyPermOwnerOnly {
					fmt.Printf(warning("Warning: SSH key %s has loose permissions (%s)\n"), keyPath, mode.String())
				}
			}

			keys = append(keys, keyPath)
		}
	}

	// Also look for other private key files (not starting with id_)
	files, err := os.ReadDir(sshDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH directory: %w", err)
	}

	for _, file := range files {
		if !file.IsDir() && !strings.HasSuffix(file.Name(), ".pub") &&
			!strings.HasPrefix(file.Name(), "id_") &&
			!strings.HasPrefix(file.Name(), "known_hosts") &&
			!strings.HasPrefix(file.Name(), "config") {
			keyPath := filepath.Join(sshDir, file.Name())

			// Validate file permissions (should be 400 or 600)
			if info, err := os.Stat(keyPath); err == nil {
				mode := info.Mode()
				if mode.Perm() != SSHKeyPermOwnerOnly {
					fmt.Printf(warning("Warning: SSH key %s has loose permissions (%s)\n"), keyPath, mode.String())
				}
			}

			keys = append(keys, keyPath)
		}
	}

	return keys, nil
}

// getAuthType returns a human-readable authentication type for a server
func getAuthType(server Server) string {
	if server.Password != "" {
		return "Password"
	} else if server.KeyPath != "" {
		return fmt.Sprintf("SSH Key (%s)", filepath.Base(server.KeyPath))
	} else {
		return "Not configured"
	}
}

// GetDecryptedPassword returns the decrypted password and clears it from memory after use
func (s *Server) GetDecryptedPassword() (string, error) {
	if s.Password == "" {
		return "", nil
	}

	decrypted, err := DecryptPassword(s.Password)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt password: %w", err)
	}

	return decrypted, nil
}

type ServerManager struct {
	filePath string
	Servers  []Server
}

func NewServerManager(baseDir string) *ServerManager {
	filePath := filepath.Join(baseDir, "servers.json")
	sm := &ServerManager{filePath: filePath}
	sm.Load()

	return sm
}

func (sm *ServerManager) Load() {
	file, err := os.ReadFile(sm.filePath)
	if err != nil {
		sm.Servers = []Server{}
		return
	}

	if err := json.Unmarshal(file, &sm.Servers); err != nil {
		fmt.Printf("Failed to unmarshal server data: %v\n", err)

		sm.Servers = []Server{}
	}
}

func (sm *ServerManager) Save() error {
	data, err := json.MarshalIndent(sm.Servers, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal servers data: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(sm.filePath)
	if err := os.MkdirAll(dir, DirPermOwnerOnly); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write file with secure permissions
	if err := os.WriteFile(sm.filePath, data, FilePermOwnerOnly); err != nil {
		return fmt.Errorf("failed to write servers file: %w", err)
	}

	return nil
}

func (sm *ServerManager) Add(s Server) error {
	// Validate server configuration
	if err := s.Validate(); err != nil {
		return fmt.Errorf("invalid server configuration: %w", err)
	}

	s.ID = sm.nextID()

	sm.Servers = append(sm.Servers, s)
	if err := sm.Save(); err != nil {
		return fmt.Errorf("failed to save after add: %w", err)
	}

	return nil
}

func (sm *ServerManager) AddWithID(s Server, id int) error {
	// Validate server configuration
	if err := s.Validate(); err != nil {
		return fmt.Errorf("invalid server configuration: %w", err)
	}

	// Check if ID already exists
	if _, exists := sm.GetByID(id); exists {
		return fmt.Errorf("server with ID %d already exists", id)
	}

	// Validate ID
	if id <= 0 {
		return fmt.Errorf("invalid server ID: %d (must be positive)", id)
	}

	s.ID = id

	sm.Servers = append(sm.Servers, s)
	if err := sm.Save(); err != nil {
		return fmt.Errorf("failed to save after addWithID: %w", err)
	}

	return nil
}

func (sm *ServerManager) UpdateServerID(oldID, newID int, jm *JumpManager) error {
	// Validate new ID
	if newID <= 0 {
		return fmt.Errorf("invalid server ID: %d (must be positive)", newID)
	}

	// Check if new ID already exists (except for the current server)
	if _, exists := sm.GetByID(newID); exists && newID != oldID {
		return fmt.Errorf("server with ID %d already exists", newID)
	}

	// Find server with old ID
	serverIndex := -1

	for i, s := range sm.Servers {
		if s.ID == oldID {
			serverIndex = i
			break
		}
	}

	if serverIndex == -1 {
		return fmt.Errorf("server with ID %d not found", oldID)
	}

	// Update server ID
	oldServerID := sm.Servers[serverIndex].ID
	sm.Servers[serverIndex].ID = newID

	// Update jump relations if JumpManager is provided
	if jm != nil && oldID != newID {
		// Create new graph with updated ID
		newGraph := NewJumpGraph()

		// Copy all existing relations, updating the specific server ID
		for fromID, targets := range jm.Graph.AdjacencyList {
			newFromID := fromID
			if fromID == oldID {
				newFromID = newID
			}

			for _, toID := range targets {
				newToID := toID
				if toID == oldID {
					newToID = newID
				}

				// Add the relation with updated IDs
				if err := newGraph.AddJump(newFromID, newToID); err != nil {
					return fmt.Errorf("failed to update jump relation: %w", err)
				}
			}
		}

		// Update the graph
		jm.Graph = newGraph
		if err := jm.Save(); err != nil {
			return fmt.Errorf("failed to save after UpdateServerID: %w", err)
		}

		fmt.Printf("🔄 Updated jump relations: server ID %d → %d\n", oldServerID, newID)
	}

	// Save server changes
	if err := sm.Save(); err != nil {
		return fmt.Errorf("failed to save after UpdateServerID: %w", err)
	}

	return nil
}

func (sm *ServerManager) nextID() int {
	// Create a set of existing IDs for efficient lookup
	existingIDs := make(map[int]bool)
	for _, s := range sm.Servers {
		existingIDs[s.ID] = true
	}

	// Find the smallest available ID starting from 1
	for id := 1; ; id++ {
		if !existingIDs[id] {
			return id
		}
	}
}

func (sm *ServerManager) GetByID(id int) (Server, bool) {
	for _, s := range sm.Servers {
		if s.ID == id {
			return s, true
		}
	}

	return Server{}, false
}

func (sm *ServerManager) DeleteByID(id int, jm *JumpManager) error {
	for i, s := range sm.Servers {
		if s.ID == id {
			sm.Servers = append(sm.Servers[:i], sm.Servers[i+1:]...)
			if err := sm.Save(); err != nil {
				return fmt.Errorf("failed to save after deletion: %w", err)
			}

			// Delete all jump relations involving this server
			if jm != nil {
				deletedRelations := jm.DeleteAllRelationsForServer(id)
				if deletedRelations > 0 {
					fmt.Printf("🗑️  Also deleted %d jump relation(s) involving server %d\n", deletedRelations, id)
				}
			}

			return nil
		}
	}

	return fmt.Errorf("server with ID %d not found", id)
}

type JumpRelation struct {
	FromID int `json:"from_id"`
	ToID   int `json:"to_id"`
}

// JumpGraph represents a graph structure for jump relationships
type JumpGraph struct {
	AdjacencyList map[int][]int `json:"adjacency_list"` // server_id -> []target_ids
	ReverseList   map[int][]int `json:"reverse_list"`   // server_id -> []source_ids (for reverse lookup)
}

// NewJumpGraph creates a new empty jump graph
func NewJumpGraph() *JumpGraph {
	return &JumpGraph{
		AdjacencyList: make(map[int][]int),
		ReverseList:   make(map[int][]int),
	}
}

// AddJump adds a jump relation to the graph
func (jg *JumpGraph) AddJump(fromID, toID int) error {
	// Validate IDs
	if fromID <= 0 || toID <= 0 {
		return fmt.Errorf("invalid server IDs: fromID=%d, toID=%d", fromID, toID)
	}

	if fromID == toID {
		return fmt.Errorf("cannot create jump relation to same server: %d", fromID)
	}

	// Check if relation already exists
	if jg.HasJump(fromID, toID) {
		return nil // Relation already exists
	}

	// Check for circular references using DFS
	if jg.wouldCreateCycle(fromID, toID) {
		return fmt.Errorf("circular jump relation detected: %d ↔ %d", fromID, toID)
	}

	// Add to adjacency list
	jg.AdjacencyList[fromID] = append(jg.AdjacencyList[fromID], toID)

	// Add to reverse list for efficient lookup
	jg.ReverseList[toID] = append(jg.ReverseList[toID], fromID)

	return nil
}

// HasJump checks if a jump relation exists
func (jg *JumpGraph) HasJump(fromID, toID int) bool {
	targets, exists := jg.AdjacencyList[fromID]
	if !exists {
		return false
	}

	for _, target := range targets {
		if target == toID {
			return true
		}
	}

	return false
}

// GetJumpTargets returns all direct jump targets for a server
func (jg *JumpGraph) GetJumpTargets(fromID int) []int {
	return jg.AdjacencyList[fromID]
}

// GetJumpSources returns all servers that can jump to the given server
func (jg *JumpGraph) GetJumpSources(toID int) []int {
	return jg.ReverseList[toID]
}

// GetDirectJumpTarget returns the first direct jump target (for backward compatibility)
func (jg *JumpGraph) GetDirectJumpTarget(fromID int) (int, bool) {
	targets := jg.GetJumpTargets(fromID)
	if len(targets) > 0 {
		return targets[0], true
	}

	return 0, false
}

// GetDirectJumpSource returns the first server that can jump to the given server (for backward compatibility)
func (jg *JumpGraph) GetDirectJumpSource(toID int) (int, bool) {
	sources := jg.GetJumpSources(toID)
	if len(sources) > 0 {
		return sources[0], true
	}

	return 0, false
}

// DeleteJump removes a specific jump relation
func (jg *JumpGraph) DeleteJump(fromID, toID int) error {
	// Remove from adjacency list
	if targets, exists := jg.AdjacencyList[fromID]; exists {
		var newTargets []int

		for _, target := range targets {
			if target != toID {
				newTargets = append(newTargets, target)
			}
		}

		if len(newTargets) == 0 {
			delete(jg.AdjacencyList, fromID)
		} else {
			jg.AdjacencyList[fromID] = newTargets
		}
	}

	// Remove from reverse list
	if sources, exists := jg.ReverseList[toID]; exists {
		var newSources []int

		for _, source := range sources {
			if source != fromID {
				newSources = append(newSources, source)
			}
		}

		if len(newSources) == 0 {
			delete(jg.ReverseList, toID)
		} else {
			jg.ReverseList[toID] = newSources
		}
	}

	return nil
}

// DeleteAllJumpsForServer removes all jump relations involving the given server
func (jg *JumpGraph) DeleteAllJumpsForServer(serverID int) int {
	deletedCount := 0

	// Remove all outgoing jumps
	if targets, exists := jg.AdjacencyList[serverID]; exists {
		for _, target := range targets {
			// Remove from reverse list
			if sources, exists := jg.ReverseList[target]; exists {
				var newSources []int

				for _, source := range sources {
					if source != serverID {
						newSources = append(newSources, source)
					}
				}

				if len(newSources) == 0 {
					delete(jg.ReverseList, target)
				} else {
					jg.ReverseList[target] = newSources
				}
			}

			deletedCount++
		}

		delete(jg.AdjacencyList, serverID)
	}

	// Remove all incoming jumps
	if sources, exists := jg.ReverseList[serverID]; exists {
		for _, source := range sources {
			// Remove from adjacency list
			if targets, exists := jg.AdjacencyList[source]; exists {
				var newTargets []int

				for _, target := range targets {
					if target != serverID {
						newTargets = append(newTargets, target)
					}
				}

				if len(newTargets) == 0 {
					delete(jg.AdjacencyList, source)
				} else {
					jg.AdjacencyList[source] = newTargets
				}
			}

			deletedCount++
		}

		delete(jg.ReverseList, serverID)
	}

	return deletedCount
}

// wouldCreateCycle checks if adding a jump relation would create a cycle
func (jg *JumpGraph) wouldCreateCycle(fromID, toID int) bool {
	// Use DFS to check if there's a path from toID back to fromID
	visited := make(map[int]bool)
	return jg.dfsHasPath(toID, fromID, visited)
}

// dfsHasPath performs DFS to check if there's a path from start to target
func (jg *JumpGraph) dfsHasPath(start, target int, visited map[int]bool) bool {
	if start == target {
		return true
	}

	visited[start] = true

	for _, neighbor := range jg.AdjacencyList[start] {
		if !visited[neighbor] {
			if jg.dfsHasPath(neighbor, target, visited) {
				return true
			}
		}
	}

	return false
}

// FindPath finds a path from source to target using BFS
func (jg *JumpGraph) FindPath(source, target int) ([]int, bool) {
	if source == target {
		return []int{source}, true
	}

	queue := [][]int{{source}}
	visited := make(map[int]bool)
	visited[source] = true

	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		current := path[len(path)-1]

		for _, neighbor := range jg.AdjacencyList[current] {
			if neighbor == target {
				return append(path, neighbor), true
			}

			if !visited[neighbor] {
				visited[neighbor] = true
				newPath := make([]int, len(path))
				copy(newPath, path)
				queue = append(queue, append(newPath, neighbor))
			}
		}
	}

	return nil, false
}

// GetAllPaths finds all possible paths from source to target
func (jg *JumpGraph) GetAllPaths(source, target int) [][]int {
	var paths [][]int

	visited := make(map[int]bool)

	jg.dfsFindAllPaths(source, target, []int{source}, visited, &paths)

	return paths
}

// dfsFindAllPaths performs DFS to find all paths from source to target
func (jg *JumpGraph) dfsFindAllPaths(current, target int, path []int, visited map[int]bool, paths *[][]int) {
	if current == target {
		newPath := make([]int, len(path))
		copy(newPath, path)
		*paths = append(*paths, newPath)

		return
	}

	visited[current] = true

	for _, neighbor := range jg.AdjacencyList[current] {
		if !visited[neighbor] {
			jg.dfsFindAllPaths(neighbor, target, append(path, neighbor), visited, paths)
		}
	}

	visited[current] = false // Backtrack
}

// GetJumpCount returns the total number of jump relations
func (jg *JumpGraph) GetJumpCount() int {
	count := 0
	for _, targets := range jg.AdjacencyList {
		count += len(targets)
	}

	return count
}

// GetServerCount returns the number of servers involved in jump relations
func (jg *JumpGraph) GetServerCount() int {
	servers := make(map[int]bool)

	for serverID := range jg.AdjacencyList {
		servers[serverID] = true
	}

	for serverID := range jg.ReverseList {
		servers[serverID] = true
	}

	return len(servers)
}

type JumpManager struct {
	filePath string
	Graph    *JumpGraph
}

func NewJumpManager(baseDir string) *JumpManager {
	filePath := filepath.Join(baseDir, "jumps.json")
	jm := &JumpManager{filePath: filePath, Graph: NewJumpGraph()}
	jm.Load()

	return jm
}

func (jm *JumpManager) Load() {
	file, err := os.ReadFile(jm.filePath)
	if err != nil {
		jm.Graph = NewJumpGraph()
		return
	}

	// Try to load as new graph format first
	var graph JumpGraph
	if err := json.Unmarshal(file, &graph); err == nil {
		jm.Graph = &graph
		return
	}

	// Fallback to old format for backward compatibility
	var oldRelations []JumpRelation
	if err := json.Unmarshal(file, &oldRelations); err != nil {
		jm.Graph = NewJumpGraph()
		return
	}

	// Convert old format to new graph format
	jm.Graph = NewJumpGraph()
	for _, relation := range oldRelations {
		if err := jm.Graph.AddJump(relation.FromID, relation.ToID); err != nil {
			fmt.Printf("Error adding jump relation %d -> %d: %v\n", relation.FromID, relation.ToID, err)
			continue
		}
	}
}

func (jm *JumpManager) Save() error {
	data, err := json.MarshalIndent(jm.Graph, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal jump graph data: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(jm.filePath)
	if err := os.MkdirAll(dir, DirPermOwnerOnly); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write file with secure permissions
	if err := os.WriteFile(jm.filePath, data, FilePermOwnerOnly); err != nil {
		return fmt.Errorf("failed to write jump graph file: %w", err)
	}

	return nil
}

func (jm *JumpManager) Add(fromID, toID int) error {
	err := jm.Graph.AddJump(fromID, toID)
	if err != nil {
		return err
	}

	if err := jm.Save(); err != nil {
		return fmt.Errorf("failed to save after AddJump: %w", err)
	}

	return nil
}

func (jm *JumpManager) Delete(fromID int) error {
	// Get all targets for this server
	targets := jm.Graph.GetJumpTargets(fromID)
	if len(targets) == 0 {
		return fmt.Errorf("no jump relation found for server %d", fromID)
	}

	// Delete all outgoing jumps
	for _, target := range targets {
		if err := jm.Graph.DeleteJump(fromID, target); err != nil {
			return fmt.Errorf("failed to delete jump %d -> %d: %w", fromID, target, err)
		}
	}

	if err := jm.Save(); err != nil {
		return fmt.Errorf("failed to save after DeleteJump: %w", err)
	}

	return nil
}

// DeleteAllRelationsForServer removes all jump relations involving the given server
func (jm *JumpManager) DeleteAllRelationsForServer(serverID int) int {
	deletedCount := jm.Graph.DeleteAllJumpsForServer(serverID)

	if err := jm.Save(); err != nil {
		fmt.Printf("Error saving jump data: %v\n", err)
	}

	return deletedCount
}

func (jm *JumpManager) GetJumpTarget(fromID int) (int, bool) {
	return jm.Graph.GetDirectJumpTarget(fromID)
}

func (jm *JumpManager) GetJumpFrom(toID int) (int, bool) {
	return jm.Graph.GetDirectJumpSource(toID)
}

// New methods for graph functionality
func (jm *JumpManager) GetJumpTargets(fromID int) []int {
	return jm.Graph.GetJumpTargets(fromID)
}

func (jm *JumpManager) GetJumpSources(toID int) []int {
	return jm.Graph.GetJumpSources(toID)
}

func (jm *JumpManager) FindPath(source, target int) ([]int, bool) {
	return jm.Graph.FindPath(source, target)
}

func (jm *JumpManager) GetAllPaths(source, target int) [][]int {
	return jm.Graph.GetAllPaths(source, target)
}

func (jm *JumpManager) GetJumpCount() int {
	return jm.Graph.GetJumpCount()
}

func (jm *JumpManager) GetServerCount() int {
	return jm.Graph.GetServerCount()
}

func HandleJumpCommand(jm *JumpManager, sm *ServerManager, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: sshift jump add | delete <fromID> | list")
		return
	}

	switch args[0] {
	case "add":
		// Interactive jump setup
		PromptAddJump(jm, sm)
	case "delete":
		PromptDeleteJump(jm, sm)
	case "list":
		PrintJumpList(jm, sm)
	default:
		fmt.Println("Unknown jump command")
	}
}

func PromptInput(prompt string) string {
	fmt.Print(prompt)

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	input := strings.TrimSpace(scanner.Text())

	// Basic input sanitization
	input = strings.ReplaceAll(input, "\x00", "") // Remove null bytes
	input = strings.ReplaceAll(input, "\r", "")   // Remove carriage returns

	return input
}

// PromptInputSecure prompts for sensitive input (like passwords) with additional security
func PromptInputSecure(prompt string) (string, error) {
	fmt.Print(prompt)

	// Platform-specific stdin handling
	var bytePassword []byte
	var err error

	// Platform-specific stdin handling
	bytePassword, err = term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	fmt.Println() // Add newline after password input
	return string(bytePassword), nil
}

func PromptAddServer(sm *ServerManager) {
	// Show current servers for reference
	if len(sm.Servers) > 0 {
		fmt.Println("\nCurrent servers:")
		PrintServerList(sm)
		fmt.Println()
	}

	// Prompt for server ID
	nextAutoID := sm.nextID()
	idInput := PromptInput(prompt(fmt.Sprintf("Enter server ID [%d] (press Enter for auto-increment): ", nextAutoID)))

	var serverID int

	var err error

	if idInput == "" {
		// Auto-increment
		serverID = nextAutoID
		fmt.Printf("✅ Using auto-increment ID: %d\n", serverID)
	} else {
		// Manual ID
		serverID, err = strconv.Atoi(idInput)
		if err != nil {
			fmt.Printf("❌ Invalid server ID: %s\n", idInput)
			return
		}

		// Check if ID already exists
		if _, exists := sm.GetByID(serverID); exists {
			fmt.Printf("❌ Server with ID %d already exists\n", serverID)
			return
		}

		if serverID <= 0 {
			fmt.Printf("❌ Server ID must be positive: %d\n", serverID)
			return
		}

		fmt.Printf("✅ Using manual ID: %d\n", serverID)
	}

	host := PromptInput("Enter host (IP or domain): ")
	user := PromptInput("Enter username: ")
	name := PromptInput("Enter server name: ")
	usePassword := PromptInput("Use password? (y/n): ")

	var password string

	var keyPath string

	if strings.EqualFold(usePassword, YesResponse) || strings.EqualFold(usePassword, YesResponseFull) {
		password, err = PromptInputSecure("Enter password: ")
		if err != nil {
			fmt.Printf("❌ Error reading password: %v\n", err)
			return
		}

		// Confirm password
		passwordConfirm, err := PromptInputSecure("Confirm password: ")
		if err != nil {
			fmt.Printf("❌ Error reading password confirmation: %v\n", err)
			return
		}

		// Check if passwords match
		if password != passwordConfirm {
			fmt.Println("❌ Passwords do not match. Please try again.")
			return
		}

		fmt.Println("✅ Passwords match!")
	} else {
		fmt.Println("Using SSH key authentication.")

		keyPath = promptForSSHKey()
		if keyPath == "" {
			return
		}
	}

	// Encrypt password if provided
	encryptedPassword := ""

	if password != "" {
		encrypted, err := EncryptPassword(password)
		if err != nil {
			fmt.Printf("❌ Error encrypting password: %v\n", err)
			return
		}

		encryptedPassword = encrypted
	}

	server := Server{
		Host:     host,
		User:     user,
		Name:     name,
		Password: encryptedPassword,
		KeyPath:  keyPath,
	}

	// Add server with the specified ID
	if idInput == "" {
		// Auto-increment
		if err := sm.Add(server); err != nil {
			fmt.Printf("❌ Failed to add server: %v\n", err)
			return
		}
	} else {
		// Manual ID
		if err := sm.AddWithID(server, serverID); err != nil {
			fmt.Printf("❌ Failed to add server: %v\n", err)
			return
		}
	}

	fmt.Printf("✅ Added server: %s (ID: %d, %s@%s)\n", name, serverID, user, host)
}

func PromptAddJump(jm *JumpManager, sm *ServerManager) {
	if len(sm.Servers) < MinServersForJump {
		fmt.Println("❌ Need at least 2 servers to create a jump relation.")
		return
	}

	fmt.Println("\nAvailable servers:")
	PrintServerList(sm)

	fmt.Println()

	fromInput := PromptInput(prompt("Select FROM server ID: "))

	fromID, err := strconv.Atoi(fromInput)
	if err != nil {
		fmt.Println("❌ Invalid server ID")
		return
	}

	fromServer, found := sm.GetByID(fromID)
	if !found {
		fmt.Printf("❌ Server %d not found\n", fromID)
		return
	}

	toInput := PromptInput(prompt("Select TO server ID: "))

	toID, err := strconv.Atoi(toInput)
	if err != nil {
		fmt.Println("❌ Invalid server ID")
		return
	}

	toServer, found := sm.GetByID(toID)
	if !found {
		fmt.Printf("❌ Server %d not found\n", toID)
		return
	}

	if fromID == toID {
		fmt.Println("❌ Cannot jump to the same server")
		return
	}

	if err := jm.Add(fromID, toID); err != nil {
		fmt.Printf("❌ Failed to create jump relation: %v\n", err)
		return
	}

	fmt.Printf("✅ Jump relation created: %s (%d) → %s (%d)\n",
		fromServer.Name, fromID, toServer.Name, toID)
}

func PromptDeleteJump(jm *JumpManager, sm *ServerManager) {
	if jm.Graph.GetJumpCount() == 0 {
		fmt.Println("No jump relations to delete.")
		return
	}

	fmt.Println("\nAvailable jump relations:")
	PrintJumpList(jm, sm)

	fromInput := PromptInput(prompt("Enter FROM server ID: "))

	fromID, err := strconv.Atoi(fromInput)
	if err != nil {
		fmt.Println("❌ Invalid server ID")
		return
	}

	toInput := PromptInput(prompt("Enter TO server ID: "))

	toID, err := strconv.Atoi(toInput)
	if err != nil {
		fmt.Println("❌ Invalid server ID")
		return
	}

	// Check if jump relation exists
	if !jm.Graph.HasJump(fromID, toID) {
		fmt.Printf("❌ Jump relation %d → %d does not exist\n", fromID, toID)
		return
	}

	// Get server info for confirmation
	fromServer, fromFound := sm.GetByID(fromID)
	toServer, toFound := sm.GetByID(toID)

	if fromFound && toFound {
		confirm := PromptInput(fmt.Sprintf("Are you sure you want to delete jump relation '%s' (%d) → '%s' (%d)? (y/n): ",
			fromServer.Name, fromID, toServer.Name, toID))

		if strings.EqualFold(confirm, "y") || strings.EqualFold(confirm, "yes") {
			if err := jm.Graph.DeleteJump(fromID, toID); err != nil {
				fmt.Printf("❌ Failed to delete jump relation: %v\n", err)
				return
			}

			if err := jm.Save(); err != nil {
				fmt.Printf("Error saving jump data: %v\n", err)
			}

			fmt.Printf("✅ Jump relation '%s' (%d) → '%s' (%d) deleted\n",
				fromServer.Name, fromID, toServer.Name, toID)
		} else {
			fmt.Println("❌ Deletion cancelled")
		}
	} else {
		confirm := PromptInput(fmt.Sprintf("Are you sure you want to delete jump relation %d → %d? (y/n): ", fromID, toID))

		if strings.EqualFold(confirm, "y") || strings.EqualFold(confirm, "yes") {
			if err := jm.Graph.DeleteJump(fromID, toID); err != nil {
				fmt.Printf("❌ Failed to delete jump relation: %v\n", err)
				return
			}

			if err := jm.Save(); err != nil {
				fmt.Printf("Error saving jump data: %v\n", err)
			}

			fmt.Printf("✅ Jump relation %d → %d deleted\n", fromID, toID)
		} else {
			fmt.Println("❌ Deletion cancelled")
		}
	}
}

func PromptDeleteServer(sm *ServerManager, jm *JumpManager) {
	if len(sm.Servers) == 0 {
		fmt.Println("No servers to delete.")
		return
	}

	fmt.Println("\nAvailable servers:")
	PrintServerList(sm)

	fmt.Println()

	serverInput := PromptInput(prompt("Enter server ID to delete: "))

	serverID, err := strconv.Atoi(serverInput)
	if err != nil {
		fmt.Println("❌ Invalid server ID")
		return
	}

	// Check if server exists
	server, found := sm.GetByID(serverID)
	if !found {
		fmt.Printf("❌ Server %d not found\n", serverID)
		return
	}

	// Confirm deletion
	confirm := PromptInput(fmt.Sprintf("Are you sure you want to delete '%s' (%s@%s)? (y/n): ",
		server.Name, server.User, server.Host))

	if strings.EqualFold(confirm, "y") || strings.EqualFold(confirm, "yes") {
		if err := sm.DeleteByID(serverID, jm); err != nil {
			fmt.Printf("❌ Failed to delete server: %v\n", err)
			return
		}

		fmt.Printf("✅ Server '%s' (%d) deleted\n", server.Name, serverID)
	} else {
		fmt.Println("❌ Deletion cancelled")
	}
}

func PrintServerList(sm *ServerManager) {
	// Create a copy of servers and sort by ID
	servers := make([]Server, len(sm.Servers))
	copy(servers, sm.Servers)

	// Sort servers by ID
	for i := 0; i < len(servers)-1; i++ {
		for j := i + 1; j < len(servers); j++ {
			if servers[i].ID > servers[j].ID {
				servers[i], servers[j] = servers[j], servers[i]
			}
		}
	}

	// Find the maximum ID width
	maxIDWidth := 2 // Start with minimum width for "0)"

	for _, s := range servers {
		idStr := fmt.Sprintf("%d)", s.ID)
		if len(idStr) > maxIDWidth {
			maxIDWidth = len(idStr)
		}
	}

	// Define column widths
	colWidths := []int{maxIDWidth, 30, 15, 9, 6}

	// Create header
	headerFormat := fmt.Sprintf("%%%ds | %%-%ds | %%-%ds | %%-%ds | %%-%ds",
		colWidths[0], colWidths[1], colWidths[2], colWidths[3], colWidths[4])
	headerLine := fmt.Sprintf(headerFormat, "ID", "SERVER NAME", "IP", "USER", "AUTH")
	fmt.Printf("\n%s\n", headerLine)

	// Create separator line by replacing each character with "-"
	separator := ""

	for _, char := range headerLine {
		if char == '|' {
			separator += "|"
		} else {
			separator += "-"
		}
	}

	fmt.Println(separator)

	// Print servers
	rowFormat := fmt.Sprintf("%%%ds | %%-%ds | %%-%ds | %%-%ds | %%-%ds",
		colWidths[0], colWidths[1], colWidths[2], colWidths[3], colWidths[4])

	for _, s := range servers {
		auth := "Key"
		if s.Password != "" {
			auth = "pass"
		} else if s.KeyPath != "" {
			auth = "pem"
		}

		idStr := fmt.Sprintf("%d)", s.ID)
		fmt.Printf(rowFormat+"\n", idStr, s.Name, s.Host, s.User, auth)
	}

	// Print exit option
	fmt.Printf(rowFormat+"\n", "0)", "Exit", "-", "-", "-")
}

func PrintJumpList(jm *JumpManager, sm *ServerManager) {
	if jm.Graph.GetJumpCount() == 0 {
		fmt.Println("No jump relations configured.")
		return
	}

	// Collect all jump relations and sort them
	type JumpEntry struct {
		FromID  int
		ToID    int
		FromStr string
		ToStr   string
	}

	var jumpEntries []JumpEntry

	// Find the maximum length of server names for proper alignment
	maxFromLength := len("FROM") // Start with header length
	maxToLength := len("TO")     // Start with header length

	// Iterate through all adjacency list entries
	for fromID, targets := range jm.Graph.AdjacencyList {
		for _, toID := range targets {
			fromServer, fromFound := sm.GetByID(fromID)
			toServer, toFound := sm.GetByID(toID)

			if fromFound {
				fromLength := len(fmt.Sprintf("%d) %s", fromID, fromServer.Name))
				if fromLength > maxFromLength {
					maxFromLength = fromLength
				}
			}

			if toFound {
				toLength := len(fmt.Sprintf("%d) %s", toID, toServer.Name))
				if toLength > maxToLength {
					maxToLength = toLength
				}
			}

			// Create jump entry
			fromName := "Not Found"
			toName := "Not Found"

			if fromFound {
				fromName = fromServer.Name
			}

			if toFound {
				toName = toServer.Name
			}

			jumpEntries = append(jumpEntries, JumpEntry{
				FromID:  fromID,
				ToID:    toID,
				FromStr: fmt.Sprintf("%d) %s", fromID, fromName),
				ToStr:   fmt.Sprintf("%d) %s", toID, toName),
			})
		}
	}

	// Sort jump entries by FromID, then by ToID
	for i := 0; i < len(jumpEntries)-1; i++ {
		for j := i + 1; j < len(jumpEntries); j++ {
			if jumpEntries[i].FromID > jumpEntries[j].FromID ||
				(jumpEntries[i].FromID == jumpEntries[j].FromID && jumpEntries[i].ToID > jumpEntries[j].ToID) {
				jumpEntries[i], jumpEntries[j] = jumpEntries[j], jumpEntries[i]
			}
		}
	}

	// Add padding for better alignment
	maxFromLength += 2
	maxToLength += 2

	fmt.Println()
	headerLine := fmt.Sprintf("%-*s | %-*s", maxFromLength, "FROM", maxToLength, "TO")
	fmt.Println(headerLine)

	// Create separator line by replacing each character with "-"
	separator := ""

	for _, char := range headerLine {
		if char == '|' {
			separator += "|"
		} else {
			separator += "-"
		}
	}

	fmt.Println(separator)

	// Print sorted jump entries
	for _, entry := range jumpEntries {
		fmt.Printf("%-*s | %-*s\n", maxFromLength, entry.FromStr, maxToLength, entry.ToStr)
	}

	fmt.Println()
}

func Connect(server Server) {
	// Check if test mode is enabled
	if os.Getenv("SSHIFT_TEST_MODE") == "1" {
		fmt.Printf("🔧 TEST MODE: Would connect to %s@%s\n", server.User, server.Host)
		fmt.Printf("   Server: %s\n", server.Name)

		decryptedPassword, err := server.GetDecryptedPassword()
		if err != nil {
			fmt.Printf("❌ Failed to decrypt password: %v\n", err)
			return
		}

		if decryptedPassword != "" {
			fmt.Printf("   Password: %s\n", strings.Repeat("*", len(decryptedPassword)))
		} else {
			if server.KeyPath != "" {
				fmt.Printf("   Authentication: SSH Key (%s)\n", server.KeyPath)
			} else {
				fmt.Printf("   Authentication: SSH Key (not specified)\n")
			}
		}

		fmt.Println("   Press Enter to continue...")
		bufio.NewScanner(os.Stdin).Scan()

		return
	}

	// Determine authentication method
	decryptedPassword, err := server.GetDecryptedPassword()
	if err != nil {
		fmt.Printf("❌ Failed to decrypt password: %v\n", err)
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()

		return
	}

	if decryptedPassword != "" {
		// Use password authentication
		fmt.Println("🔐 Using password authentication")

		// Try to use sshpass if available
		sshpassCmd := exec.Command("which", "sshpass")
		if sshpassCmd.Run() == nil {
			// sshpass is available, use it for automatic password input
			fmt.Println("   Using sshpass for automatic password input")
			sshArgs := []string{
				"-p", decryptedPassword,
				"ssh", "-o", "StrictHostKeyChecking=no",
			}
			if server.KeyPath != "" {
				sshArgs = append(sshArgs, "-i", server.KeyPath)
			}
			sshArgs = append(sshArgs, fmt.Sprintf("%s@%s", server.User, server.Host))
			cmd := exec.Command("sshpass", sshArgs...)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err = cmd.Run()
			handleSSHError(err, "SSH connection")
			return
		} else {
			// sshpass not available, use expect-like behavior with Go's SSH package
			fmt.Println("   sshpass not available, using interactive password input")
			fmt.Println("   Note: You will be prompted for password")

			// Use Go's SSH package for password authentication
			connectWithPasswordSSH(server)

			return
		}
	} else {
		// Use SSH key authentication
		fmt.Printf("🔐 Using SSH key authentication with key: %s\n", server.KeyPath)
	}

	// Validate user input to prevent command injection
	if server.User == "" || server.Host == "" {
		fmt.Println("❌ Invalid server configuration")
		return
	}

	// Sanitize user and host to prevent command injection
	user := strings.TrimSpace(server.User)
	host := strings.TrimSpace(server.Host)

	// Basic validation - reject potentially dangerous characters
	if strings.ContainsAny(user+host, ";&|`$(){}[]<>\"'\\") {
		fmt.Println("❌ Invalid characters in server configuration")
		return
	}

	// Use hardcoded command to prevent command injection
	sshArgs := []string{"-o", "StrictHostKeyChecking=no"}
	// Add key path if specified
	if server.KeyPath != "" {
		sshArgs = append(sshArgs, "-i", server.KeyPath)
	}

	sshArgs = append(sshArgs, fmt.Sprintf("%s@%s", user, host))
	cmd := exec.Command("ssh", sshArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Run command - if SSH exits normally, exit the program
	err = cmd.Run()
	handleSSHError(err, "SSH connection")
}

func ConnectWithJump(fromServer, toServer Server) {
	fromPassword, _ := fromServer.GetDecryptedPassword()
	toPassword, _ := toServer.GetDecryptedPassword()
	fromKeyPath := fromServer.KeyPath
	toKeyPath := toServer.KeyPath

	// pass/pass: double sshpass
	if fromPassword != "" && toPassword != "" && fromKeyPath == "" && toKeyPath == "" {
		fmt.Println("🔐 Using double sshpass + ProxyCommand for full password automation")
		connectWithSSHPass(fromServer, toServer)
		return
	}

	// pass/pem: jump=pass, target=pem
	if fromPassword != "" && toKeyPath != "" && fromKeyPath == "" && toPassword == "" {
		fmt.Println("🔐 Using sshpass + ProxyJump + -i for jump password, target key")
		proxyJump := fmt.Sprintf("%s@%s", fromServer.User, fromServer.Host)
		sshArgs := []string{
			"-p", fromPassword,
			"ssh",
			"-J", proxyJump,
			"-i", toKeyPath,
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", toServer.User, toServer.Host),
		}
		cmd := exec.Command("sshpass", sshArgs...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		handleSSHError(err, "SSH jump pass/pem")
		return
	}

	// pem/pass: jump=pem, target=pass
	if fromKeyPath != "" && toPassword != "" && fromPassword == "" && toKeyPath == "" {
		fmt.Println("🔐 Using ProxyCommand with jump key and target password")
		proxyCmd := fmt.Sprintf("ssh -i %s -W %%h:%%p -o StrictHostKeyChecking=no %s@%s",
			fromKeyPath, fromServer.User, fromServer.Host)
		sshArgs := []string{
			"-p", toPassword,
			"ssh",
			"-o", fmt.Sprintf("ProxyCommand=%s", proxyCmd),
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", toServer.User, toServer.Host),
		}
		cmd := exec.Command("sshpass", sshArgs...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		handleSSHError(err, "SSH jump pem/pass")
		return
	}

	// pem/pem: ProxyCommand with separate keys for jump and target
	if fromKeyPath != "" && toKeyPath != "" && fromPassword == "" && toPassword == "" {
		fmt.Println("🔐 Using ProxyCommand with separate keys for jump and target")
		proxyCmd := fmt.Sprintf("ssh -i %s -W %%h:%%p -o StrictHostKeyChecking=no %s@%s",
			fromKeyPath, fromServer.User, fromServer.Host)
		sshArgs := []string{
			"-o", fmt.Sprintf("ProxyCommand=%s", proxyCmd),
			"-i", toKeyPath,
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", toServer.User, toServer.Host),
		}
		cmd := exec.Command("ssh", sshArgs...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		handleSSHError(err, "SSH jump pem/pem")
		return
	}

	fmt.Println("❌ Unsupported authentication combination for jump connection")
	fmt.Println("Press Enter to return to menu...")
	bufio.NewScanner(os.Stdin).Scan()
}

// connectWithPasswordSSH connects using Go's SSH package with password authentication
func connectWithPasswordSSH(server Server) {
	decryptedPassword, err := server.GetDecryptedPassword()
	if err != nil {
		fmt.Printf("❌ Failed to decrypt password: %v\n", err)
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()

		return
	}

	// Create SSH client with password authentication
	client, err := createSSHClient(server.Host, server.User, decryptedPassword, "")
	if err != nil {
		fmt.Printf("❌ Failed to connect: %v\n", err)
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()

		return
	}
	defer client.Close()

	// Request interactive session
	session, err := client.NewSession()
	if err != nil {
		fmt.Printf("❌ Failed to create session: %v\n", err)
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()

		return
	}
	defer session.Close()

	// If PTY is requested, do not bind standard input/output (prevents duplicate output)
	// session.Stdout = os.Stdout
	// session.Stderr = os.Stderr
	// session.Stdin = os.Stdin

	// Request PTY with proper modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.ECHOCTL:       0,
		ssh.ECHOKE:        0,
		ssh.ECHONL:        0,
		ssh.ICANON:        1,
		ssh.ISIG:          1,
		ssh.TTY_OP_ISPEED: TTYISpeed,
		ssh.TTY_OP_OSPEED: TTYOSpeed,
		ssh.OPOST:         0,
		ssh.ONLCR:         0,
		ssh.OCRNL:         0,
		ssh.ONOCR:         0,
		ssh.IXON:          1,
		ssh.IXOFF:         1,
		ssh.IXANY:         0,
		ssh.IMAXBEL:       1,
		ssh.IUTF8:         1,
	}

	if err := session.RequestPty("xterm", TTYRows, TTYCols, modes); err != nil {
		fmt.Printf("❌ Failed to request PTY: %v\n", err)
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()
		return
	}

	// Bind standard input/output (used with PTY)
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	// Start shell
	if err := session.Shell(); err != nil {
		fmt.Printf("❌ Failed to start shell: %v\n", err)
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()
		return
	}

	// Wait for session to end - if session ends normally, exit the program
	err = session.Wait()
	handleSSHSessionEnd(session, err)
}

// createSSHClient creates an SSH client with password or key authentication
func createSSHClient(host, user, password, keyPath string) (*ssh.Client, error) {
	var err error
	// Validate input parameters
	if host == "" {
		return nil, fmt.Errorf("host cannot be empty")
	}

	if user == "" {
		return nil, fmt.Errorf("user cannot be empty")
	}

	if password == "" && keyPath == "" {
		return nil, fmt.Errorf("either password or keyPath must be provided")
	}

	var authMethods []ssh.AuthMethod

	// Add password authentication if provided
	if password != "" {
		// Use secure string wrapper for password
		securePass := NewSecureString(password)
		defer securePass.Clear()
		authMethods = append(authMethods, ssh.Password(securePass.String()))
	}

	// Add key authentication if provided
	if keyPath != "" {
		// Validate key file permissions (allow 400 or 600)
		if info, err := os.Stat(keyPath); err == nil {
			mode := info.Mode()
			if mode.Perm() != SSHKeyPermOwnerOnly {
				return nil, fmt.Errorf("SSH key file %s has loose permissions (%s), should be 400", keyPath, mode.String())
			}
		}

		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %s: %w", keyPath, err)
		}

		defer func() {
			// Clear key bytes from memory
			for i := range keyBytes {
				keyBytes[i] = 0
			}
		}()

		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key %s: %w", keyPath, err)
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication method provided")
	}

	// Create secure SSH configuration
	var hostKeyCallback ssh.HostKeyCallback

	knownHostsPath := filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")

	// Try to use known_hosts first, fallback to InsecureIgnoreHostKey if needed
	hostKeyCallback, err = knownhosts.New(knownHostsPath)
	if err != nil {
		// If known_hosts file doesn't exist or can't be read, use InsecureIgnoreHostKey
		fmt.Println(warning(
			"⚠️  Host key verification is disabled (known_hosts not available). " +
				"This is insecure and should only be used if absolutely necessary.",
		))

		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	} else {
		// Wrap the hostKeyCallback to handle key mismatch automatically (no prompt)
		originalCallback := hostKeyCallback
		hostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			err := originalCallback(hostname, remote, key)
			if err != nil {
				// Silently ignore host key verification failures for internal servers
				return nil
			}

			return err
		}
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         SSHTimeoutSeconds * time.Second,
		ClientVersion:   "SSH-2.0-SSHift",
		BannerCallback: func(message string) error {
			fmt.Printf(info("SSH Banner: %s\n"), message)
			return nil
		},
	}

	// Validate host format
	if !strings.Contains(host, ":") {
		host += ":22"
	}

	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		return nil, fmt.Errorf("failed to establish SSH connection: %w", err)
	}

	return client, nil
}

// connectWithSSHPass connects through jump server using sshpass + ssh command
func connectWithSSHPass(fromServer, toServer Server) {
	var err error

	fmt.Println("🔐 Using double sshpass + ProxyCommand for full password automation")

	// Get passwords
	fromPassword, err := fromServer.GetDecryptedPassword()
	if err != nil {
		fmt.Printf("❌ Failed to decrypt from server password: %v\n", err)
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()
		return
	}

	toPassword, err := toServer.GetDecryptedPassword()
	if err != nil {
		fmt.Printf("❌ Failed to decrypt to server password: %v\n", err)
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()
		return
	}

	if fromPassword == "" || toPassword == "" {
		fmt.Println("❌ Both servers need password authentication for this method")
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()
		return
	}

	proxyCmd := fmt.Sprintf("sshpass -p '%s' ssh -W %%h:%%p -o StrictHostKeyChecking=no %s@%s",
		fromPassword, fromServer.User, fromServer.Host)
	sshArgs := []string{
		"-p", toPassword,
		"ssh",
		"-o", fmt.Sprintf("ProxyCommand=%s", proxyCmd),
		"-o", "StrictHostKeyChecking=no",
		fmt.Sprintf("%s@%s", toServer.User, toServer.Host),
	}

	cmd := exec.Command("sshpass", sshArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	handleSSHError(err, "SSH jump connection with double sshpass")
}

// handleSSHSessionEnd handles SSH session end with consistent error reporting
func handleSSHSessionEnd(session *ssh.Session, err error) {
	if session != nil {
		session.Close()
	}

	if err != nil {
		// Check if it's a normal exit (exit code 0, 127, 130, 143)
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			if code == 0 || code == 127 || code == 130 || code == 143 {
				os.Exit(0)
			}
		}

		fmt.Printf("❌ SSH session ended with error: %v\n", err)
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()
	} else {
		os.Exit(0)
	}
}

func RunMenu(sm *ServerManager, jm *JumpManager) {
	for {
		if len(sm.Servers) == 0 {
			// Show logo only on first visit (no servers configured)
			printLogo()
			PrintEmptyMenu()

			input := PromptInput(prompt("Select an option: "))

			index, err := strconv.Atoi(input)
			if err != nil || (index != 0 && index != 1) {
				fmt.Println(errorMsg("Invalid selection."))
				continue
			}

			switch index {
			case 1:
				PromptAddServer(sm)
			case 0:
				fmt.Println(info("Exiting."))
				return
			}
		} else {
			PrintServerList(sm)
			fmt.Println()

			input := PromptInput(prompt("Select a server to connect: "))

			index, err := strconv.Atoi(input)
			if err != nil {
				fmt.Println(errorMsg("Invalid selection."))
				continue
			}

			if index == 0 {
				fmt.Println(info("Exiting."))
				return
			}

			// Find server by ID
			targetServer, found := sm.GetByID(index)
			if !found {
				fmt.Printf(errorMsg("Server %d not found.\n"), index)
				continue
			}

			// Check if this server requires a jump (either direct or chain)
			// First check for direct jump
			jumpFromID, isDirectJump := jm.GetJumpFrom(index)
			if isDirectJump {
				// Direct jump found
				fromServer, fromFound := sm.GetByID(jumpFromID)
				if !fromFound {
					fmt.Printf(errorMsg("Jump FROM server %d not found.\n"), jumpFromID)
					continue
				}

				fmt.Printf("%s %s (%d) %s %s (%d)\n",
					colorize(Cyan+Bold, "🔄 Direct jump:"), serverName(fromServer.Name), jumpFromID,
					jump("→"), serverName(targetServer.Name), index)

				// Use SSH ProxyJump to connect through FROM server to TO server
				ConnectWithJump(fromServer, targetServer)
			} else {
				// Check for chain jump - find the shortest path to target
				var bestPath []int

				var bestSource int

				// Try to find a path from any server to the target
				for _, server := range sm.Servers {
					if server.ID != index { // Don't check path to itself
						path, found := jm.FindPath(server.ID, index)
						if found && (bestPath == nil || len(path) < len(bestPath)) {
							bestPath = path
							bestSource = server.ID
						}
					}
				}

				if len(bestPath) > 1 {
					// Chain jump found
					fromServer, fromFound := sm.GetByID(bestSource)
					if !fromFound {
						fmt.Printf(errorMsg("Chain jump FROM server %d not found.\n"), bestSource)
						continue
					}

					// Display the chain path
					pathStr := ""

					for i, serverID := range bestPath {
						if i > 0 {
							pathStr += jump(" → ")
						}

						server, _ := sm.GetByID(serverID)
						pathStr += fmt.Sprintf("%s (%d)", serverName(server.Name), serverID)
					}

					fmt.Printf("%s %s\n", colorize(Cyan+Bold, "🔄 Chain jump:"), pathStr)

					// Use SSH ProxyJump to connect through the chain
					ConnectWithJump(fromServer, targetServer)
				} else {
					// Direct connection or FROM server
					Connect(targetServer)
				}
			}
		}
	}
}

func PrintEmptyMenu() {
	fmt.Printf("\n%s\n", colorize(Cyan+Bold, "Welcome to SSHift! 🚀"))
	fmt.Println(colorize(Yellow, "No servers configured yet."))
	fmt.Printf("\n%s\n", colorize(Blue+Bold, "No | OPTION"))
	fmt.Println(colorize(Blue, "-------------"))
	fmt.Printf(" %s | %s\n", colorize(White+Bold, "1"), colorize(Green, "Add new server"))
	fmt.Printf(" %s | %s\n", colorize(White+Bold, "0"), colorize(Red, "Exit"))
}

// printLogo displays the SSHift logo with version information
func printLogo() {
	fmt.Printf("%s", colorize(Cyan+Bold, SSHiftLogo))
}

func main() {
	homeDir, _ := os.UserHomeDir()

	baseDir := filepath.Join(homeDir, ".sshift")
	if err := os.MkdirAll(baseDir, DirPermStandard); err != nil {
		fmt.Printf("Error creating directory: %v\n", err)
	}

	// Load saved encryption key if available
	loadEncryptionKeyFromFile(baseDir)

	// Check if this is the first run and setup encryption key
	if isFirstRun(baseDir) {
		setupEncryptionKey()
	}

	sm := NewServerManager(baseDir)
	jm := NewJumpManager(baseDir)

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "add":
			PromptAddServer(sm)
		case "jump":
			HandleJumpCommand(jm, sm, os.Args[2:])
		case "version", "-v", "--version":
			printLogo()
			fmt.Printf("\n%s: %s\n\n", colorize(Blue+Bold, "version"), colorize(Cyan, Version))
		case "help", "-h", "--help":
			printHelp()
		case "list":
			PrintServerList(sm)
			fmt.Println()
		case "test":
			os.Setenv("SSHIFT_TEST_MODE", "1")
			fmt.Printf("%s\n", colorize(Yellow+Bold, "�� Test mode enabled. SSH connections will be simulated."))
			RunMenu(sm, jm)
		case "delete":
			PromptDeleteServer(sm, jm)
		case "sort":
			SortServers(sm, jm)
		case "edit":
			PromptEditServer(sm, jm)
		case "export":
			ExportData(sm, jm)
		case "import":
			ImportData(sm, jm)
		case "setup":
			setupEncryptionKey()
		case "key":
			showEncryptionKeyInfo()
		default:
			fmt.Printf("%s\n", errorMsg("Unknown command. Use 'sshift help' for usage information."))
		}
	} else {
		RunMenu(sm, jm)
	}
}

func SortServers(sm *ServerManager, jm *JumpManager) {
	if len(sm.Servers) == 0 {
		fmt.Println(warning("No servers to sort."))
		return
	}

	fmt.Printf("%s\n", colorize(Cyan+Bold, "🔄 Sorting server IDs and updating jump relations..."))

	// Create a map of old ID to new ID
	idMapping := make(map[int]int)
	newServers := make([]Server, 0, len(sm.Servers))

	// Sort servers by current ID and create new IDs
	for i, server := range sm.Servers {
		oldID := server.ID
		newID := i + 1
		idMapping[oldID] = newID

		// Create new server with updated ID
		newServer := server
		newServer.ID = newID
		newServers = append(newServers, newServer)

		if oldID != newID {
			fmt.Printf("  %s: ID %d %s %d\n", serverName(server.Name), oldID, jump("→"), newID)
		}
	}

	// Update jump relations with new IDs
	updatedRelations := 0

	// Create new graph with updated IDs
	newGraph := NewJumpGraph()

	// Iterate through all adjacency list entries
	for fromID, targets := range jm.Graph.AdjacencyList {
		for _, toID := range targets {
			newFromID, fromExists := idMapping[fromID]
			newToID, toExists := idMapping[toID]

			if fromExists && toExists {
				if err := newGraph.AddJump(newFromID, newToID); err != nil {
					fmt.Printf("Error adding jump relation %d -> %d: %v\n", newFromID, newToID, err)
					continue
				}

				if fromID != newFromID || toID != newToID {
					fmt.Printf("  %s: %d%s%d %s %d%s%d\n",
						colorize(Blue+Bold, "Jump relation"), fromID, jump("→"), toID, jump("→"), newFromID, jump("→"), newToID)

					updatedRelations++
				}
			} else {
				fmt.Printf("  %s %d%s%d (server not found)\n",
					warning("Skipping jump relation"), fromID, jump("→"), toID)
			}
		}
	}

	// Update the managers
	sm.Servers = newServers
	if err := sm.Save(); err != nil {
		fmt.Printf("Error saving server data: %v\n", err)
	}

	jm.Graph = newGraph
	if err := jm.Save(); err != nil {
		fmt.Printf("Error saving jump data: %v\n", err)
	}

	fmt.Print(success("Sorting completed!\n"))
	fmt.Printf("  - %d servers reordered\n", len(sm.Servers))
	fmt.Printf("  - %d jump relations updated\n", updatedRelations)
}

func PromptEditServer(sm *ServerManager, jm *JumpManager) {
	if len(sm.Servers) == 0 {
		fmt.Println(warning("No servers to edit."))
		return
	}

	fmt.Printf("\n%s\n", colorize(Blue+Bold, "Available servers:"))
	PrintServerList(sm)

	fmt.Println()

	serverInput := PromptInput(prompt("Enter server ID to edit: "))

	serverID, err := strconv.Atoi(serverInput)
	if err != nil {
		fmt.Println(errorMsg("Invalid server ID"))
		return
	}

	// Find server by ID
	server, found := sm.GetByID(serverID)
	if !found {
		fmt.Printf(errorMsg("Server %d not found\n"), serverID)
		return
	}

	fmt.Printf("\n%s %s (ID: %d, %s@%s)\n",
		colorize(Cyan+Bold, "🔧 Editing server:"), serverName(server.Name), server.ID, server.User, server.Host)
	fmt.Println("Press Enter to keep current value, or type new value:")

	// Edit server ID
	currentID := server.ID
	idInput := PromptInput(fmt.Sprintf("Server ID [%d]: ", currentID))

	var newID int

	var idChanged bool

	if idInput == "" {
		newID = currentID
		idChanged = false
	} else {
		newID, err = strconv.Atoi(idInput)
		if err != nil {
			fmt.Printf("❌ Invalid server ID: %s\n", idInput)
			return
		}

		if newID <= 0 {
			fmt.Printf("❌ Server ID must be positive: %d\n", newID)
			return
		}

		if newID != currentID {
			// Check if new ID already exists
			if _, exists := sm.GetByID(newID); exists {
				fmt.Printf("❌ Server with ID %d already exists\n", newID)
				return
			}

			idChanged = true
		} else {
			idChanged = false
		}
	}

	// Edit host
	currentHost := server.Host
	newHost := PromptInput(fmt.Sprintf("Host [%s]: ", currentHost))

	if newHost == "" {
		newHost = currentHost
	}

	// Edit user
	currentUser := server.User
	newUser := PromptInput(fmt.Sprintf("Username [%s]: ", currentUser))

	if newUser == "" {
		newUser = currentUser
	}

	// Edit name
	currentName := server.Name
	newName := PromptInput(fmt.Sprintf("Server name [%s]: ", currentName))

	if newName == "" {
		newName = currentName
	}

	// Edit authentication
	fmt.Printf("\nCurrent authentication: ")

	if server.Password != "" {
		fmt.Println("Password")
	} else if server.KeyPath != "" {
		fmt.Printf("SSH Key (%s)\n", server.KeyPath)
	} else {
		fmt.Println("Default SSH Key")
	}

	changeAuth := PromptInput("Change authentication method? (y/n): ")

	var newPassword, newKeyPath string

	if strings.EqualFold(changeAuth, YesResponse) || strings.EqualFold(changeAuth, YesResponseFull) {
		usePassword := PromptInput("Use password? (y/n): ")

		if strings.EqualFold(usePassword, YesResponse) || strings.EqualFold(usePassword, YesResponseFull) {
			fmt.Print("Enter new password: ")

			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				fmt.Println("Error reading password:", err)
				return
			}

			fmt.Println() // Add newline after password input

			newPassword = string(bytePassword)

			// Confirm password
			fmt.Print("Confirm new password: ")

			bytePasswordConfirm, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				fmt.Println("Error reading password confirmation:", err)
				return
			}

			fmt.Println() // Add newline after password input

			passwordConfirm := string(bytePasswordConfirm)

			// Check if passwords match
			if newPassword != passwordConfirm {
				fmt.Println("❌ Passwords do not match. Edit cancelled.")
				return
			}

			fmt.Println("✅ Passwords match!")

			// Encrypt new password
			encrypted, err := EncryptPassword(newPassword)
			if err != nil {
				fmt.Printf("❌ Error encrypting password: %v\n", err)
				return
			}

			newPassword = encrypted
		} else {
			fmt.Println("Using SSH key authentication.")

			newKeyPath = promptForSSHKey()
			if newKeyPath == "" {
				return
			}
		}
	} else {
		// Keep current authentication
		newPassword = server.Password
		newKeyPath = server.KeyPath
	}

	// Update server
	updatedServer := Server{
		ID:       newID,
		Host:     newHost,
		User:     newUser,
		Name:     newName,
		Password: newPassword,
		KeyPath:  newKeyPath,
	}

	// Handle ID change if needed
	if idChanged {
		// Use the UpdateServerID method to handle ID change and jump relation updates
		if err := sm.UpdateServerID(serverID, newID, jm); err != nil {
			fmt.Printf("❌ Error updating server ID: %v\n", err)
			return
		}

		// Update the server in the list with new ID
		for i, s := range sm.Servers {
			if s.ID == newID {
				sm.Servers[i] = updatedServer
				break
			}
		}
	} else {
		// Just update the server in the list (ID unchanged)
		for i, s := range sm.Servers {
			if s.ID == serverID {
				sm.Servers[i] = updatedServer
				break
			}
		}
	}

	if err := sm.Save(); err != nil {
		fmt.Printf("Error saving server data: %v\n", err)
		return
	}

	fmt.Printf("✅ Server '%s' updated successfully!\n", updatedServer.Name)

	if idChanged {
		fmt.Printf("🔄 Server ID changed from %d to %d\n", serverID, newID)
	}
}

// ExportData exports all server and jump data to a JSON file
func ExportData(sm *ServerManager, jm *JumpManager) {
	homeDir, _ := os.UserHomeDir()
	sshDir := filepath.Join(homeDir, ".ssh")

	// Create .ssh directory if it doesn't exist
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		if err := os.MkdirAll(sshDir, DirPermOwnerOnly); err != nil {
			fmt.Printf("Error creating .ssh directory: %v\n", err)
			return
		}
	}

	// Create export data structure
	exportData := struct {
		Version    string     `json:"version"`
		ExportDate string     `json:"export_date"`
		Servers    []Server   `json:"servers"`
		JumpGraph  *JumpGraph `json:"jump_graph"`
	}{
		Version:    Version,
		ExportDate: time.Now().Format("2006-01-02 15:04:05"),
		Servers:    sm.Servers,
		JumpGraph:  jm.Graph,
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("sshift_export_%s.json", timestamp)
	filePath := filepath.Join(sshDir, filename)

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		fmt.Printf(errorMsg("Error creating export data: %v\n"), err)
		return
	}

	// Write to file
	err = os.WriteFile(filePath, data, FilePermOwnerOnly)
	if err != nil {
		fmt.Printf(errorMsg("Error writing export file: %v\n"), err)
		return
	}

	fmt.Print(success("Data exported successfully!\n"))
	fmt.Printf("  File: %s\n", colorize(Cyan, filePath))
	fmt.Printf("  Servers: %d\n", len(sm.Servers))
	fmt.Printf("  Jump relations: %d\n", jm.Graph.GetJumpCount())
}

// ImportData imports server and jump data from a JSON file
func ImportData(sm *ServerManager, jm *JumpManager) {
	homeDir, _ := os.UserHomeDir()
	sshDir := filepath.Join(homeDir, ".ssh")

	// List available export files
	files, err := os.ReadDir(sshDir)
	if err != nil {
		fmt.Printf(errorMsg("Error reading .ssh directory: %v\n"), err)
		return
	}

	var exportFiles []string

	for _, file := range files {
		if !file.IsDir() && strings.HasPrefix(file.Name(), "sshift_export_") && strings.HasSuffix(file.Name(), ".json") {
			exportFiles = append(exportFiles, file.Name())
		}
	}

	if len(exportFiles) == 0 {
		fmt.Println(warning("No export files found in ~/.ssh/"))
		fmt.Println(info("Use 'sshift export' to create an export file first."))

		return
	}

	fmt.Println(colorize(Blue+Bold, "Available export files:"))

	for i, file := range exportFiles {
		fmt.Printf("  %d) %s\n", i+1, file)
	}

	fmt.Printf("  %d) Enter custom path\n", len(exportFiles)+1)

	choice := PromptInput(fmt.Sprintf("\nSelect file to import (1-%d): ", len(exportFiles)+1))

	choiceNum, err := strconv.Atoi(choice)
	if err != nil || choiceNum < 1 || choiceNum > len(exportFiles)+1 {
		fmt.Println(errorMsg("Invalid selection"))
		return
	}

	var filePath string
	if choiceNum <= len(exportFiles) {
		filePath = filepath.Join(sshDir, exportFiles[choiceNum-1])
	} else {
		customPath := PromptInput("Enter file path: ")
		if strings.HasPrefix(customPath, "~") {
			filePath = filepath.Join(homeDir, customPath[1:])
		} else {
			filePath = customPath
		}
	}

	// Read and parse the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf(errorMsg("Error reading file: %v\n"), err)
		return
	}

	var importData struct {
		Version       string         `json:"version"`
		ExportDate    string         `json:"export_date"`
		Servers       []Server       `json:"servers"`
		JumpGraph     *JumpGraph     `json:"jump_graph"`
		JumpRelations []JumpRelation `json:"jump_relations"` // For backward compatibility
	}

	if err := json.Unmarshal(data, &importData); err != nil {
		fmt.Printf(errorMsg("Error parsing JSON: %v\n"), err)
		return
	}

	// Check for encrypted passwords and warn about potential issues
	hasEncryptedPasswords := false

	for _, server := range importData.Servers {
		if server.Password != "" {
			hasEncryptedPasswords = true
			break
		}
	}

	if hasEncryptedPasswords {
		fmt.Println()
		fmt.Println(warning("Warning: Imported data contains encrypted passwords."))
		fmt.Println("   If the encryption key is different, passwords may not work.")
		fmt.Println("   You may need to re-enter passwords for affected servers.")
	}

	// Show import preview
	fmt.Printf("\n%s\n", colorize(Cyan+Bold, "📋 Import Preview:"))
	fmt.Printf("  Export date: %s\n", importData.ExportDate)
	fmt.Printf("  SSHift version: %s\n", importData.Version)
	fmt.Printf("  Servers: %d\n", len(importData.Servers))

	// Handle both new and old format
	var jumpCount int
	if importData.JumpGraph != nil {
		jumpCount = importData.JumpGraph.GetJumpCount()
	} else {
		jumpCount = len(importData.JumpRelations)
	}

	fmt.Printf("  Jump relations: %d\n", jumpCount)

	// Show server details
	if len(importData.Servers) > 0 {
		fmt.Println(colorize(Blue+Bold, "\nServers to import:"))

		for _, server := range importData.Servers {
			auth := "Key"
			if server.Password != "" {
				auth = "pass"
			} else if server.KeyPath != "" {
				auth = "pem"
			}

			fmt.Printf("  - %s (%s@%s) [%s]\n", serverName(server.Name), server.User, server.Host, colorize(Yellow, auth))
		}
	}

	// Show jump relations
	if importData.JumpGraph != nil {
		// New format
		if importData.JumpGraph.GetJumpCount() > 0 {
			fmt.Println(colorize(Blue+Bold, "\nJump relations to import:"))

			for fromID, targets := range importData.JumpGraph.AdjacencyList {
				for _, toID := range targets {
					fmt.Printf("  - %d %s %d\n", fromID, jump("→"), toID)
				}
			}
		}
	} else {
		// Old format
		if len(importData.JumpRelations) > 0 {
			fmt.Println(colorize(Blue+Bold, "\nJump relations to import:"))

			for _, relation := range importData.JumpRelations {
				fmt.Printf("  - %d %s %d\n", relation.FromID, jump("→"), relation.ToID)
			}
		}
	}

	// Confirm import
	confirm := PromptInput(prompt("\nImport will replace all current data. Continue? (y/n): "))
	if !strings.EqualFold(confirm, YesResponse) && !strings.EqualFold(confirm, YesResponseFull) {
		fmt.Println(errorMsg("Import cancelled"))
		return
	}

	// Perform import
	sm.Servers = importData.Servers

	// Handle jump data import
	if importData.JumpGraph != nil {
		// New format
		jm.Graph = importData.JumpGraph
	} else {
		// Convert old format to new graph format
		jm.Graph = NewJumpGraph()
		for _, relation := range importData.JumpRelations {
			if err := jm.Graph.AddJump(relation.FromID, relation.ToID); err != nil {
				fmt.Printf("Error adding jump relation %d -> %d: %v\n", relation.FromID, relation.ToID, err)
				continue
			}
		}
	}

	// Save data
	if err := sm.Save(); err != nil {
		fmt.Printf("Error saving server data: %v\n", err)
	}

	if err := jm.Save(); err != nil {
		fmt.Printf("Error saving jump data: %v\n", err)
	}

	fmt.Print(success("Data imported successfully!\n"))
	fmt.Printf("  Servers: %d\n", len(sm.Servers))
	fmt.Printf("  Jump relations: %d\n", jm.Graph.GetJumpCount())
}

// showEncryptionKeyInfo displays information about the current encryption key
func showEncryptionKeyInfo() {
	fmt.Println(colorize(Cyan+Bold, "🔐 SSHift Encryption Key Information"))
	fmt.Println()

	if customKey := os.Getenv("SSHIFT_ENCRYPTION_KEY"); customKey != "" {
		fmt.Println(colorize(Blue+Bold, "Key Type:") + " Custom (Environment Variable)")
		fmt.Printf(colorize(Blue+Bold, "Key Length:")+" %d characters\n", len(customKey))
		fmt.Println(colorize(Blue+Bold, "Source:") + " SSHIFT_ENCRYPTION_KEY environment variable")
		fmt.Println()
		fmt.Println(warning("Security Note:"))
		fmt.Println("   - Custom key is being used")
		fmt.Println("   - This key must be identical across all systems")
		fmt.Println("   - Consider using system auto-generated key for better security")
	} else {
		homeDir, _ := os.UserHomeDir()
		currentUser, _ := user.Current()
		username := ""

		if currentUser != nil {
			username = currentUser.Username
		}

		fmt.Println(colorize(Blue+Bold, "Key Type:") + " System Auto-Generated")
		fmt.Println(colorize(Blue+Bold, "Key Length:") + " 32 bytes (SHA-256)")
		fmt.Printf(colorize(Blue+Bold, "Generated from:")+" %s:%s\n", homeDir, username)
		fmt.Println()
		fmt.Println(success("Security Note:"))
		fmt.Println("   - System-specific key provides better security")
		fmt.Println("   - Key is unique to this system and user")
		fmt.Println("   - No manual key management required")
	}

	fmt.Println()
	fmt.Println(info("To change encryption key, run: sshift setup"))
}

// isFirstRun checks if this is the first time running SSHift
func isFirstRun(baseDir string) bool {
	setupFile := filepath.Join(baseDir, ".setup_complete")
	_, err := os.Stat(setupFile)

	return os.IsNotExist(err)
}

// setupEncryptionKey prompts user to set up encryption key
func setupEncryptionKey() {
	homeDir, _ := os.UserHomeDir()
	baseDir := filepath.Join(homeDir, ".sshift")

	// Check if this is a re-setup (not first run)
	isReSetup := !isFirstRun(baseDir)

	if isReSetup {
		fmt.Println("🔐 SSHift Encryption Key Re-Setup")
		fmt.Println("Changing encryption key for existing data.")
		fmt.Println()

		// Load existing data to check for encrypted passwords
		sm := NewServerManager(baseDir)
		hasEncryptedData := false

		for _, server := range sm.Servers {
			if server.Password != "" {
				hasEncryptedData = true
				break
			}
		}

		if hasEncryptedData {
			fmt.Println(warning("⚠️  WARNING: You have existing servers with encrypted passwords."))
			fmt.Println("   Changing the encryption key will require re-encrypting all passwords.")
			fmt.Println("   Make sure you have the current key available for migration.")
			fmt.Println()
		}
	} else {
		fmt.Println("🔐 SSHift Initial Setup")
		fmt.Println("Setting up encryption key for secure password storage.")
		fmt.Println()
	}

	fmt.Println("Choose an option:")
	fmt.Println("1) Use system auto-generated key (recommended)")
	fmt.Println("2) Set custom encryption key")

	if !isReSetup {
		fmt.Println("3) Setup later")
	}

	choice := PromptInput(fmt.Sprintf("\nSelect (1-%s): ", func() string {
		if isReSetup {
			return "2"
		}

		return "3"
	}()))

	switch choice {
	case "1":
		fmt.Println("✅ Using system auto-generated key.")
		fmt.Println("   A unique key will be generated for each system.")

		if isReSetup {
			fmt.Println("   ⚠️  Note: This will make existing encrypted data inaccessible!")
			fmt.Println("   Consider using option 2 for data migration.")
		}

	case "2":
		fmt.Println("🔑 Setting up custom encryption key.")
		fmt.Println("   This key must be identical across all systems.")
		fmt.Println("   Enter a secure key with at least 32 characters.")

		for {
			key := PromptInput("Enter encryption key: ")
			if len(key) < MinKeyLength {
				fmt.Printf("❌ Key must be at least %d characters long.\n", MinKeyLength)
				continue
			}

			if len(key) > MaxKeyLength {
				fmt.Printf("❌ Key cannot be longer than %d characters.\n", MaxKeyLength)
				continue
			}

			confirm := PromptInput("Confirm key (enter again): ")
			if key != confirm {
				fmt.Println("❌ Keys do not match. Please try again.")
				continue
			}

			// Handle data migration if this is a re-setup
			if isReSetup {
				if err := migrateEncryptedData(key, baseDir); err != nil {
					fmt.Printf("❌ Failed to migrate encrypted data: %v\n", err)
					fmt.Println("   Setup cancelled. Your data remains unchanged.")

					return
				}
			}

			// Save key to permanent storage
			if err := saveEncryptionKey(key, baseDir); err != nil {
				fmt.Printf("❌ Failed to save encryption key: %v\n", err)
				return
			}

			// Set environment variable for current session
			os.Setenv("SSHIFT_ENCRYPTION_KEY", key)
			fmt.Println("✅ Custom key has been set and saved permanently.")

			break
		}

	case "3":
		if !isReSetup {
			fmt.Println("⚠️  You can run 'sshift setup' later to configure.")
			return
		}

		fallthrough

	default:
		fmt.Println("❌ Invalid selection. Using system auto-generated key.")
	}

	// Mark setup as complete
	setupFile := filepath.Join(baseDir, ".setup_complete")
	setupContent := "Setup completed on " + time.Now().Format("2006-01-02 15:04:05")

	if err := os.WriteFile(setupFile, []byte(setupContent), FilePermOwnerOnly); err != nil {
		fmt.Printf("Error writing setup file: %v\n", err)
	}

	fmt.Println()

	if isReSetup {
		fmt.Println("Encryption key re-setup completed! 🎉")
	} else {
		fmt.Println("Initial setup completed! 🎉")
	}

	fmt.Println("You can now add servers.")
	fmt.Println()
}

// migrateEncryptedData migrates existing encrypted passwords to new key
func migrateEncryptedData(newKey, baseDir string) error {
	sm := NewServerManager(baseDir)

	// Check if there are any encrypted passwords to migrate
	hasEncryptedData := false

	for _, server := range sm.Servers {
		if server.Password != "" {
			hasEncryptedData = true
			break
		}
	}

	if !hasEncryptedData {
		fmt.Println("ℹ️  No encrypted passwords found. Migration not needed.")
		return nil
	}

	fmt.Println("🔄 Migrating encrypted passwords to new key...")

	// Temporarily set the new key to test decryption
	oldKey := os.Getenv("SSHIFT_ENCRYPTION_KEY")
	os.Setenv("SSHIFT_ENCRYPTION_KEY", newKey)

	// Try to decrypt and re-encrypt each password
	migratedCount := 0
	failedCount := 0

	for i, server := range sm.Servers {
		if server.Password == "" {
			continue
		}

		// Try to decrypt with new key
		decrypted, err := DecryptPassword(server.Password)
		if err == nil {
			// Successfully decrypted with new key, re-encrypt to ensure consistency
			reEncrypted, err := EncryptPassword(decrypted)
			if err != nil {
				failedCount++

				fmt.Printf("  ❌ Failed to re-encrypt password for server: %s\n", server.Name)

				continue
			}

			sm.Servers[i].Password = reEncrypted
			migratedCount++

			fmt.Printf("  ✅ Migrated password for server: %s\n", server.Name)

			continue
		}

		// If decryption fails, try with old key (if available)
		if oldKey == "" {
			failedCount++

			fmt.Printf("  ❌ Failed to migrate password for server: %s\n", server.Name)

			continue
		}

		os.Setenv("SSHIFT_ENCRYPTION_KEY", oldKey)

		decrypted, err = DecryptPassword(server.Password)
		if err != nil {
			failedCount++

			fmt.Printf("  ❌ Failed to migrate password for server: %s\n", server.Name)

			continue
		}

		// Successfully decrypted with old key, now re-encrypt with new key
		os.Setenv("SSHIFT_ENCRYPTION_KEY", newKey)

		reEncrypted, err := EncryptPassword(decrypted)
		if err != nil {
			failedCount++

			fmt.Printf("  ❌ Failed to re-encrypt password for server: %s\n", server.Name)

			continue
		}

		sm.Servers[i].Password = reEncrypted
		migratedCount++

		fmt.Printf("  ✅ Migrated password for server: %s\n", server.Name)
	}

	// Restore original key if it existed
	if oldKey != "" {
		os.Setenv("SSHIFT_ENCRYPTION_KEY", oldKey)
	}

	// Save migrated data
	if err := sm.Save(); err != nil {
		return fmt.Errorf("failed to save migrated data: %w", err)
	}

	fmt.Printf("🔄 Migration completed: %d passwords migrated, %d failed\n", migratedCount, failedCount)

	if failedCount > 0 {
		return fmt.Errorf("some passwords could not be migrated")
	}

	return nil
}

// saveEncryptionKey saves the encryption key to a permanent file
func saveEncryptionKey(key, baseDir string) error {
	keyFile := filepath.Join(baseDir, ".encryption_key")

	// Create a simple encrypted storage for the key
	// In production, you might want to use a more secure method
	keyData := fmt.Sprintf("SSHIFT_ENCRYPTION_KEY=%s\n", key)

	if err := os.WriteFile(keyFile, []byte(keyData), FilePermOwnerOnly); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	fmt.Println("💾 Encryption key saved to permanent storage.")
	fmt.Println("   The key will be automatically loaded on next startup.")

	return nil
}

// loadEncryptionKeyFromFile loads the encryption key from permanent storage
func loadEncryptionKeyFromFile(baseDir string) {
	keyFile := filepath.Join(baseDir, ".encryption_key")

	data, err := os.ReadFile(keyFile)
	if err != nil {
		return // No saved key file, use system-generated key
	}

	// Parse the key file
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SSHIFT_ENCRYPTION_KEY=") {
			key := strings.TrimPrefix(line, "SSHIFT_ENCRYPTION_KEY=")
			if key != "" {
				os.Setenv("SSHIFT_ENCRYPTION_KEY", key)
				return
			}
		}
	}
}

func printHelp() {
	printLogo()
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  sshift                    - Run interactive menu")
	fmt.Println("  sshift add                - Add new server")
	fmt.Println("  sshift list               - List all servers")
	fmt.Println("  sshift delete             - Delete server")
	fmt.Println("  sshift edit               - Edit server")
	fmt.Println("  sshift jump add           - Add jump relation")
	fmt.Println("  sshift jump list          - List jump relations")
	fmt.Println("  sshift jump delete        - Delete jump relation")
	fmt.Println("  sshift sort               - Sort server IDs and update jump relations")
	fmt.Println("  sshift export             - Export data to JSON file")
	fmt.Println("  sshift import             - Import data from JSON file")
	fmt.Println("  sshift key                - Show encryption key information")
	fmt.Println("  sshift setup              - Setup encryption key")
	fmt.Println("  sshift version            - Show version")
	fmt.Println("  sshift test               - Run in test mode (simulate connections)")
	fmt.Println("  sshift help               - Show this help")

	fmt.Println("\nSecurity Features:")
	fmt.Println("  🔐 AES-256 encryption for password storage")
	fmt.Println("  🔑 System-specific or custom encryption keys")
	fmt.Println("  🛡️ Secure memory handling with automatic clearing")
	fmt.Println("  🔒 SSH key file permission validation")
	fmt.Println("  ✅ Input validation and sanitization")
	fmt.Println("  🚫 Circular jump relation prevention")
	fmt.Println("  📝 Basic password validation")
	fmt.Println("\nSecurity Notes:")
	fmt.Println("  - Passwords are encrypted with AES-256-CFB")
	fmt.Println("  - SSH keys must have 600 permissions")
	fmt.Println("  - Passwords are validated for basic security (no null bytes, length limits)")
	fmt.Println("  - Run 'sshift setup' to configure encryption key")
	fmt.Println("  - Use 'sshift key' to view encryption information")
}

// promptForSSHKey prompts user to select an SSH key and returns the selected path
func promptForSSHKey() string {
	homeDir, _ := os.UserHomeDir()
	sshDir := filepath.Join(homeDir, ".ssh")

	availableKeys, err := findSSHKeys(sshDir)
	if err != nil {
		fmt.Printf("❌ Error finding SSH keys: %v\n", err)
		return ""
	}

	if len(availableKeys) > 0 {
		fmt.Println("\nAvailable SSH keys:")

		for i, key := range availableKeys {
			fmt.Printf("  %d) %s\n", i+1, key)
		}

		fmt.Printf("  %d) Enter custom path\n", len(availableKeys)+1)

		choice := PromptInput(fmt.Sprintf("\nSelect SSH key (1-%d): ", len(availableKeys)+1))

		choiceNum, err := strconv.Atoi(choice)
		if err != nil || choiceNum < 1 || choiceNum > len(availableKeys)+1 {
			fmt.Println("❌ Invalid selection. Please try again.")
			return ""
		} else if choiceNum <= len(availableKeys) {
			keyPath := availableKeys[choiceNum-1]
			fmt.Printf("✅ Selected: %s\n", keyPath)

			return keyPath
		} else {
			keyPath := PromptInput("Enter SSH key path (e.g., ~/.ssh/my_key): ")
			if strings.HasPrefix(keyPath, "~") {
				keyPath = filepath.Join(homeDir, keyPath[1:])
			}

			return keyPath
		}
	} else {
		fmt.Println("No SSH keys found in ~/.ssh/")

		keyPath := PromptInput("Enter SSH key path (e.g., ~/.ssh/my_key): ")
		if strings.HasPrefix(keyPath, "~") {
			keyPath = filepath.Join(homeDir, keyPath[1:])
		}

		return keyPath
	}
}

// handleSSHError handles SSH command execution errors with consistent error reporting
func handleSSHError(err error, connectionType string) {
	if err != nil {
		// Only show error message if it's not a normal exit
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			// Treat common exit codes as normal termination
			// 0: normal exit, 127: logout/exit, 130: Ctrl+C, 143: SIGTERM
			if code == 0 || code == 127 || code == 130 || code == 143 {
				os.Exit(0)
			}

			fmt.Printf("❌ %s failed (exit code %d): %v\n", connectionType, code, err)
			// Show stderr output if available
			if len(exitErr.Stderr) > 0 {
				fmt.Printf("   Error details: %s\n", string(exitErr.Stderr))
			}

			fmt.Println("Press Enter to return to menu...")
			bufio.NewScanner(os.Stdin).Scan()
		} else {
			fmt.Printf("❌ %s failed: %v\n", connectionType, err)

			fmt.Println("Press Enter to return to menu...")
			bufio.NewScanner(os.Stdin).Scan()
		}
	} else {
		// SSH exited normally (no error), exit the program
		os.Exit(0)
	}
}
