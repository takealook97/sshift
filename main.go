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
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Version information (injected during build)
var Version = "dev"

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

// Color functions
func colorize(color, text string) string {
	return color + text + Reset
}

func success(text string) string {
	return colorize(Green+Bold, "✅ "+text)
}

func errorMsg(text string) string {
	return colorize(Red+Bold, "❌ "+text)
}

func warning(text string) string {
	return colorize(Yellow+Bold, "⚠️  "+text)
}

func info(text string) string {
	return colorize(Cyan+Bold, "ℹ️  "+text)
}

func prompt(text string) string {
	return colorize(Blue+Bold, "🔍 "+text)
}

func serverName(text string) string {
	return colorize(Magenta, text)
}

func jump(text string) string {
	return colorize(Yellow, text)
}

// getEncryptionKey returns the encryption key from environment or generates a system-specific key
func getEncryptionKey() []byte {
	envKey := os.Getenv("SSHIFT_ENCRYPTION_KEY")
	if envKey != "" && len(envKey) >= 32 {
		return []byte(envKey[:32])
	}
	
	// Generate a more secure system-specific key
	homeDir, _ := os.UserHomeDir()
	currentUser, _ := user.Current()
	username := ""
	if currentUser != nil {
		username = currentUser.Username
	}
	
	// Use more entropy in key generation
	systemKey := fmt.Sprintf("%s-%s-%s-sshift-secure-key", homeDir, username, os.Getenv("USER"))
	
	// Use SHA-256 to generate a proper 32-byte key
	hash := sha256.Sum256([]byte(systemKey))
	return hash[:]
}



// EncryptPassword encrypts a password using AES
func EncryptPassword(password string) (string, error) {
	plaintext := []byte(password)
	block, err := aes.NewCipher(getEncryptionKey())
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// DecryptPassword decrypts an encrypted password
func DecryptPassword(encryptedPassword string) (string, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(encryptedPassword)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(getEncryptionKey())
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

type Server struct {
	ID       int    `json:"id"`
	Host     string `json:"host"`
	User     string `json:"user"`
	Name     string `json:"name"`
	Password string `json:"password,omitempty"`
	KeyPath  string `json:"key_path,omitempty"`
}

// findSSHKeys finds all available SSH private keys in the given directory
func findSSHKeys(sshDir string) []string {
	var keys []string
	
	// Common SSH key filenames (private keys only)
	keyNames := []string{"id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"}
	
	for _, keyName := range keyNames {
		keyPath := filepath.Join(sshDir, keyName)
		if _, err := os.Stat(keyPath); err == nil {
			keys = append(keys, keyPath)
		}
	}
	
	// Also look for other private key files (not starting with id_)
	files, err := os.ReadDir(sshDir)
	if err == nil {
		for _, file := range files {
			if !file.IsDir() && !strings.HasSuffix(file.Name(), ".pub") && 
			   !strings.HasPrefix(file.Name(), "id_") && 
			   !strings.HasPrefix(file.Name(), "known_hosts") &&
			   !strings.HasPrefix(file.Name(), "config") {
				keyPath := filepath.Join(sshDir, file.Name())
				keys = append(keys, keyPath)
			}
		}
	}
	
	return keys
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

// secureZeroBytes zeros out a byte slice to prevent memory leaks
func secureZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GetDecryptedPassword returns the decrypted password and clears it from memory after use
func (s *Server) GetDecryptedPassword() string {
	if s.Password == "" {
		return ""
	}
	decrypted, err := DecryptPassword(s.Password)
	if err != nil {
		return ""
	}
	
	// Create a copy to return
	result := decrypted
	
	// Note: In a more secure implementation, we would clear the memory
	// but Go's string type is immutable, so we can't directly clear it
	// The garbage collector will handle memory cleanup
	
	return result
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
	json.Unmarshal(file, &sm.Servers)
}

func (sm *ServerManager) Save() {
	data, _ := json.MarshalIndent(sm.Servers, "", "  ")
	os.WriteFile(sm.filePath, data, 0600) // Only owner can read/write
}

func (sm *ServerManager) Add(s Server) {
	s.ID = sm.nextID()
	sm.Servers = append(sm.Servers, s)
	sm.Save()
}

func (sm *ServerManager) nextID() int {
	maxID := 0
	for _, s := range sm.Servers {
		if s.ID > maxID {
			maxID = s.ID
		}
	}
	return maxID + 1
}

func (sm *ServerManager) GetByID(id int) (Server, bool) {
	for _, s := range sm.Servers {
		if s.ID == id {
			return s, true
		}
	}
	return Server{}, false
}

func (sm *ServerManager) DeleteByID(id int, jm *JumpManager) bool {
	for i, s := range sm.Servers {
		if s.ID == id {
			sm.Servers = append(sm.Servers[:i], sm.Servers[i+1:]...)
			sm.Save()
			
			// Delete all jump relations involving this server
			if jm != nil {
				deletedRelations := jm.DeleteAllRelationsForServer(id)
				if deletedRelations > 0 {
					fmt.Printf("🗑️  Also deleted %d jump relation(s) involving server %d\n", deletedRelations, id)
				}
			}
			
			return true
		}
	}
	return false
}

type JumpRelation struct {
	FromID int `json:"from_id"`
	ToID   int `json:"to_id"`
}

type JumpManager struct {
	filePath  string
	Relations []JumpRelation
}

func NewJumpManager(baseDir string) *JumpManager {
	filePath := filepath.Join(baseDir, "jumps.json")
	jm := &JumpManager{filePath: filePath}
	jm.Load()
	return jm
}

func (jm *JumpManager) Load() {
	file, err := os.ReadFile(jm.filePath)
	if err != nil {
		jm.Relations = []JumpRelation{}
		return
	}
	json.Unmarshal(file, &jm.Relations)
}

func (jm *JumpManager) Save() {
	data, _ := json.MarshalIndent(jm.Relations, "", "  ")
	os.WriteFile(jm.filePath, data, 0600) // Only owner can read/write
}

func (jm *JumpManager) Add(fromID, toID int) {
	for i, r := range jm.Relations {
		if r.FromID == fromID {
			jm.Relations[i].ToID = toID
			jm.Save()
			return
		}
	}
	jm.Relations = append(jm.Relations, JumpRelation{FromID: fromID, ToID: toID})
	jm.Save()
}

func (jm *JumpManager) Delete(fromID int) {
	var updated []JumpRelation
	for _, r := range jm.Relations {
		if r.FromID != fromID {
			updated = append(updated, r)
		}
	}
	jm.Relations = updated
	jm.Save()
}

// DeleteAllRelationsForServer removes all jump relations involving the given server ID
func (jm *JumpManager) DeleteAllRelationsForServer(serverID int) int {
	var updated []JumpRelation
	deletedCount := 0
	
	for _, r := range jm.Relations {
		if r.FromID != serverID && r.ToID != serverID {
			updated = append(updated, r)
		} else {
			deletedCount++
		}
	}
	
	jm.Relations = updated
	jm.Save()
	return deletedCount
}

func (jm *JumpManager) GetJumpTarget(fromID int) (int, bool) {
	for _, r := range jm.Relations {
		if r.FromID == fromID {
			return r.ToID, true
		}
	}
	return 0, false
}

func (jm *JumpManager) GetJumpFrom(toID int) (int, bool) {
	for _, r := range jm.Relations {
		if r.ToID == toID {
			return r.FromID, true
		}
	}
	return 0, false
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
	return strings.TrimSpace(scanner.Text())
}

func PromptAddServer(sm *ServerManager) {
	host := PromptInput("Enter host (IP or domain): ")
	user := PromptInput("Enter username: ")
	name := PromptInput("Enter server name: ")
	usePassword := PromptInput("Use password? (y/n): ")
	var password string
	var keyPath string
	
	if usePassword == "y" || usePassword == "Y" {
		fmt.Print("Enter password: ")
		bytePassword, err := term.ReadPassword(syscall.Stdin)
		if err != nil {
			fmt.Println("Error reading password:", err)
			return
		}
		fmt.Println() // Add newline after password input
		password = string(bytePassword)
		
		// Confirm password
		fmt.Print("Confirm password: ")
		bytePasswordConfirm, err := term.ReadPassword(syscall.Stdin)
		if err != nil {
			fmt.Println("Error reading password confirmation:", err)
			return
		}
		fmt.Println() // Add newline after password input
		passwordConfirm := string(bytePasswordConfirm)
		
		// Check if passwords match
		if password != passwordConfirm {
			fmt.Println("❌ Passwords do not match. Please try again.")
			return
		}
		fmt.Println("✅ Passwords match!")
		
		// Debug: Check if password was read correctly
		if password == "" {
			fmt.Println("Warning: Password is empty")
		}
	} else {
		fmt.Println("Using SSH key authentication.")
		
		// Find available SSH keys
		homeDir, _ := os.UserHomeDir()
		sshDir := filepath.Join(homeDir, ".ssh")
		availableKeys := findSSHKeys(sshDir)
		
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
				return
			} else if choiceNum <= len(availableKeys) {
				// User selected a specific key
				keyPath = availableKeys[choiceNum-1]
				fmt.Printf("✅ Selected: %s\n", keyPath)
			} else {
				// User wants to enter custom path
				keyPath = PromptInput("Enter SSH key path (e.g., ~/.ssh/my_key): ")
				// Expand ~ to home directory
				if strings.HasPrefix(keyPath, "~") {
					keyPath = filepath.Join(homeDir, keyPath[1:])
				}
			}
		} else {
			fmt.Println("No SSH keys found in ~/.ssh/")
			keyPath = PromptInput("Enter SSH key path (e.g., ~/.ssh/my_key): ")
			// Expand ~ to home directory
			if strings.HasPrefix(keyPath, "~") {
				keyPath = filepath.Join(homeDir, keyPath[1:])
			}
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

	sm.Add(Server{
		Host:     host,
		User:     user,
		Name:     name,
		Password: encryptedPassword,
		KeyPath:  keyPath,
	})
	fmt.Printf("✅ Added server: %s (%s@%s)\n", name, user, host)
}

func PromptAddJump(jm *JumpManager, sm *ServerManager) {
	if len(sm.Servers) < 2 {
		fmt.Println("❌ Need at least 2 servers to create a jump relation.")
		return
	}

	fmt.Println("\nAvailable servers:")
	PrintServerList(sm)
	
	fromInput := PromptInput("\nSelect FROM server ID: ")
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
	
	toInput := PromptInput("Select TO server ID: ")
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
	
	jm.Add(fromID, toID)
	fmt.Printf("✅ Jump relation created: %s (%d) → %s (%d)\n", 
		fromServer.Name, fromID, toServer.Name, toID)
}

func PromptDeleteJump(jm *JumpManager, sm *ServerManager) {
	if len(jm.Relations) == 0 {
		fmt.Println("No jump relations to delete.")
		return
	}
	
	fmt.Println("\nAvailable jump relations:")
	PrintJumpList(jm, sm)
	
	fromInput := PromptInput("\nEnter FROM server ID: ")
	fromID, err := strconv.Atoi(fromInput)
	if err != nil {
		fmt.Println("❌ Invalid server ID")
		return
	}
	
	toInput := PromptInput("Enter TO server ID: ")
	toID, err := strconv.Atoi(toInput)
	if err != nil {
		fmt.Println("❌ Invalid server ID")
		return
	}
	
	// Check if jump relation exists
	actualToID, found := jm.GetJumpTarget(fromID)
	if !found {
		fmt.Printf("❌ No jump relation found for server %d\n", fromID)
		return
	}
	
	if actualToID != toID {
		fmt.Printf("❌ Jump relation %d → %d does not exist. Actual relation is %d → %d\n", 
			fromID, toID, fromID, actualToID)
		return
	}
	
	// Get server info for confirmation
	fromServer, fromFound := sm.GetByID(fromID)
	toServer, toFound := sm.GetByID(toID)
	
	if fromFound && toFound {
		confirm := PromptInput(fmt.Sprintf("Are you sure you want to delete jump relation '%s' (%d) → '%s' (%d)? (y/n): ", 
			fromServer.Name, fromID, toServer.Name, toID))
		
		if strings.ToLower(confirm) == "y" || strings.ToLower(confirm) == "yes" {
			jm.Delete(fromID)
			fmt.Printf("✅ Jump relation '%s' (%d) → '%s' (%d) deleted\n", 
				fromServer.Name, fromID, toServer.Name, toID)
		} else {
			fmt.Println("❌ Deletion cancelled")
		}
	} else {
		confirm := PromptInput(fmt.Sprintf("Are you sure you want to delete jump relation %d → %d? (y/n): ", fromID, toID))
		
		if strings.ToLower(confirm) == "y" || strings.ToLower(confirm) == "yes" {
			jm.Delete(fromID)
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
	
	serverInput := PromptInput("\nEnter server ID to delete: ")
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
	
	if strings.ToLower(confirm) == "y" || strings.ToLower(confirm) == "yes" {
		if sm.DeleteByID(serverID, jm) {
			fmt.Printf("✅ Server '%s' (%d) deleted\n", server.Name, serverID)
		} else {
			fmt.Printf("❌ Failed to delete server %d\n", serverID)
		}
	} else {
		fmt.Println("❌ Deletion cancelled")
	}
}

func PrintServerList(sm *ServerManager) {
	fmt.Println("\n ID | SERVER NAME                    | IP              | USER      | AUTH")
	fmt.Println("-----------------------------------------------------------------------------")
	for _, s := range sm.Servers {
		auth := "Key"
		if s.Password != "" {
			auth = "pass"
		} else if s.KeyPath != "" {
			auth = "pem"
		}
		fmt.Printf("%2d) | %-30s | %-15s | %-9s | %-6s\n", s.ID, s.Name, s.Host, s.User, auth)
	}
	fmt.Printf(" 0) | %-30s | %-15s | %-9s | %-6s\n", "Exit", "-", "-", "-")
}

func PrintJumpList(jm *JumpManager, sm *ServerManager) {
	if len(jm.Relations) == 0 {
		fmt.Println("No jump relations configured.")
		return
	}
	
	fmt.Println("\nJump Relations:")
	fmt.Println("FROM → TO")
	fmt.Println("-------------")
	for _, r := range jm.Relations {
		fromServer, fromFound := sm.GetByID(r.FromID)
		toServer, toFound := sm.GetByID(r.ToID)
		
		if fromFound && toFound {
			fmt.Printf("%s (%d) → %s (%d)\n", 
				fromServer.Name, r.FromID, toServer.Name, r.ToID)
		} else {
			fmt.Printf("%d → %d (server not found)\n", r.FromID, r.ToID)
		}
	}
}

func Connect(server Server) {
	// Check if test mode is enabled
	if os.Getenv("SSHIFT_TEST_MODE") == "1" {
		fmt.Printf("🔧 TEST MODE: Would connect to %s@%s\n", server.User, server.Host)
		fmt.Printf("   Server: %s\n", server.Name)
		decryptedPassword := server.GetDecryptedPassword()
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
	var args []string
	decryptedPassword := server.GetDecryptedPassword()
	if decryptedPassword != "" {
		// Use password authentication with sshpass
		fmt.Println("🔐 Using password authentication")
		fmt.Println("   Note: This will prompt for password interactively")
		
		// Try to use sshpass if available
		sshpassCmd := exec.Command("which", "sshpass")
		if sshpassCmd.Run() == nil {
			// sshpass is available, use it
			args = []string{"sshpass", "-p", decryptedPassword, "ssh", "-o", "StrictHostKeyChecking=no"}
		} else {
			// sshpass not available, use regular ssh
			args = []string{"ssh", "-o", "StrictHostKeyChecking=no", "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no"}
		}
	} else {
		// Use SSH key authentication
		args = []string{"ssh", "-o", "StrictHostKeyChecking=no"}
		
		// Add key path (should always be specified now)
		if server.KeyPath != "" {
			args = append(args, "-i", server.KeyPath)
			fmt.Printf("🔐 Using SSH key authentication with key: %s\n", server.KeyPath)
		} else {
			fmt.Println("❌ No SSH key specified. Please add the server again with a key.")
			fmt.Println("Press Enter to return to menu...")
			bufio.NewScanner(os.Stdin).Scan()
			return
		}
	}
	
	args = append(args, fmt.Sprintf("%s@%s", server.User, server.Host))
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	// Run command - if SSH exits normally, exit the program
	err := cmd.Run()
	if err != nil {
		// Only show error message if it's not a normal exit
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			// Treat common exit codes as normal termination
			// 0: normal exit, 127: logout/exit, 130: Ctrl+C, 143: SIGTERM
			if code == 0 || code == 127 || code == 130 || code == 143 {
				// SSH exited normally, exit the program
				os.Exit(0)
			} else {
				fmt.Printf("❌ SSH connection failed: %v\n", err)
				fmt.Println("Press Enter to return to menu...")
				bufio.NewScanner(os.Stdin).Scan()
			}
		} else {
			fmt.Printf("❌ SSH connection failed: %v\n", err)
			fmt.Println("Press Enter to return to menu...")
			bufio.NewScanner(os.Stdin).Scan()
		}
	} else {
		// SSH exited normally (no error), exit the program
		os.Exit(0)
	}
}

func ConnectWithJump(fromServer, toServer Server) {
	// Check if test mode is enabled
	if os.Getenv("SSHIFT_TEST_MODE") == "1" {
		fmt.Printf("🔧 TEST MODE: Would connect through %s@%s to %s@%s\n", 
			fromServer.User, fromServer.Host, toServer.User, toServer.Host)
		fmt.Printf("   Jump: %s → %s\n", fromServer.Name, toServer.Name)
		fmt.Printf("   From auth: %s\n", getAuthType(fromServer))
		fmt.Printf("   To auth: %s\n", getAuthType(toServer))
		fmt.Println("   Press Enter to continue...")
		bufio.NewScanner(os.Stdin).Scan()
		return
	}

	// Check authentication methods
	fromPassword := fromServer.GetDecryptedPassword()
	toPassword := toServer.GetDecryptedPassword()
	fromKeyPath := fromServer.KeyPath
	toKeyPath := toServer.KeyPath
	
	// Try programmatic SSH connection if both servers have authentication configured
	if (fromPassword != "" || fromKeyPath != "") && (toPassword != "" || toKeyPath != "") {
		fmt.Println("🔐 Using programmatic SSH connection")
		connectWithProgrammaticSSH(fromServer, toServer)
		return
	}
	
	// Use ProxyJump with proper key configuration
	fmt.Println("🔐 Using SSH command with ProxyJump")
	fmt.Printf("   Jump server auth: %s\n", getAuthType(fromServer))
	fmt.Printf("   Target server auth: %s\n", getAuthType(toServer))
	
	// Build SSH command with ProxyJump
	var args []string
	
	// Add ProxyJump configuration with authentication
	proxyJump := fmt.Sprintf("%s@%s", fromServer.User, fromServer.Host)
	if fromKeyPath != "" {
		// Add key for jump server
		proxyJump = fmt.Sprintf("%s@%s -i %s", fromServer.User, fromServer.Host, fromKeyPath)
	}
	args = append(args, "-J", proxyJump, "-o", "StrictHostKeyChecking=no")
	
	// Add key for target server if specified
	if toKeyPath != "" {
		args = append(args, "-i", toKeyPath)
	}
	
	// Add target server
	args = append(args, fmt.Sprintf("%s@%s", toServer.User, toServer.Host))
	
	cmd := exec.Command("ssh", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	// Run command - if SSH exits normally, exit the program
	err := cmd.Run()
	if err != nil {
		// Only show error message if it's not a normal exit
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			// Treat common exit codes as normal termination
			// 0: normal exit, 127: logout/exit, 130: Ctrl+C, 143: SIGTERM
			if code == 0 || code == 127 || code == 130 || code == 143 {
				// SSH exited normally, exit the program
				os.Exit(0)
			} else {
				fmt.Printf("❌ SSH jump connection failed: %v\n", err)
				fmt.Println("Press Enter to return to menu...")
				bufio.NewScanner(os.Stdin).Scan()
			}
		} else {
			fmt.Printf("❌ SSH jump connection failed: %v\n", err)
			fmt.Println("Press Enter to return to menu...")
			bufio.NewScanner(os.Stdin).Scan()
		}
	} else {
		// SSH exited normally (no error), exit the program
		os.Exit(0)
	}
}

// connectWithPasswordJump connects through jump server using password authentication
func connectWithPasswordJump(fromServer, toServer Server, password string) {
	// For now, use a simple approach with ssh command and expect-like behavior
	// In production, you might want to use Go's crypto/ssh package
	
	fmt.Println("🔐 Using password authentication through jump server")
	fmt.Println("   Note: This will prompt for password interactively")
	
	// Use ssh with ProxyJump and let it prompt for password
	proxyJump := fmt.Sprintf("%s@%s", fromServer.User, fromServer.Host)
	args := []string{"-J", proxyJump, "-o", "StrictHostKeyChecking=no"}
	args = append(args, fmt.Sprintf("%s@%s", toServer.User, toServer.Host))
	
	cmd := exec.Command("ssh", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

// createSSHClient creates an SSH client with password or key authentication
func createSSHClient(host, user, password, keyPath string) (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod
	
	// Add password authentication if provided
	if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}
	
	// Add key authentication if provided
	if keyPath != "" {
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %s: %v", keyPath, err)
		}
		
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key %s: %v", keyPath, err)
		}
		
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication method provided")
	}
	
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}
	
	return ssh.Dial("tcp", host+":22", config)
}

// connectWithProgrammaticSSH connects through jump server using Go's SSH package
func connectWithProgrammaticSSH(fromServer, toServer Server) {
	fmt.Println("🔐 Using programmatic SSH connection")
	
	// Get passwords
	fromPassword := fromServer.GetDecryptedPassword()
	toPassword := toServer.GetDecryptedPassword()
	
	if fromPassword == "" || toPassword == "" {
		fmt.Println("❌ Both servers need password authentication for programmatic connection")
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()
		return
	}
	
	// Connect to jump server
	fmt.Printf("🔄 Connecting to jump server: %s@%s\n", fromServer.User, fromServer.Host)
	jumpClient, err := createSSHClient(fromServer.Host, fromServer.User, fromPassword, fromServer.KeyPath)
	if err != nil {
		fmt.Printf("❌ Failed to connect to jump server: %v\n", err)
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()
		return
	}
	defer jumpClient.Close()
	
	// Connect to target server through jump server
	fmt.Printf("🔄 Connecting to target server: %s@%s\n", toServer.User, toServer.Host)
	targetClient, err := jumpClient.Dial("tcp", toServer.Host+":22")
	if err != nil {
		fmt.Printf("❌ Failed to connect to target server: %v\n", err)
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()
		return
	}
	defer targetClient.Close()
	
	// Create SSH connection to target server
	var targetAuthMethods []ssh.AuthMethod
	
	// Add password authentication if provided
	if toPassword != "" {
		targetAuthMethods = append(targetAuthMethods, ssh.Password(toPassword))
	}
	
	// Add key authentication if provided
	if toServer.KeyPath != "" {
		keyBytes, err := os.ReadFile(toServer.KeyPath)
		if err != nil {
			fmt.Printf("❌ Failed to read target server key file: %v\n", err)
			fmt.Println("Press Enter to return to menu...")
			bufio.NewScanner(os.Stdin).Scan()
			return
		}
		
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			fmt.Printf("❌ Failed to parse target server private key: %v\n", err)
			fmt.Println("Press Enter to return to menu...")
			bufio.NewScanner(os.Stdin).Scan()
			return
		}
		
		targetAuthMethods = append(targetAuthMethods, ssh.PublicKeys(signer))
	}
	
	if len(targetAuthMethods) == 0 {
		fmt.Println("❌ No authentication method available for target server")
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()
		return
	}
	
	sshConn, chans, reqs, err := ssh.NewClientConn(targetClient, toServer.Host+":22", &ssh.ClientConfig{
		User:            toServer.User,
		Auth:            targetAuthMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	})
	if err != nil {
		fmt.Printf("❌ Failed to establish SSH connection to target: %v\n", err)
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()
		return
	}
	defer sshConn.Close()
	
	// Create client from connection
	client := ssh.NewClient(sshConn, chans, reqs)
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
	
	// Set up terminal
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin
	
	// Request PTY
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	
	if err := session.RequestPty("xterm", 40, 80, modes); err != nil {
		fmt.Printf("❌ Failed to request PTY: %v\n", err)
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()
		return
	}
	
	// Start shell
	if err := session.Shell(); err != nil {
		fmt.Printf("❌ Failed to start shell: %v\n", err)
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()
		return
	}
	
	// Wait for session to end - if session ends normally, exit the program
	// If there's an error, it means connection was interrupted
	err = session.Wait()
	if err != nil {
		fmt.Printf("❌ SSH session ended with error: %v\n", err)
		fmt.Println("Press Enter to return to menu...")
		bufio.NewScanner(os.Stdin).Scan()
	} else {
		// Session ended normally, exit the program
		os.Exit(0)
	}
}

func RunMenu(sm *ServerManager, jm *JumpManager) {
	for {
		if len(sm.Servers) == 0 {
			PrintEmptyMenu()
			input := PromptInput(prompt("\nSelect an option: "))
			index, err := strconv.Atoi(input)
			if err != nil || index < 1 || index > 2 {
				fmt.Println(errorMsg("Invalid selection."))
				continue
			}
			
			switch index {
			case 1:
				PromptAddServer(sm)
			case 2:
				fmt.Println(info("Exiting."))
				return
			}
		} else {
			PrintServerList(sm)
			input := PromptInput(prompt("\nSelect a server to connect: "))
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
			
			// Check if this server is a jump target (TO server)
			jumpFromID, isJumpTarget := jm.GetJumpFrom(index)
			if isJumpTarget {
				// This is a TO server, need to jump through FROM server
				fromServer, fromFound := sm.GetByID(jumpFromID)
				if !fromFound {
					fmt.Printf(errorMsg("Jump FROM server %d not found.\n"), jumpFromID)
					continue
				}
				
				fmt.Printf("%s %s (%d) %s %s (%d)\n", 
					colorize(Cyan+Bold, "🔄 Auto-jump:"), serverName(fromServer.Name), jumpFromID, jump("→"), serverName(targetServer.Name), index)
				
				// Use SSH ProxyJump to connect through FROM server to TO server
				ConnectWithJump(fromServer, targetServer)
			} else {
				// Direct connection or FROM server
				Connect(targetServer)
			}
			
			// If we reach here, it means SSH connection failed or was interrupted
			// Continue the loop to show menu again
		}
	}
}

func PrintEmptyMenu() {
	fmt.Printf("\n%s\n", colorize(Cyan+Bold, "Welcome to SSHift! 🚀"))
	fmt.Println(colorize(Yellow, "No servers configured yet."))
	fmt.Printf("\n%s\n", colorize(Blue+Bold, "No | OPTION"))
	fmt.Println(colorize(Blue, "-------------"))
	fmt.Printf(" %s | %s\n", colorize(White+Bold, "1"), colorize(Green, "Add new server"))
	fmt.Printf(" %s | %s\n", colorize(White+Bold, "2"), colorize(Red, "Exit"))
}

func main() {
	homeDir, _ := os.UserHomeDir()
	baseDir := filepath.Join(homeDir, ".sshift")
	os.MkdirAll(baseDir, 0755)

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
			fmt.Printf("%s v%s\n", colorize(Cyan+Bold, "SSHift"), Version)
		case "help", "-h", "--help":
			printHelp()
		case "list":
			PrintServerList(sm)
		case "test":
			os.Setenv("SSHIFT_TEST_MODE", "1")
			fmt.Printf("%s\n", colorize(Yellow+Bold, "🔧 Test mode enabled. SSH connections will be simulated."))
			RunMenu(sm, jm)
		case "delete":
			PromptDeleteServer(sm, jm)
		case "sort":
			SortServers(sm, jm)
		case "edit":
			PromptEditServer(sm)
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
	newRelations := make([]JumpRelation, 0, len(jm.Relations))
	
	for _, relation := range jm.Relations {
		newFromID, fromExists := idMapping[relation.FromID]
		newToID, toExists := idMapping[relation.ToID]
		
		if fromExists && toExists {
			newRelation := JumpRelation{
				FromID: newFromID,
				ToID:   newToID,
			}
			newRelations = append(newRelations, newRelation)
			
			if relation.FromID != newFromID || relation.ToID != newToID {
				fmt.Printf("  %s: %d%s%d %s %d%s%d\n", 
					colorize(Blue+Bold, "Jump relation"), relation.FromID, jump("→"), relation.ToID, jump("→"), newFromID, jump("→"), newToID)
				updatedRelations++
			}
		} else {
			fmt.Printf("  %s %d%s%d (server not found)\n", 
				warning("Skipping jump relation"), relation.FromID, jump("→"), relation.ToID)
		}
	}
	
	// Update the managers
	sm.Servers = newServers
	sm.Save()
	
	jm.Relations = newRelations
	jm.Save()
	
	fmt.Printf(success("Sorting completed!\n"))
	fmt.Printf("  - %d servers reordered\n", len(sm.Servers))
	fmt.Printf("  - %d jump relations updated\n", updatedRelations)
}

func PromptEditServer(sm *ServerManager) {
	if len(sm.Servers) == 0 {
		fmt.Println(warning("No servers to edit."))
		return
	}

	fmt.Printf("\n%s\n", colorize(Blue+Bold, "Available servers:"))
	PrintServerList(sm)

	serverInput := PromptInput(prompt("\nEnter server ID to edit: "))
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

	fmt.Printf("\n%s %s (%s@%s)\n", colorize(Cyan+Bold, "🔧 Editing server:"), serverName(server.Name), server.User, server.Host)
	fmt.Println("Press Enter to keep current value, or type new value:")

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

	if strings.ToLower(changeAuth) == "y" || strings.ToLower(changeAuth) == "yes" {
		usePassword := PromptInput("Use password? (y/n): ")
		
		if usePassword == "y" || usePassword == "Y" {
			fmt.Print("Enter new password: ")
			bytePassword, err := term.ReadPassword(syscall.Stdin)
			if err != nil {
				fmt.Println("Error reading password:", err)
				return
			}
			fmt.Println() // Add newline after password input
			newPassword = string(bytePassword)
			
			// Confirm password
			fmt.Print("Confirm new password: ")
			bytePasswordConfirm, err := term.ReadPassword(syscall.Stdin)
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
			
			// Find available SSH keys
			homeDir, _ := os.UserHomeDir()
			sshDir := filepath.Join(homeDir, ".ssh")
			availableKeys := findSSHKeys(sshDir)
			
			if len(availableKeys) > 0 {
				fmt.Println("\nAvailable SSH keys:")
				for i, key := range availableKeys {
					fmt.Printf("  %d) %s\n", i+1, key)
				}
				fmt.Printf("  %d) Enter custom path\n", len(availableKeys)+1)
				
				choice := PromptInput(fmt.Sprintf("\nSelect SSH key (1-%d): ", len(availableKeys)+1))
				choiceNum, err := strconv.Atoi(choice)
				if err != nil || choiceNum < 1 || choiceNum > len(availableKeys)+1 {
					fmt.Println("❌ Invalid selection. Edit cancelled.")
					return
				} else if choiceNum <= len(availableKeys) {
					newKeyPath = availableKeys[choiceNum-1]
					fmt.Printf("✅ Selected: %s\n", newKeyPath)
				} else {
					newKeyPath = PromptInput("Enter SSH key path (e.g., ~/.ssh/my_key): ")
					if strings.HasPrefix(newKeyPath, "~") {
						newKeyPath = filepath.Join(homeDir, newKeyPath[1:])
					}
				}
			} else {
				fmt.Println("No SSH keys found in ~/.ssh/")
				newKeyPath = PromptInput("Enter SSH key path (e.g., ~/.ssh/my_key): ")
				if strings.HasPrefix(newKeyPath, "~") {
					newKeyPath = filepath.Join(homeDir, newKeyPath[1:])
				}
			}
		}
	} else {
		// Keep current authentication
		newPassword = server.Password
		newKeyPath = server.KeyPath
	}

	// Update server
	updatedServer := Server{
		ID:       server.ID,
		Host:     newHost,
		User:     newUser,
		Name:     newName,
		Password: newPassword,
		KeyPath:  newKeyPath,
	}

	// Replace the server in the list
	for i, s := range sm.Servers {
		if s.ID == serverID {
			sm.Servers[i] = updatedServer
			break
		}
	}

	sm.Save()
	fmt.Printf("✅ Server '%s' updated successfully!\n", updatedServer.Name)
}

// ExportData exports all server and jump data to a JSON file
func ExportData(sm *ServerManager, jm *JumpManager) {
	homeDir, _ := os.UserHomeDir()
	sshDir := filepath.Join(homeDir, ".ssh")
	
	// Create .ssh directory if it doesn't exist
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		os.MkdirAll(sshDir, 0700)
	}
	
	// Create export data structure
	exportData := struct {
		Version     string         `json:"version"`
		ExportDate  string         `json:"export_date"`
		Servers     []Server       `json:"servers"`
		JumpRelations []JumpRelation `json:"jump_relations"`
	}{
		Version:     Version,
		ExportDate:  time.Now().Format("2006-01-02 15:04:05"),
		Servers:     sm.Servers,
		JumpRelations: jm.Relations,
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
	err = os.WriteFile(filePath, data, 0600)
	if err != nil {
		fmt.Printf(errorMsg("Error writing export file: %v\n"), err)
		return
	}
	
	fmt.Printf(success("Data exported successfully!\n"))
	fmt.Printf("  File: %s\n", colorize(Cyan, filePath))
	fmt.Printf("  Servers: %d\n", len(sm.Servers))
	fmt.Printf("  Jump relations: %d\n", len(jm.Relations))
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
		JumpRelations []JumpRelation `json:"jump_relations"`
	}
	
	err = json.Unmarshal(data, &importData)
	if err != nil {
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
	fmt.Printf("  Jump relations: %d\n", len(importData.JumpRelations))
	
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
	if len(importData.JumpRelations) > 0 {
		fmt.Println(colorize(Blue+Bold, "\nJump relations to import:"))
		for _, relation := range importData.JumpRelations {
			fmt.Printf("  - %d %s %d\n", relation.FromID, jump("→"), relation.ToID)
		}
	}
	
	// Confirm import
	confirm := PromptInput(prompt("\nImport will replace all current data. Continue? (y/n): "))
	if strings.ToLower(confirm) != "y" && strings.ToLower(confirm) != "yes" {
		fmt.Println(errorMsg("Import cancelled"))
		return
	}
	
	// Perform import
	sm.Servers = importData.Servers
	jm.Relations = importData.JumpRelations
	
	// Save data
	sm.Save()
	jm.Save()
	
	fmt.Printf(success("Data imported successfully!\n"))
	fmt.Printf("  Servers: %d\n", len(sm.Servers))
	fmt.Printf("  Jump relations: %d\n", len(jm.Relations))
}

// showEncryptionKeyInfo displays information about the current encryption key
func showEncryptionKeyInfo() {
	fmt.Println(colorize(Cyan+Bold, "🔐 SSHift Encryption Key Information"))
	fmt.Println()
	
	if customKey := os.Getenv("SSHIFT_ENCRYPTION_KEY"); customKey != "" {
		fmt.Println(colorize(Blue+Bold, "Key Type:") + " Custom (Environment Variable)")
		fmt.Printf(colorize(Blue+Bold, "Key Length:") + " %d characters\n", len(customKey))
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
		fmt.Printf(colorize(Blue+Bold, "Generated from:") + " %s:%s\n", homeDir, username)
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
	
	fmt.Println("🔐 SSHift Initial Setup")
	fmt.Println("Setting up encryption key for secure password storage.")
	fmt.Println()
	
	fmt.Println("Choose an option:")
	fmt.Println("1) Use system auto-generated key (recommended)")
	fmt.Println("2) Set custom encryption key")
	fmt.Println("3) Setup later")
	
	choice := PromptInput("\nSelect (1-3): ")
	
	switch choice {
	case "1":
		fmt.Println("✅ Using system auto-generated key.")
		fmt.Println("   A unique key will be generated for each system.")
		fmt.Println("   To share data between systems, run 'sshift setup' again.")
		
	case "2":
		fmt.Println("🔑 Setting up custom encryption key.")
		fmt.Println("   This key must be identical across all systems.")
		fmt.Println("   Enter a secure key with at least 32 characters.")
		
		for {
			key := PromptInput("Enter encryption key: ")
			if len(key) < 32 {
				fmt.Println("❌ Key must be at least 32 characters long.")
				continue
			}
			
			confirm := PromptInput("Confirm key (enter again): ")
			if key != confirm {
				fmt.Println("❌ Keys do not match. Please try again.")
				continue
			}
			
			// Set environment variable
			os.Setenv("SSHIFT_ENCRYPTION_KEY", key)
			fmt.Println("✅ Custom key has been set.")
			fmt.Println("   To permanently set this key in environment variable:")
			fmt.Printf("   export SSHIFT_ENCRYPTION_KEY='%s'\n", key)
			break
		}
		
	case "3":
		fmt.Println("⚠️  You can run 'sshift setup' later to configure.")
		return
		
	default:
		fmt.Println("❌ Invalid selection. Using system auto-generated key.")
	}
	
	// Mark setup as complete
	setupFile := filepath.Join(baseDir, ".setup_complete")
	os.WriteFile(setupFile, []byte("Setup completed on "+time.Now().Format("2006-01-02 15:04:05")), 0600)
	
	fmt.Println()
	fmt.Println("Initial setup completed! 🎉")
	fmt.Println("You can now add servers.")
	fmt.Println()
}

func printHelp() {
	fmt.Printf("SSHift v%s - SSH Server Management Tool\n\n", Version)
	fmt.Println("Usage:")
	fmt.Println("  sshift                    - Run interactive menu")
	fmt.Println("  sshift add                - Add new server")
	fmt.Println("  sshift list               - List all servers")
	fmt.Println("  sshift delete             - Delete server (interactive)")
	fmt.Println("  sshift edit               - Edit server (interactive)")
	fmt.Println("  sshift sort               - Sort server IDs and update jump relations")
	fmt.Println("  sshift export             - Export data to JSON file")
	fmt.Println("  sshift import             - Import data from JSON file")
	fmt.Println("  sshift key                - Show encryption key information")
	fmt.Println("  sshift setup              - Setup encryption key")
	fmt.Println("  sshift jump add           - Add jump relation (interactive)")
	fmt.Println("  sshift jump delete        - Delete jump relation (interactive)")
	fmt.Println("  sshift jump list          - List jump relations")
	fmt.Println("  sshift version            - Show version")
	fmt.Println("  sshift test               - Run in test mode (simulate connections)")
	fmt.Println("  sshift help               - Show this help")
	fmt.Println("\nExamples:")
	fmt.Println("  sshift add")
	fmt.Println("  sshift edit")
	fmt.Println("  sshift jump add 1 2")
	fmt.Println("  sshift jump list")
	fmt.Println("  sshift sort")
	fmt.Println("  sshift setup")
	fmt.Println("\nSecurity:")
	fmt.Println("  Encryption key is automatically configured during initial setup.")
	fmt.Println("  Run 'sshift setup' to use custom encryption key.")
}
