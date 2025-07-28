# SSHift - SSH Server Management Tool

```
              __    _ ______
   __________/ /_  (_) __/ /_______________________
  / ___/ ___/ __ \/ / /_/ __/________________
 (__  |__  ) / / / / __/ /_____________
/____/____/_/ /_/_/_/  \__/______
```

SSHift is a powerful Go-based CLI tool for managing SSH servers with advanced features including jump server support, encrypted password storage, and an interactive menu system.

## 🚀 Features

- **🔐 Secure Password Management**: AES-256-CFB encrypted password storage with system-specific or custom keys
- **🔄 Jump Server Support**: Automatic connection through jump servers using SSH ProxyJump
- **📋 Interactive Menu**: User-friendly terminal interface with colored output and emojis
- **🔑 Multiple Authentication**: Password, SSH key, and PEM file support
- **📊 Data Export/Import**: Backup and restore server configurations
- **🛡️ Security**: File permissions (0600), memory-safe password handling, and input validation
- **🎨 Beautiful UI**: Colored terminal output with emojis for better user experience
- **🔒 Security Features**: SSH key permission validation, circular jump prevention, secure memory handling
- **📋 Smart ID Management**: Auto-increment uses smallest available ID for efficient numbering
- **📊 Organized Display**: Servers and jump relations automatically sorted by ID for better organization
- **🎯 Consistent UI**: Unified prompt style with 🔍 emoji and proper table formatting

## 🚀 Installation

### Quick Install (Recommended)

```bash
# One-line installation (auto-detects OS/ARCH)
curl -fsSL https://raw.githubusercontent.com/takealook97/sshift/main/install.sh | bash

# Uninstall
curl -fsSL https://raw.githubusercontent.com/takealook97/sshift/main/install.sh | bash -s uninstall
```

### Homebrew (macOS/Linux)

```bash
brew install takealook97/sshift/sshift
```

### Manual Download

1. Download the binary for your OS/architecture from [GitHub Releases](https://github.com/takealook97/sshift/releases)
2. Make it executable: `chmod +x sshift`
3. Move to your PATH: `sudo mv sshift /usr/local/bin/`

### Build from Source

```bash
git clone https://github.com/takealook97/sshift.git
cd sshift
go build -o sshift main.go
sudo mv sshift /usr/local/bin/
```

---

## ⚙️ Build & Release Automation

- All platform binaries are built and uploaded automatically by **GitHub Actions (Ubuntu environment)**.
- Users can simply download the right file from Releases without worrying about the build environment.
- Homebrew, install script, and manual download all use the same Release binaries.
- You can check the latest automation status in the [Actions tab](https://github.com/takealook97/sshift/actions).

## 🎯 Usage

### Basic Commands

````bash
# Run interactive menu
sshift

# Direct connection by server ID or name
sshift <server_id|name>

# Direct connection with command execution
sshift <server_id|name> --cmd <command>

# Add new server
sshift add

# List all servers
sshift list

# Delete server (interactive)
sshift delete

# Edit server (interactive)
sshift edit

# Sort server IDs and update jump relations
sshift sort

# Manage jump relations
sshift jump add
sshift jump delete
sshift jump list

# Export/Import data
sshift export
sshift import

# Security
sshift key          # Show encryption key info
sshift setup        # Setup encryption key
sshift test         # Run in test mode (simulate connections)
sshift version      # Show version
sshift help         # Show help

### Direct Connection Examples

```bash
# Connect to server by ID
sshift 1

# Connect to server by name (case-insensitive)
sshift "Web Server"
sshift web-server

# Connect and execute a command
sshift 1 --cmd "ls -la"
sshift "Database" --cmd "df -h"

# Connect and execute multiple commands
sshift 2 --cmd "cd /var/log && tail -f access.log"
````

```

### Interactive Menu

When you run `sshift` without arguments, you'll see an interactive menu:

```

Welcome to SSHift! 🚀

| ID  | SERVER NAME   | IP            | USER  | AUTH |
| --- | ------------- | ------------- | ----- | ---- |
| 1)  | Web Server    | 192.168.1.100 | admin | pass |
| 2)  | Database      | 192.168.1.101 | root  | pem  |
| 3)  | Backup Server | 192.168.1.102 | user  | Key  |
| 0)  | Exit          | -             | -     | -    |

🔍 Select a server to connect:

````

**Note**: Servers are automatically sorted by ID for better organization.

### Add Server Example

```bash
$ sshift add

Current servers:

 ID | SERVER NAME                    | IP              | USER      | AUTH
----|--------------------------------|-----------------|-----------|------
 1) | Web Server                     | 192.168.1.100   | admin     | pass
 2) | Database                       | 192.168.1.101   | root      | pem

🔍  Enter server ID [3] (press Enter for auto-increment):
🔍  Enter host (IP or domain): 192.168.1.102
🔍  Enter username: backup
🔍  Enter server name: Backup Server
🔍  Use password? (y/n): n
Using SSH key authentication.

Available SSH keys:
  1) ~/.ssh/id_rsa
  2) ~/.ssh/id_ed25519
  3) Enter custom path

🔍  Select SSH key (1-3): 1
✅ Selected: ~/.ssh/id_rsa
✅ Added server: Backup Server (ID: 3, backup@192.168.1.102)
````

**Note**: Auto-increment uses the smallest available ID, not the maximum + 1.

### Jump Server Setup

```bash
# Add jump relation (interactive)
sshift jump add
# Select FROM server ID: 1
# Select TO server ID: 2
# ✅ Jump relation created: Web Server (1) → Database (2)

# List jump relations
sshift jump list
FROM                    | TO
----------------------------------------
1) Web Server           | 2) Database
1) Web Server           | 3) Backup Server

# Connect through jump server (automatic when selecting target server)
sshift
# Select server 2 → automatically jumps through server 1
```

**Note**: Jump relations are sorted by FROM ID, then by TO ID when FROM IDs are equal.

## 🔐 Security Features

### Encryption

SSHift uses AES-256-CFB encryption for password storage:

- **System Auto-Generated Key**: Default encryption using system-specific information with high entropy
- **Custom Key**: Set `SSHIFT_ENCRYPTION_KEY` environment variable for cross-system compatibility
- **Secure Memory Handling**: Automatic memory clearing of sensitive data
- **File Permissions**: All data files use 0600 permissions (owner read/write only)

### Authentication Methods

1. **Password Authentication**:
   - Encrypted storage with confirmation and basic validation
   - Automatic password input using `sshpass` (if available)
   - Fallback to Go's SSH package for interactive password input
   - Secure memory handling with automatic clearing
2. **SSH Key Authentication**: Uses default SSH keys or custom key paths with permission validation
3. **PEM File Authentication**: Support for custom private key files

### Security Validations

- **SSH Key Permissions**: Validates 600 permissions for SSH key files
- **Input Sanitization**: Removes null bytes and problematic characters
- **Circular Jump Prevention**: Prevents circular jump server relationships
- **Basic Password Validation**: Checks for empty passwords and invalid characters

### Key Management

```bash
# View current encryption key info
sshift key

# Setup custom encryption key (with data migration)
sshift setup

# Set environment variable for cross-system use
export SSHIFT_ENCRYPTION_KEY='your-32-character-secret-key'
```

**Important Notes:**

- **System Auto-Generated Key**: Consistent key generation on the same system
- **Custom Key**: Automatically saved to permanent storage
- **Data Migration**: Existing encrypted passwords are automatically migrated when changing keys
- **Cross-System Sharing**: Use custom keys for sharing data between systems
- **Export/Import Compatibility**: Same encryption key required for importing encrypted passwords

## 📁 Data Structure

### Server Information (`~/.sshift/servers.json`)

```json
[
  {
    "id": 1,
    "host": "192.168.1.100",
    "user": "admin",
    "name": "Web Server",
    "password": "encrypted-password-here",
    "key_path": ""
  }
]
```

### Jump Relations (`~/.sshift/jumps.json`)

```json
[
  {
    "from_id": 1,
    "to_id": 2
  }
]
```

### Export Files (`~/.ssh/sshift_export_*.json`)

```json
{
  "version": "dev",
  "export_date": "2024-01-15 10:30:00",
  "servers": [...],
  "jump_relations": [...]
}
```

**Security Information:**

- **Encrypted Passwords**: Passwords remain encrypted in export files
- **Key Dependency**: Import requires the same encryption key used during export
- **File Permissions**: Export files use 0600 permissions (owner read/write only)
- **Storage Location**: Files stored in `~/.ssh/` directory for security consistency

## 🔧 Configuration

### Data Storage

All data is stored in `~/.sshift/` directory:

- `servers.json`: Server information with encrypted passwords
- `jumps.json`: Jump server relationships
- File permissions: 0600 (owner read/write only)

### Environment Variables

```bash
# Custom encryption key (32+ characters)
export SSHIFT_ENCRYPTION_KEY='your-secret-key-here'

# Test mode (simulate connections)
export SSHIFT_TEST_MODE=1
```

## 🛠️ Development

### Project Structure

```
sshift/
├── main.go              # Main application
├── go.mod               # Go module definition
├── go.sum               # Dependency checksums
├── README.md            # Project documentation
├── Formula/             # Homebrew formula
│   └── sshift.rb
├── .github/             # GitHub Actions
├── Makefile             # Build automation
└── main_test.go         # Tests
```

### Build Commands

```bash
# Build for current platform
go build -o sshift

# Build for multiple platforms
make build-all

# Run tests
go test ./...

# Run in test mode
SSHIFT_TEST_MODE=1 ./sshift
```

### Dependencies

```go
require (
    golang.org/x/crypto v0.17.0
    golang.org/x/term v0.15.0
)
```

## 🚀 Advanced Features

### Export/Import

```bash
# Export all data to JSON file
sshift export
# Creates: ~/.ssh/sshift_export_20240115_143022.json

# Import data from JSON file
sshift import
# Interactive file selection and preview
```

**⚠️ Important Security Note:**

- **Encryption Key Requirement**: Imported data with encrypted passwords requires the **same encryption key** used during export
- **Cross-System Import**: Use custom encryption keys (`sshift setup`) for sharing data between systems
- **System Auto-Generated Keys**: Cannot be shared between different systems (system-specific)
- **Password Recovery**: If encryption keys don't match, passwords will be inaccessible and need to be re-entered

### Server Management

```bash
# Sort server IDs and update jump relations
sshift sort

# Edit existing server
sshift edit

# Delete server (removes related jump relations)
sshift delete

# List servers (sorted by ID)
sshift list
```

### Jump Server Features

- **Automatic Detection**: Auto-jump when connecting to target servers
- **ProxyJump Support**: Uses SSH ProxyJump for secure connections
- **Password Support**: Handles password authentication through jump servers
- **SSH Key Support**: Works with SSH keys for jump connections
- **Circular Prevention**: Prevents circular jump relationships
- **Organized Display**: Jump relations sorted by FROM ID, then by TO ID
- **Clean Interface**: Removed redundant headers for cleaner output

## 🔍 Troubleshooting

### Common Issues

1. **Password Decryption Failed**

   - Run `sshift setup` to configure encryption key
   - Check if `SSHIFT_ENCRYPTION_KEY` is set correctly
   - Verify system-specific key generation
   - If changing keys, ensure data migration completed successfully
   - **For imported data**: Ensure the same encryption key is used as during export
   - **Cross-system import**: Use custom encryption keys instead of system auto-generated keys

2. **Jump Server Connection Issues**

   - Verify both servers are accessible
   - Check SSH key permissions (600)
   - Ensure jump relation is correctly configured
   - Check for circular jump relationships

3. **Permission Denied**

   - Check file permissions: `ls -la ~/.sshift/`
   - Should be 0600 for all files
   - Check SSH key permissions: `ls -la ~/.ssh/`

4. **SSH Key Permission Warnings**

   - Fix SSH key permissions: `chmod 600 ~/.ssh/your_key`
   - SSHift validates key file permissions for security

5. **Password Authentication Issues**

   - Install `sshpass` for automatic password input: `brew install sshpass` (macOS) or `apt install sshpass` (Ubuntu)
   - Without `sshpass`, passwords will be prompted interactively
   - Check if password is correctly encrypted and decrypted
   - Verify encryption key is consistent across sessions

6. **Table Formatting Issues**
   - Table separators automatically align with content
   - Server lists are sorted by ID for consistent display
   - Jump relations are organized by FROM/TO ID order

### Debug Mode

```bash
# Enable test mode for debugging
SSHIFT_TEST_MODE=1 ./sshift
```

## 📝 License

MIT License - see LICENSE file for details.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/takealook97/sshift/issues)
- **Discussions**: [GitHub Discussions](https://github.com/takealook97/sshift/discussions)
- **Security**: Report security issues privately

## 🎉 Acknowledgments

- Built with Go and the `golang.org/x/crypto/ssh` package
- Inspired by the need for better SSH server management
- Thanks to the open-source community for amazing tools and libraries

---

**SSHift** - Making SSH server management simple and secure! 🔐✨

## Recommended Development Environment

- Go: **1.22.x**

> **Note**: This project uses Go 1.22.x for both local development and CI/CD to ensure compatibility.

### Example: Setting up the development environment

#### Using asdf

```bash
asdf install golang 1.22.4
asdf global golang 1.22.4
```

#### Using Homebrew

```bash
brew install go@1.22
brew unlink go && brew link --force --overwrite go@1.22
```

---

## How to run lint and tests

```bash
# Code formatting
go fmt ./...

# Code analysis
go vet ./...

# Tests
go test -v ./...
```

---

## CI/CD

GitHub Actions workflows use the following linting tools:

- **go fmt**: Code formatting
- **go vet**: Code analysis and common mistakes detection
- **go test**: Unit tests and coverage
