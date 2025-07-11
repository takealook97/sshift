# SSHift - SSH Server Management Tool

SSHift is a powerful Go-based CLI tool for managing SSH servers with advanced features including jump server support, encrypted password storage, and an interactive menu system.

## 🚀 Features

- **🔐 Secure Password Management**: AES-256 encrypted password storage with system-specific keys
- **🔄 Jump Server Support**: Automatic connection through jump servers using SSH ProxyJump
- **📋 Interactive Menu**: User-friendly terminal interface with colored output
- **🔑 Multiple Authentication**: Password, SSH key, and PEM file support
- **📊 Data Export/Import**: Backup and restore server configurations
- **🛡️ Security**: File permissions (0600) and memory-safe password handling
- **🎨 Beautiful UI**: Colored terminal output for better user experience

## 📦 Installation

### Prerequisites

- Go 1.24 or higher
- SSH client
- macOS, Linux, or Windows (WSL)

### Build from Source

```bash
# Clone repository
git clone https://github.com/takealook97/sshift.git
cd sshift

# Install dependencies
go mod tidy

# Build
go build -o sshift

# Install globally (optional)
sudo cp sshift /usr/local/bin/
```

### Install via Homebrew

```bash
# Add custom tap
brew tap takealook97/sshift

# Install SSHift
brew install sshift
```

### Install via Homebrew (Alternative)

```bash
# Install directly from Formula
brew install takealook97/sshift/sshift
```

## 🎯 Usage

### Basic Commands

```bash
# Run interactive menu
sshift

# Add new server
sshift add

# List all servers
sshift list

# Connect to server
sshift connect <id>

# Delete server (interactive)
sshift delete

# Edit server (interactive)
sshift edit

# Manage jump relations
sshift jump add
sshift jump delete
sshift jump list
sshift jump connect <from_id> <to_id>

# Export/Import data
sshift export
sshift import

# Security
sshift key          # Show encryption key info
sshift setup        # Setup encryption key
```

### Interactive Menu

When you run `sshift` without arguments, you'll see an interactive menu:

```
Welcome to SSHift! 🚀

ID | NAME           | HOST            | USER  | AUTH
---|----------------|-----------------|-------|------
 1 | Web Server     | 192.168.1.100   | admin | pass
 2 | Database       | 192.168.1.101   | root  | pem
 3 | Backup Server  | 192.168.1.102   | user  | Key

Select a server to connect:
```

### Add Server Example

```bash
$ sshift add
Enter host (IP or domain): 192.168.1.100
Enter username: admin
Enter server name: Web Server
Use password? (y/n): y
Enter password: ********
Confirm password: ********
✅ Added server: Web Server (admin@192.168.1.100)
```

### Jump Server Setup

```bash
# Add jump relation (from server 1 to server 2)
sshift jump add 1 2

# List jump relations
sshift jump list
Jump Relations:
- 1 → 2

# Connect through jump server
sshift jump connect 1 2
```

## 🔐 Security Features

### Encryption

SSHift uses AES-256-CFB encryption for password storage:

- **System Auto-Generated Key**: Default encryption using system-specific information
- **Custom Key**: Set `SSHIFT_ENCRYPTION_KEY` environment variable for cross-system compatibility
- **File Permissions**: All data files use 0600 permissions (owner read/write only)

### Authentication Methods

1. **Password Authentication**: Encrypted storage with confirmation
2. **SSH Key Authentication**: Uses default SSH keys or custom key paths
3. **PEM File Authentication**: Support for custom private key files

### Key Management

```bash
# View current encryption key info
sshift key

# Setup custom encryption key
sshift setup

# Set environment variable for cross-system use
export SSHIFT_ENCRYPTION_KEY='your-32-character-secret-key'
```

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
  "version": "1.0.0",
  "export_date": "2024-01-15 10:30:00",
  "servers": [...],
  "jump_relations": [...]
}
```

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

### Server Management

```bash
# Sort server IDs and update jump relations
sshift sort

# Edit existing server
sshift edit

# Delete server (removes related jump relations)
sshift delete
```

### Jump Server Features

- **Automatic Detection**: Auto-jump when connecting to target servers
- **ProxyJump Support**: Uses SSH ProxyJump for secure connections
- **Password Support**: Handles password authentication through jump servers
- **SSH Key Support**: Works with SSH keys for jump connections

## 🔍 Troubleshooting

### Common Issues

1. **Password Decryption Failed**

   - Run `sshift setup` to configure encryption key
   - Check if `SSHIFT_ENCRYPTION_KEY` is set correctly

2. **Jump Server Connection Issues**

   - Verify both servers are accessible
   - Check SSH key permissions (600)
   - Ensure jump relation is correctly configured

3. **Permission Denied**
   - Check file permissions: `ls -la ~/.sshift/`
   - Should be 0600 for all files

### Debug Mode

```bash
# Enable test mode for debugging
SSHIFT_TEST_MODE=1 ./sshift
```

## 📝 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

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
