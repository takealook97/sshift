# Homebrew SSHift Tap

This repository contains the Homebrew formula for [SSHift](https://github.com/takealook97/sshift), a powerful SSH server management tool with jump server support.

## 🚀 Installation

### Add the tap and install

```bash
# Add this tap
brew tap takealook97/sshift

# Install SSHift
brew install sshift
```

### Install directly

```bash
# Install without adding the tap
brew install takealook97/sshift/sshift
```

## 📦 What is SSHift?

SSHift is a powerful Go-based CLI tool for managing SSH servers with advanced features:

- **🔐 Secure Password Management**: AES-256 encrypted password storage
- **🔄 Jump Server Support**: Automatic connection through jump servers
- **📋 Interactive Menu**: User-friendly terminal interface
- **🔑 Multiple Authentication**: Password, SSH key, and PEM file support
- **📊 Data Export/Import**: Backup and restore server configurations
- **🛡️ Security**: File permissions and memory-safe password handling

## 🎯 Quick Start

```bash
# Run interactive menu
sshift

# Add new server
sshift add

# List all servers
sshift list

# Show help
sshift help
```

## 📋 Requirements

- macOS or Linux
- Go 1.24+ (for building from source)
- SSH client

## 🔧 Development

### Building from source

```bash
# Clone the main repository
git clone https://github.com/takealook97/sshift.git
cd sshift

# Build
go build -o sshift main.go

# Install
sudo cp sshift /usr/local/bin/
```

### Updating the formula

The formula is automatically updated when new releases are published. For manual updates:

1. Update the version in `sshift.rb`
2. Calculate the new SHA256 hash
3. Update the URL and SHA256 in the formula

## 📝 License

This tap is licensed under the MIT License. See the [main SSHift repository](https://github.com/takealook97/sshift) for more details.

## 🔗 Links

- [SSHift Repository](https://github.com/takealook97/sshift)
- [SSHift Documentation](https://github.com/takealook97/sshift#readme)
- [Homebrew Documentation](https://docs.brew.sh/)

## 🤝 Contributing

Issues and pull requests are welcome! Please visit the [main SSHift repository](https://github.com/takealook97/sshift) for contribution guidelines.
