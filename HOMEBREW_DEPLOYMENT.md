# Homebrew Deployment Guide

This document explains how to deploy SSHift through Homebrew.

## 📋 Prerequisites

1. **GitHub Repository**: SSHift source code must be on GitHub
2. **GitHub Personal Access Token**: Token with access to Homebrew tap repository
3. **Release Tags**: Git tags required for each version (e.g., `v1.0.0`)

## 🏗️ Homebrew Tap Repository Setup

### 1. Create Tap Repository

Create `homebrew-sshift` repository on GitHub:

- Repository name: `homebrew-sshift`
- Set as public repository
- Create README file

### 2. GitHub Secrets Configuration

Set up the following secrets in the main SSHift repository:

1. GitHub repository settings → Secrets and variables → Actions
2. Add `HOMEBREW_TAP_TOKEN`:
   - Personal Access Token (Classic)
   - Requires `repo` permission
   - Requires `workflow` permission

## 🔄 Automated Deployment Workflow

### Release Process

1. **Create and push tag**:

   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. **GitHub Actions execution**:

   - `release.yml`: Binary build and GitHub release creation
   - `homebrew-tap.yml`: Homebrew Formula update

3. **Automatic updates**:
   - Formula version update
   - SHA256 hash calculation and update
   - Automatic commit to tap repository

## 📦 Manual Deployment (if needed)

### 1. Manual Formula Update

```bash
# Calculate source tarball SHA256
VERSION="v1.0.0"
SOURCE_URL="https://github.com/takealook97/sshift/archive/refs/tags/${VERSION}.tar.gz"
SHA256=$(curl -sL "$SOURCE_URL" | shasum -a 256 | cut -d' ' -f1)
echo "SHA256: $SHA256"
```

### 2. Update Formula File

Modify `homebrew-sshift/sshift.rb` file:

```ruby
class Sshift < Formula
  desc "SSH server management tool with jump server support"
  homepage "https://github.com/takealook97/sshift"
  version "1.0.0"
  license "MIT"

  url "https://github.com/takealook97/sshift/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "calculated_sha256_hash"

  depends_on "go" => :build

  def install
    ldflags = %W[
      -s -w
      -X main.Version=#{version}
    ]

    system "go", "build", *std_go_args(ldflags: ldflags), "-o", bin/"sshift", "main.go"
  end

  test do
    assert_match "SSHift v#{version}", shell_output("#{bin}/sshift version")
    assert_match "Usage:", shell_output("#{bin}/sshift help")
  end
end
```

### 3. Test Formula

```bash
# Test Formula locally
brew install --build-from-source ./sshift.rb

# Test installation
brew install sshift
sshift version
```

## 🚀 User Installation Methods

### Basic Installation

```bash
# Add tap
brew tap takealook97/sshift

# Install SSHift
brew install sshift
```

### Direct Installation

```bash
# Use Formula directly
brew install takealook97/sshift/sshift
```

### Update

```bash
# Check for updates
brew update

# Update SSHift
brew upgrade sshift
```

## 🔧 Troubleshooting

### Common Issues

1. **SHA256 Mismatch**:

   ```bash
   # Recalculate SHA256
   curl -sL "https://github.com/takealook97/sshift/archive/refs/tags/v1.0.0.tar.gz" | shasum -a 256
   ```

2. **Build Failure**:

   ```bash
   # Check Go version
   go version

   # Check dependencies
   brew install go
   ```

3. **Permission Issues**:
   ```bash
   # Fix Homebrew permissions
   sudo chown -R $(whoami) $(brew --prefix)/*
   ```

### Debugging

```bash
# Check Formula information
brew info sshift

# Check installation logs
brew install -v sshift

# Validate Formula
brew audit --strict sshift
```

## 📝 Release Checklist

- [ ] Create Git tag (`v1.0.0`)
- [ ] Create GitHub release
- [ ] Verify Formula SHA256 update
- [ ] Verify Homebrew tap update
- [ ] Complete installation testing
- [ ] Update documentation

## 🔗 Useful Links

- [Homebrew Formula Cookbook](https://docs.brew.sh/Formula-Cookbook)
- [Homebrew Tap](https://docs.brew.sh/Taps)
- [GitHub Actions](https://docs.github.com/en/actions)
- [Go Modules](https://golang.org/ref/mod)
