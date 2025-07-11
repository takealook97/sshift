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

## 🚀 배포 과정 (Deployment Process)

### 1단계: Tap Repository 생성

```bash
# GitHub에서 새 저장소 생성
# Repository name: homebrew-sshift
# Public repository로 설정
# README 파일 생성
```

### 2단계: Formula 파일 준비

현재 `Formula/sshift.rb` 파일이 올바르게 설정되어 있는지 확인:

```ruby
class Sshift < Formula
  desc "SSH server management tool with jump server support"
  homepage "https://github.com/takealook97/sshift"
  version "1.0.0"
  license "MIT"

  url "https://github.com/takealook97/sshift/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "실제_SHA256_해시"

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

### 3단계: GitHub Release 생성

```bash
# 태그 생성 및 푸시
git tag v1.0.0
git push origin v1.0.0

# GitHub에서 Release 생성
# - Tag: v1.0.0
# - Title: SSHift v1.0.0
# - Description: 릴리즈 노트 작성
```

### 4단계: SHA256 계산

```bash
# 소스 tarball의 SHA256 계산
VERSION="v1.0.0"
SOURCE_URL="https://github.com/takealook97/sshift/archive/refs/tags/${VERSION}.tar.gz"
SHA256=$(curl -sL "$SOURCE_URL" | shasum -a 256 | cut -d' ' -f1)
echo "SHA256: $SHA256"
```

### 5단계: Formula 업데이트

`homebrew-sshift` 저장소의 `sshift.rb` 파일을 업데이트:

```ruby
# version과 sha256 업데이트
version "1.0.0"
sha256 "계산된_SHA256_해시"
```

### 6단계: 자동화 (GitHub Actions)

메인 저장소에 GitHub Actions 워크플로우 추가:

```yaml
# .github/workflows/homebrew-tap.yml
name: Update Homebrew Tap

on:
  release:
    types: [published]

jobs:
  update-homebrew:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout tap repository
        uses: actions/checkout@v3
        with:
          repository: takealook97/homebrew-sshift
          token: ${{ secrets.HOMEBREW_TAP_TOKEN }}
          path: homebrew-tap

      - name: Calculate SHA256
        id: sha256
        run: |
          VERSION=${GITHUB_REF#refs/tags/}
          SOURCE_URL="https://github.com/takealook97/sshift/archive/refs/tags/${VERSION}.tar.gz"
          SHA256=$(curl -sL "$SOURCE_URL" | shasum -a 256 | cut -d' ' -f1)
          echo "sha256=$SHA256" >> $GITHUB_OUTPUT
          echo "version=${VERSION#v}" >> $GITHUB_OUTPUT

      - name: Update Formula
        run: |
          cd homebrew-tap
          sed -i "s/version \".*\"/version \"${{ steps.sha256.outputs.version }}\"/" sshift.rb
          sed -i "s/sha256 \".*\"/sha256 \"${{ steps.sha256.outputs.sha256 }}\"/" sshift.rb
          sed -i "s|url \".*\"|url \"https://github.com/takealook97/sshift/archive/refs/tags/${{ github.ref_name }}.tar.gz\"|" sshift.rb

      - name: Commit and push
        run: |
          cd homebrew-tap
          git config user.name "GitHub Actions"
          git config user.email "actions@github.com"
          git add sshift.rb
          git commit -m "Update sshift to ${{ steps.sha256.outputs.version }}"
          git push
```

### 7단계: GitHub Secrets 설정

메인 저장소의 Settings → Secrets and variables → Actions에서:

- `HOMEBREW_TAP_TOKEN`: Personal Access Token (repo 권한 필요)

## 📝 License

This tap is licensed under the MIT License. See the [main SSHift repository](https://github.com/takealook97/sshift) for more details.

## 🔗 Links

- [SSHift Repository](https://github.com/takealook97/sshift)
- [SSHift Documentation](https://github.com/takealook97/sshift#readme)
- [Homebrew Documentation](https://docs.brew.sh/)

## 🤝 Contributing

Issues and pull requests are welcome! Please visit the [main SSHift repository](https://github.com/takealook97/sshift) for contribution guidelines.
