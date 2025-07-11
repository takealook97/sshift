# SSHift Makefile

# 변수 정의
BINARY_NAME=sshift
BUILD_DIR=build
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

# 기본 타겟
.PHONY: all
all: clean build

# 빌드
.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) main.go
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# 릴리즈 빌드 (최적화)
.PHONY: release
release:
	@echo "Building release version..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -a -installsuffix cgo -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 main.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -a -installsuffix cgo -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 main.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -a -installsuffix cgo -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 main.go
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -a -installsuffix cgo -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe main.go
	@echo "Release builds complete"

# 설치
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME)..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "Installation complete"

# 의존성 설치
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	go mod tidy
	go mod download
	@echo "Dependencies installed"

# 테스트
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...
	@echo "Tests complete"

# 테스트 커버리지
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# 린트
.PHONY: lint
lint:
	@echo "Running linter..."
	golangci-lint run
	@echo "Linting complete"

# 포맷팅
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...
	@echo "Formatting complete"

# 정리
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	@echo "Clean complete"

# 개발 모드 실행
.PHONY: dev
dev: build
	@echo "Running in development mode..."
	./$(BUILD_DIR)/$(BINARY_NAME)

# 테스트 모드 실행
.PHONY: test-run
test-run: build
	@echo "Running in test mode..."
	SSHIFT_TEST_MODE=1 ./$(BUILD_DIR)/$(BINARY_NAME)

# Generate Homebrew Formula
.PHONY: homebrew-formula
homebrew-formula:
	@echo "Generating Homebrew Formula..."
	@mkdir -p Formula
	@cat > Formula/sshift.rb << EOF
class Sshift < Formula
  desc "SSH server management tool with jump server support"
  homepage "https://github.com/takealook97/sshift"
  version "$(VERSION)"
  license "MIT"
  
  # Go source code
  url "https://github.com/takealook97/sshift/archive/refs/tags/$(VERSION).tar.gz"
  sha256 "$$(curl -sL "https://github.com/takealook97/sshift/archive/refs/tags/$(VERSION).tar.gz" | shasum -a 256 | cut -d' ' -f1)"
  
  depends_on "go" => :build

  def install
    # Set version from git tag
    ldflags = %W[
      -s -w
      -X main.Version=#{version}
    ]
    
    system "go", "build", *std_go_args(ldflags: ldflags), "-o", bin/"sshift", "main.go"
  end

  test do
    # Test version command
    assert_match "SSHift v#{version}", shell_output("#{bin}/sshift version")
    
    # Test help command
    assert_match "Usage:", shell_output("#{bin}/sshift help")
  end
end
EOF
	@echo "Homebrew Formula generated: Formula/sshift.rb"

# Test Homebrew Formula
.PHONY: homebrew-test
homebrew-test: homebrew-formula
	@echo "Testing Homebrew Formula..."
	@brew install --build-from-source ./Formula/sshift.rb
	@echo "Homebrew Formula test completed"

# Update Homebrew Formula SHA256
.PHONY: homebrew-sha256
homebrew-sha256:
	@echo "Calculating SHA256 for version $(VERSION)..."
	@SHA256=$$(curl -sL "https://github.com/takealook97/sshift/archive/refs/tags/$(VERSION).tar.gz" | shasum -a 256 | cut -d' ' -f1); \
	echo "SHA256: $$SHA256"; \
	sed -i '' "s/sha256 \"[^\"]*\"/sha256 \"$$SHA256\"/" Formula/sshift.rb
	@echo "SHA256 updated in Formula/sshift.rb"

# 도움말
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build        - Build the application"
	@echo "  release      - Build release versions for multiple platforms"
	@echo "  install      - Install to /usr/local/bin"
	@echo "  deps         - Install dependencies"
	@echo "  test         - Run tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  lint         - Run linter"
	@echo "  fmt          - Format code"
	@echo "  clean        - Clean build artifacts"
	@echo "  dev          - Build and run in development mode"
	@echo "  test-run     - Build and run in test mode"
	@echo "  homebrew-formula - Generate Homebrew Formula"
	@echo "  homebrew-test    - Test Homebrew Formula"
	@echo "  homebrew-sha256  - Update SHA256 in Formula"
	@echo "  help         - Show this help message" 