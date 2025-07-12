# SSHift Makefile

# Variable definitions
BINARY_NAME=sshift
BUILD_DIR=build
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

# Default target
.PHONY: all
all: clean build

# Build
.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) main.go
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Release build (optimized)
.PHONY: release
release:
	@echo "Building release version..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -a -installsuffix cgo -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 main.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -a -installsuffix cgo -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 main.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -a -installsuffix cgo -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 main.go
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -a -installsuffix cgo -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe main.go
	@echo "Release builds complete"

# Install
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME)..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "Installation complete"

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	go mod tidy
	go mod download
	@echo "Dependencies installed"

# Test
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...
	@echo "Tests complete"

# Test coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Coverage report (no threshold)
.PHONY: test-coverage-report
test-coverage-report:
	@echo "Running tests with coverage report..."
	@go test -v -coverprofile=coverage.out -covermode=atomic ./...
	@COVERAGE=$$(go tool cover -func=coverage.out | grep total: | awk '{print $$3}' | sed 's/%//'); \
	echo "Total coverage: $$COVERAGE%"; \
	go tool cover -html=coverage.out -o coverage.html; \
	echo "Coverage report generated: coverage.html"

# Lint
.PHONY: lint
lint:
	@echo "Running linter..."
	golangci-lint run
	@echo "Linting complete"

# Format
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...
	@echo "Formatting complete"

# Clean
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	@echo "Clean complete"

# Development mode run
.PHONY: dev
dev: build
	@echo "Running in development mode..."
	./$(BUILD_DIR)/$(BINARY_NAME)

# Test mode run
.PHONY: test-run
test-run: build
	@echo "Running in test mode..."
	SSHIFT_TEST_MODE=1 ./$(BUILD_DIR)/$(BINARY_NAME)

# Generate Homebrew Formula
.PHONY: homebrew-formula
homebrew-formula:
	@echo "Generating Homebrew Formula..."
	@mkdir -p Formula
	@echo 'class Sshift < Formula' > Formula/sshift.rb
	@echo '  desc "SSH server management tool with jump server support"' >> Formula/sshift.rb
	@echo '  homepage "https://github.com/takealook97/sshift"' >> Formula/sshift.rb
	@echo '  version "$(VERSION)"' >> Formula/sshift.rb
	@echo '  license "MIT"' >> Formula/sshift.rb
	@echo '' >> Formula/sshift.rb
	@echo '  # Go source code' >> Formula/sshift.rb
	@echo '  url "https://github.com/takealook97/sshift/archive/refs/tags/$(VERSION).tar.gz"' >> Formula/sshift.rb
	@echo '  sha256 "$$(curl -sL "https://github.com/takealook97/sshift/archive/refs/tags/$(VERSION).tar.gz" | shasum -a 256 | cut -d" " -f1)"' >> Formula/sshift.rb
	@echo '' >> Formula/sshift.rb
	@echo '  depends_on "go" => :build' >> Formula/sshift.rb
	@echo '' >> Formula/sshift.rb
	@echo '  def install' >> Formula/sshift.rb
	@echo '    # Set version from git tag' >> Formula/sshift.rb
	@echo '    ldflags = %W[' >> Formula/sshift.rb
	@echo '      -s -w' >> Formula/sshift.rb
	@echo '      -X main.Version=#{version}' >> Formula/sshift.rb
	@echo '    ]' >> Formula/sshift.rb
	@echo '' >> Formula/sshift.rb
	@echo '    system "go", "build", *std_go_args(ldflags: ldflags), "-o", bin/"sshift", "main.go"' >> Formula/sshift.rb
	@echo '  end' >> Formula/sshift.rb
	@echo '' >> Formula/sshift.rb
	@echo '  test do' >> Formula/sshift.rb
	@echo '    # Test version command' >> Formula/sshift.rb
	@echo '    assert_match "SSHift v#{version}", shell_output("#{bin}/sshift version")' >> Formula/sshift.rb
	@echo '' >> Formula/sshift.rb
	@echo '    # Test help command' >> Formula/sshift.rb
	@echo '    assert_match "Usage:", shell_output("#{bin}/sshift help")' >> Formula/sshift.rb
	@echo '  end' >> Formula/sshift.rb
	@echo 'end' >> Formula/sshift.rb
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

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build        - Build the application"
	@echo "  release      - Build release versions for multiple platforms"
	@echo "  install      - Install to /usr/local/bin"
	@echo "  deps         - Install dependencies"
	@echo "  test         - Run tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  test-coverage-report - Run tests with coverage report (no threshold)"
	@echo "  lint         - Run linter"
	@echo "  fmt          - Format code"
	@echo "  clean        - Clean build artifacts"
	@echo "  dev          - Build and run in development mode"
	@echo "  test-run     - Build and run in test mode"
	@echo "  homebrew-formula - Generate Homebrew Formula"
	@echo "  homebrew-test    - Test Homebrew Formula"
	@echo "  homebrew-sha256  - Update SHA256 in Formula"
	@echo "  help         - Show this help message" 