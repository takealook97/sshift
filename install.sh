#!/bin/bash

# SSHift Installer
# https://github.com/takealook97/sshift

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="takealook97/sshift"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="sshift"

# Get latest version
get_latest_version() {
    # Try GitHub API first, fallback to parsing releases page
    VERSION=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    
    if [ -z "$VERSION" ]; then
        # Fallback: parse the releases page directly
        echo -e "${YELLOW}GitHub API rate limit reached, trying alternative method...${NC}" >&2
        VERSION=$(curl -s "https://github.com/$REPO/releases" 2>/dev/null | grep -o 'href="/takealook97/sshift/releases/tag/v[^"]*"' | head -1 | sed 's/.*v\([^"]*\)".*/v\1/')
    fi
    
    echo "$VERSION"
}

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        arm64|aarch64) ARCH="arm64" ;;
        *) echo -e "${RED}Unsupported architecture: $ARCH${NC}" && exit 1 ;;
    esac
    
    case $OS in
        darwin) OS="darwin" ;;
        linux) OS="linux" ;;
        *) echo -e "${RED}Unsupported OS: $OS${NC}" && exit 1 ;;
    esac
    
    echo "${OS}-${ARCH}"
}

# Download and install
install_sshift() {
    echo -e "${BLUE}🚀 Installing SSHift...${NC}"
    
    # Get latest version
    VERSION=$(get_latest_version)
    if [ -z "$VERSION" ]; then
        echo -e "${RED}Failed to get latest version${NC}"
        echo -e "${YELLOW}Please check if there are any releases available at: https://github.com/$REPO/releases${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}Latest version: $VERSION${NC}"
    
    # Detect platform
    PLATFORM=$(detect_platform)
    echo -e "${YELLOW}Platform: $PLATFORM${NC}"
    
    # Download URL
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/sshift-$PLATFORM"
    
    # Create temp directory
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    echo -e "${BLUE}📥 Downloading SSHift...${NC}"
    echo -e "${YELLOW}URL: $DOWNLOAD_URL${NC}"
    
    # Download with better error handling
    if ! curl -L -o "$BINARY_NAME" "$DOWNLOAD_URL"; then
        echo -e "${RED}Download failed${NC}"
        echo -e "${YELLOW}Please check if the release assets are available at: https://github.com/$REPO/releases/tag/$VERSION${NC}"
        exit 1
    fi
    
    if [ ! -f "$BINARY_NAME" ]; then
        echo -e "${RED}Download failed - file not found${NC}"
        exit 1
    fi
    
    # Check file size
    FILE_SIZE=$(stat -c%s "$BINARY_NAME" 2>/dev/null || stat -f%z "$BINARY_NAME" 2>/dev/null || echo "0")
    if [ "$FILE_SIZE" -lt 1000 ]; then
        echo -e "${RED}Downloaded file is too small ($FILE_SIZE bytes) - likely an error page${NC}"
        echo -e "${YELLOW}Please check if the release assets are properly uploaded${NC}"
        exit 1
    fi
    
    # Make executable
    chmod +x "$BINARY_NAME"
    
    # Check if binary is valid
    if ! file "$BINARY_NAME" | grep -q "executable"; then
        echo -e "${RED}Invalid binary file${NC}"
        echo -e "${YELLOW}File type: $(file "$BINARY_NAME")${NC}"
        echo -e "${YELLOW}Please check if the release assets are properly uploaded${NC}"
        exit 1
    fi
    
    # Install to system
    echo -e "${BLUE}📦 Installing to $INSTALL_DIR...${NC}"
    if [ ! -w "$INSTALL_DIR" ]; then
        echo -e "${YELLOW}Need sudo permission to install to $INSTALL_DIR${NC}"
        sudo cp "$BINARY_NAME" "$INSTALL_DIR/"
    else
        cp "$BINARY_NAME" "$INSTALL_DIR/"
    fi
    
    # Cleanup
    cd /
    rm -rf "$TEMP_DIR"
    
    # Verify installation
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ SSHift installed successfully!${NC}"
        echo -e "${BLUE}Version: $($BINARY_NAME version 2>/dev/null || echo 'Unknown')${NC}"
        echo -e "${YELLOW}Run '$BINARY_NAME' to start${NC}"
    else
        echo -e "${RED}Installation failed${NC}"
        exit 1
    fi
}

# Uninstall
uninstall_sshift() {
    echo -e "${BLUE}🗑️  Uninstalling SSHift...${NC}"
    
    if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        if [ ! -w "$INSTALL_DIR" ]; then
            echo -e "${YELLOW}Need sudo permission to remove from $INSTALL_DIR${NC}"
            sudo rm -f "$INSTALL_DIR/$BINARY_NAME"
        else
            rm -f "$INSTALL_DIR/$BINARY_NAME"
        fi
        echo -e "${GREEN}✅ SSHift uninstalled successfully!${NC}"
    else
        echo -e "${YELLOW}SSHift not found in $INSTALL_DIR${NC}"
    fi
}

# Show help
show_help() {
    echo "SSHift Installer"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  install    Install SSHift (default)"
    echo "  uninstall  Uninstall SSHift"
    echo "  help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | bash"
    echo "  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | bash -s uninstall"
}

# Main
case "${1:-install}" in
    install)
        install_sshift
        ;;
    uninstall)
        uninstall_sshift
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}Unknown option: $1${NC}"
        show_help
        exit 1
        ;;
esac 