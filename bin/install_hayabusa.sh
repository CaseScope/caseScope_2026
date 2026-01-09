#!/bin/bash
# ============================================
# Hayabusa Installation Script for CaseScope
# ============================================
# This script downloads and configures Hayabusa for EVTX parsing
# with Sigma detection rules.

set -e

# Configuration
INSTALL_DIR="${CASESCOPE_BIN:-/opt/casescope/bin}"
RULES_DIR="${CASESCOPE_RULES:-/opt/casescope/rules}"
HAYABUSA_VERSION="${HAYABUSA_VERSION:-2.18.0}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Hayabusa Installation for CaseScope  ${NC}"
echo -e "${GREEN}========================================${NC}"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)
        ARCH="x64"
        ;;
    aarch64|arm64)
        ARCH="aarch64"
        ;;
    *)
        echo -e "${RED}Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

case "$OS" in
    linux)
        PLATFORM="linux"
        ;;
    darwin)
        PLATFORM="mac"
        ;;
    *)
        echo -e "${RED}Unsupported OS: $OS${NC}"
        exit 1
        ;;
esac

echo -e "${YELLOW}Detected platform: ${PLATFORM}-${ARCH}${NC}"

# Create directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$RULES_DIR"

# Download Hayabusa
DOWNLOAD_URL="https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-${PLATFORM}-${ARCH}.zip"
TEMP_DIR=$(mktemp -d)
TEMP_ZIP="$TEMP_DIR/hayabusa.zip"

echo -e "${YELLOW}Downloading Hayabusa v${HAYABUSA_VERSION}...${NC}"
echo "URL: $DOWNLOAD_URL"

if command -v wget &> /dev/null; then
    wget -q --show-progress -O "$TEMP_ZIP" "$DOWNLOAD_URL"
elif command -v curl &> /dev/null; then
    curl -L -o "$TEMP_ZIP" "$DOWNLOAD_URL"
else
    echo -e "${RED}Neither wget nor curl found. Please install one.${NC}"
    exit 1
fi

# Extract
echo -e "${YELLOW}Extracting...${NC}"
unzip -q "$TEMP_ZIP" -d "$TEMP_DIR"

# Find the hayabusa binary
HAYABUSA_BIN=$(find "$TEMP_DIR" -name "hayabusa*" -type f ! -name "*.zip" | head -1)

if [ -z "$HAYABUSA_BIN" ]; then
    echo -e "${RED}Could not find Hayabusa binary in archive${NC}"
    exit 1
fi

# Install binary
echo -e "${YELLOW}Installing Hayabusa to ${INSTALL_DIR}...${NC}"
cp "$HAYABUSA_BIN" "$INSTALL_DIR/hayabusa"
chmod +x "$INSTALL_DIR/hayabusa"

# Verify installation
if ! "$INSTALL_DIR/hayabusa" --version &> /dev/null; then
    echo -e "${RED}Hayabusa installation failed - binary not executable${NC}"
    exit 1
fi

VERSION=$("$INSTALL_DIR/hayabusa" --version 2>&1 | head -1)
echo -e "${GREEN}Installed: $VERSION${NC}"

# Download rules
echo -e "${YELLOW}Downloading Hayabusa rules...${NC}"
"$INSTALL_DIR/hayabusa" update-rules -r "$RULES_DIR/hayabusa-rules" 2>&1 || {
    echo -e "${YELLOW}Rule update via hayabusa failed, trying git...${NC}"
    if command -v git &> /dev/null; then
        if [ -d "$RULES_DIR/hayabusa-rules" ]; then
            cd "$RULES_DIR/hayabusa-rules" && git pull
        else
            git clone --depth 1 https://github.com/Yamato-Security/hayabusa-rules.git "$RULES_DIR/hayabusa-rules"
        fi
    else
        echo -e "${YELLOW}Git not available, downloading rules archive...${NC}"
        RULES_URL="https://github.com/Yamato-Security/hayabusa-rules/archive/refs/heads/main.zip"
        wget -q -O "$TEMP_DIR/rules.zip" "$RULES_URL" || curl -L -o "$TEMP_DIR/rules.zip" "$RULES_URL"
        unzip -q "$TEMP_DIR/rules.zip" -d "$TEMP_DIR"
        rm -rf "$RULES_DIR/hayabusa-rules"
        mv "$TEMP_DIR/hayabusa-rules-main" "$RULES_DIR/hayabusa-rules"
    fi
}

# Count rules
RULE_COUNT=$(find "$RULES_DIR/hayabusa-rules" -name "*.yml" | wc -l)
echo -e "${GREEN}Downloaded ${RULE_COUNT} detection rules${NC}"

# Cleanup
rm -rf "$TEMP_DIR"

# Set permissions if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}Setting permissions...${NC}"
    chown -R casescope:casescope "$INSTALL_DIR" 2>/dev/null || true
    chown -R casescope:casescope "$RULES_DIR" 2>/dev/null || true
fi

# Create config file
echo -e "${YELLOW}Creating configuration...${NC}"
cat > "$RULES_DIR/hayabusa.conf" << EOF
# Hayabusa Configuration for CaseScope
HAYABUSA_BIN=$INSTALL_DIR/hayabusa
HAYABUSA_RULES=$RULES_DIR/hayabusa-rules
HAYABUSA_VERSION=$HAYABUSA_VERSION
INSTALLED_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Installation Complete!               ${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Hayabusa binary: $INSTALL_DIR/hayabusa"
echo "Rules directory: $RULES_DIR/hayabusa-rules"
echo "Rule count: $RULE_COUNT"
echo ""
echo "Test with:"
echo "  $INSTALL_DIR/hayabusa --help"
echo ""
echo "Parse EVTX file:"
echo "  $INSTALL_DIR/hayabusa json-timeline -f /path/to/file.evtx -o output.jsonl -L"
echo ""
