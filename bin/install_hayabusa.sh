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
HAYABUSA_VERSION="${HAYABUSA_VERSION:-3.7.0}"
RULES_TARGET="$RULES_DIR/hayabusa-rules"

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
TEMP_DIR=$(mktemp -d)
TEMP_ZIP="$TEMP_DIR/hayabusa.zip"

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

echo -e "${YELLOW}Downloading Hayabusa v${HAYABUSA_VERSION}...${NC}"

download_file() {
    local url="$1"
    local output="$2"

    if command -v wget &> /dev/null; then
        wget -q --show-progress -O "$output" "$url"
    elif command -v curl &> /dev/null; then
        curl -fL -o "$output" "$url"
    else
        echo -e "${RED}Neither wget nor curl found. Please install one.${NC}"
        return 1
    fi
}

DOWNLOAD_CANDIDATES=()
case "${PLATFORM}-${ARCH}" in
    linux-x64)
        DOWNLOAD_CANDIDATES=("lin-x64-gnu" "lin-x64-musl" "linux-x64")
        ;;
    linux-aarch64)
        DOWNLOAD_CANDIDATES=("lin-aarch64-gnu" "lin-aarch64-musl" "linux-aarch64")
        ;;
    mac-x64)
        DOWNLOAD_CANDIDATES=("mac-x64")
        ;;
    mac-aarch64)
        DOWNLOAD_CANDIDATES=("mac-aarch64")
        ;;
    *)
        DOWNLOAD_CANDIDATES=("${PLATFORM}-${ARCH}")
        ;;
esac

DOWNLOAD_SUCCESS=0
SELECTED_ASSET_PLATFORM=""
for ASSET_PLATFORM in "${DOWNLOAD_CANDIDATES[@]}"; do
    DOWNLOAD_URL="https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-${ASSET_PLATFORM}.zip"
    echo "URL: $DOWNLOAD_URL"
    rm -f "$TEMP_ZIP"

    if download_file "$DOWNLOAD_URL" "$TEMP_ZIP"; then
        DOWNLOAD_SUCCESS=1
        SELECTED_ASSET_PLATFORM="$ASSET_PLATFORM"
        break
    fi
done

if [ "$DOWNLOAD_SUCCESS" -ne 1 ]; then
    echo -e "${RED}Failed to download Hayabusa v${HAYABUSA_VERSION}.${NC}"
    exit 1
fi

# Extract
echo -e "${YELLOW}Extracting...${NC}"
unzip -q "$TEMP_ZIP" -d "$TEMP_DIR"

# Find the hayabusa binary. Newer archives include files such as
# config/html_report/hayabusa_report.css, so avoid a broad recursive match.
HAYABUSA_BIN="$TEMP_DIR/hayabusa-${HAYABUSA_VERSION}-${SELECTED_ASSET_PLATFORM}"
if [ ! -f "$HAYABUSA_BIN" ]; then
    HAYABUSA_BIN=$(find "$TEMP_DIR" -maxdepth 1 -name "hayabusa*" -type f ! -name "*.zip" | head -1)
fi

if [ -z "$HAYABUSA_BIN" ]; then
    echo -e "${RED}Could not find Hayabusa binary in archive${NC}"
    exit 1
fi

# Install binary
echo -e "${YELLOW}Installing Hayabusa to ${INSTALL_DIR}...${NC}"
cp "$HAYABUSA_BIN" "$INSTALL_DIR/hayabusa"
chmod +x "$INSTALL_DIR/hayabusa"

# Verify installation
if ! "$INSTALL_DIR/hayabusa" help &> /dev/null; then
    echo -e "${RED}Hayabusa installation failed - binary not executable${NC}"
    exit 1
fi

VERSION=$("$INSTALL_DIR/hayabusa" help 2>&1 | head -1)
echo -e "${GREEN}Installed: $VERSION${NC}"

# Download rules
count_rules() {
    if [ -d "$RULES_TARGET" ]; then
        find "$RULES_TARGET" -name "*.yml" | wc -l
    else
        echo 0
    fi
}

rules_installed() {
    [ "$(count_rules)" -gt 0 ]
}

download_rules_archive() {
    echo -e "${YELLOW}Downloading rules archive...${NC}"
    RULES_URL="https://github.com/Yamato-Security/hayabusa-rules/archive/refs/heads/main.zip"
    RULES_ZIP="$TEMP_DIR/rules.zip"

    if ! download_file "$RULES_URL" "$RULES_ZIP"; then
        return 1
    fi

    unzip -q "$RULES_ZIP" -d "$TEMP_DIR"
    rm -rf "$RULES_TARGET"
    mv "$TEMP_DIR/hayabusa-rules-main" "$RULES_TARGET"
}

download_rules_git() {
    if ! command -v git &> /dev/null; then
        return 1
    fi

    echo -e "${YELLOW}Downloading rules with git...${NC}"
    if [ -d "$RULES_TARGET/.git" ]; then
        git -C "$RULES_TARGET" pull --ff-only
    else
        rm -rf "$RULES_TARGET"
        git clone --depth 1 https://github.com/Yamato-Security/hayabusa-rules.git "$RULES_TARGET"
    fi
}

echo -e "${YELLOW}Downloading Hayabusa rules...${NC}"
if "$INSTALL_DIR/hayabusa" update-rules -r "$RULES_TARGET" 2>&1 && rules_installed; then
    echo -e "${GREEN}Rules updated by Hayabusa.${NC}"
elif download_rules_git && rules_installed; then
    echo -e "${GREEN}Rules updated by git.${NC}"
elif download_rules_archive && rules_installed; then
    echo -e "${GREEN}Rules updated from archive.${NC}"
else
    echo -e "${RED}Failed to install Hayabusa rules into $RULES_TARGET${NC}"
    exit 1
fi

# Count rules
RULE_COUNT=$(count_rules)
echo -e "${GREEN}Downloaded ${RULE_COUNT} detection rules${NC}"

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
HAYABUSA_RULES=$RULES_TARGET
HAYABUSA_VERSION=$HAYABUSA_VERSION
INSTALLED_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Installation Complete!               ${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Hayabusa binary: $INSTALL_DIR/hayabusa"
echo "Rules directory: $RULES_TARGET"
echo "Rule count: $RULE_COUNT"
echo ""
echo "Test with:"
echo "  $INSTALL_DIR/hayabusa --help"
echo ""
echo "Parse EVTX file:"
echo "  $INSTALL_DIR/hayabusa json-timeline -f /path/to/file.evtx -o output.jsonl -L"
echo ""
