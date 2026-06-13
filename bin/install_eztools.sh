#!/bin/bash
# Install .NET Runtime and Eric Zimmerman's EZ Tools for CaseScope
# Reference: https://www.sans.org/blog/running-ez-tools-natively-on-linux-a-step-by-step-guide

set -e

INSTALL_DIR="/opt/casescope/bin"
DOTNET_DIR="/opt/casescope/.dotnet"
NET_VERSION="9.0"

echo "=== Installing .NET Runtime and EZ Tools ==="

# Create directories
mkdir -p "$INSTALL_DIR/EvtxECmd"
mkdir -p "$INSTALL_DIR/SumECmd"
mkdir -p "$INSTALL_DIR/AppCompatCacheParser"
mkdir -p "$INSTALL_DIR/SBECmd"
mkdir -p "$INSTALL_DIR/RLA"
mkdir -p "$DOTNET_DIR"

# Step 1: Install .NET Runtime
echo "[1/4] Installing .NET $NET_VERSION Runtime..."
if [ -f "$DOTNET_DIR/dotnet" ]; then
    echo "  .NET already installed, checking version..."
    "$DOTNET_DIR/dotnet" --version || true
else
    wget -q https://builds.dotnet.microsoft.com/dotnet/scripts/v1/dotnet-install.sh -O /tmp/dotnet-install.sh
    chmod +x /tmp/dotnet-install.sh
    DOTNET_INSTALL_DIR="$DOTNET_DIR" /tmp/dotnet-install.sh --channel "$NET_VERSION" --runtime dotnet
    rm -f /tmp/dotnet-install.sh
    echo "  .NET installed to $DOTNET_DIR"
fi

# Create dotnet symlink/wrapper
cat > "$INSTALL_DIR/dotnet" << 'WRAPPER'
#!/bin/bash
export DOTNET_ROOT="/opt/casescope/.dotnet"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
exec "$DOTNET_ROOT/dotnet" "$@"
WRAPPER
chmod +x "$INSTALL_DIR/dotnet"

# Verify .NET works
echo "  Testing .NET..."
"$INSTALL_DIR/dotnet" --info | head -5

install_ez_tool() {
    local tool_name="$1"
    local dll_name="$2"
    local wrapper_name="$3"
    local target_dir="$INSTALL_DIR/$tool_name"
    local archive_path="/tmp/${tool_name}.zip"
    local tool_url="https://download.ericzimmermanstools.com/net9/${tool_name}.zip"

    echo "  Downloading $tool_name..."
    wget -q "$tool_url" -O "$archive_path"
    unzip -o "$archive_path" -d "$target_dir/"
    rm -f "$archive_path"

    cat > "$INSTALL_DIR/$wrapper_name" << WRAPPER
#!/bin/bash
export DOTNET_ROOT="/opt/casescope/.dotnet"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
exec "\$DOTNET_ROOT/dotnet" "/opt/casescope/bin/$tool_name/$dll_name" "\$@"
WRAPPER
    chmod +x "$INSTALL_DIR/$wrapper_name"
    echo "  $tool_name installed to $target_dir"
}

# Step 2: Download EZ tools
echo "[2/4] Downloading EZ Tools..."
install_ez_tool "EvtxECmd" "EvtxECmd.dll" "evtxecmd"
install_ez_tool "SumECmd" "SumECmd.dll" "sumecmd"
install_ez_tool "AppCompatCacheParser" "AppCompatCacheParser.dll" "appcompatcacheparser"
install_ez_tool "SBECmd" "SBECmd.dll" "sbecmd"
install_ez_tool "RLA" "RLA.dll" "rla"

# Step 3: Download EvtxECmd Maps (field normalization rules)
echo "[3/4] Downloading EvtxECmd Maps..."
MAPS_DIR="$INSTALL_DIR/EvtxECmd/Maps"
if [ -d "$MAPS_DIR/.git" ]; then
    echo "  Maps repo exists, pulling updates..."
    git -C "$MAPS_DIR" pull || true
else
    rm -rf "$MAPS_DIR"
    git clone --depth 1 https://github.com/EricZimmerman/evtx.git /tmp/evtx-maps
    mv /tmp/evtx-maps/evtx/Maps "$MAPS_DIR"
    rm -rf /tmp/evtx-maps
fi
echo "  Maps installed to $MAPS_DIR"
echo "  Maps count: $(find "$MAPS_DIR" -name "*.map" 2>/dev/null | wc -l)"

# Step 4: Test EvtxECmd
echo "[4/4] Testing EvtxECmd..."
"$INSTALL_DIR/evtxecmd" --help 2>&1 | head -10 || {
    echo "WARNING: EvtxECmd test failed. This may be a .NET compatibility issue."
}

# Fix permissions
chown -R casescope:casescope "$INSTALL_DIR" "$DOTNET_DIR" 2>/dev/null || true

echo ""
echo "=== Installation Complete ==="
echo "EvtxECmd: $INSTALL_DIR/evtxecmd"
echo "SumECmd: $INSTALL_DIR/sumecmd"
echo "AppCompatCacheParser: $INSTALL_DIR/appcompatcacheparser"
echo "SBECmd: $INSTALL_DIR/sbecmd"
echo "RLA: $INSTALL_DIR/rla"
echo "Maps: $MAPS_DIR"
echo ".NET: $DOTNET_DIR"
echo ""
echo "Test with: $INSTALL_DIR/evtxecmd -f /path/to/file.evtx --json /tmp --jsonf test.json"
