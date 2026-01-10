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

# Step 2: Download EvtxECmd
echo "[2/4] Downloading EvtxECmd..."
EVTX_URL="https://download.ericzimmermanstools.com/net9/EvtxECmd.zip"
wget -q "$EVTX_URL" -O /tmp/EvtxECmd.zip
unzip -o /tmp/EvtxECmd.zip -d "$INSTALL_DIR/EvtxECmd/"
rm -f /tmp/EvtxECmd.zip
echo "  EvtxECmd installed to $INSTALL_DIR/EvtxECmd"

# Create wrapper script for EvtxECmd
cat > "$INSTALL_DIR/evtxecmd" << 'WRAPPER'
#!/bin/bash
export DOTNET_ROOT="/opt/casescope/.dotnet"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
exec "$DOTNET_ROOT/dotnet" "/opt/casescope/bin/EvtxECmd/EvtxECmd.dll" "$@"
WRAPPER
chmod +x "$INSTALL_DIR/evtxecmd"

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
echo "Maps: $MAPS_DIR"
echo ".NET: $DOTNET_DIR"
echo ""
echo "Test with: $INSTALL_DIR/evtxecmd -f /path/to/file.evtx --json /tmp --jsonf test.json"
