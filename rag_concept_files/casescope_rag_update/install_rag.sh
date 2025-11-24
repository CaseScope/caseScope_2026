#!/bin/bash
# CaseScope RAG Installation Script
# Installs the AI Question feature with semantic search

set -e

CASESCOPE_DIR="/opt/casescope"
BACKUP_DIR="/opt/casescope/backups/rag_install_$(date +%Y%m%d_%H%M%S)"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║   CaseScope AI Question (RAG) Installation Script          ║"
echo "║   With Semantic Search (sentence-transformers)             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  Please run with sudo: sudo bash install_rag.sh"
    exit 1
fi

# Check CaseScope directory exists
if [ ! -d "$CASESCOPE_DIR/app" ]; then
    echo "❌ CaseScope not found at $CASESCOPE_DIR"
    echo "   Please adjust CASESCOPE_DIR in this script"
    exit 1
fi

echo "📁 Creating backup directory: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

# Backup existing files
echo "📦 Backing up existing files..."
cp "$CASESCOPE_DIR/app/main.py" "$BACKUP_DIR/" 2>/dev/null || true
cp "$CASESCOPE_DIR/app/templates/search_events.html" "$BACKUP_DIR/" 2>/dev/null || true
cp "$CASESCOPE_DIR/app/requirements.txt" "$BACKUP_DIR/" 2>/dev/null || true

echo "✅ Backup complete"
echo ""

# Check if update files exist in current directory
if [ ! -f "./app/ai_search.py" ]; then
    echo "❌ Update files not found in current directory"
    echo "   Please extract the casescope_rag_update.zip first:"
    echo "   unzip casescope_rag_update.zip"
    exit 1
fi

echo "📥 Installing new files..."

# Copy new files
cp ./app/ai_search.py "$CASESCOPE_DIR/app/"
echo "   ✓ ai_search.py"

cp ./app/routes/ai_search.py "$CASESCOPE_DIR/app/routes/"
echo "   ✓ routes/ai_search.py"

cp ./app/main.py "$CASESCOPE_DIR/app/"
echo "   ✓ main.py (updated with blueprint registration)"

cp ./app/templates/search_events.html "$CASESCOPE_DIR/app/templates/"
echo "   ✓ templates/search_events.html (with AI Question button)"

cp ./app/requirements.txt "$CASESCOPE_DIR/app/"
echo "   ✓ requirements.txt (with sentence-transformers)"

cp ./site_docs/AI_QUESTION_RAG_SETUP.md "$CASESCOPE_DIR/site_docs/" 2>/dev/null || \
    mkdir -p "$CASESCOPE_DIR/docs" && cp ./site_docs/AI_QUESTION_RAG_SETUP.md "$CASESCOPE_DIR/docs/" 2>/dev/null || \
    echo "   ⚠️  Could not copy documentation (optional)"

echo ""
echo "✅ Files installed successfully"
echo ""

# Install Python dependencies
echo "📦 Installing Python dependencies..."
cd "$CASESCOPE_DIR"

if [ -d "venv" ]; then
    source venv/bin/activate
    echo "   Activated virtual environment"
else
    echo "   ⚠️  No venv found, using system Python"
fi

pip install sentence-transformers numpy --break-system-packages 2>/dev/null || \
    pip install sentence-transformers numpy || \
    echo "   ⚠️  Failed to install dependencies. Please run manually:"
    echo "      pip install sentence-transformers numpy --break-system-packages"

echo ""

# Check Ollama
echo "🔍 Checking Ollama status..."
if systemctl is-active --quiet ollama; then
    echo "   ✓ Ollama is running"
    
    # Check for models
    MODELS=$(curl -s http://localhost:11434/api/tags 2>/dev/null | grep -o '"name":"[^"]*"' | head -5)
    if [ -n "$MODELS" ]; then
        echo "   ✓ Found models: $(echo $MODELS | tr -d '"name:' | tr ' ' ', ')"
    else
        echo "   ⚠️  No models found. Install at least one:"
        echo "      ollama pull llama3.1:8b-instruct-q4_K_M"
    fi
else
    echo "   ⚠️  Ollama is not running"
    echo "      Start it with: sudo systemctl start ollama"
fi

echo ""
echo "🔄 Restarting CaseScope services..."

systemctl restart casescope 2>/dev/null && echo "   ✓ casescope restarted" || echo "   ⚠️  Could not restart casescope service"
systemctl restart casescope-worker 2>/dev/null && echo "   ✓ casescope-worker restarted" || echo "   ⚠️  Could not restart casescope-worker service"

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                  Installation Complete!                     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Next Steps:"
echo "   1. Go to any case's Search Events page"
echo "   2. Click the 🤖 AI Question button"
echo "   3. Ask a question like: 'Were there signs of lateral movement?'"
echo ""
echo "⏱️  Note: First query downloads the embedding model (~90MB)"
echo "   This takes ~30 seconds once, then it's cached."
echo ""
echo "📖 Full documentation: $CASESCOPE_DIR/site_docs/AI_QUESTION_RAG_SETUP.md"
echo ""
echo "🔙 To rollback, restore from: $BACKUP_DIR"
