#!/bin/bash
set -e

echo "========================================="
echo "  CaseScope AI Setup"
echo "========================================="

# 1. Check Ollama
if ! command -v ollama &> /dev/null; then
    echo "❌ Ollama not found!"
    echo "Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
else
    echo "✅ Ollama already installed"
fi

# 2. Create directories
echo ""
echo "Creating directories..."
mkdir -p /opt/casescope/data/sigma
chown -R casescope:casescope /opt/casescope/data
echo "✅ Directories created"

# 3. Pull LLM models (Q4_K_M quantization for 8GB VRAM)
echo ""
echo "========================================="
echo "  Pulling LLM Models"
echo "========================================="
echo "This will download ~4.5GB per model..."
echo ""

echo "Pulling qwen2.5:7b-instruct-q4_K_M (Chat & Analysis)..."
ollama pull qwen2.5:7b-instruct-q4_K_M

echo ""
echo "Pulling qwen2.5-coder:7b-instruct-q4_K_M (Code Generation)..."
ollama pull qwen2.5-coder:7b-instruct-q4_K_M

echo "✅ Models pulled successfully"

# 4. Download Sigma rules
echo ""
echo "========================================="
echo "  Downloading Sigma Rules"
echo "========================================="
if [ ! -d "/opt/casescope/data/sigma/sigma" ]; then
    echo "Cloning Sigma repository..."
    git clone --depth 1 https://github.com/SigmaHQ/sigma.git /opt/casescope/data/sigma/sigma
    echo "✅ Sigma rules downloaded"
else
    echo "Sigma rules already exist, updating..."
    cd /opt/casescope/data/sigma/sigma && git pull
    echo "✅ Sigma rules updated"
fi

# 5. Download MITRE ATT&CK data
echo ""
echo "========================================="
echo "  Downloading MITRE ATT&CK"
echo "========================================="
curl -s https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json \
    -o /opt/casescope/data/sigma/mitre_attack.json
echo "✅ MITRE ATT&CK data downloaded"

# 6. Ensure pgvector is installed
echo ""
echo "========================================="
echo "  Setting up PostgreSQL pgvector"
echo "========================================="
echo "Ensuring pgvector extension is installed..."
apt-get update && apt-get install -y postgresql-16-pgvector

echo "Enabling pgvector in database..."
sudo -u postgres psql casescope -c "CREATE EXTENSION IF NOT EXISTS vector;"
echo "✅ pgvector configured"

# 7. Set permissions
chown -R casescope:casescope /opt/casescope/data

echo ""
echo "========================================="
echo "  Setup Complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "  1. Run: python3 scripts/ingest_patterns.py"
echo "  2. Restart Flask: sudo systemctl restart casescope-new"
echo ""
echo "Ollama models installed:"
ollama list


