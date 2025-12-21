#!/bin/bash
#
# CaseScope 2026 - Complete Fresh Installation Script
# This script will DESTROY the old installation and start completely fresh
#
# Usage: sudo bash fresh_install.sh
#

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_step() {
    echo -e "${BLUE}==>${NC} ${GREEN}$1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run as root (use sudo)"
    exit 1
fi

# Confirmation prompt
echo -e "${RED}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    ⚠️  DANGER ZONE ⚠️                          ║"
echo "║                                                                ║"
echo "║  This script will COMPLETELY DESTROY the old installation:    ║"
echo "║  • Stop all CaseScope services                                 ║"
echo "║  • Delete OpenSearch data and installation                     ║"
echo "║  • Delete Redis data                                           ║"
echo "║  • Delete all case files and uploads                           ║"
echo "║  • Delete Python virtual environment                           ║"
echo "║  • Remove systemd services                                     ║"
echo "║  • Then install everything fresh                               ║"
echo "║                                                                ║"
echo "║  ALL DATA WILL BE PERMANENTLY LOST!                            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

read -p "Type 'YES DELETE EVERYTHING' to continue: " confirmation
if [ "$confirmation" != "YES DELETE EVERYTHING" ]; then
    print_error "Aborted."
    exit 1
fi

print_warning "Starting complete destruction and reinstall in 5 seconds..."
sleep 5

#######################################
# STEP 1: STOP ALL SERVICES
#######################################
print_step "Step 1: Stopping all services..."

systemctl stop casescope 2>/dev/null || true
systemctl stop casescope-worker 2>/dev/null || true
systemctl stop opensearch 2>/dev/null || true
systemctl stop redis-server 2>/dev/null || true

# Kill any remaining processes
pkill -f gunicorn || true
pkill -f celery || true
pkill -f opensearch || true

sleep 3
print_success "All services stopped"

#######################################
# STEP 2: DISABLE AND REMOVE SERVICES
#######################################
print_step "Step 2: Removing systemd services..."

systemctl disable casescope 2>/dev/null || true
systemctl disable casescope-worker 2>/dev/null || true
systemctl disable opensearch 2>/dev/null || true

rm -f /etc/systemd/system/casescope.service
rm -f /etc/systemd/system/casescope-worker.service
rm -f /etc/systemd/system/opensearch.service

systemctl daemon-reload
print_success "Systemd services removed"

#######################################
# STEP 3: REMOVE OLD INSTALLATIONS
#######################################
print_step "Step 3: Removing old installations..."

# Remove OpenSearch
if [ -d "/opt/opensearch" ]; then
    print_warning "Deleting OpenSearch..."
    rm -rf /opt/opensearch
fi

# Remove CaseScope
if [ -d "/opt/casescope" ]; then
    print_warning "Deleting CaseScope (ALL DATA)..."
    rm -rf /opt/casescope
fi

# Clean Redis data
if [ -d "/var/lib/redis" ]; then
    print_warning "Clearing Redis data..."
    rm -rf /var/lib/redis/*
fi

# Clean temp files
rm -rf /tmp/opensearch-* 2>/dev/null || true
rm -rf /tmp/evtx* 2>/dev/null || true

print_success "Old installations removed"

#######################################
# STEP 4: UPDATE SYSTEM
#######################################
print_step "Step 4: Updating system packages..."

apt update
apt upgrade -y

print_success "System updated"

#######################################
# STEP 5: INSTALL DEPENDENCIES
#######################################
print_step "Step 5: Installing dependencies..."

apt install -y python3 python3-pip python3-venv redis-server git curl wget

# Start Redis
systemctl enable redis-server
systemctl start redis-server

# Verify Redis
if redis-cli ping | grep -q "PONG"; then
    print_success "Redis is running"
else
    print_error "Redis failed to start"
    exit 1
fi

#######################################
# STEP 6: INSTALL OPENSEARCH
#######################################
print_step "Step 6: Installing OpenSearch 2.11.0..."

cd /tmp
wget -q --show-progress https://artifacts.opensearch.org/releases/bundle/opensearch/2.11.0/opensearch-2.11.0-linux-x64.tar.gz
tar -xzf opensearch-2.11.0-linux-x64.tar.gz
mv opensearch-2.11.0 /opt/opensearch

# Configure OpenSearch
cat >> /opt/opensearch/config/opensearch.yml <<EOF
discovery.type: single-node
plugins.security.disabled: true
EOF

# Create systemd service
cat > /etc/systemd/system/opensearch.service <<EOF
[Unit]
Description=OpenSearch
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/opensearch/bin/opensearch
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Start OpenSearch
systemctl daemon-reload
systemctl enable opensearch
systemctl start opensearch

print_warning "Waiting 45 seconds for OpenSearch to start..."
sleep 45

# Verify OpenSearch
if curl -s localhost:9200/_cluster/health | grep -q "cluster_name"; then
    print_success "OpenSearch is running"
    curl -X GET "localhost:9200/_cluster/health?pretty"
else
    print_error "OpenSearch failed to start"
    journalctl -u opensearch -n 50
    exit 1
fi

#######################################
# STEP 7: CREATE DIRECTORY STRUCTURE
#######################################
print_step "Step 7: Creating directory structure..."

mkdir -p /opt/casescope/{data,uploads,staging,archive,local_uploads,logs,bin,chainsaw/mappings}

print_success "Directories created"

#######################################
# STEP 8: CLONE APPLICATION
#######################################
print_step "Step 8: Cloning CaseScope application..."

# Prompt for GitHub username
read -p "Enter your GitHub username (or press Enter to skip git clone): " github_username

if [ -z "$github_username" ]; then
    print_warning "Skipping git clone. You need to manually copy the application to /opt/casescope/app"
    print_warning "Or rerun this script with your GitHub username"
    mkdir -p /opt/casescope/app
else
    cd /opt/casescope
    git clone https://github.com/${github_username}/caseScope_2026.git app
    print_success "Repository cloned"
fi

#######################################
# STEP 9: SETUP PYTHON ENVIRONMENT
#######################################
print_step "Step 9: Setting up Python virtual environment..."

cd /opt/casescope
python3 -m venv venv
source venv/bin/activate

cd /opt/casescope/app
if [ -f "requirements.txt" ]; then
    pip install --upgrade pip
    pip install -r requirements.txt
    print_success "Python packages installed"
else
    print_warning "requirements.txt not found, skipping pip install"
fi

#######################################
# STEP 10: DOWNLOAD FORENSIC TOOLS
#######################################
print_step "Step 10: Downloading forensic tools..."

# evtx_dump
cd /opt/casescope/bin
wget -q --show-progress https://github.com/omerbenamram/evtx/releases/download/v0.8.2/evtx_dump-v0.8.2-x86_64-unknown-linux-gnu
mv evtx_dump-v0.8.2-x86_64-unknown-linux-gnu evtx_dump
chmod +x evtx_dump

# Chainsaw
wget -q --show-progress https://github.com/WithSecureLabs/chainsaw/releases/download/v2.9.1/chainsaw_x86_64-unknown-linux-gnu
mv chainsaw_x86_64-unknown-linux-gnu chainsaw
chmod +x chainsaw

# Chainsaw mappings
cd /opt/casescope/chainsaw/mappings
wget -q --show-progress https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/mappings/sigma-event-logs-all.yml

# Verify
if /opt/casescope/bin/evtx_dump --version >/dev/null 2>&1; then
    print_success "evtx_dump installed: $(/opt/casescope/bin/evtx_dump --version)"
fi

if /opt/casescope/bin/chainsaw --version >/dev/null 2>&1; then
    print_success "chainsaw installed: $(/opt/casescope/bin/chainsaw --version)"
fi

#######################################
# STEP 11: SETUP SIGMA RULES
#######################################
print_step "Step 11: Cloning SIGMA rules..."

cd /opt/casescope
git clone https://github.com/SigmaHQ/sigma.git sigma_rules_repo
ln -s /opt/casescope/sigma_rules_repo/rules /opt/casescope/sigma_rules

print_success "SIGMA rules installed ($(find /opt/casescope/sigma_rules -name '*.yml' | wc -l) rules)"

#######################################
# STEP 12: INITIALIZE DATABASE
#######################################
print_step "Step 12: Initializing database..."

cd /opt/casescope/app
source /opt/casescope/venv/bin/activate

if [ -f "main.py" ]; then
    export FLASK_APP=main.py
    flask init-db
    print_success "Database initialized"
else
    print_warning "main.py not found, skipping database initialization"
fi

#######################################
# STEP 13: CREATE SYSTEMD SERVICES
#######################################
print_step "Step 13: Creating systemd services..."

# CaseScope Web Service
cat > /etc/systemd/system/casescope.service <<EOF
[Unit]
Description=CaseScope 2026 Web Application
After=network.target opensearch.service redis.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/casescope/app
Environment="PATH=/opt/casescope/venv/bin"
ExecStart=/opt/casescope/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 wsgi:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# CaseScope Worker Service
cat > /etc/systemd/system/casescope-worker.service <<EOF
[Unit]
Description=CaseScope 2026 Celery Worker
After=network.target redis.service opensearch.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/casescope/app
Environment="PATH=/opt/casescope/venv/bin"
ExecStart=/opt/casescope/venv/bin/celery -A celery_app worker --loglevel=info --concurrency=2
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
print_success "Systemd services created"

#######################################
# STEP 14: START CASESCOPE
#######################################
print_step "Step 14: Starting CaseScope services..."

systemctl enable casescope
systemctl enable casescope-worker

systemctl start casescope
systemctl start casescope-worker

sleep 5

print_success "Services started"

#######################################
# STEP 15: VERIFY INSTALLATION
#######################################
print_step "Step 15: Verifying installation..."

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SERVICE STATUS:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

services=("redis" "opensearch" "casescope" "casescope-worker")
for service in "${services[@]}"; do
    if systemctl is-active --quiet $service; then
        echo -e "  ${GREEN}✓${NC} $service: ${GREEN}RUNNING${NC}"
    else
        echo -e "  ${RED}✗${NC} $service: ${RED}FAILED${NC}"
    fi
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "HEALTH CHECKS:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Redis
if redis-cli ping | grep -q "PONG"; then
    echo -e "  ${GREEN}✓${NC} Redis: ${GREEN}OK${NC}"
else
    echo -e "  ${RED}✗${NC} Redis: ${RED}FAILED${NC}"
fi

# OpenSearch
if curl -s localhost:9200/_cluster/health | grep -q "cluster_name"; then
    echo -e "  ${GREEN}✓${NC} OpenSearch: ${GREEN}OK${NC}"
else
    echo -e "  ${RED}✗${NC} OpenSearch: ${RED}FAILED${NC}"
fi

# Web Application
if curl -s -o /dev/null -w "%{http_code}" http://localhost:5000 | grep -q "200\|302"; then
    echo -e "  ${GREEN}✓${NC} Web Application: ${GREEN}OK${NC}"
else
    echo -e "  ${YELLOW}⚠${NC} Web Application: ${YELLOW}CHECK LOGS${NC}"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "INSTALLATION SUMMARY:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  📍 Application Path: /opt/casescope/app"
echo "  📍 Data Directory:   /opt/casescope/data"
echo "  📍 Upload Directory: /opt/casescope/uploads"
echo "  📍 Virtual Env:      /opt/casescope/venv"
echo ""
echo "  🌐 Web Interface:    http://$(hostname -I | awk '{print $1}'):5000"
echo ""
echo "  👤 Default Login:"
echo "     Username: admin"
echo "     Password: admin"
echo ""
echo -e "  ${RED}⚠️  CHANGE THE DEFAULT PASSWORD IMMEDIATELY!${NC}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "USEFUL COMMANDS:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  # Check service status"
echo "  sudo systemctl status casescope"
echo "  sudo systemctl status casescope-worker"
echo ""
echo "  # View logs"
echo "  sudo journalctl -u casescope -f"
echo "  sudo journalctl -u casescope-worker -f"
echo ""
echo "  # Restart services"
echo "  sudo systemctl restart casescope"
echo "  sudo systemctl restart casescope-worker"
echo ""
echo "  # Check queue"
echo "  redis-cli LLEN celery"
echo ""
echo "  # Check OpenSearch indices"
echo "  curl localhost:9200/_cat/indices?v"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
print_success "Installation complete! 🎉"
echo ""

