# 📦 CaseScope 2026 - Installation Guide

**Complete installation instructions for Ubuntu 24.04 LTS**

---

## 📋 Table of Contents

1. [System Requirements](#-system-requirements)
2. [Quick Start (Automated)](#-quick-start-automated-installation)
3. [Manual Installation](#-manual-installation)
4. [Post-Installation](#-post-installation)
5. [Verification](#-verification)
6. [Troubleshooting](#-troubleshooting)

---

## 💻 System Requirements

### Minimum Hardware
- **CPU**: 4 cores
- **RAM**: 16GB
- **Storage**: 100GB SSD
- **OS**: Ubuntu 24.04 LTS

### Recommended Hardware
- **CPU**: 8+ cores
- **RAM**: 32GB
- **Storage**: 500GB NVMe SSD
- **OS**: Ubuntu 24.04 LTS

### For Large Datasets (40M+ events)
- **CPU**: 16+ cores
- **RAM**: 64GB
- **Storage**: 1TB+ NVMe SSD

---

## 🚀 Quick Start (Automated Installation)

### Option 1: Fresh Install Script (Recommended)

⚠️ **WARNING**: This will completely destroy any existing CaseScope installation!

```bash
# Download the installation script
wget https://raw.githubusercontent.com/JustinTDCT/caseScope_2026/main/app/fresh_install.sh

# Make it executable
chmod +x fresh_install.sh

# Run the script
sudo bash fresh_install.sh
```

The script will:
- ✅ Install all prerequisites (PostgreSQL, Redis, Python)
- ✅ Download and configure OpenSearch 2.11.0
- ✅ Set up CaseScope application
- ✅ Download forensic tools (evtx_dump, chainsaw)
- ✅ Clone SIGMA rules repository
- ✅ Create systemd services
- ✅ Initialize database with admin user
- ✅ Start all services

**Installation time**: ~15-20 minutes

After installation completes, access the application at:
```
http://YOUR_SERVER_IP:5000
Default credentials: admin / admin
```

---

## 🛠️ Manual Installation

If you prefer manual control or the script doesn't work for your environment:

### Step 1: Install Prerequisites

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y \
    python3 python3-pip python3-venv \
    redis-server \
    postgresql postgresql-contrib \
    git curl wget tar
```

### Step 2: Install and Configure PostgreSQL

```bash
# PostgreSQL should already be installed from prerequisites
# Create database and user
sudo -u postgres psql << 'EOF'
CREATE DATABASE casescope;
CREATE USER casescope WITH PASSWORD 'casescope_secure_2026';
GRANT ALL PRIVILEGES ON DATABASE casescope TO casescope;
\c casescope
GRANT ALL ON SCHEMA public TO casescope;
ALTER DATABASE casescope OWNER TO casescope;
EOF

# Verify connection
psql -U casescope -d casescope -c "SELECT version();"
# You should see PostgreSQL version information
```

### Step 3: Install OpenSearch

```bash
# Download OpenSearch 2.11.0
cd /tmp
wget https://artifacts.opensearch.org/releases/bundle/opensearch/2.11.0/opensearch-2.11.0-linux-x64.tar.gz
tar -xzf opensearch-2.11.0-linux-x64.tar.gz
sudo mv opensearch-2.11.0 /opt/opensearch

# Configure OpenSearch
echo "discovery.type: single-node" | sudo tee -a /opt/opensearch/config/opensearch.yml
echo "plugins.security.disabled: true" | sudo tee -a /opt/opensearch/config/opensearch.yml

# Set heap size to 16GB (adjust based on your RAM)
sudo sed -i 's/-Xms[0-9]*[gGmM]/-Xms16g/' /opt/opensearch/config/jvm.options
sudo sed -i 's/-Xmx[0-9]*[gGmM]/-Xmx16g/' /opt/opensearch/config/jvm.options

# Create opensearch user
sudo useradd -r -s /bin/bash opensearch
sudo chown -R opensearch:opensearch /opt/opensearch

# Create systemd service
sudo tee /etc/systemd/system/opensearch.service > /dev/null << 'OSEOF'
[Unit]
Description=OpenSearch
After=network.target

[Service]
Type=simple
User=opensearch
Group=opensearch
ExecStart=/opt/opensearch/bin/opensearch
Restart=on-failure
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
OSEOF

# Start OpenSearch
sudo systemctl daemon-reload
sudo systemctl enable opensearch
sudo systemctl start opensearch

# Wait for OpenSearch to start (takes ~30 seconds)
sleep 45

# Increase circuit breaker limit
curl -X PUT "localhost:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
  "persistent": {
    "indices.breaker.total.limit": "95%"
  }
}'
```

### Step 4: Install CaseScope Application

```bash
# Create casescope user
sudo useradd -r -s /bin/bash -m -d /home/casescope casescope

# Create directory structure
sudo mkdir -p /opt/casescope/{app,data,uploads,staging,archive,local_uploads,bulk_import,logs,bin,sigma_rules}
sudo chown -R casescope:casescope /opt/casescope

# Switch to casescope user
sudo -u casescope bash

# Clone repository
cd /opt/casescope
git clone https://github.com/JustinTDCT/caseScope_2026.git app
cd app

# Create virtual environment
python3 -m venv /opt/casescope/venv
source /opt/casescope/venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Configure database connection
cat > /opt/casescope/app/config.py << 'CONFIGEOF'
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # PostgreSQL Configuration
    SQLALCHEMY_DATABASE_URI = 'postgresql://casescope:casescope_secure_2026@localhost/casescope'
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,          # 10 persistent connections
        'max_overflow': 20,        # +20 on-demand connections
        'pool_pre_ping': True,     # Health check before use
        'pool_recycle': 3600       # Recycle after 1 hour
    }
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Celery Configuration
    CELERY_BROKER_URL = 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
    
    # Upload Configuration
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024 * 1024  # 16GB max upload
    UPLOAD_FOLDER = '/opt/casescope/uploads'
CONFIGEOF

# Exit casescope user shell
exit
```

### Step 5: Download Forensic Tools

```bash
# Switch to casescope user
sudo -u casescope bash
cd /opt/casescope/bin

# Download evtx_dump
wget https://github.com/omerbenamram/evtx/releases/download/v0.8.2/evtx_dump-v0.8.2-x86_64-unknown-linux-gnu
mv evtx_dump-v0.8.2-x86_64-unknown-linux-gnu evtx_dump
chmod +x evtx_dump

# Download chainsaw
wget https://github.com/WithSecureLabs/chainsaw/releases/download/v2.13.1/chainsaw_x86_64-unknown-linux-gnu.tar.gz
tar -xzf chainsaw_x86_64-unknown-linux-gnu.tar.gz
mv chainsaw/chainsaw_x86_64-unknown-linux-gnu chainsaw
chmod +x chainsaw
rm -rf chainsaw_x86_64-unknown-linux-gnu.tar.gz chainsaw/

exit
```

### Step 6: Clone SIGMA Rules

```bash
sudo -u casescope bash
cd /opt/casescope
git clone https://github.com/SigmaHQ/sigma.git sigma_rules_repo
exit
```

### Step 7: Initialize Database

```bash
cd /opt/casescope/app
source /opt/casescope/venv/bin/activate

# Create database tables
python << 'PYEOF'
from main import app, db
with app.app_context():
    db.create_all()
    print("✓ Database tables created successfully")
PYEOF

# Create admin user
python << 'PYEOF'
from main import app, db
from models import User
from werkzeug.security import generate_password_hash

with app.app_context():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@localhost',
            password_hash=generate_password_hash('admin'),
            role='administrator'
        )
        db.session.add(admin)
        db.session.commit()
        print("✓ Admin user created (username: admin, password: admin)")
    else:
        print("Admin user already exists")
PYEOF
```

### Step 8: Create Systemd Services

```bash
# Create web application service
sudo tee /etc/systemd/system/casescope.service > /dev/null << 'EOF'
[Unit]
Description=CaseScope 2026 Web Application
After=network.target opensearch.service redis.service postgresql.service

[Service]
Type=simple
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope/app
Environment="PATH=/opt/casescope/venv/bin"
ExecStart=/opt/casescope/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 --timeout 300 wsgi:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create worker service
sudo tee /etc/systemd/system/casescope-worker.service > /dev/null << 'EOF'
[Unit]
Description=CaseScope 2026 Celery Worker
After=network.target redis.service opensearch.service postgresql.service

[Service]
Type=simple
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope/app
Environment="PATH=/opt/casescope/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="PYTHONPATH=/opt/casescope/app"
ExecStart=/opt/casescope/venv/bin/celery -A celery_app worker --loglevel=info --concurrency=4
Restart=always
RestartSec=10

# Memory Limits (adjust based on available RAM)
MemoryHigh=10G
MemoryMax=12G

[Install]
WantedBy=multi-user.target
EOF

# Create wsgi.py entry point
sudo -u casescope tee /opt/casescope/app/wsgi.py > /dev/null << 'EOF'
from main import app

if __name__ == "__main__":
    app.run()
EOF
```

### Step 9: Start Services

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable services to start on boot
sudo systemctl enable casescope casescope-worker

# Start services
sudo systemctl start casescope casescope-worker

# Check status
sudo systemctl status casescope
sudo systemctl status casescope-worker
```

---

## 🎉 Post-Installation

### 1. Access the Application

Open your browser and navigate to:
```
http://YOUR_SERVER_IP:5000
```

**Default credentials:**
- Username: `admin`
- Password: `admin`

⚠️ **IMPORTANT**: Change the admin password immediately!

### 2. Change Default Password

1. Login with admin/admin
2. Click your username in the top-right
3. Click "Change Password"
4. Enter a strong password

### 3. Create Your First Case

1. Click "+ New Case"
2. Fill in case details:
   - Case Name
   - Company
   - Description (optional)
3. Click "Create Case"

### 4. Upload Test Files

1. Open your case
2. Click "+ Upload Files"
3. Select EVTX, JSON, CSV, or ZIP files
4. Click "Upload"
5. Monitor processing on the Case Files page

### 5. Optional: Install Ollama for AI Reports

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull default AI model
ollama pull phi3:mini

# Create systemd service
sudo tee /etc/systemd/system/ollama.service > /dev/null << 'EOF'
[Unit]
Description=Ollama Service
After=network.target

[Service]
Type=simple
User=ollama
Group=ollama
ExecStart=/usr/local/bin/ollama serve
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Start Ollama
sudo systemctl daemon-reload
sudo systemctl enable ollama
sudo systemctl start ollama
```

---

## ✅ Verification

### Check All Services

```bash
# Check service status
sudo systemctl status redis
sudo systemctl status opensearch
sudo systemctl status casescope
sudo systemctl status casescope-worker

# All should show "active (running)" in green
```

### Test Components

```bash
# Test PostgreSQL
psql -U casescope -d casescope -c "SELECT COUNT(*) FROM \"user\";"
# Should show: 1 (the admin user)

# Test Redis
redis-cli ping
# Should return: PONG

# Test OpenSearch
curl localhost:9200/_cluster/health?pretty
# Should show: "status" : "green" or "yellow"

# Test Web Application
curl -I localhost:5000
# Should return: HTTP/1.1 200 OK

# Check queue (should be 0 when idle)
redis-cli LLEN celery
# Should return: (integer) 0
```

### Monitor Logs

```bash
# Web application logs
sudo journalctl -u casescope -f

# Worker logs (watch this during file uploads)
sudo journalctl -u casescope-worker -f

# OpenSearch logs
sudo journalctl -u opensearch -f

# Application log files
tail -f /opt/casescope/app/logs/app.log
tail -f /opt/casescope/app/logs/workers.log
```

---

## 🐛 Troubleshooting

### Services Not Starting

**Problem**: CaseScope service won't start
```bash
# Check status
sudo systemctl status casescope

# View logs
sudo journalctl -u casescope -n 100

# Common issues:
# 1. PostgreSQL not running
sudo systemctl status postgresql

# 2. Virtual environment issues
ls -la /opt/casescope/venv/bin/

# 3. Permission issues
ls -la /opt/casescope/app/
# All files should be owned by casescope:casescope
```

**Problem**: Worker not processing files
```bash
# Check worker status
sudo systemctl status casescope-worker

# Check if tasks are queued
redis-cli LLEN celery

# Restart worker
sudo systemctl restart casescope-worker

# Check for errors
sudo journalctl -u casescope-worker -n 100
```

### Database Connection Issues

```bash
# Verify PostgreSQL is running
sudo systemctl status postgresql

# Check connections
sudo -u postgres psql -c "SELECT count(*) FROM pg_stat_activity WHERE datname='casescope';"

# Test connection manually
psql -U casescope -d casescope -c "\\conninfo"

# Reset PostgreSQL password if needed
sudo -u postgres psql -c "ALTER USER casescope WITH PASSWORD 'casescope_secure_2026';"
```

### OpenSearch Issues

```bash
# Check OpenSearch health
curl localhost:9200/_cluster/health?pretty

# Check heap usage
curl -s localhost:9200/_nodes/stats/jvm | grep heap_used_percent

# If heap consistently > 90%, increase heap size:
sudo nano /opt/opensearch/config/jvm.options
# Change -Xms16g and -Xmx16g to higher values (e.g., 24g)

# Restart OpenSearch
sudo systemctl restart opensearch
```

### Files Stuck in "Queued" Status

```bash
# Check if Celery workers are running
sudo systemctl status casescope-worker
ps aux | grep celery | grep -v grep

# Check Redis queue
redis-cli LLEN celery

# Restart worker
sudo systemctl restart casescope-worker

# Requeue failed files via UI:
# Go to Case → Files → Click "Requeue Failed" button
```

### Permission Errors

```bash
# Fix file ownership
sudo chown -R casescope:casescope /opt/casescope

# Fix file permissions
sudo chmod -R 755 /opt/casescope/app
sudo chmod -R 775 /opt/casescope/uploads
sudo chmod -R 775 /opt/casescope/staging
sudo chmod -R 775 /opt/casescope/archive
```

### Clear Everything and Start Fresh

```bash
# Stop all services
sudo systemctl stop casescope casescope-worker opensearch redis

# Clear Redis
redis-cli FLUSHALL

# Clear OpenSearch data
sudo rm -rf /opt/opensearch/data/*

# Clear case files
sudo rm -rf /opt/casescope/uploads/*
sudo rm -rf /opt/casescope/staging/*
sudo rm -rf /opt/casescope/archive/*

# Reset database
sudo -u postgres psql -c "DROP DATABASE casescope;"
sudo -u postgres psql -c "CREATE DATABASE casescope;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE casescope TO casescope;"

# Reinitialize database
cd /opt/casescope/app
source /opt/casescope/venv/bin/activate
python -c "from main import app, db; app.app_context().push(); db.create_all()"

# Start services
sudo systemctl start opensearch
sleep 45  # Wait for OpenSearch
sudo systemctl start redis casescope casescope-worker
```

---

## 🔒 Security Hardening (Production)

### 1. Change Default Passwords

```bash
# Change PostgreSQL password
sudo -u postgres psql -c "ALTER USER casescope WITH PASSWORD 'YOUR_STRONG_PASSWORD';"

# Update config.py with new password
sudo -u casescope nano /opt/casescope/app/config.py
# Change: SQLALCHEMY_DATABASE_URI = 'postgresql://casescope:YOUR_STRONG_PASSWORD@localhost/casescope'

# Change admin user password in the web UI
```

### 2. Setup Firewall

```bash
# Install UFW
sudo apt install ufw

# Allow SSH
sudo ufw allow 22/tcp

# Allow HTTP (only from trusted IPs in production)
sudo ufw allow from YOUR_IP to any port 5000

# Enable firewall
sudo ufw enable
```

### 3. Add Reverse Proxy (nginx)

```bash
# Install nginx
sudo apt install nginx

# Create config
sudo tee /etc/nginx/sites-available/casescope > /dev/null << 'EOF'
server {
    listen 80;
    server_name YOUR_DOMAIN_OR_IP;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300;
        client_max_body_size 16G;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/casescope /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# Now access via: http://YOUR_DOMAIN_OR_IP (port 80)
```

### 4. Add SSL/TLS (Let's Encrypt)

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d YOUR_DOMAIN

# Auto-renewal is configured automatically
```

---

## 📞 Getting Help

If you encounter issues:

1. **Check logs first**:
   - `sudo journalctl -u casescope -n 100`
   - `sudo journalctl -u casescope-worker -n 100`
   - `/opt/casescope/app/logs/app.log`

2. **Verify all services running**:
   - `sudo systemctl status casescope casescope-worker opensearch redis postgresql`

3. **Test with minimal data**:
   - Upload 1-2 small files first
   - Verify processing completes

4. **Check GitHub Issues**:
   - Search for similar problems
   - Open new issue with logs

5. **Join Community**:
   - DFIR Discord channels
   - GitHub Discussions

---

## 📚 Next Steps

After successful installation:

1. ✅ Read the [README.md](README.md) for feature overview
2. ✅ Check [ARCHITECTURE_OVERVIEW.md](ARCHITECTURE_OVERVIEW.md) for system understanding
3. ✅ Review [QUICK_REFERENCE_AI.md](QUICK_REFERENCE_AI.md) for common patterns
4. ✅ Check [CURRENT_STATE.md](CURRENT_STATE.md) for known issues
5. ✅ Create user accounts for your team
6. ✅ Configure SIGMA rules for your environment
7. ✅ Import your IOC lists
8. ✅ Start processing your forensic data!

⚠️ **IMPORTANT**: Review [CURRENT_STATE.md](CURRENT_STATE.md) for known bugs (re-index is currently broken)

---

**Installation Guide Version**: 1.16.24  
**Compatible with**: Ubuntu 24.04 LTS  
**Last Updated**: November 20, 2025
