# CaseScope

> **WARNING: WORK IN PROGRESS**
>
> This application is under active development. Not all features are fully implemented yet, and you may encounter bugs or incomplete functionality. Use at your own risk and report issues as you find them.

---

CaseScope is a comprehensive digital forensics and incident response (DFIR) platform designed to streamline case management, artifact analysis, and threat hunting workflows. Built for security analysts and forensic investigators, it provides an integrated environment for processing, correlating, and investigating security events across multiple data sources.

## Key Features

### Case & Client Management
- **Multi-tenant architecture** with client organizations and per-client cases
- **Multi-case support** with UUID-based identification
- **Timezone-aware** case configuration for accurate timestamp correlation
- **Status tracking** (New, Assigned, In Progress, In Review, Finished, Archived)
- **Case archiving and restoration** with LZMA-compressed ZIP bundles
- **EDR report integration** for attaching and viewing endpoint detection reports
- **Role-based access control** with Administrator, Analyst, and Viewer permission levels
- **Audit logging** across all entities for compliance

### Evidence Processing Pipeline
- **Multi-format parser support** including:
  - Windows Event Logs (EVTX) with EvtxECmd + Hayabusa dual-engine processing
  - Browser artifacts (Chrome, Firefox — history, cookies, downloads, sessions, extensions)
  - Registry hives via Dissect framework (SAM, SECURITY, SOFTWARE, SYSTEM, NTUSER.DAT)
  - Prefetch files (.pf) with execution timestamps
  - LNK shortcut files and Jump Lists
  - MFT ($MFT) with MACB timestamps
  - SRUM (System Resource Usage Monitor) via ESE database parsing
  - Scheduled Tasks (XML)
  - Windows Timeline (ActivitiesCache.db)
  - WebCache (IE/Edge ESE databases)
  - Memory dumps via Volatility3
  - Network captures (PCAP/PCAPNG) via Zeek
  - IIS logs (W3C Extended Log Format)
  - Firewall logs (SonicWall, pfSense, syslog)
  - Huntress EDR exports (ECS/NDJSON)
  - Generic JSON, NDJSON, CSV log formats
- **Automatic artifact type detection** with intelligent parser routing (magic bytes, extensions, content patterns)
- **Batch file processing** with Celery async task queue
- **SFTP upload support** for large file ingestion
- **ZIP archive extraction** for bundled evidence files
- **Duplicate detection** via SHA-256 hashing
- **Event deduplication** in ClickHouse after ingestion

### Threat Hunting
- **ClickHouse-powered event search** with millisecond query performance
- **Advanced search syntax** with boolean operators, field queries, and wildcards
- **Timeline visualization** of security events
- **MITRE ATT&CK framework integration** via Hayabusa Sigma rules
- **Severity-based event classification** (Critical, High, Medium, Low, Informational)
- **Noise filtering system** with customizable rule categories for hiding known-good software
- **Field enhancement** with automatic Windows event ID descriptions
- **Analyst tagging and notes** on individual events

### Automated Case Analysis
- **Behavioral profiling** of users and systems with baseline comparison
- **Peer group clustering** to identify outlier behavior
- **Gap detection** for password spraying, brute force, and behavioral anomalies
- **Composite anomaly scoring** (auth volume, failure rates, off-hours activity, target patterns)
- **AI-enhanced analysis** with LLM-generated reasoning for findings
- **Suggested remediation actions** based on analysis results

### Memory Forensics
- **Volatility3 integration** for memory dump analysis
- **Automatic plugin selection** based on OS detection (Windows, Linux, macOS)
- **Chunked file upload** for large memory dumps
- **Process tree visualization** with parent-child relationships
- **Network connection analysis** from memory
- **Service enumeration** and suspicious binary detection
- **Malfind analysis** for injected code detection
- **Credential extraction** (hashdump, cachedump, lsadump)
- **Cross-memory search** across multiple dumps within a case

### Network Forensics
- **PCAP file management** with automatic format detection and chunked upload
- **Zeek integration** for network log generation
- **Network hunting interface** with tabs for:
  - Connection logs (TCP/UDP flows)
  - DNS queries and responses
  - HTTP requests
  - SSL/TLS certificates
  - File transfers
- **ClickHouse-indexed network logs** for fast searching
- **Cross-log correlation** with pivot to event data

### IOC Management
- **Comprehensive IOC type support**:
  - Network: IP addresses, domains, URLs, JA3/JA3S hashes
  - File: MD5, SHA1, SHA256 hashes, file paths, filenames
  - Email: addresses, subjects, headers
  - Process: names, paths, command lines
  - Registry: keys and values
  - Authentication: usernames, SIDs
  - And more (cryptocurrency addresses, CVEs, etc.)
- **Intelligent match type detection** (token, substring, regex)
- **Artifact tagging** for tracking IOC appearances across events
- **System sighting tracking** showing which hosts exhibited IOCs
- **OpenCTI integration** for threat intelligence enrichment
- **IOC timeline builder** for tracking IOC activity over time

### AI-Powered Analysis (Optional)
- **RAG (Retrieval-Augmented Generation)** with Qdrant vector database
- **Ollama LLM integration** for natural language hunting queries and event review
- **Attack pattern detection** with semantic similarity matching
- **Pattern discovery** from ingested events
- **AI correlation analysis** across case findings
- **DFIR chat assistant** with SSE streaming and tool execution
- **Ask AI** for context-aware hunting assistance
- **Campaign detection** linking related attack patterns

### Known Systems & Users Discovery
- **Automatic system enumeration** from artifact hostnames
- **IP and MAC address correlation**
- **Network share discovery**
- **User SID tracking** with alias management
- **Behavioral profiling** per user and system
- **Cross-case reference tracking**

### Reporting
- **DOCX report generation** from customizable templates
- **Markdown-to-DOCX conversion** for flexible report authoring
- **Multiple report types** with template management
- **Per-case report archival**

### System Administration
- **User management** with password policies and account lockout
- **Client and agent management** for multi-tenant deployments
- **Audit logging** for compliance across all data modifications
- **System settings** for AI, integrations, and behavior configuration
- **Hayabusa rule management** with automatic updates
- **License activation** with machine-bound fingerprinting

## Technology Stack

### Backend
- **Flask** — Python web framework with Gunicorn (gthread workers) for production
- **PostgreSQL** — Primary database for case, user, IOC, and entity metadata
- **ClickHouse** — High-performance columnar database for event and network log storage
- **Celery** — Distributed task queue for async processing (parsing, analysis, memory, PCAP)
- **Redis** — Message broker for Celery and progress tracking

### Processing Tools
- **EvtxECmd** — Windows event log parser with field normalization maps (requires .NET Runtime)
- **Hayabusa** — Windows event log analyzer with Sigma/Hayabusa detection rules
- **Volatility3** — Memory forensics framework
- **Zeek** — Network security monitor for PCAP analysis
- **Dissect** — Forensic artifact parsing framework (registry, prefetch, MFT, SRUM, etc.)

### AI/ML (Optional)
- **Qdrant** — Vector database for semantic search and pattern matching
- **Ollama** — Local LLM inference server
- **sentence-transformers** — Text embedding generation (all-MiniLM-L6-v2)

### Frontend
- **Jinja2 templates** served by Flask
- **Centralized CSS** (`static/css/main.css`)

## System Requirements

- **OS**: Ubuntu 24.04 LTS (recommended)
- **Python**: 3.12+
- **PostgreSQL**: 16+
- **ClickHouse**: 25+
- **Redis**: 7+
- **Zeek**: 7+ LTS
- **.NET Runtime**: 9.0 (for EvtxECmd)
- **Memory**: 16 GB minimum, 32 GB+ recommended for memory forensics and AI features
- **Storage**: SSD recommended; space depends on case sizes
- **GPU** (optional): NVIDIA GPU with CUDA for faster embeddings

## Installation on Ubuntu 24.04 LTS

### 1. System Preparation

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential git curl wget unzip python3 python3-pip python3-venv \
    libpq-dev libffi-dev libssl-dev pkg-config
```

### 2. Create the CaseScope User and Directory

```bash
sudo groupadd casescope
sudo useradd -r -g casescope -d /opt/casescope -s /bin/bash casescope
sudo mkdir -p /opt/casescope
sudo chown casescope:casescope /opt/casescope
```

### 3. Clone the Repository

```bash
sudo -u casescope git clone <REPO_URL> /opt/casescope
cd /opt/casescope
```

### 4. Install PostgreSQL

```bash
sudo apt install -y postgresql postgresql-contrib

sudo -u postgres psql <<EOF
CREATE USER casescope WITH PASSWORD 'casescope';
CREATE DATABASE casescope OWNER casescope;
GRANT ALL PRIVILEGES ON DATABASE casescope TO casescope;
EOF
```

### 5. Install ClickHouse

```bash
sudo apt install -y apt-transport-https ca-certificates gnupg
curl -fsSL https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key | \
    sudo gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb stable main" | \
    sudo tee /etc/apt/sources.list.d/clickhouse.list

sudo apt update
sudo apt install -y clickhouse-server clickhouse-client
sudo systemctl enable --now clickhouse-server

# Create the casescope database
clickhouse-client -q "CREATE DATABASE IF NOT EXISTS casescope"
```

The ClickHouse events table schema is created automatically by the application on first run. It includes the `events` and `events_buffer` tables with full-text search indexes.

### 6. Install Redis

```bash
sudo apt install -y redis-server
sudo systemctl enable --now redis-server
```

### 7. Install Zeek

```bash
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | \
    sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | \
    gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

sudo apt update
sudo apt install -y zeek-lts
```

Zeek installs to `/opt/zeek/bin/zeek` by default.

### 8. Set Up the Python Virtual Environment

```bash
cd /opt/casescope
sudo -u casescope python3 -m venv venv
sudo -u casescope venv/bin/pip install --upgrade pip
sudo -u casescope venv/bin/pip install -r requirements.txt
```

Volatility3 is installed separately (not in requirements.txt) due to its dependency footprint:

```bash
sudo -u casescope venv/bin/pip install volatility3
```

### 9. Install EvtxECmd and .NET Runtime

```bash
sudo bash bin/install_eztools.sh
```

This script installs the .NET 9.0 runtime to `/opt/casescope/.dotnet` and downloads EvtxECmd with its field normalization maps.

### 10. Install Hayabusa

```bash
sudo bash bin/install_hayabusa.sh
```

This downloads the Hayabusa binary and Sigma detection rules.

### 11. Generate SSL Certificates

CaseScope runs HTTPS on port 443. Generate a self-signed certificate for development or provide your own:

```bash
sudo -u casescope mkdir -p /opt/casescope/ssl
sudo -u casescope openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /opt/casescope/ssl/key.pem \
    -out /opt/casescope/ssl/cert.pem \
    -days 365 -subj "/CN=casescope"
```

### 12. Create Required Directories

```bash
sudo -u casescope mkdir -p /opt/casescope/{uploads/web,uploads/sftp,uploads/pcap,staging,storage,evidence,evidence_uploads,logs,temp}
```

### 13. Install Qdrant (Optional — for AI/RAG Features)

```bash
# Download Qdrant binary
curl -L -o /tmp/qdrant.tar.gz https://github.com/qdrant/qdrant/releases/download/v1.7.4/qdrant-x86_64-unknown-linux-gnu.tar.gz
sudo tar -xzf /tmp/qdrant.tar.gz -C /usr/local/bin/
rm /tmp/qdrant.tar.gz

# Create Qdrant data directory and config
sudo -u casescope mkdir -p /opt/casescope/qdrant/{storage,snapshots}

sudo -u casescope tee /opt/casescope/qdrant/config.yaml > /dev/null <<EOF
service:
  http_port: 6333
  grpc_port: 6334
  max_request_size_mb: 32

storage:
  storage_path: /opt/casescope/qdrant/storage
  wal:
    wal_capacity_mb: 256
    wal_segments_ahead: 0

log_level: INFO
EOF

# Create systemd service
sudo tee /etc/systemd/system/qdrant.service > /dev/null <<EOF
[Unit]
Description=Qdrant Vector Database
After=network.target

[Service]
Type=simple
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope/qdrant
ExecStart=/usr/local/bin/qdrant --config-path /opt/casescope/qdrant/config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now qdrant
```

### 14. Install Ollama (Optional — for AI Features)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:14b-instruct-q5_K_M
```

### 15. Create Systemd Services

**Web Application Service:**

```bash
sudo tee /etc/systemd/system/casescope-web.service > /dev/null <<EOF
[Unit]
Description=CaseScope 2026 Web Application
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope
Environment="PATH=/opt/casescope/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/opt/casescope/venv/bin/gunicorn --worker-class gthread --workers 4 --threads 4 --bind 0.0.0.0:443 --certfile=/opt/casescope/ssl/cert.pem --keyfile=/opt/casescope/ssl/key.pem --timeout 1800 wsgi:app
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
EOF
```

**Celery Workers Service:**

```bash
sudo tee /etc/systemd/system/casescope-workers.service > /dev/null <<EOF
[Unit]
Description=CaseScope 2026 Celery Workers
After=network.target redis.service postgresql.service
Wants=redis.service postgresql.service

[Service]
LimitNOFILE=65536
Type=simple
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope
Environment="PATH=/opt/casescope/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="PYTHONPATH=/opt/casescope"
ExecStart=/opt/casescope/venv/bin/celery -A tasks worker --loglevel=info --concurrency=12
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### 16. Fix Permissions and Start Services

```bash
sudo chown -R casescope:casescope /opt/casescope
sudo systemctl daemon-reload
sudo systemctl enable --now casescope-web casescope-workers
```

### 17. Verify Installation

```bash
# Check all services are running
sudo systemctl status casescope-web casescope-workers redis-server postgresql clickhouse-server

# Check the web application
curl -k https://localhost/login
```

Open your browser and navigate to `https://<server-ip>`. Log in with the default credentials (see below) and change the password immediately.

## Services

CaseScope runs as two main services:
- `casescope-web` — Flask/Gunicorn web application (HTTPS on port 443)
- `casescope-workers` — Celery worker processes for background tasks (parsing, analysis, memory forensics, PCAP processing, archiving)

Optional services:
- `qdrant` — Vector database for RAG/AI functionality (port 6333)

Dependent services:
- `postgresql` — Primary metadata database
- `clickhouse-server` — Event and network log storage
- `redis-server` — Celery broker and progress tracking

## Configuration

Configuration is managed via `config.py` with environment variable overrides:

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://casescope:casescope@localhost/casescope` |
| `CLICKHOUSE_HOST` | ClickHouse server hostname | `localhost` |
| `CLICKHOUSE_PORT` | ClickHouse HTTP port | `8123` |
| `CLICKHOUSE_DATABASE` | ClickHouse database name | `casescope` |
| `REDIS_HOST` | Redis server hostname | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `OLLAMA_HOST` | Ollama API endpoint | `http://localhost:11434` |
| `OLLAMA_MODEL` | LLM model for AI features | `qwen2.5:14b-instruct-q5_K_M` |
| `QDRANT_HOST` | Qdrant server hostname | `localhost` |
| `QDRANT_PORT` | Qdrant HTTP port | `6333` |
| `EMBEDDING_MODEL` | Sentence-transformer model | `all-MiniLM-L6-v2` |
| `EMBEDDING_DEVICE` | Embedding compute device | `cuda` |
| `SECRET_KEY` | Flask secret key | (generate for production) |
| `SSL_CERT` | Path to SSL certificate | `/opt/casescope/ssl/cert.pem` |
| `SSL_KEY` | Path to SSL private key | `/opt/casescope/ssl/key.pem` |

## Directory Structure

```
/opt/casescope/
├── app.py              # Flask application factory
├── config.py           # Configuration settings
├── run.py              # Development server
├── wsgi.py             # Production WSGI entry point
├── version.json        # Version and changelog
├── requirements.txt    # Python dependencies
├── bin/                # External tools (EvtxECmd, Hayabusa, install scripts)
├── models/             # SQLAlchemy database models
├── parsers/            # Artifact parsers (EVTX, browser, registry, logs, memory, etc.)
├── routes/             # Flask route blueprints
├── rules/              # Detection rules (Hayabusa, Sigma)
├── scrapers/           # Event description scrapers
├── static/             # CSS, templates, assets
│   ├── css/main.css    # Central stylesheet
│   └── templates/      # Jinja2 HTML templates
├── tasks/              # Celery background tasks
├── utils/              # Utility modules (AI, detection, IOC, licensing, etc.)
├── migrations/         # Database migration scripts
├── uploads/            # Incoming file uploads (web, SFTP, PCAP)
├── staging/            # Files being processed
├── storage/            # Processed case files
├── evidence/           # Evidence file storage (screenshots, exports)
├── qdrant/             # Qdrant vector database storage
├── logs/               # Application logs
├── ssl/                # SSL certificates
└── temp/               # Temporary processing files
```

## Default Credentials

On first run, an admin account is created:
- **Username**: `admin`
- **Password**: `admin`

**Change the default password immediately after first login.**

## API Routes

The application exposes the following API blueprints:

| Blueprint | Prefix | Purpose |
|-----------|--------|---------|
| `main_bp` | `/` | Dashboard, cases, clients, users, settings |
| `auth_bp` | `/` | Login, logout, session management |
| `api_bp` | `/api` | File upload, event hunting, IOC management, system config |
| `parsing_bp` | `/api/parsing` | File parsing, parser management, rule updates |
| `analysis_bp` | `/api/case` | Behavioral analysis, gap detection, suggested actions |
| `memory_bp` | `/api/memory` | Memory forensics upload, processing, hunting |
| `pcap_bp` | `/api/pcap` | PCAP file management, Zeek processing |
| `network_hunting_bp` | `/api/network` | Network log querying and indexing |
| `noise_bp` | `/settings/noise` | Noise filter rule management |
| `rag_bp` | `/api/rag` | AI/RAG pattern detection, semantic search, Ask AI |
| `chat_bp` | `/api/chat` | DFIR chat assistant with SSE streaming |
| `evidence_bp` | `/evidence` | Evidence file archival storage |
| `activation_bp` | `/activation` | License activation and management |

## Troubleshooting

**Services won't start:**
```bash
sudo journalctl -u casescope-web -f
sudo journalctl -u casescope-workers -f
```

**ClickHouse connection issues:**
```bash
clickhouse-client -q "SELECT 1"
clickhouse-client -q "SHOW DATABASES"
```

**Redis connection issues:**
```bash
redis-cli ping
```

**File permission issues:**
```bash
sudo chown -R casescope:casescope /opt/casescope
```

**Celery workers not processing tasks:**
```bash
sudo systemctl restart casescope-workers
sudo journalctl -u casescope-workers --since "5 minutes ago"
```

## Version

Current version: See `version.json` for detailed changelog.

## License

Proprietary — All rights reserved.

---

*CaseScope — Digital Forensics Made Efficient*
