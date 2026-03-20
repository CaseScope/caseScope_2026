# CaseScope

> **Warning: work in progress**
>
> CaseScope is under active development. Expect schema changes, feature churn, and the occasional rough edge while testing.

CaseScope is a DFIR platform for case management, evidence intake, event hunting, IOC tracking, memory analysis, and PCAP processing. The application uses Flask for the web UI, PostgreSQL for metadata, ClickHouse for event and network log storage, and Celery workers for background processing.

## What It Does

- Case and client management with audit logging and role-based access
- Event ingestion for EVTX, browser artifacts, registry hives, prefetch, LNK, MFT, SRUM, JSON, NDJSON, CSV, firewall logs, and more
- EVTX processing with `EvtxECmd` plus Hayabusa detection enrichment
- Memory processing with Volatility3
- PCAP processing with Zeek
- IOC tracking, artifact tagging, and case-scoped correlation
- Optional AI and RAG features with Ollama and Qdrant

## Runtime Architecture

Core services:

- `casescope-web`: Gunicorn serving the Flask app over HTTPS
- `casescope-workers`: Celery workers for parsing, memory, PCAP, archive, and analysis tasks
- `postgresql`: relational metadata store
- `clickhouse-server`: event and network log store
- `redis-server`: Celery broker and result backend

Optional services:

- `qdrant`: vector store for semantic and RAG features
- `ollama`: local LLM endpoint for AI features

## Tested Baseline

- Ubuntu 24.04 LTS
- Python 3.12
- PostgreSQL 15+
- Redis 7+
- ClickHouse with HTTP interface on port `8123`
- Zeek installed at `/opt/zeek/bin/zeek`
- .NET 9 runtime for `EvtxECmd`

## Beta Tester Installation

The steps below install a single-host test deployment on Ubuntu 24.04.

### 1. Install Base Packages

```bash
sudo apt update
sudo apt install -y \
  build-essential git curl wget unzip \
  python3 python3-pip python3-venv \
  libpq-dev libffi-dev libssl-dev pkg-config \
  postgresql postgresql-contrib redis-server \
  apt-transport-https ca-certificates gnupg
```

### 2. Create the Service User and Base Directories

```bash
sudo groupadd -f casescope
id -u casescope >/dev/null 2>&1 || sudo useradd -r -g casescope -d /opt/casescope -s /bin/bash casescope

sudo mkdir -p /opt/casescope /etc/casescope /originals /archive
sudo chown -R casescope:casescope /opt/casescope /originals /archive
sudo chmod 2775 /originals /archive
```

### 3. Clone the Repository

```bash
sudo -u casescope git clone <REPO_URL> /opt/casescope
cd /opt/casescope
```

### 4. Create the Python Environment

```bash
sudo -u casescope python3 -m venv /opt/casescope/venv
sudo -u casescope /opt/casescope/venv/bin/pip install --upgrade pip
sudo -u casescope /opt/casescope/venv/bin/pip install -r /opt/casescope/requirements.txt
sudo -u casescope /opt/casescope/venv/bin/pip install volatility3
```

`volatility3` is installed separately because the application expects the `vol` command but it is not pinned in `requirements.txt`.

### 5. Install ClickHouse

```bash
curl -fsSL https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key | \
  sudo gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb stable main" | \
  sudo tee /etc/apt/sources.list.d/clickhouse.list >/dev/null

sudo apt update
sudo apt install -y clickhouse-server clickhouse-client
sudo systemctl enable --now clickhouse-server
clickhouse-client -q "CREATE DATABASE IF NOT EXISTS casescope"
```

CaseScope creates its ClickHouse tables on first application start.

### 6. Install Zeek

```bash
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | \
  sudo tee /etc/apt/sources.list.d/security:zeek.list >/dev/null

curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | \
  gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg >/dev/null

sudo apt update
sudo apt install -y zeek-lts
```

CaseScope expects Zeek at `/opt/zeek/bin/zeek`.

### 7. Install EVTX Tooling and Hayabusa

Run the repository-provided installers:

```bash
cd /opt/casescope
sudo bash /opt/casescope/bin/install_eztools.sh
sudo bash /opt/casescope/bin/install_hayabusa.sh
```

These scripts install:

- `.NET 9` under `/opt/casescope/.dotnet`
- `EvtxECmd` under `/opt/casescope/bin/EvtxECmd`
- the `evtxecmd` wrapper at `/opt/casescope/bin/evtxecmd`
- the Hayabusa binary at `/opt/casescope/bin/hayabusa`
- Hayabusa rules under `/opt/casescope/rules/hayabusa-rules`

### 8. Create the PostgreSQL Database

```bash
sudo systemctl enable --now postgresql redis-server

sudo -u postgres psql <<'EOF'
DO $$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'casescope') THEN
      CREATE ROLE casescope LOGIN PASSWORD 'casescope';
   END IF;
END
$$;
EOF

sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = 'casescope'" | grep -q 1 || \
  sudo -u postgres createdb -O casescope casescope
```

### 9. Create the Environment File

`SECRET_KEY` is required. The app will not start without it.

Create `/etc/casescope/casescope.env`:

```bash
sudo tee /etc/casescope/casescope.env >/dev/null <<'EOF'
SECRET_KEY=replace_with_a_long_random_secret
DEFAULT_ADMIN_PASSWORD=ChangeMeNow123!
DATABASE_URL=postgresql://casescope:casescope@localhost/casescope
CLICKHOUSE_HOST=localhost
CLICKHOUSE_PORT=8123
CLICKHOUSE_DATABASE=casescope
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
EMBEDDING_DEVICE=cpu
SSL_CERT=/opt/casescope/ssl/cert.pem
SSL_KEY=/opt/casescope/ssl/key.pem
EOF

sudo chown root:casescope /etc/casescope/casescope.env
sudo chmod 640 /etc/casescope/casescope.env
```

Notes:

- Set `DEFAULT_ADMIN_PASSWORD` for predictable first login during beta testing.
- If you omit `DEFAULT_ADMIN_PASSWORD`, CaseScope generates a random password on first boot and prints it to the web service log.
- `EMBEDDING_DEVICE=cpu` is recommended unless the host has a working CUDA stack.

### 10. Create SSL Certificates

```bash
sudo -u casescope mkdir -p /opt/casescope/ssl
sudo -u casescope openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /opt/casescope/ssl/key.pem \
  -out /opt/casescope/ssl/cert.pem \
  -days 365 -subj "/CN=casescope"
```

Replace these with real certificates for any environment beyond local testing.

### 11. Create the Working Directories

```bash
sudo -u casescope mkdir -p \
  /opt/casescope/uploads/web \
  /opt/casescope/uploads/sftp \
  /opt/casescope/uploads/pcap \
  /opt/casescope/staging \
  /opt/casescope/storage \
  /opt/casescope/evidence \
  /opt/casescope/evidence_uploads \
  /opt/casescope/logs \
  /opt/casescope/temp
```

Current storage behavior:

- live parsed working data is stored under `/opt/casescope/storage`
- retained original uploads default to `/originals`
- archived cases default to `/archive`

### 12. Optional AI Services

Install these only after the core application is working.

#### Qdrant

CaseScope expects Qdrant at `http://localhost:6333` by default.

#### Ollama

CaseScope expects Ollama at `http://localhost:11434` by default.

If you enable AI features, install a model that matches your `OLLAMA_MODEL` setting. The current default in `config.py` is `qwen2.5:14b-instruct-q5_K_M`.

### 13. Create Systemd Services

Web service:

```bash
sudo tee /etc/systemd/system/casescope-web.service >/dev/null <<'EOF'
[Unit]
Description=CaseScope Web Application
After=network.target postgresql.service redis-server.service clickhouse-server.service
Wants=postgresql.service redis-server.service clickhouse-server.service

[Service]
Type=simple
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope
EnvironmentFile=/etc/casescope/casescope.env
Environment="PATH=/opt/casescope/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/opt/casescope/venv/bin/gunicorn --worker-class gthread --workers 4 --threads 4 --bind 0.0.0.0:443 --certfile=/opt/casescope/ssl/cert.pem --keyfile=/opt/casescope/ssl/key.pem --timeout 1800 wsgi:app
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
EOF
```

Worker service:

```bash
sudo tee /etc/systemd/system/casescope-workers.service >/dev/null <<'EOF'
[Unit]
Description=CaseScope Celery Workers
After=network.target postgresql.service redis-server.service clickhouse-server.service
Wants=postgresql.service redis-server.service clickhouse-server.service

[Service]
Type=simple
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope
EnvironmentFile=/etc/casescope/casescope.env
Environment="PATH=/opt/casescope/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="PYTHONPATH=/opt/casescope"
LimitNOFILE=65536
ExecStart=/opt/casescope/venv/bin/celery -A tasks worker --loglevel=info --concurrency=12
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### 14. Start the Application

```bash
sudo chown -R casescope:casescope /opt/casescope /originals /archive
sudo systemctl daemon-reload
sudo systemctl enable --now casescope-web casescope-workers
```

### 15. Verify the Install

```bash
sudo systemctl status casescope-web casescope-workers redis-server postgresql clickhouse-server
curl -k https://localhost/login
```

If you set `DEFAULT_ADMIN_PASSWORD`, the first admin login is:

- Username: `admin`
- Password: the value you set in `/etc/casescope/casescope.env`

If you did not set `DEFAULT_ADMIN_PASSWORD`, fetch the generated password from the web service log:

```bash
sudo journalctl -u casescope-web -n 100 --no-pager
```

Look for a message like:

```text
*** Created admin user 'admin' with generated password: ...
```

## Quick Manual Smoke Test

Before enabling systemd, you can test the app directly:

```bash
sudo -u casescope bash -lc 'cd /opt/casescope && set -a && source /etc/casescope/casescope.env && set +a && python3 run.py'
```

Then open `https://<server-ip>/login`.

## Configuration Notes

Important environment variables:

| Variable | Required | Notes |
|----------|----------|-------|
| `SECRET_KEY` | Yes | Required at startup |
| `DEFAULT_ADMIN_PASSWORD` | No | Strongly recommended for beta testers |
| `DATABASE_URL` | No | Defaults to local PostgreSQL |
| `CLICKHOUSE_HOST` | No | Defaults to `localhost` |
| `CLICKHOUSE_PORT` | No | Defaults to `8123` |
| `CLICKHOUSE_DATABASE` | No | Defaults to `casescope` |
| `REDIS_HOST` | No | Defaults to `localhost` |
| `REDIS_PORT` | No | Defaults to `6379` |
| `CELERY_BROKER_URL` | No | Defaults to Redis DB 0 |
| `CELERY_RESULT_BACKEND` | No | Defaults to Redis DB 0 |
| `SSL_CERT` | No | Defaults to `/opt/casescope/ssl/cert.pem` |
| `SSL_KEY` | No | Defaults to `/opt/casescope/ssl/key.pem` |
| `QDRANT_HOST` | No | Optional AI service |
| `QDRANT_PORT` | No | Optional AI service |
| `OLLAMA_HOST` | No | Optional AI service |
| `OLLAMA_MODEL` | No | Defaults to `qwen2.5:14b-instruct-q5_K_M` |
| `EMBEDDING_MODEL` | No | Defaults to `all-MiniLM-L6-v2` |
| `EMBEDDING_DEVICE` | No | Defaults to `cuda`; set `cpu` on non-GPU systems |

## Directory Layout

```text
/opt/casescope/
├── app.py
├── config.py
├── run.py
├── wsgi.py
├── requirements.txt
├── version.json
├── bin/
├── migrations/
├── models/
├── parsers/
├── routes/
├── rules/
├── scrapers/
├── static/
│   ├── css/
│   └── templates/
├── tasks/
├── tests/
├── uploads/
├── staging/
├── storage/
├── evidence/
├── evidence_uploads/
├── logs/
├── ssl/
└── temp/

/originals/   # retained original uploads, case-scoped
/archive/     # archived cases
```

## First-Run Behavior

On first application start, CaseScope:

- creates PostgreSQL tables with `db.create_all()`
- runs tracked schema migrations
- creates the default `admin` user if it does not already exist
- creates ClickHouse tables when event storage is first used

There is no fixed built-in `admin/admin` credential.

## Troubleshooting

Service logs:

```bash
sudo journalctl -u casescope-web -f
sudo journalctl -u casescope-workers -f
```

Check PostgreSQL:

```bash
sudo -u postgres psql -d casescope -c "SELECT 1;"
```

Check ClickHouse:

```bash
clickhouse-client -q "SELECT 1"
clickhouse-client -q "SHOW DATABASES"
```

Check Redis:

```bash
redis-cli ping
```

Check Zeek:

```bash
/opt/zeek/bin/zeek --version
```

Check Volatility3:

```bash
/opt/casescope/venv/bin/vol -h
```

Fix ownership:

```bash
sudo chown -R casescope:casescope /opt/casescope /originals /archive
```

## Version

Current application version: see `version.json`.

## License

Proprietary. All rights reserved.
