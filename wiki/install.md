# Install CaseScope

This page walks through a single-host CaseScope installation on Ubuntu 24.04 LTS. It assumes you have already reviewed [Getting Started: Pre-Install Planning](getting-started.md) and prepared the VM or physical host.

## Before You Begin

You need:

- Ubuntu 24.04 LTS
- `sudo` access
- outbound internet access for packages and tool downloads
- a CaseScope repository URL
- planned storage for `/opt/casescope`, `/originals`, and `/archive`
- first-login and secret values ready

The commands below install CaseScope under `/opt/casescope` and run services as the `casescope` user and group.

## 1. Update The Host

```bash
sudo apt update
sudo apt upgrade -y
sudo reboot
```

After the reboot, reconnect to the host.

## 2. Install Base Packages

```bash
sudo apt update
sudo apt install -y \
  build-essential git curl wget unzip \
  python3 python3-pip python3-venv \
  libpq-dev libffi-dev libssl-dev pkg-config \
  postgresql postgresql-contrib redis-server \
  apt-transport-https ca-certificates gnupg
```

## 3. Create The Service User And Directories

```bash
sudo groupadd -f casescope
id -u casescope >/dev/null 2>&1 || sudo useradd -r -g casescope -d /opt/casescope -s /bin/bash casescope

sudo mkdir -p /opt/casescope /etc/casescope /originals /archive
sudo chown -R casescope:casescope /opt/casescope /originals /archive
sudo chmod 2775 /originals /archive
```

## 4. Clone The Repository

Replace `<REPO_URL>` with the CaseScope repository URL.

```bash
sudo -u casescope git clone <REPO_URL> /opt/casescope
cd /opt/casescope
```

## 5. Create The Python Environment

```bash
sudo -u casescope python3 -m venv /opt/casescope/venv
sudo -u casescope /opt/casescope/venv/bin/pip install --upgrade pip
sudo -u casescope /opt/casescope/venv/bin/pip install -r /opt/casescope/requirements.txt
sudo -u casescope /opt/casescope/venv/bin/pip install volatility3
```

`volatility3` is installed separately because CaseScope expects the `vol` command.

## 6. Install ClickHouse

If the ClickHouse package prompts for the default user password, do not set a user or password. Leave it blank by pressing Enter at the password prompt and Enter again at the confirmation prompt.

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

CaseScope uses ClickHouse for event and network telemetry. Keep ClickHouse on fast storage when possible.

## 7. Install Zeek

```bash
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | \
  sudo tee /etc/apt/sources.list.d/security:zeek.list >/dev/null

curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | \
  gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg >/dev/null

sudo apt update
sudo apt install -y zeek-lts
```

CaseScope expects Zeek at `/opt/zeek/bin/zeek`.

## 8. Install EVTX Tooling And Hayabusa

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

## 9. Create The PostgreSQL Database

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

For shared or production-like deployments, replace the example database password and update `DATABASE_URL` in the environment file below.

## 10. Create The Environment File

Generate a strong `SECRET_KEY`:

```bash
openssl rand -hex 32
```

Create `/etc/casescope/casescope.env` and replace the example secrets before starting the app:

```bash
sudo tee /etc/casescope/casescope.env >/dev/null <<'EOF'
SECRET_KEY=replace_with_a_long_random_secret
DEFAULT_ADMIN_PASSWORD=ChangeMeNow123!
SESSION_TIMEOUT_MINUTES=90
REMEMBER_COOKIE_DAYS=7
DATABASE_URL=postgresql://casescope:casescope@localhost/casescope
CLICKHOUSE_HOST=localhost
CLICKHOUSE_PORT=8123
CLICKHOUSE_DATABASE=casescope
QDRANT_HOST=localhost
QDRANT_PORT=6333
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
EMBEDDING_DEVICE=cpu
SSL_CERT=/opt/casescope/ssl/cert.pem
SSL_KEY=/opt/casescope/ssl/key.pem
# Optional hardening flags
# ALLOW_DESTRUCTIVE_STARTUP_MIGRATIONS=false
# ADMIN_BOOTSTRAP_PASSWORD_FILE=/opt/casescope/temp/generated_admin_password.txt
EOF

sudo chown root:casescope /etc/casescope/casescope.env
sudo chmod 640 /etc/casescope/casescope.env
```

Notes:

- `SECRET_KEY` is required.
- `DEFAULT_ADMIN_PASSWORD` sets a predictable first admin password for testing.
- If `DEFAULT_ADMIN_PASSWORD` is omitted, CaseScope generates a first-boot password and writes it to `ADMIN_BOOTSTRAP_PASSWORD_FILE` or `/opt/casescope/temp/generated_admin_password.txt`.
- Keep `ALLOW_DESTRUCTIVE_STARTUP_MIGRATIONS` unset unless you are intentionally completing a cleanup migration.
- `EMBEDDING_DEVICE=cpu` is recommended unless the host has a validated CUDA stack.

## 11. Optional AI Services

Install these only after the core application is working.

### Qdrant

CaseScope expects Qdrant on host `localhost` and port `6333` by default.

```bash
QDRANT_DEB_URL=$(curl -fsSL https://api.github.com/repos/qdrant/qdrant/releases/latest | \
  python3 -c "import json, sys; print(next(a['browser_download_url'] for a in json.load(sys.stdin)['assets'] if a['name'].endswith('_amd64.deb')))")

curl -fL "$QDRANT_DEB_URL" -o /tmp/qdrant.deb
sudo apt install -y /tmp/qdrant.deb
sudo systemctl enable --now qdrant
```

Verify:

```bash
curl -fsSL http://localhost:6333/
```

If Qdrant is not installed, CaseScope will still run, but RAG-backed AI features will show Qdrant as unavailable.

### Ollama

CaseScope expects Ollama at `http://localhost:11434` by default.

If you enable AI features, install a model that matches your `OLLAMA_MODEL` setting. The current default in `config.py` is `qwen2.5:14b-instruct-q5_K_M`.

AI and OpenCTI-backed features are additionally gated by valid license activation.

## 12. Create SSL Certificates

For a test deployment, create a self-signed certificate:

```bash
sudo -u casescope mkdir -p /opt/casescope/ssl
sudo -u casescope openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /opt/casescope/ssl/key.pem \
  -out /opt/casescope/ssl/cert.pem \
  -days 365 -subj "/CN=casescope"
```

Use a trusted certificate for any shared, long-running, or production-like deployment.

## 13. Create Working Directories

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

Storage behavior:

- live parsed working data is stored under `/opt/casescope/storage`
- retained original uploads default to `/originals`
- archived cases default to `/archive`

## 14. Create Systemd Services

Create the web service:

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
Environment="PATH=/opt/casescope/venv/bin:/opt/zeek/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/opt/casescope/venv/bin/gunicorn --worker-class gthread --workers 4 --threads 4 --bind 0.0.0.0:443 --certfile=/opt/casescope/ssl/cert.pem --keyfile=/opt/casescope/ssl/key.pem --timeout 1800 wsgi:app
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
EOF
```

Create the worker service:

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
Environment="PATH=/opt/casescope/venv/bin:/opt/zeek/bin:/usr/local/bin:/usr/bin:/bin"
Environment="PYTHONPATH=/opt/casescope"
LimitNOFILE=65536
ExecStart=/opt/casescope/venv/bin/celery -A tasks worker --loglevel=info --concurrency=12 -Q celery,ioc
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

Create the beat scheduler service:

```bash
sudo tee /etc/systemd/system/casescope-beat.service >/dev/null <<'EOF'
[Unit]
Description=CaseScope Celery Beat Scheduler
After=network.target postgresql.service redis-server.service clickhouse-server.service
Wants=postgresql.service redis-server.service clickhouse-server.service

[Service]
Type=simple
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope
EnvironmentFile=/etc/casescope/casescope.env
Environment="PATH=/opt/casescope/venv/bin:/opt/zeek/bin:/usr/local/bin:/usr/bin:/bin"
Environment="PYTHONPATH=/opt/casescope"
ExecStart=/opt/casescope/venv/bin/celery -A tasks beat --loglevel=info
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

The worker example listens to both the default `celery` queue and the `ioc` queue. For heavier ingest, consider a separate worker dedicated to `-Q ioc`.

## 15. Run The PCAP Network Log Migration

This is recommended for hosts that will use PCAP workflows:

```bash
sudo -u casescope bash -lc 'cd /opt/casescope && set -a && source /etc/casescope/casescope.env && set +a && /opt/casescope/venv/bin/python migrations/add_network_logs_table.py'
```

The migration creates the ClickHouse `network_logs` tables used by Zeek and PCAP analysis if they are not already present.

## 16. Start CaseScope

```bash
sudo chown -R casescope:casescope /opt/casescope /originals /archive
sudo systemctl daemon-reload
sudo systemctl enable --now casescope-web casescope-workers casescope-beat
```

## 17. Verify Services

```bash
sudo systemctl status casescope-web casescope-workers casescope-beat redis-server postgresql clickhouse-server
curl -k https://localhost/login
```

If you set `DEFAULT_ADMIN_PASSWORD`, the first admin login is:

- Username: `admin`
- Password: the value set in `/etc/casescope/casescope.env`

If you did not set `DEFAULT_ADMIN_PASSWORD`, fetch the generated password from the web service log:

```bash
sudo journalctl -u casescope-web -n 100 --no-pager
```

Look for a message similar to:

```text
*** Created admin user 'admin' with generated password: ...
```

## 18. Optional Manual Smoke Test

Before enabling systemd, you can test the web process directly:

```bash
sudo -u casescope bash -lc 'cd /opt/casescope && set -a && source /etc/casescope/casescope.env && set +a && python3 run.py'
```

Then open `https://<server-ip>/login`.

This validates the Flask web process only. File ingestion, scheduled jobs, memory processing, PCAP processing, and analysis tasks still require Celery workers, and periodic maintenance tasks require Beat.

## 19. Troubleshooting Checks

Service logs:

```bash
sudo journalctl -u casescope-web -f
sudo journalctl -u casescope-workers -f
sudo journalctl -u casescope-beat -f
```

PostgreSQL:

```bash
sudo -u postgres psql -d casescope -c "SELECT 1;"
```

ClickHouse:

```bash
clickhouse-client -q "SELECT 1"
clickhouse-client -q "SHOW DATABASES"
```

Redis:

```bash
redis-cli ping
```

Zeek:

```bash
/opt/zeek/bin/zeek --version
```

Volatility3:

```bash
/opt/casescope/venv/bin/vol -h
```

Fix ownership if needed:

```bash
sudo chown -R casescope:casescope /opt/casescope /originals /archive
```

## Install Complete

After services are running and `https://<server-ip>/login` responds, CaseScope is ready for first login and basic validation.

For future releases, follow the [Update Software](update-software.md) guide instead of repeating the full installation process.
