# Update Software

This page outlines how to update an existing single-host CaseScope installation. It assumes CaseScope is installed under `/opt/casescope`, runs as the `casescope` user, and uses the systemd services described in the [Install CaseScope guide](install.md).

## Before You Update

Review the release notes, changelog, or commits you plan to deploy before updating. CaseScope is under active development, so updates may include schema changes, dependency changes, service changes, or new background jobs.

Before starting, confirm:

- You have shell access with `sudo`.
- You know which branch, tag, or commit should be deployed.
- You have a current backup of PostgreSQL.
- You have a current backup or snapshot of important ClickHouse data.
- You have retained copies or backups of `/originals`, `/archive`, and any other evidence storage paths.
- No critical ingest, memory, PCAP, archive, or analysis jobs are running.
- Analysts know the application will be unavailable during the update.

## 1. Check Current Version And Status

```bash
cd /opt/casescope
sudo -u casescope git status -sb
sudo -u casescope git log --oneline -5
sudo -u casescope /opt/casescope/venv/bin/python - <<'PY'
import json
with open('/opt/casescope/version.json', 'r', encoding='utf-8') as f:
    print(json.load(f).get('version'))
PY
```

If `git status` shows local changes, stop and decide whether those changes should be committed, backed up, or discarded. Do not overwrite local changes unless you are sure they are not needed.

## 2. Back Up Data

Back up PostgreSQL:

```bash
sudo mkdir -p /opt/casescope/backups
sudo chown casescope:casescope /opt/casescope/backups
sudo -u postgres pg_dump -Fc casescope > /opt/casescope/backups/casescope-postgres-$(date +%Y%m%d-%H%M%S).dump
sudo chown casescope:casescope /opt/casescope/backups/casescope-postgres-*.dump
```

For ClickHouse, use your normal snapshot or backup process. At minimum, confirm the service is healthy before proceeding:

```bash
clickhouse-client -q "SELECT 1"
clickhouse-client -q "SHOW DATABASES"
```

If the host stores original evidence or archives locally, confirm those paths are backed up or protected by storage snapshots:

```bash
sudo du -sh /originals /archive /opt/casescope/storage 2>/dev/null
```

## 3. Stop CaseScope Services

Stop the web process, workers, and scheduler before pulling code or running migrations:

```bash
sudo systemctl stop casescope-web casescope-workers casescope-beat
```

Leave PostgreSQL, Redis, and ClickHouse running unless the update instructions specifically require stopping them.

## 4. Pull The Updated Code

Update the repository as the `casescope` user:

```bash
cd /opt/casescope
sudo -u casescope git fetch --all --prune
sudo -u casescope git pull --ff-only
```

If deploying a specific tag or commit, check it out explicitly:

```bash
sudo -u casescope git checkout <tag-or-commit>
```

Use `git pull --ff-only` for normal branch updates so the update fails instead of creating an unexpected merge commit.

## 5. Update Python Dependencies

Refresh the virtual environment dependencies after pulling code:

```bash
sudo -u casescope /opt/casescope/venv/bin/pip install --upgrade pip
sudo -u casescope /opt/casescope/venv/bin/pip install -r /opt/casescope/requirements.txt
sudo -u casescope /opt/casescope/venv/bin/pip install volatility3
```

Run the requirements install after updates so new parser dependencies, such as `dissect.etl` and Airbus CERT `etl-parser` for ETL trace decoding, are present before workers restart. `volatility3` is installed separately because CaseScope expects the `vol` command. Optional external backends such as NTFS Log Tracker are not installed by `requirements.txt`; keep them managed as local forensic tooling and expose them to workers through `/etc/casescope/casescope.env`.

## 6. Review And Run Migrations

CaseScope runs some startup schema work automatically, but the repository also includes standalone migration scripts under `migrations/`. Review new migration files before starting services:

```bash
cd /opt/casescope
sudo -u casescope git diff --name-only HEAD@{1}..HEAD -- migrations 2>/dev/null || true
ls -1 migrations
```

Run any migration scripts required by the release notes or update instructions. The event table migration is safe to rerun and verifies the ClickHouse tables required for artifact ingestion:

```bash
sudo -u casescope bash -lc 'cd /opt/casescope && set -a && source /etc/casescope/casescope.env && set +a && /opt/casescope/venv/bin/python migrations/add_events_table.py'
```

Hosts using PCAP workflows should also have the network log table migration applied:

```bash
sudo -u casescope bash -lc 'cd /opt/casescope && set -a && source /etc/casescope/casescope.env && set +a && /opt/casescope/venv/bin/python migrations/add_network_logs_table.py'
```

Do not enable `ALLOW_DESTRUCTIVE_STARTUP_MIGRATIONS` unless the release notes or a maintainer specifically instructs you to do so.

## 7. Update External Tooling When Needed

Most software updates only require pulling code and refreshing Python dependencies. Some updates may also require updated forensic tooling.

If the update notes mention EVTX tooling or Hayabusa changes, rerun:

```bash
cd /opt/casescope
sudo bash /opt/casescope/bin/install_eztools.sh
sudo bash /opt/casescope/bin/install_hayabusa.sh
```

If the update notes mention Zeek, ClickHouse, PostgreSQL, Redis, Qdrant, or Ollama changes, update those services according to the vendor or internal package-management process.

If the update notes mention NTFS `$LogFile` semantic events, confirm any configured `NTFS_LOG_TRACKER_CMD` still points to an executable backend and that the command writes CSV or SQLite output under `{output_dir}`. Keep the value quoted in `/etc/casescope/casescope.env` because the command contains spaces and maintenance commands shell-source the file. For the included NTFSparse wrapper, also confirm the `--ntfs-parse-home` path points to a readable `NTFSparse/ntfs_parse` checkout. If the backend was newly installed or moved, update `/etc/casescope/casescope.env` before restarting `casescope-workers`.

```bash
sudo -u casescope git -C /opt/ntfs_parse pull --ff-only
sudo -u casescope /opt/casescope/bin/ntfs_logfile_ntfsparse_adapter.py --help
```

For NTFS Log Tracker exports produced outside the server, verify that CSV or SQLite files still resolve to the `ntfs_log_tracker_export` parser before bulk upload. A quick smoke test is to upload one export and confirm the File System tab shows the parent export row plus `ntfs_logfile_event` child rows with resolved paths when the source export includes them.

## 8. Check Ownership And Permissions

Before restarting services, make sure CaseScope-owned paths are owned by `casescope:casescope`:

```bash
sudo chown -R casescope:casescope /opt/casescope /originals /archive
```

Keep `/etc/casescope/casescope.env` owned by `root:casescope` with restricted permissions:

```bash
sudo chown root:casescope /etc/casescope/casescope.env
sudo chmod 640 /etc/casescope/casescope.env
```

## 9. Restart Services

Reload systemd in case service definitions changed, then start CaseScope:

```bash
sudo systemctl daemon-reload
sudo systemctl start casescope-beat casescope-workers casescope-web
```

Confirm services are running:

```bash
sudo systemctl status casescope-web casescope-workers casescope-beat --no-pager
```

## 10. Verify The Update

Check the login page:

```bash
curl -k https://localhost/login
```

Check supporting services:

```bash
sudo -u postgres psql -d casescope -c "SELECT 1;"
clickhouse-client -q "SELECT 1"
redis-cli ping
```

Check logs for startup errors:

```bash
sudo journalctl -u casescope-web -n 100 --no-pager
sudo journalctl -u casescope-workers -n 100 --no-pager
sudo journalctl -u casescope-beat -n 100 --no-pager
```

In the web UI, confirm:

- login works
- the expected version is visible where applicable
- existing cases load
- hunting views load
- uploads and background jobs can start
- IOC, PCAP, memory, AI, or RAG features relevant to the update still work

## Rollback Notes

If the update fails before migrations or data changes, you can usually stop services, check out the previous commit or tag, reinstall dependencies, and restart services:

```bash
cd /opt/casescope
sudo systemctl stop casescope-web casescope-workers casescope-beat
sudo -u casescope git checkout <previous-tag-or-commit>
sudo -u casescope /opt/casescope/venv/bin/pip install -r /opt/casescope/requirements.txt
sudo systemctl start casescope-beat casescope-workers casescope-web
```

If migrations or data changes were applied, rollback may require restoring PostgreSQL, ClickHouse, and evidence storage backups. Treat database restore as an incident-response activity: preserve logs, record the failed version, and verify data integrity before reopening the system to analysts.

## Practical Update Checklist

- Notify users of downtime.
- Check `git status`.
- Back up PostgreSQL.
- Confirm ClickHouse and evidence backups or snapshots.
- Stop `casescope-web`, `casescope-workers`, and `casescope-beat`.
- Pull the target code.
- Update Python dependencies.
- Review and run required migrations.
- Update external tools only when required.
- Verify optional `NTFS_LOG_TRACKER_CMD` tooling if `$LogFile` event extraction is enabled.
- Smoke test standalone NTFS Log Tracker CSV or SQLite exports when using an external Windows analysis workflow.
- Reprocess any `$LogFile` items that were previously metadata-only if decoded transaction events are needed.
- Fix ownership and environment file permissions.
- Restart services.
- Verify logs, login, cases, and relevant workflows.
