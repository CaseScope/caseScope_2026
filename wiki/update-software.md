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

## Updating To Version 4

Read this section before starting so you know whether any version-specific work applies. Which parts apply depends on where you are coming from:

A `git pull` moves to the newest commit on the branch, so you land on the current release rather than on an intermediate version. That matters for which sections apply: coming from 3.x you run every migration using current code, which already does what the later sections describe.

| Installed version | Read |
|---|---|
| Earlier than 4.0.0 | [Updating To Version 4.0.0](#updating-to-version-400) only. **Do not** run the alias vault rebuild; the backfill you run at step 6 already uses current code |
| Exactly 4.0.0 | [Updating To Versions 4.0.1 Through 4.3.2](#updating-to-versions-401-through-432), including the alias vault rebuild |
| 4.0.1 to 4.2.x | [Updating To Versions 4.0.1 Through 4.3.2](#updating-to-versions-401-through-432), skipping the alias vault rebuild |
| 4.3.0 or later | [Updating From 4.3.0 Or Later To Current](#updating-from-430-or-later-to-current) |

## Updating From 4.3.0 Or Later To Current

Use this path for installs already on 4.3.0 or newer, including 4.14.1. The older 4.0 audit immutability, alias vault rebuild, and chat transcript conversion sections do not need to be rerun as part of this path. The normal update still needs backups, dependency refreshes, current ClickHouse table migrations, ownership checks, and service restarts.

Start with backups and a clean tree:

```bash
cd /opt/casescope
sudo -u casescope git status -sb
sudo mkdir -p /opt/casescope/backups
sudo chown casescope:casescope /opt/casescope/backups
sudo -u postgres pg_dump -Fc casescope > /opt/casescope/backups/casescope-postgres-$(date +%Y%m%d-%H%M%S).dump
sudo chown casescope:casescope /opt/casescope/backups/casescope-postgres-*.dump
clickhouse-client -q "SELECT 1"
```

Stop the CaseScope app services before changing code or schema. Leave PostgreSQL, Redis, and ClickHouse running:

```bash
sudo systemctl stop casescope-web
sudo systemctl stop casescope-workers
sudo systemctl stop casescope-beat
```

Pull the target release and refresh Python dependencies:

```bash
cd /opt/casescope
sudo -u casescope git fetch --all --prune
sudo -u casescope git pull --ff-only
sudo apt install -y libcairo2
sudo -u casescope /opt/casescope/venv/bin/pip install --upgrade pip
sudo -u casescope /opt/casescope/venv/bin/pip install -r /opt/casescope/requirements.txt
sudo -u casescope /opt/casescope/venv/bin/pip install volatility3
```

Run the current safe migrations. `add_events_table.py` is safe to rerun and verifies the ClickHouse events schema. Run the network log migration too on hosts that use PCAP workflows:

```bash
sudo -u casescope bash -lc 'cd /opt/casescope && set -a && source /etc/casescope/casescope.env && set +a && /opt/casescope/venv/bin/python migrations/add_events_table.py'
sudo -u casescope bash -lc 'cd /opt/casescope && set -a && source /etc/casescope/casescope.env && set +a && /opt/casescope/venv/bin/python migrations/add_network_logs_table.py'
```

Review new migration files before restart. Run any additional migration only when the release notes or a maintainer call it out:

```bash
cd /opt/casescope
sudo -u casescope git diff --name-only HEAD@{1}..HEAD -- migrations 2>/dev/null || true
```

Fix ownership and restart services:

```bash
sudo chown -R casescope:casescope /opt/casescope /originals /archive
sudo chown root:casescope /etc/casescope/casescope.env
sudo chmod 640 /etc/casescope/casescope.env
sudo systemctl daemon-reload
sudo systemctl start casescope-beat
sudo systemctl start casescope-workers
sudo systemctl start casescope-web
```

Verify the update before returning the system to analysts:

```bash
curl -k https://localhost/login
sudo -u postgres psql -d casescope -c "SELECT 1;"
clickhouse-client -q "SELECT 1"
redis-cli ping
sudo journalctl -u casescope-web -n 100 --no-pager
sudo journalctl -u casescope-workers -n 100 --no-pager
sudo journalctl -u casescope-beat -n 100 --no-pager
```

Confirm login works, the expected version is shown where applicable, existing cases load, hunting views load, and upload/background workflows relevant to the update still run. Do not enable `ALLOW_DESTRUCTIVE_STARTUP_MIGRATIONS` unless the release notes or a maintainer specifically instructs you to do so.

## Updating To Version 4.0.0

Read this section before starting if the installed version is earlier than 4.0.0. This release spans the forensic audit hash chain, fail-closed AI privacy egress, and a rewrite of deterministic pattern scoring. It requires four migrations in a specific order, changes AI behaviour on first restart, and changes pattern scores.

### Run The Migrations In This Order

Order matters. `add_audit_log_forensic_columns.py` needs `UPDATE` on `audit_log` to seed the hash chain across existing rows, and `enforce_audit_log_immutability.py` permanently revokes that privilege and moves table ownership to `postgres`. Running them out of order fails on a table the application role can no longer alter.

These are additional to the migrations described in step 6, not a replacement for them. Run them at step 6, after stopping services and pulling code:

```bash
cd /opt/casescope
RUN='cd /opt/casescope && set -a && source /etc/casescope/casescope.env && set +a && ./venv/bin/python'

sudo -u casescope bash -lc "$RUN migrations/add_audit_log_forensic_columns.py"
sudo -u casescope bash -lc "$RUN migrations/add_audit_reconciliation_markers.py"
sudo -u casescope bash -lc "$RUN migrations/backfill_privacy_alias_vault.py"

sudo -u postgres /opt/casescope/venv/bin/python migrations/enforce_audit_log_immutability.py
```

The last one runs as the `postgres` OS user so peer authentication applies.

All four are idempotent. If the installed version is somewhere in the 3.4xx range rather than exactly 3.400.0, run the full set anyway; migrations that were already applied report their existing state and skip.

`backfill_privacy_alias_vault.py` scans the original ClickHouse events for every case, so on an installation with substantial evidence it takes time proportional to the stored event count. Start it early rather than leaving it until the end of the window.

### Backfill The Alias Vault Before Analysts Use AI

The `ai_privacy_fail_closed` setting was introduced in 3.409.0 and defaults to on. Cloud AI requests are re-scanned after aliasing, and a request still carrying a protected value is refused rather than sent.

A populated alias vault is not strictly required, because aliases are also created lazily from each outgoing payload. The difference is what the sanitizer knows. A case that was never backfilled depends entirely on every identifier appearing in recognisable form in the prompt text itself, and anything missed becomes a residual that refuses the request. The backfill scans the original ClickHouse events for the case, so the control starts from full knowledge of the evidence rather than from whatever happened to appear in the first prompt.

The practical effect on a case ingested before 3.409.0 is intermittent refused AI requests rather than a clean block, which is harder to diagnose. Run the backfill before returning the system to analysts. Confirm the setting afterwards under Settings, where it appears as the privacy fail-closed control.

The backfill vaults only the entity types the configured privacy level substitutes, so raising the level later means rescanning. Pass `--reset` to discard the previously backfilled aliases and rebuild them:

```bash
sudo -u casescope bash -lc "$RUN migrations/backfill_privacy_alias_vault.py --reset"
```

### The Audit Immutability Migration Is A One-Way Step

After `enforce_audit_log_immutability.py` runs, `audit_log` and `ai_audit_log` are owned by `postgres` and carry triggers rejecting `UPDATE`, `DELETE` and `TRUNCATE`. The application role keeps only `SELECT` and `INSERT`.

Checking out an earlier commit does not undo this. Any later schema change to those two tables must be applied as `postgres`. Plan the rollback path in the Rollback Notes section with that in mind.

### Pattern Scores Change And Existing Findings Are Not Comparable

Scoring version 2.2 scores a pattern as a percentage of the evidence that was actually evaluable rather than as a raw point total. The nine gateway patterns, including pass the ticket, LSASS memory dump, PsExec execution and DCSync, moved to it.

No stored data is invalidated, but findings produced before the update are on the previous scale. Re-run pattern analysis on any case that is still active so analysts are not comparing scores from two different scoring versions. Closed cases can be left as they are, provided the scale difference is recorded wherever those findings were reported.

### PATTERN_WINDOW_STRICT Stays Off Through The Update

`PATTERN_WINDOW_STRICT` was added in 3.411.0 and is off by default. It holds each pattern evidence window to its configured length instead of stretching it to span every anchor in a correlation key. It changes detection results, so leave it off during the update and enable it deliberately afterwards, comparing one analysis run before adopting it.

## Updating To Versions 4.0.1 Through 4.3.2

These sections apply on top of the numbered steps below, not instead of them. The commands use the same `RUN` helper as the 4.0.0 section; if you skipped that section, define it first:

```bash
cd /opt/casescope
RUN='cd /opt/casescope && set -a && source /etc/casescope/casescope.env && set +a && ./venv/bin/python'
```

### Rebuild The Alias Vault After 4.0.1

This applies only if 4.0.0 was installed and its alias vault was backfilled while 4.0.0 was the running version.

Skip it if you came from 3.x or earlier. The backfill you ran at step 6 already used current code, so the vault is already built to current rules and a rebuild would repeat a full scan of every case for no benefit.

A vault built under 4.0.0 holds entries that later releases no longer create. 4.0.0 vaulted every entity type regardless of the configured privacy level, recorded unlabelled GUIDs from Windows volume and servicing paths, and scanned typed columns without a cap, so a case carrying firewall logs could contribute one alias per distinct public address. Those entries make substitution slower without protecting anything.

A rebuild is a cleanup rather than a correctness requirement. Later releases stop substituting the entries they no longer create, so an un-rebuilt vault still produces correct output, only more slowly. Rebuild during the maintenance window:

```bash
sudo -u casescope bash -lc "$RUN migrations/backfill_privacy_alias_vault.py --reset"
```

Expect this to take time proportional to the stored event count, as with the original backfill.

`--reset` requires 4.3.6 or later. Earlier releases restarted alias numbering at 1 while keeping aliases created during AI egress, which reissued a number the case already held and aborted the rebuild on a unique constraint. Because the reset commits its deletion before rebuilding, a case that failed this way was left holding only its egress-created aliases. If you hit `duplicate key value violates unique constraint "uq_privacy_alias_case_alias"`, update to 4.3.6 or later and rerun the backfill to restore the affected cases:

```bash
sudo -u casescope bash -lc "$RUN migrations/backfill_privacy_alias_vault.py"
```

### The Chat Transcript Column Changes In 4.3.0

Skip this if the installed version is 4.3.0 or later.

From 4.3.0 a chat turn appends its new messages to the stored transcript instead of rewriting the whole transcript, which requires the transcript column to be `jsonb` rather than `json`. The conversion runs automatically at startup and is recorded in `schema_migrations` as `chat_sessions_messages_to_jsonb`, so no action is normally needed.

It matters because the failure is quiet. If the column is still `json` the append fails with `operator does not exist: json || jsonb`, CaseScope catches the error so the analyst's turn is not interrupted, and the transcript silently stops saving. Chat appears to work until the conversation is reloaded and the history is missing.

Confirm the conversion after restarting, and run the standalone migration if it did not apply:

```bash
sudo -u postgres psql -d casescope -c \
  "SELECT data_type FROM information_schema.columns
   WHERE table_name = 'chat_conversation_sessions' AND column_name = 'messages';"

sudo -u casescope bash -lc "$RUN migrations/convert_chat_transcript_to_jsonb.py"
```

The query should report `jsonb`. Both the startup conversion and the standalone script are idempotent.

### Tool Approvals Move To Redis In 4.3.0

No action is required, but the behaviour visibly changes. Analyst approvals for sensitive chat tools were previously held in one web worker's memory, so an approval was invisible to the worker serving the next turn and lasted until the service restarted. They are now shared through Redis and expire after eight hours.

Analysts will see approvals persist across a page reload where they previously did not, and be asked again after eight hours where a long-lived process previously remembered indefinitely. If Redis is unreachable CaseScope falls back to per-worker memory and simply asks again, so this never blocks a tool call. Redis is already required by the installation, so there is nothing new to provision.

### Detection Pattern Search Is Repaired In 4.3.0

No action is required. Semantic search over the detection pattern library had been returning no results on every call because the installed Qdrant client renamed the method CaseScope was calling, and the resulting error was logged and treated as an empty result. Pattern searches that previously came back empty will start returning matches, so AI analysis output on an existing case can differ from the same case analysed before the update. No stored data changes.

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
sudo apt install -y libcairo2
sudo -u casescope /opt/casescope/venv/bin/pip install --upgrade pip
sudo -u casescope /opt/casescope/venv/bin/pip install -r /opt/casescope/requirements.txt
sudo -u casescope /opt/casescope/venv/bin/pip install volatility3
```

Run the requirements install after updates so new parser dependencies, such as `dissect.etl` and Airbus CERT `etl-parser` for ETL trace decoding, are present before workers restart. `libcairo2` is required by CairoSVG for local report graph rasterization. `volatility3` is installed separately because CaseScope expects the `vol` command. Optional external backends such as NTFS Log Tracker are not installed by `requirements.txt`; keep them managed as local forensic tooling and expose them to workers through `/etc/casescope/casescope.env`.

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

If you are updating from a version earlier than 4.0.0, run the ordered migration set in [Updating To Version 4.0.0](#updating-to-version-400) as well. That set has an ordering requirement and one migration that must run as the `postgres` user.

Coming from a 4.0.x, 4.1.x or 4.2.x install, see [Updating To Version 4](#updating-to-version-4) for which of the later steps apply. The chat transcript conversion runs automatically at startup, so the only migration to consider running by hand here is the alias vault rebuild.

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

On an update to 4.3.0 or later, confirm chat history survives a reload. Send a chat message in a case, reload the page, and reopen the conversation. If the exchange is missing, the transcript column conversion did not apply; see [The Chat Transcript Column Changes In 4.3.0](#the-chat-transcript-column-changes-in-430).

```bash
sudo -u postgres psql -d casescope -c \
  "SELECT name, applied_at FROM schema_migrations WHERE name = 'chat_sessions_messages_to_jsonb';"
```

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

The chat transcript conversion in 4.3.0 does not need reversing. Releases before 4.3.0 write the whole transcript rather than appending to it, and PostgreSQL accepts those writes against a `jsonb` column, so checking out an earlier commit leaves chat working. Leave the column as `jsonb`.

The audit immutability migration is the exception that cannot be undone by checking out an earlier commit; see [The Audit Immutability Migration Is A One-Way Step](#the-audit-immutability-migration-is-a-one-way-step).

## Practical Update Checklist

- Read [Updating To Version 4](#updating-to-version-4) first and work out which of its sections apply to the installed version.
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
- On a 4.0.0 update, confirm the alias vault backfill completed before analysts use AI features, and re-run pattern analysis on active cases.
- Coming from 4.0.0, rebuild the alias vault with `--reset` to shed entries later releases no longer create.
- On a 4.3.0 or later update, confirm the chat transcript column converted to `jsonb` and that chat history survives a page reload.
