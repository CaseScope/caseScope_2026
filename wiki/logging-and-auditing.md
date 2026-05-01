# Logging and Auditing

CaseScope uses both filesystem logs and database audit records. Logs help administrators troubleshoot services and background jobs. Audit records preserve user, case, file, IOC, license, settings, and security activity for review.

AI prompt and response auditing uses a separate tamper-evident audit system. This page summarizes where it fits, but detailed AI audit behavior is documented in [AI Compliance](AI-Compliance.md).

## Overview

There are three main layers:

- **Service logs** from systemd services such as `casescope-web`, `casescope-workers`, and `casescope-beat`.
- **Application log files** under the configured CaseScope log path.
- **Database audit tables** in PostgreSQL for durable activity history.

These layers serve different purposes. Service logs show runtime behavior. Application logs capture application and task messages. Database audit records provide structured history for important actions.

## Service Logs

CaseScope normally runs through systemd services:

- `casescope-web`
- `casescope-workers`
- `casescope-beat`

Use `journalctl` to inspect service output:

```bash
sudo journalctl -u casescope-web -f
sudo journalctl -u casescope-workers -f
sudo journalctl -u casescope-beat -f
```

Use service logs when debugging startup problems, worker failures, scheduled jobs, dependency errors, or uncaught exceptions.

## Application Log Files

The central logging helper is `utils/logger.py`.

By default, CaseScope writes logs under:

```text
/opt/casescope/logs
```

The effective log location and behavior can be controlled with system settings:

- `LOG_PATH`
- `LOG_LEVEL`
- `LOG_MAX_SIZE_MB`
- `LOG_RETENTION_DAYS`

The logging helper uses rotating file handlers. Logger names determine the primary log file:

- Celery and task-oriented loggers write to `celery.log`.
- AI, RAG, and Ollama-oriented loggers write to `ai.log`.
- Other application loggers write to `webserver.log`.
- ERROR and higher messages are also written to `error.log`.

Not every module necessarily uses the central helper directly. Some modules use standard Python logging, which may appear in service logs depending on how the process is started and configured.

## Case-Scoped Logs

CaseScope can also write case-focused log files under the configured log path:

```text
logs/cases/<case_uuid>/
```

Examples include:

- `files.log`
- `activity.log`
- `runs/<timestamp>_<run_type>.log`

These logs are useful when tracing case-specific file activity, ingestion runs, or analysis runs.

## Hunting Logs

Hunting logging uses `utils/hunting_logger.py`.

It creates case/session-specific loggers for hunting activity. These logs help troubleshoot long-running hunting sessions, query behavior, and case-specific analysis paths.

## Viewing Logs In The UI

Operational log viewing is exposed through routes in `routes/ops.py`.

Relevant APIs include:

- `/api/settings/logging`
- `/api/logs/view/<path>`
- `/api/logs/case/<case_uuid>`

The log viewer is path-restricted to the configured log tree to avoid arbitrary file access. Administrative access is required for operational log and audit views.

## Log Rotation And Cleanup

Application logs rotate using Python rotating file handlers. Main log files keep a limited number of backups, and `error.log` keeps additional backups.

`utils/logger.py` also includes `cleanup_old_logs()`, which removes old log files based on `LOG_RETENTION_DAYS`. If log cleanup is needed, confirm whether your deployment runs this helper through a scheduled job, maintenance process, or external cron.

For production-like hosts, monitor log disk usage under `/opt/casescope/logs` or the configured `LOG_PATH`.

## Unified Audit Log

The main structured audit table is `audit_log`, implemented by `models/audit_log.py`.

It records who did what, when, where, and against which entity. It can capture:

- user identity
- username
- IP address
- user agent
- entity type
- entity ID
- action
- case UUID when relevant
- structured details

Audit records are append-oriented. The model includes guards that prevent normal ORM update and delete operations against audit rows.

## Audit Entity Types

The unified audit system supports entity types such as:

- case
- case file
- case report
- IOC
- known system
- known user
- system user
- setting
- noise rule
- client
- evidence file
- attack pattern
- AI audit bridge records
- session

This lets different parts of the application write to a common audit trail while preserving entity-specific context.

## Audit Actions

Audit actions include common lifecycle and security events such as:

- create
- update
- delete
- upload
- extract
- queue
- ingest
- reindex
- duplicate handling
- login
- logout
- failed login
- password changes
- settings changes
- AI audit verification or write-failure bridge events

The exact action set is defined in `models/audit_log.py`.

## Authentication Auditing

Authentication routes in `routes/auth.py` write audit records for:

- successful login
- failed login
- logout

Failed login records include details such as the reason when available. These records use the session audit entity type and help administrators review access attempts.

## Case, Client, And Settings Auditing

General case, client, user, settings, and administrative activity is audited through route logic, especially in `routes/main.py`.

Settings changes can use audit helpers that record old and new values. This is important because configuration changes can affect ingest behavior, AI availability, logging paths, rule behavior, and analyst workflows.

## File And Ingest Auditing

Indexed file upload and ingest paths write audit records around `CaseFile` activity.

Common file audit events include:

- preflight
- upload
- extract
- queue
- ingest
- reindex
- duplicate handling

The ingest routes and Celery tasks record file lifecycle details so administrators can trace how an artifact entered the case, whether it was parsed, and how it moved through the processing pipeline.

There is also a lightweight `file_audit_log` model in `models/file_audit_log.py` for file deletion activity such as duplicate cleanup or manual deletion.

## Evidence Auditing

The unified audit model includes an `evidence_file` entity type. Evidence upload, edit, delete, and download behavior should be reviewed through the relevant evidence routes and operational audit views when investigating evidence handling.

Evidence files are not parsed like indexed case files, so audit review is especially useful for understanding who added, changed, downloaded, or removed retained evidence.

## IOC Auditing

IOC auditing has more than one layer:

- The unified `audit_log` can record IOC-related activity.
- `IOCAudit` in `models/ioc.py` records field-level IOC create, update, and delete history.
- IOC routes expose audit history for IOC review.

This separation lets CaseScope preserve both broad action history and detailed IOC field changes.

Do not confuse IOC field auditing with `utils/ioc_audit.py`. That utility supports AI-assisted IOC extraction review logic and is not the same thing as the main database audit table.

## Noise Rule Auditing

Noise rules have their own audit model through `NoiseRuleAudit`.

Noise rule audit history is useful because changing a noise rule can affect which events are hidden from default hunting views. Review rule changes when a case appears to hide too much or too little activity.

See [Noise Tagging](noise-tagging.md) for the noise rule workflow.

## License Activation Auditing

License and activation actions are tracked separately through `ActivationAuditLog` in `models/license.py` and activation routes.

This records actions such as:

- activation
- deactivation
- validation

License audit records can include IP address, username, and structured details. They are separate from normal case auditing because activation state affects product access and license-gated features.

## Background Task Logging And Auditing

Celery tasks log operational messages and may also write audit records.

Examples include:

- file parsing and reindexing
- archive tasks
- PCAP processing
- memory processing
- Hayabusa rule updates
- IOC and noise tagging workflows

When a task writes an audit record outside a user request, the audit username may be recorded as `system`. This is expected for background work.

## AI Auditing

AI auditing is intentionally separate from normal application logging and unified audit records.

AI audit records can include provider metadata, prompt and response hashes, privacy metadata, usage data, and a hash chain for tamper-evident verification.

For details about:

- AI audit settings
- strict mode
- prompt and response audit records
- hash-chain verification
- AI audit APIs
- AI privacy and compliance operations

review [AI Compliance](AI-Compliance.md).

The unified audit log may still record bridge events such as AI audit verification or AI audit write failures, but the detailed AI prompt/response audit trail lives in the AI audit system.

## Viewing Audit Records

Audit and log APIs are implemented in `routes/ops.py`.

Relevant APIs include:

- `/api/audit-log`
- `/api/audit-log/entity/<entity_type>/<entity_id>`
- `/api/logs/audit/file_audit_log`

The settings UI includes audit-related tabs that use these APIs. Access is administrative.

## Retention And Maintenance Notes

Audit tables are intended to preserve durable history. Do not modify or delete audit rows during normal operations.

Maintenance scripts may remove case data and related audit records during explicit cleanup workflows. For example, bulk cleanup scripts can bypass normal ORM immutability protections by issuing direct bulk deletes. Use those scripts only when intentionally clearing case data.

For operational logs, configure retention and rotation so log volume does not fill the server disk.

## Troubleshooting

No application log files appear:

- Confirm `LOG_PATH` or the default `/opt/casescope/logs` exists.
- Confirm ownership allows the `casescope` user to write logs.
- Confirm modules are using the central logger helper or check systemd logs instead.

No audit records appear for an action:

- Confirm the action path writes to the unified audit log or a domain-specific audit table.
- Check whether the action was performed by a background task and recorded as `system`.
- Check administrator audit APIs and entity-specific audit history.

Log settings changes do not take effect:

- Confirm settings were saved.
- Confirm the logging settings cache was invalidated.
- Restart services if needed for long-lived processes.

AI calls fail when audit storage is unavailable:

- Check whether AI audit strict mode is enabled.
- Review [AI Compliance](AI-Compliance.md) for AI audit behavior.
- Check unified audit records for AI audit write-failure bridge events.

Permission errors under `/opt/casescope/logs`:

- Fix ownership of the log tree.
- Confirm the service user is `casescope`.
- Check service logs for path or permission errors.

## Key Files

- `utils/logger.py`
- `utils/hunting_logger.py`
- `models/audit_log.py`
- `models/file_audit_log.py`
- `models/ai_audit_log.py`
- `utils/ai_audit.py`
- `routes/ops.py`
- `routes/ai.py`
- `routes/auth.py`
- `routes/ingest.py`
- `routes/main.py`
- `models/ioc.py`
- `models/noise.py`
- `models/license.py`
- `tasks/celery_tasks.py`
- `tasks/archive_tasks.py`
- `static/templates/settings.html`
- `bin/clear_cases.py`
