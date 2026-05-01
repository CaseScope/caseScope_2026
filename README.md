# CaseScope

> **Proprietary software owned by The Dubes LLC.**
>
> Public access to this repository does not grant fork, redistribution, resale, modification, sublicensing, hosted-use, derivative-work, competing-work, or license-bypass rights. You may view and use this repository for evaluation/testing purposes only unless The Dubes LLC gives prior written permission. Licensed or registered features require a valid entitlement. Review the [LICENSE](LICENSE) and [Terms of Use](wiki/Terms-of-Use.md) before installing, testing, copying, or using CaseScope.

> **Warning: work in progress**
>
> CaseScope is under active development. Expect schema changes, feature churn, and the occasional rough edge while testing.

CaseScope is a DFIR platform for case management, evidence intake, artifact parsing, event hunting, IOC tracking, memory analysis, PCAP review, and AI-assisted investigation workflows. The application uses Flask for the web UI, PostgreSQL for relational metadata, ClickHouse for event and network telemetry, and Celery for background ingestion, enrichment, and analysis jobs.

## What It Does

- Case and client management with audit logging and role-based access
- Event ingestion for EVTX, browser artifacts, registry hives, prefetch, LNK, MFT, SRUM, JSON, NDJSON, CSV, firewall logs, and more
- EVTX processing with `EvtxECmd` plus Hayabusa detection enrichment
- Memory processing with Volatility3
- PCAP processing with Zeek
- IOC tracking, artifact tagging, and case-scoped correlation
- Optional AI and RAG features with Ollama and Qdrant

## Architecture At A Glance

Core services:

- `casescope-web`: Gunicorn serving the Flask app over HTTPS
- `casescope-workers`: Celery workers for parsing, memory, PCAP, archive, and analysis tasks
- `casescope-beat`: Celery Beat scheduler for periodic jobs such as license heartbeats and Hayabusa rule updates
- `postgresql`: relational metadata store for users, cases, files, reports, licensing, and analysis state
- `clickhouse-server`: high-volume event and network log store
- `redis-server`: Celery broker and result backend

Optional services:

- `qdrant`: vector store for semantic and RAG features
- `ollama`: local LLM endpoint for AI features
- `OpenCTI`: optional threat-intel source for enrichment workflows

## Core Application Flows

### Standard Artifact Ingestion

1. Files are uploaded into a case-scoped staging area.
2. Celery queues parser jobs and auto-detects artifact type through `parsers/registry.py`.
3. Parsed events are written to ClickHouse.
4. Completion tasks run deduplication, known-user discovery, known-system discovery, and ingest summary generation.

### PCAP Processing

1. PCAP files are staged and tracked in PostgreSQL.
2. Celery runs Zeek against the capture.
3. Zeek logs are indexed into ClickHouse `network_logs` tables for network hunting views and searches.

### Memory Processing

1. Memory images are tracked as jobs in PostgreSQL.
2. Celery runs Volatility3 plugins via the `vol` CLI.
3. Parsed plugin output is stored in dedicated PostgreSQL memory tables for review and pivots.

### Analysis And AI

1. Deterministic analysis uses behavioral profiling, peer grouping, gap detectors, and pattern correlation.
2. Optional AI and RAG features use Ollama and Qdrant.
3. AI and OpenCTI-backed features are license-gated and degrade gracefully when activation or services are unavailable.

## Tested Baseline

- Ubuntu 24.04 LTS
- Python 3.12
- PostgreSQL 15+
- Redis 7+
- ClickHouse with HTTP interface on port `8123`
- Zeek installed at `/opt/zeek/bin/zeek`
- .NET 9 runtime for `EvtxECmd`

## Installation And Administration

The root README is intentionally a product and architecture overview. Installation steps, service setup, migrations, upgrade guidance, and troubleshooting live in the wiki:

- Start with [Getting Started](wiki/getting-started.md) for host planning, storage, networking, permissions, and evidence-handling considerations.
- Continue with [Install CaseScope](wiki/install.md) for the current single-host installation workflow.
- Use [Update Software](wiki/update-software.md) for backups, pulls, migrations, dependency refreshes, and service restarts.
- Review [Vector / RAG Analysis](wiki/vector-rag-analysis.md) before enabling optional Qdrant/Ollama-assisted workflows.
- Review [Artifact Hunting](wiki/artifact-hunting.md) for the Hunt Artifacts page, searchable artifact tabs, filters, tagging, exports, and supported artifact families.
- Review [Process Hunting](wiki/ProcessHunting.md) for the Hunt Processes page, Events/EDR and memory-backed process sources, filters, process trees, and related memory artifacts.
- Review [Memory Hunting](wiki/MemoryHunting.md) for the Hunt Memory page, Volatility-derived artifact tabs, cross-memory search, and memory-specific caveats.
- Review [Network Hunting](wiki/NetworkHunting.md) for the Hunt Network page, PCAP/Zeek indexing flow, dedicated network tabs, global search, and network-specific caveats.
- Review [IOC System](wiki/IOC-System.md) and [IOC Extraction](wiki/ioc-extraction.md) for indicator storage, extraction, AI review, and event matching.

## Current System Notes

- CaseScope runs as a Flask/Gunicorn web service with Celery workers and Celery Beat.
- PostgreSQL is the source of truth for cases, users, files, reports, licenses, IOCs, AI enhancement runs, memory results, and relational metadata.
- ClickHouse stores high-volume event and network telemetry for hunting, tagging, and timeline workflows.
- Redis is used for Celery broker/result traffic and short-lived task progress payloads.
- IOC-heavy analyst tasks route to the dedicated `ioc` queue, so workers must consume `celery,ioc` or a separate IOC worker must be deployed.
- First startup creates core PostgreSQL tables and the initial admin user when needed; standalone scripts in `migrations/` handle additive schema work and backfills.
- AI, RAG, and threat intelligence features are optional and license-gated. Core deterministic parsing and case workflows should degrade gracefully when optional AI services are unavailable.
- Destructive startup cleanup is disabled by default and should only be enabled intentionally through `ALLOW_DESTRUCTIVE_STARTUP_MIGRATIONS`.

## Repository Layout

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
- runs tracked inline schema migrations
- creates the default `admin` user if it does not already exist

The repository also contains standalone migration scripts in `migrations/` for upgrade scenarios, backfills, and feature-specific schema changes. Review them during upgrades instead of assuming Flask startup covers every historical schema change.

There is no fixed built-in `admin/admin` credential.

## Troubleshooting

Operational troubleshooting commands and service checks are maintained in the wiki install and update guides:

- [Install CaseScope](wiki/install.md)
- [Update Software](wiki/update-software.md)

## Version

Current application version: see `version.json`.

## License

Proprietary software owned by The Dubes LLC. All rights reserved. You may view and use this repository for evaluation/testing purposes only. You may not copy, modify, fork, redistribute, resell, sublicense, host, commercialize, create derivative or competing works, bypass registration or licensing, or reuse proprietary code, workflows, designs, documentation, or concepts without prior written permission. See [LICENSE](LICENSE) and [Terms of Use](wiki/Terms-of-Use.md).
