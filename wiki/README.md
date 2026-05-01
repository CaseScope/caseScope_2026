# CaseScope Wiki

> **Note:** CaseScope is under active development. Some features, schemas, and workflows may change as the platform matures.

## Overview

CaseScope is a digital forensics and incident response platform for managing investigations, ingesting evidence, parsing forensic artifacts, hunting across event data, tracking indicators of compromise, reviewing memory and network artifacts, and supporting AI-assisted analysis workflows.

The project is designed as a case-centered analysis workspace. Evidence is uploaded or staged into a case, processed by background workers, indexed into the appropriate data stores, and made available to analysts through hunting, review, reporting, tagging, and correlation features.

CaseScope is proprietary software owned by The Dubes LLC. Review the root [LICENSE](../LICENSE) and [Terms of Use](Terms-of-Use.md) for evaluation/testing use, license-gated features, and restrictions on copying, modification, forking, redistribution, hosted use, derivative works, competing works, and license bypassing.

## Purpose

CaseScope helps investigators centralize DFIR work that often spans many tools and artifact types. Its goal is to provide a repeatable workflow for:

- Managing clients, cases, users, roles, and audit history. See [Logging and Auditing](logging-and-auditing.md) for application logs, service logs, audit records, and operational review.
- Preserving and tracking uploaded evidence
- Parsing common forensic artifacts into searchable records
- Hunting across Windows events, browser artifacts, firewall logs, network telemetry, and other structured data. See [Artifact Hunting](artifact-hunting.md) for the Hunt Artifacts reference, [Process Hunting](ProcessHunting.md) for the Hunt Processes reference, [Memory Hunting](MemoryHunting.md) for the Hunt Memory reference, [Network Hunting](NetworkHunting.md) for the Hunt Network reference, and [Noise Tagging](noise-tagging.md) for how known-good activity is rule-tagged and filtered from default views.
- Reviewing memory and PCAP analysis results
- Tracking IOCs, tags, findings, and case-scoped correlations. See [IOC System](IOC-System.md) for how indicators are stored, extracted, reviewed, saved, enriched, and matched in events.
- Supporting optional AI and RAG-assisted investigation workflows, including privacy and audit controls described in [AI Compliance](AI-Compliance.md)

## What CaseScope Uses

Core application components:

- **Flask** provides the web application and analyst interface.
- **PostgreSQL** stores relational metadata such as users, cases, files, reports, licensing state, and analysis records.
- **ClickHouse** stores high-volume event and network telemetry for fast hunting and review.
- **Redis** provides the Celery broker and result backend.
- **Celery** runs background parsing, enrichment, memory, PCAP, archive, and analysis jobs.
- **Celery Beat** schedules recurring maintenance jobs, including license heartbeats and rule updates.

Forensic and enrichment tooling:

- **EvtxECmd** processes Windows EVTX data. See [EVTX/Sygma Process](evtx-sygma-process.md) for EVTX parsing, Hayabusa/Sigma detection tagging, MITRE fields, and rule updates.
- **Hayabusa** enriches EVTX processing with detection rules.
- **Volatility3** processes memory images.
- **Zeek** processes PCAP files into network logs.

Optional AI and threat intelligence services:

- **Qdrant** provides vector storage for semantic and RAG workflows. See [Vector / RAG Analysis](vector-rag-analysis.md) for how this system imports, retrieves, and uses indexed context.
- **Ollama** provides a local LLM endpoint for AI-assisted analysis.
- **OpenCTI** can be used as a threat intelligence source for enrichment workflows.

## Core Workflows

### Artifact Ingestion

Files are uploaded into a case-scoped staging area. CaseScope detects artifact types, queues parser jobs through Celery, writes parsed events to ClickHouse where appropriate, and runs completion tasks such as deduplication, known-user discovery, known-system discovery, and ingest summary generation. See [Artifact Uploads](artifact-uploads.md) for choosing the right upload path and understanding what is indexed versus retained only.

### Event Hunting

Parsed records are searchable through analyst-facing hunting views. CaseScope is built to support timeline review, filtering, pattern detection, tagging, and case-scoped correlation across supported artifact types.

### PCAP Review

PCAP files are staged and tracked in PostgreSQL. Celery runs Zeek against each capture, then indexes Zeek output into ClickHouse network log tables for review and hunting.

### Memory Analysis

Memory images are tracked as analysis jobs. Celery runs Volatility3 plugins, and parsed plugin output is stored in PostgreSQL for review and pivots.

### AI-Assisted Analysis

Deterministic analysis uses behavioral profiling, peer grouping, gap detectors, and pattern correlation. Optional AI and RAG features use Ollama and Qdrant, and license-gated features degrade gracefully when activation or optional services are unavailable.

## Main Services

Typical deployed services include:

- `casescope-web` for the Flask web UI served by Gunicorn
- `casescope-workers` for Celery background jobs
- `casescope-beat` for scheduled jobs
- `postgresql` for relational metadata
- `clickhouse-server` for high-volume event and network storage
- `redis-server` for Celery messaging

Optional services may include:

- `qdrant` for vector search and RAG
- `ollama` for local AI model access
- `OpenCTI` for threat intelligence enrichment

## Supported Artifact Areas

CaseScope is intended to support investigation workflows around:

- Windows Event Logs
- Browser artifacts
- Registry hives
- Prefetch
- LNK files
- MFT data
- SRUM data
- JSON, NDJSON, and CSV records
- Firewall logs
- PCAP captures
- Memory images
- Indicators of compromise

## Tested Baseline

The current baseline described by the project README is:

- Ubuntu 24.04 LTS
- Python 3.12
- PostgreSQL 15+
- Redis 7+
- ClickHouse with HTTP interface on port `8123`
- Zeek installed at `/opt/zeek/bin/zeek`
- .NET 9 runtime for `EvtxECmd`

## Where To Start

Before installing, review the [Getting Started pre-install planning page](getting-started.md) for VM or physical host requirements, storage planning, networking, permissions, secrets, and evidence-handling considerations.

For installation, service setup, environment variables, first-run behavior, and troubleshooting commands, continue with the [Install CaseScope guide](install.md).

For upload and ingestion guidance, review [Artifact Uploads](artifact-uploads.md).

For Windows event log parsing, Hayabusa/Sigma rule tagging, and rule update behavior, review [EVTX/Sygma Process](evtx-sygma-process.md).

For the Hunt Artifacts page, searchable artifact tabs, filters, tagging, exports, and supported artifact families, review [Artifact Hunting](artifact-hunting.md).

For the Hunt Processes page, Events/EDR and memory-backed process sources, filters, process trees, and related memory artifacts, review [Process Hunting](ProcessHunting.md).

For the Hunt Memory page, Volatility-derived artifact tabs, cross-memory search, cross-reference badges, source plugins, and memory-specific caveats, review [Memory Hunting](MemoryHunting.md).

For the Hunt Network page, PCAP/Zeek indexing, dedicated network tabs, global search, raw details, and network-specific caveats, review [Network Hunting](NetworkHunting.md).

For known-good event suppression and rule-based noise overlays, review [Noise Tagging](noise-tagging.md).

For application logs, service logs, unified audit records, and operational audit review, see [Logging and Auditing](logging-and-auditing.md).

For existing deployments, use [Update Software](update-software.md) to plan backups, pull updates, refresh dependencies, run migrations, and restart services.

For optional AI context retrieval, review [Vector / RAG Analysis](vector-rag-analysis.md). For AI privacy levels, prompt/response auditing, hash-chain verification, and compliance-oriented operations, review [AI Compliance](AI-Compliance.md).

For the full indicator lifecycle, review [IOC System](IOC-System.md). For a focused extraction workflow page, review [IOC Extraction](ioc-extraction.md).

This wiki will expand into focused help pages for installation, administration, case workflow, artifact ingestion, event hunting, memory analysis, PCAP review, IOC management, AI features, and troubleshooting.

## License

CaseScope is proprietary software owned by The Dubes LLC. All rights reserved. See the root [LICENSE](../LICENSE) and [Terms of Use](Terms-of-Use.md).
