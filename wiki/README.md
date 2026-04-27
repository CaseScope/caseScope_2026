# CaseScope Wiki

> **Note:** CaseScope is under active development. Some features, schemas, and workflows may change as the platform matures.

## Overview

CaseScope is a digital forensics and incident response platform for managing investigations, ingesting evidence, parsing forensic artifacts, hunting across event data, tracking indicators of compromise, reviewing memory and network artifacts, and supporting AI-assisted analysis workflows.

The project is designed as a case-centered analysis workspace. Evidence is uploaded or staged into a case, processed by background workers, indexed into the appropriate data stores, and made available to analysts through hunting, review, reporting, tagging, and correlation features.

## Purpose

CaseScope helps investigators centralize DFIR work that often spans many tools and artifact types. Its goal is to provide a repeatable workflow for:

- Managing clients, cases, users, roles, and audit history
- Preserving and tracking uploaded evidence
- Parsing common forensic artifacts into searchable records
- Hunting across Windows events, browser artifacts, firewall logs, network telemetry, and other structured data
- Reviewing memory and PCAP analysis results
- Tracking IOCs, tags, findings, and case-scoped correlations
- Supporting optional AI and RAG-assisted investigation workflows

## What CaseScope Uses

Core application components:

- **Flask** provides the web application and analyst interface.
- **PostgreSQL** stores relational metadata such as users, cases, files, reports, licensing state, and analysis records.
- **ClickHouse** stores high-volume event and network telemetry for fast hunting and review.
- **Redis** provides the Celery broker and result backend.
- **Celery** runs background parsing, enrichment, memory, PCAP, archive, and analysis jobs.
- **Celery Beat** schedules recurring maintenance jobs, including license heartbeats and rule updates.

Forensic and enrichment tooling:

- **EvtxECmd** processes Windows EVTX data.
- **Hayabusa** enriches EVTX processing with detection rules.
- **Volatility3** processes memory images.
- **Zeek** processes PCAP files into network logs.

Optional AI and threat intelligence services:

- **Qdrant** provides vector storage for semantic and RAG workflows.
- **Ollama** provides a local LLM endpoint for AI-assisted analysis.
- **OpenCTI** can be used as a threat intelligence source for enrichment workflows.

## Core Workflows

### Artifact Ingestion

Files are uploaded into a case-scoped staging area. CaseScope detects artifact types, queues parser jobs through Celery, writes parsed events to ClickHouse where appropriate, and runs completion tasks such as deduplication, known-user discovery, known-system discovery, and ingest summary generation.

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

This wiki will expand into focused help pages for installation, administration, case workflow, artifact ingestion, event hunting, memory analysis, PCAP review, IOC management, AI features, and troubleshooting.

## License

CaseScope is proprietary software. All rights reserved.
