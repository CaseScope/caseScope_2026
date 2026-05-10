# Getting Started: Pre-Install Planning

This page helps you prepare a virtual machine or physical host before installing CaseScope. It is intended for authorized administrators and analysts who need to understand what the server will run, what resources it needs, and what decisions should be made before following the [Install CaseScope guide](install.md).

## Deployment Model

The current baseline is a single-host CaseScope deployment. In this model, one VM or physical server runs the web application, background workers, databases, telemetry storage, and supporting services.

Typical local services include:

- `casescope-web` for the Flask web interface
- `casescope-workers` for Celery background processing
- `casescope-beat` for scheduled maintenance jobs
- `postgresql` for relational metadata
- `clickhouse-server` for event and network telemetry
- `redis-server` for Celery messaging

Optional services may include:

- `qdrant` for vector search and RAG workflows
- `ollama` for local AI model access
- `OpenCTI` for threat intelligence enrichment
- NTFS Log Tracker or another approved `$LogFile` backend for optional NTFS transaction event extraction

## Recommended Host Type

Use a dedicated VM or physical machine. Avoid installing CaseScope on a workstation that is also used for unrelated daily activity, because forensic processing can be CPU, memory, disk, and I/O intensive.

For test or beta use, a VM is usually the easiest starting point. For heavier evidence intake, PCAP review, memory processing, or multi-user analysis, a physical server or a VM backed by fast storage is recommended.

## Operating System

The tested baseline is:

- Ubuntu 24.04 LTS
- Python 3.12
- PostgreSQL 15+
- Redis 7+
- ClickHouse with HTTP access on port `8123`
- Zeek installed at `/opt/zeek/bin/zeek`
- .NET 9 runtime for `EvtxECmd`

Start from a clean Ubuntu 24.04 LTS install when possible. Keep the OS patched before installing CaseScope.

## Hardware Planning

Minimum practical test host:

- 4 CPU cores
- 16 GB RAM
- 250 GB disk
- 1 Gbps network

Recommended general-purpose host:

- 8 or more CPU cores
- 32 GB or more RAM
- 1 TB or more fast SSD storage
- 1 Gbps or faster network

Heavier investigation host:

- 16 or more CPU cores
- 64 GB or more RAM
- Several TB of SSD or fast attached storage
- 10 Gbps network if ingesting large PCAPs or evidence sets over the network

Sizing depends heavily on case volume, artifact type, and retention expectations. EVTX and structured logs can create large ClickHouse datasets. PCAP and memory workflows can require substantial temporary disk space and CPU time.

## Storage Planning

Plan storage before installation. CaseScope uses multiple working and retention locations:

- `/opt/casescope` for application code, virtual environment, local runtime files, and working directories
- `/originals` for retained original uploads
- `/archive` for archived cases
- `/opt/casescope/storage` for live parsed working data
- `/opt/casescope/staging` for staged ingest files
- `/opt/casescope/uploads` for upload handling
- `/opt/casescope/temp` for temporary processing files

Use fast SSD storage for ClickHouse and active processing paths when possible. If `/originals` or `/archive` will retain large evidence sets, place them on storage sized for long-term growth.

Before installation, decide:

- How much evidence will be retained locally
- Whether original uploads should stay on the CaseScope host
- How archived cases will be stored and backed up
- Whether `/originals` and `/archive` should be separate mount points
- How much temporary space is needed for large archives, memory images, and PCAP files

## User And Permissions

CaseScope is expected to run as the `casescope` user and group. The install process creates or uses:

- user: `casescope`
- group: `casescope`
- application path: `/opt/casescope`
- configuration path: `/etc/casescope`
- retained originals path: `/originals`
- archive path: `/archive`

All application-owned files and processing paths should be owned by `casescope:casescope` unless the install instructions specify otherwise.

## Network Requirements

Plan for these local services:

- HTTPS web access to CaseScope, typically on port `443`
- PostgreSQL local access
- Redis local access
- ClickHouse local HTTP access on port `8123`
- Optional Qdrant local access on port `6333`
- Optional Ollama local access on port `11434`

For most single-host deployments, PostgreSQL, Redis, ClickHouse, Qdrant, and Ollama should not be exposed publicly. Restrict external access to the web interface unless you have a specific reason to expose other services.

Outbound internet access is useful during installation for package downloads, Python dependencies, rule updates, and optional tooling downloads. If the host is isolated, prepare internal package mirrors or offline installation media before beginning.

## DNS, TLS, And Access

Before installation, decide how analysts will reach the application:

- Hostname or IP address
- Internal DNS name
- TLS certificate source
- Firewall allow list
- VPN or internal network requirement

The README includes steps to create a self-signed certificate for testing. Use a trusted certificate for shared, long-running, or production-like deployments.

## Accounts And Secrets

Before first start, prepare values for:

- `SECRET_KEY`
- `DEFAULT_ADMIN_PASSWORD`, if you want a predictable first login during testing
- PostgreSQL credentials
- Optional AI service settings
- Optional admin bootstrap password file location

Store secrets outside the repository. The default install path uses `/etc/casescope/casescope.env` for environment configuration.

## Evidence Handling

CaseScope is a forensic analysis platform, so host preparation should account for evidence handling expectations:

- Restrict shell and web access to authorized users.
- Keep the host clock synchronized.
- Decide how original uploads will be retained.
- Decide how backups will be handled for metadata, parsed results, retained originals, and archives.
- Avoid mixing test evidence and real case evidence on the same host unless that is intentional.
- Confirm that storage encryption, backup retention, and access logging meet your organization requirements.

## Optional Forensic Tooling Planning

Most artifact parsers are Python-native or installed by the standard setup steps. NTFS `$LogFile` semantic event extraction is different: CaseScope always preserves `$LogFile` metadata, but normalized `ntfs_logfile_event` child rows require an external NTFS Log Tracker-style backend configured through `NTFS_LOG_TRACKER_CMD`.

Before enabling that backend, decide:

- Where the backend binary or script will be installed
- Whether its license and redistribution terms fit the deployment
- Whether it runs reliably under the `casescope` service account on Linux
- How much temporary space decoded CSV or SQLite output may require
- Whether `$MFT` and `$UsnJrnl:$J` companion artifacts will normally be uploaded with `$LogFile`

## Optional AI Planning

AI and RAG workflows are optional. If you plan to use them, account for:

- Additional RAM and CPU for local embeddings and model use
- GPU availability if using GPU-backed Ollama models
- Qdrant storage growth for vector indexes
- Model download size and update process
- License-gated feature availability

If the host does not have a reliable GPU stack, set embeddings to CPU during installation unless you have validated CUDA support.

## Pre-Install Checklist

Before starting the README install steps, confirm:

- The host is dedicated to CaseScope or approved for this workload.
- Ubuntu 24.04 LTS is installed and patched.
- CPU, RAM, disk, and network capacity match expected case volume.
- `/opt/casescope`, `/originals`, and `/archive` storage choices are planned.
- Backups and retention expectations are understood.
- Firewall rules and analyst access paths are defined.
- DNS and TLS decisions are made.
- The `casescope` service account model is acceptable.
- Required outbound internet access or offline package sources are available.
- Secrets and first-login credentials are ready.
- Optional AI, Qdrant, Ollama, and OpenCTI decisions are made.

After this planning is complete, continue with the [Install CaseScope guide](install.md).
