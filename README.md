# CaseScope

> **⚠️ WARNING: WORK IN PROGRESS**
>
> This application is under active development. Not all features are fully implemented yet, and you may encounter bugs or incomplete functionality. Use at your own risk and report issues as you find them.

---

CaseScope is a comprehensive digital forensics and incident response (DFIR) platform designed to streamline case management, artifact analysis, and threat hunting workflows. Built for security analysts and forensic investigators, it provides an integrated environment for processing, correlating, and investigating security events across multiple data sources.

## Key Features

### Case Management
- **Multi-case support** with UUID-based identification for security
- **Timezone-aware** case configuration for accurate timestamp correlation
- **Status tracking** (New, Assigned, In Progress, In Review, Finished, Archived)
- **EDR report integration** for attaching and viewing endpoint detection reports
- **Role-based access control** with Administrator, Analyst, and Viewer permission levels

### Evidence Processing Pipeline
- **Multi-format parser support** including:
  - Windows Event Logs (EVTX) with Hayabusa integration
  - Browser artifacts (Chrome, Firefox history and downloads)
  - Registry hives via Dissect framework
  - Memory dumps via Volatility3
  - Network captures (PCAP/PCAPNG) via Zeek
  - Various log formats (NDJSON, CSV, text logs)
- **Automatic artifact type detection** with intelligent parser routing
- **Batch file processing** with Celery async task queue
- **SFTP upload support** for large file ingestion
- **ZIP archive extraction** for bundled evidence files

### Threat Hunting
- **ClickHouse-powered event search** with millisecond query performance
- **Advanced search syntax** with boolean operators, field queries, and wildcards
- **Timeline visualization** of security events
- **MITRE ATT&CK framework integration** via Hayabusa rules
- **Severity-based event classification** (Critical, High, Medium, Low, Informational)
- **Noise filtering system** with customizable rule categories

### Memory Forensics
- **Volatility3 integration** for memory dump analysis
- **Automatic plugin selection** based on OS detection
- **Process tree visualization** with parent-child relationships
- **Network connection analysis** from memory
- **Service enumeration** and suspicious binary detection
- **Malfind analysis** for injected code detection
- **Credential extraction** (hashdump, cachedump, lsadump)
- **Cross-memory search** across multiple dumps

### Network Forensics
- **PCAP file management** with automatic format detection
- **Zeek integration** for network log generation
- **Network hunting interface** with tabs for:
  - Connection logs (TCP/UDP flows)
  - DNS queries and responses
  - HTTP requests
  - SSL/TLS certificates
  - File transfers
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

### AI-Powered Analysis (Optional)
- **RAG (Retrieval-Augmented Generation)** with Qdrant vector database
- **Ollama LLM integration** for natural language hunting queries
- **Attack pattern matching** from ingested threat intelligence
- **IOC extraction** from event data using regex and AI

### Known Systems & Users Discovery
- **Automatic system enumeration** from artifact hostnames
- **IP and MAC address correlation**
- **Network share discovery**
- **User SID tracking** with alias management
- **Cross-case reference tracking**

### System Administration
- **User management** with password policies
- **Audit logging** for compliance
- **System settings** for AI, integrations, and behavior configuration
- **Hayabusa rule management** with automatic updates

## Technology Stack

### Backend
- **Flask** - Python web framework
- **PostgreSQL** - Primary database for case/user/IOC metadata
- **ClickHouse** - High-performance analytics database for event storage
- **Celery** - Distributed task queue for async processing
- **Redis** - Message broker and caching

### Processing Tools
- **Hayabusa** - Windows event log analyzer with Sigma rule support
- **Volatility3** - Memory forensics framework
- **Zeek** - Network security monitor
- **Dissect** - Forensic artifact parsing framework

### AI/ML (Optional)
- **Qdrant** - Vector database for semantic search
- **Ollama** - Local LLM inference
- **sentence-transformers** - Text embeddings

## System Requirements

- **OS**: Linux (tested on Ubuntu 22.04+)
- **Python**: 3.10+
- **PostgreSQL**: 14+
- **ClickHouse**: 23+
- **Redis**: 6+
- **Memory**: 16GB+ recommended (more for memory forensics)
- **Storage**: SSD recommended, space depends on case sizes

## Services

CaseScope runs as two main services:
- `casescope-web` - Flask web application (HTTPS on port 443)
- `casescope-workers` - Celery worker processes for background tasks

Optional services:
- `qdrant` - Vector database for RAG functionality

## Configuration

Configuration is managed via `config.py` with environment variable overrides:

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://casescope:casescope@localhost/casescope` |
| `CLICKHOUSE_HOST` | ClickHouse server hostname | `localhost` |
| `REDIS_HOST` | Redis server hostname | `localhost` |
| `OLLAMA_HOST` | Ollama API endpoint | `http://localhost:11434` |
| `OLLAMA_MODEL` | LLM model for AI features | `qwen2.5:14b-instruct-q5_K_M` |
| `SECRET_KEY` | Flask secret key | (generate for production) |

## Directory Structure

```
/opt/casescope/
├── app.py              # Flask application factory
├── config.py           # Configuration settings
├── run.py              # Development server
├── wsgi.py             # Production WSGI entry point
├── bin/                # External tools (hayabusa, etc.)
├── models/             # SQLAlchemy database models
├── parsers/            # Artifact parsers
├── routes/             # Flask route blueprints
├── rules/              # Detection rules (Hayabusa, Sigma)
├── static/             # CSS, templates, assets
├── tasks/              # Celery background tasks
├── utils/              # Utility modules
├── uploads/            # Incoming file uploads
├── staging/            # Files being processed
├── storage/            # Processed case files
├── evidence/           # Evidence file storage
└── logs/               # Application logs
```

## Default Credentials

On first run, an admin account is created:
- **Username**: `admin`
- **Password**: `admin`

**⚠️ Change the default password immediately after first login!**

## API Routes

The application exposes several API blueprints:

- `/api/` - General API endpoints
- `/api/auth/` - Authentication
- `/api/parsing/` - File parsing operations
- `/api/memory/` - Memory forensics
- `/api/pcap/` - PCAP file management
- `/api/network/` - Network hunting
- `/api/noise/` - Noise filter management
- `/api/rag/` - AI/RAG functionality
- `/api/evidence/` - Evidence file management

## Version

Current version: See `version.json` for detailed changelog.

## License

Proprietary - All rights reserved.

---

*CaseScope - Digital Forensics Made Efficient*
