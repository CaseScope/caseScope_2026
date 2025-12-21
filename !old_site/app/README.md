# 🔍 CaseScope 2026

**Digital Forensics & Incident Response Platform**

[![Version](https://img.shields.io/badge/version-1.16.24-blue.svg)](https://github.com/JustinTDCT/caseScope_2026)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%2024.04-orange.svg)](https://ubuntu.com/)

---

## ⚠️ BETA WARNING

**This software is in active beta development and under heavy development.**

- ✅ Core features are functional and tested
- ⚠️ Known bugs exist (documented in [CURRENT_STATE.md](CURRENT_STATE.md))
- ⚠️ Re-index operations are currently broken (fix available)
- ⚠️ Code refactoring in progress
- ⚠️ Breaking changes may occur between versions
- ⚠️ Use in test/development environments only until stable release

**Status**: Production-ready for testing, NOT recommended for critical investigations without thorough testing first.

**Known Critical Issues**:
- Re-index operations fail (workaround: delete and re-upload files)
- See [CURRENT_STATE.md](CURRENT_STATE.md) for complete list

---

## 🎯 What is CaseScope 2026?

CaseScope 2026 is a complete rewrite of CaseScope 7.x, designed from the ground up as a comprehensive DFIR platform for analyzing security events from Windows Event Logs (EVTX), JSON logs, CSV files, and IIS logs.

### **Key Features:**
- ✅ **Zero legacy code** - Clean slate, modern architecture
- ✅ **Modular processing pipeline** - 5-step automated workflow
- ✅ **Production-ready** - PostgreSQL 16 with connection pooling
- ✅ **Powerful IOC hunting** - 13 IOC types with intelligent matching
- ✅ **SIGMA detection** - 3,074+ active rules (SigmaHQ + LOLRMM)
- ✅ **Full-text search** - OpenSearch 2.11 with advanced filtering
- ✅ **AI-powered analysis** - Ollama integration for automated reports
- ✅ **Timeline generation** - AI-generated attack timelines
- ✅ **System discovery** - Automatic host categorization
- ✅ **Threat intelligence** - OpenCTI & DFIR-IRIS integration

---

## 🚀 Quick Start

### **Installation** (Ubuntu 24.04 LTS)

```bash
# Clone repository
git clone https://github.com/JustinTDCT/caseScope_2026.git
cd caseScope_2026/app

# Run automated installation (15-20 minutes)
sudo bash fresh_install.sh
```

After installation completes:
```
http://YOUR_SERVER_IP:5000
Default login: admin / admin
```

⚠️ **Change the default password immediately!**

📘 **For complete installation instructions, see [INSTALL.md](INSTALL.md)**

---

## 📋 Features

### **Case Management**
- Create and manage investigation cases
- Assign cases to analysts
- Track case status (Open, In Progress, Closed)
- Case-level statistics and reporting

### **File Processing**
- **Supported Formats**: EVTX, JSON, NDJSON, CSV, IIS logs, ZIP archives
- **Upload Methods**: HTTP upload, bulk folder upload
- **Automated Pipeline**:
  1. Duplicate detection (SHA256 + filename)
  2. Event extraction and parsing
  3. OpenSearch indexing
  4. SIGMA detection (3,074+ rules)
  5. IOC hunting (13 IOC types)
- **Background Processing**: Celery workers (4 concurrent)
- **Real-time Progress**: Live status updates
- **Zero-event Handling**: Automatically hide empty files

### **Search & Analysis**
- **Full-text Search**: OpenSearch-powered with highlighting
- **Advanced Filters**:
  - Event type (EVTX, JSON, CSV, IIS)
  - Date range (custom or relative)
  - IOC matches only
  - SIGMA violations only
  - Multiple IOC hits (2+, 3+)
- **Event Tagging**: Tag events for timeline creation
- **Event Hiding**: Hide/unhide events and files
- **CSV Export**: Unlimited export via Scroll API

### **IOC Management**
- **13 IOC Types Supported**:
  - IP addresses
  - URLs & FQDNs (domains)
  - Filenames & file paths
  - MD5 & SHA256 hashes
  - Usernames & User SIDs
  - Commands (simple & complex/obfuscated)
  - Registry keys
  - Email addresses
  - Ports
  - Malware names
- **OpenCTI Enrichment**: Threat intelligence context
- **Bulk Operations**: Enable/disable/delete/enrich multiple IOCs
- **Real-time Hunting**: Automatically hunts across all indexed events

### **SIGMA Detection**
- **3,074+ Active Rules**:
  - SigmaHQ official repository
  - LOLRMM (Living Off the Land RMM tools)
  - Custom rules support
- **Automatic Detection**: Runs on all uploaded files
- **Rule Management**: Enable/disable specific rules
- **GitHub Updates**: Sync rules from SigmaHQ repository
- **Violation Tracking**: View violated rules in event details

### **Systems Discovery**
- **Automatic Detection**: Discovers systems from events
- **System Types**: Workstation, Server, Domain Controller, Firewall, Router, etc.
- **Metadata Tracking**: OS, IP address, first/last seen
- **Manual Management**: Add/edit systems manually

### **Login Analysis**
- **Quick Analysis Buttons**:
  - Successful logins (4624)
  - Failed logins (4625)
  - RDP logins (LogonType 10)
  - Console logins (LogonType 2)
- **VPN Authentication**: NPS event support (6272/6273)
- **LogonType Classification**: Automatic categorization

### **AI Features**
- **AI Report Generation**:
  - Ollama-powered analysis
  - Multiple models (phi3:mini, dfir-qwen, custom LoRA)
  - Live streaming preview
  - Cancellation support
  - Chat-based refinement
  - Export as PDF/Markdown
- **Timeline Generation**:
  - AI-generated attack timelines
  - Event tagging support
  - Export to DFIR-IRIS
- **LoRA Training**: Fine-tune AI models on your reports

### **Integrations**
- **OpenCTI**: Threat intelligence enrichment for IOCs
- **DFIR-IRIS**: Case management synchronization
  - Case sync
  - Asset sync
  - IOC sync
  - Timeline export

### **Evidence Files**
- Upload non-processable files (PDFs, images, documents)
- Archival storage for reference
- Not indexed or searched (metadata only)

---

## 🏗️ Architecture

### **Tech Stack**
| Component | Version | Purpose |
|-----------|---------|---------|
| **Flask** | 3.x | Web framework |
| **PostgreSQL** | 16.10 | Case metadata, users, IOCs |
| **OpenSearch** | 2.11.0 | Event search engine (8GB heap) |
| **Redis** | 7.0.15 | Message queue |
| **Celery** | 5.x | Background task processing |
| **Gunicorn** | 21.x | Production WSGI server (4 workers) |
| **Ollama** | Latest | Local AI inference |
| **Chainsaw** | v2.13.1 | SIGMA detection engine |

### **Processing Pipeline**
```
┌─────────────────────┐
│   HTTP/Bulk Upload  │
└──────────┬──────────┘
           │
           ▼
┌──────────────────────┐
│   Staging Area       │
│   (Duplicate Check)  │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Celery Queue       │
│   (Background Task)  │
└──────────┬───────────┘
           │
           ▼
┌───────────────────────────────┐
│  Worker Processing (4x)       │
├───────────────────────────────┤
│  1. Extract events            │
│  2. Index to OpenSearch       │
│  3. SIGMA detection           │
│  4. IOC hunting               │
└──────────┬────────────────────┘
           │
           ▼
┌──────────────────────┐
│   Completed          │
│   (Ready to Search)  │
└──────────────────────┘
```

### **Data Storage**
- **PostgreSQL**: Case metadata, users, IOCs, SIGMA violations, IOC matches, audit logs
- **OpenSearch**: Event data (one index per case: `case_<id>`)
- **Filesystem**: Original uploaded files, evidence files, AI models

---

## 📊 Tested Scale

**Production Tested**:
- 40+ million events indexed
- 9,400+ files processed
- 331,000+ SIGMA violations detected
- 41,000+ IOC events flagged
- 3,074 active SIGMA rules
- 53 tracked IOCs
- 5 active cases

**Performance**:
- EVTX parsing: ~50,000 events/min (single worker)
- OpenSearch indexing: ~100,000 events/min (bulk operations)
- SIGMA detection: ~10,000 events/sec (Chainsaw)
- IOC hunting: ~50,000 events/sec (OpenSearch query)

---

## 💻 System Requirements

### **Minimum**
- CPU: 4 cores
- RAM: 16GB
- Storage: 100GB SSD
- OS: Ubuntu 24.04 LTS

### **Recommended**
- CPU: 8+ cores
- RAM: 32GB
- Storage: 500GB NVMe SSD
- OS: Ubuntu 24.04 LTS

### **Large Datasets (40M+ events)**
- CPU: 16+ cores
- RAM: 64GB
- Storage: 1TB+ NVMe SSD
- OS: Ubuntu 24.04 LTS

---

## 📖 Documentation

### **For Installation & Setup:**
- **[INSTALL.md](INSTALL.md)** - Complete installation guide (automated & manual)

### **For AI Code Assistants (Cursor, Copilot):**
- **[ARCHITECTURE_OVERVIEW.md](ARCHITECTURE_OVERVIEW.md)** - System architecture & data flow
- **[ROUTES_COMPLETE.md](ROUTES_COMPLETE.md)** - All 140+ HTTP endpoints
- **[QUICK_REFERENCE_AI.md](QUICK_REFERENCE_AI.md)** - Common patterns & code examples
- **[CURRENT_STATE.md](CURRENT_STATE.md)** - Active features & known issues
- **[README_DOCS.md](README_DOCS.md)** - How to use the documentation

### **For Development & Refactoring:**
- **[CaseScope_Refactoring_Analysis.md](CaseScope_Refactoring_Analysis.md)** - Code refactoring plan
- **[Reindex_Bug_Analysis_and_Fix.md](Reindex_Bug_Analysis_and_Fix.md)** - Re-index bug fix
- **[Refactoring_Search_Guide.md](Refactoring_Search_Guide.md)** - Find refactoring targets

### **For End Users:**
- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Command reference
- **[UI_SYSTEM.md](UI_SYSTEM.md)** - UI/UX documentation
- **[EVTX_DESCRIPTIONS_README.md](EVTX_DESCRIPTIONS_README.md)** - Event descriptions system

### **Historical Reference:**
- **[APP_MAP_ARCHIVE_20251120.md](APP_MAP_ARCHIVE_20251120.md)** - Full changelog (20K+ lines)
- **[version_ARCHIVE_20251120.json](version_ARCHIVE_20251120.json)** - Version history (2.7K lines)

---

## 🔧 Usage

### **Access the Application**
```
http://your-server:5000
Default credentials: admin / admin
```

⚠️ **Change the default password immediately after first login!**

### **Basic Workflow**

1. **Create a Case**
   - Click "+ New Case"
   - Enter case details
   - Assign analyst (optional)

2. **Upload Files**
   - Open case
   - Click "+ Upload Files" or "+ Bulk Upload"
   - Select EVTX/CSV/JSON/ZIP files
   - Files process automatically (5-10 minutes per GB)

3. **Add IOCs**
   - Navigate to "IOC Management"
   - Click "+ Add IOC"
   - Enter IOC details
   - IOC hunt runs automatically

4. **Search Events**
   - Navigate to "Search Events"
   - Use search bar and filters
   - Tag events for timeline
   - Export results to CSV

5. **Generate AI Report**
   - Navigate to "AI Reports"
   - Click "+ Generate Report"
   - Select model
   - Watch live generation
   - Export as PDF/Markdown

### **Monitor Processing**
```bash
# Watch worker logs
sudo journalctl -u casescope-worker -f

# Check queue
redis-cli LLEN celery

# Check services
sudo systemctl status casescope casescope-worker opensearch redis
```

---

## 🐛 Known Issues

### **Critical Bugs:**
1. **Re-Index Broken** ⚠️
   - All re-index operations (single, selected, bulk) fail
   - Workaround: Delete file and re-upload
   - Fix documented in [Reindex_Bug_Analysis_and_Fix.md](Reindex_Bug_Analysis_and_Fix.md)

### **Refactoring Needed:**
1. **main.py Too Large** - 72 routes belong in blueprints
2. **Code Duplication** - OpenSearch queries repeated 100+ times
3. **Template Redundancy** - Pagination/modals duplicated across 38 templates

See [CURRENT_STATE.md](CURRENT_STATE.md) for complete list and development priorities.

---

## 🔒 Security

### **Authentication**
- Session-based authentication (Flask-Login)
- Password hashing (Werkzeug/bcrypt)
- Role-based access control

### **Roles**
- **Administrator**: Full access (user management, settings)
- **Analyst**: Case access, file operations
- **Read-only**: View-only access

### **Audit Logging**
- All user actions logged
- IP address tracking
- Resource tracking (what was changed)

### **Production Hardening**
See [INSTALL.md](INSTALL.md) for:
- Changing default passwords
- Setting up firewall (UFW)
- Configuring reverse proxy (nginx)
- Adding SSL/TLS (Let's Encrypt)

---

## 🧪 Development

### **Run Locally (Development Mode)**
```bash
cd /opt/casescope/app
source /opt/casescope/venv/bin/activate

# Terminal 1: Flask app
python main.py

# Terminal 2: Celery worker (with hot reload)
watchmedo auto-restart --directory=./ --pattern=*.py --recursive -- \
  celery -A celery_app worker --loglevel=debug --concurrency=2
```

### **Database Migrations**
```bash
cd /opt/casescope/app
source /opt/casescope/venv/bin/activate

python << 'EOF'
from main import app, db
with app.app_context():
    db.create_all()
    print("Database updated")
EOF
```

### **Code Style**
- Follow PEP 8 for Python
- Use descriptive variable names
- Add comments for complex logic
- Update documentation with changes
- Test with PostgreSQL (not SQLite)

---

## 🤝 Contributing

Contributions are welcome! This is a complete rewrite from scratch.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly (run full pipeline with test data)
5. Update documentation
6. Submit a pull request

**Before Contributing:**
- Read [ARCHITECTURE_OVERVIEW.md](ARCHITECTURE_OVERVIEW.md) to understand the system
- Check [CURRENT_STATE.md](CURRENT_STATE.md) for known issues
- Follow patterns in [QUICK_REFERENCE_AI.md](QUICK_REFERENCE_AI.md)
- Review [CaseScope_Refactoring_Analysis.md](CaseScope_Refactoring_Analysis.md) for refactoring priorities

---

## 📜 Version History

**Current**: v1.16.24 (November 20, 2025)

### **Recent Versions**
- **v1.16.24** - Search blob field for improved IOC matching
- **v1.16.15** - Timeline delete audit logger error fixed
- **v1.16.14** - AI report viewer 500 error fixed
- **v1.14.0** - IIS event detail view fixed
- **v1.13.9** - File statistics API hidden file filter fixed
- **v1.13.1** - Consolidated indices (one per case instead of per file)
- **v1.12.21** - SIGMA rule title extraction fix
- **v1.11.0** - PostgreSQL 16 migration (from SQLite)
- **v1.10.47** - AI report generation with Ollama

See [CURRENT_STATE.md](CURRENT_STATE.md) for recent changes.  
See [APP_MAP_ARCHIVE_20251120.md](APP_MAP_ARCHIVE_20251120.md) for complete history.

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file

---

## 🙏 Acknowledgments

- **SigmaHQ** - Detection rules repository
- **LOLRMM** - Remote management tool detection rules
- **OpenSearch Project** - Search engine
- **Chainsaw** - SIGMA detection engine by WithSecureLabs
- **Ollama** - Local AI inference engine
- **Flask & SQLAlchemy** - Web framework & ORM
- **PostgreSQL** - Production database
- **DFIR Community** - Continuous feedback and support

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/JustinTDCT/caseScope_2026/issues)
- **Discussions**: [GitHub Discussions](https://github.com/JustinTDCT/caseScope_2026/discussions)
- **Documentation**: See [INSTALL.md](INSTALL.md) and other docs above
- **Community**: DFIR Discord/Slack channels

---

## 🎯 Roadmap

### **Short-term (Next Release)**
- ✅ Fix re-index operations
- ✅ Move routes from main.py to blueprints
- ⏳ Implement OpenSearch query builder
- ⏳ Consolidate JavaScript patterns

### **Medium-term**
- ⏳ Database query helpers
- ⏳ Template component library
- ⏳ Performance optimizations
- ⏳ Additional AI models

### **Long-term**
- ⏳ Multi-tenancy support
- ⏳ API v2 with authentication
- ⏳ Real-time collaboration
- ⏳ Cloud deployment options

---

**Built with ❤️ for the DFIR community**

**🔥 Powered by PostgreSQL 16, OpenSearch 2.11, and Ollama AI 🔥**

---

## ⚠️ Beta Reminder

This software is under active development. While core features are functional and tested, bugs exist and breaking changes may occur. Review [CURRENT_STATE.md](CURRENT_STATE.md) before using in production environments.

**Test thoroughly before deploying for critical investigations.**
