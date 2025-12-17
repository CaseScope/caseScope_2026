# CaseScope Database Structure

**Complete PostgreSQL Schema Documentation**  
**Last Updated:** December 17, 2025  
**Version:** CaseScope 2026 v1.0.0

---

## Database Overview

CaseScope uses **PostgreSQL** for relational data storage and **OpenSearch** for event/log storage.

This document covers the PostgreSQL schema only.

---

## Schema Tree Structure

```
CaseScope PostgreSQL Database
│
├── 👤 USER MANAGEMENT
│   └── user (UserMixin)
│       ├── id (PK, Integer)
│       ├── username (String 80, Unique, Indexed) - Login username
│       ├── email (String 120, Unique) - User email
│       ├── password_hash (String 255) - Bcrypt hashed password
│       ├── full_name (String 120) - Display name
│       ├── role (String 20, Default='analyst') - administrator, analyst, read-only
│       ├── is_active (Boolean, Default=True) - Account enabled/disabled
│       ├── created_at (DateTime, Default=utcnow)
│       ├── created_by (FK → user.id, Nullable) - Who created this user
│       └── last_login (DateTime) - Last successful login timestamp
│
├── 📁 CASE MANAGEMENT
│   ├── case
│   │   ├── id (PK, Integer)
│   │   ├── name (String 200, Indexed) - Case name/title
│   │   ├── description (Text) - Case details
│   │   ├── company (String 200) - Client/organization name
│   │   ├── status (String 20, Default='New') - New, Assigned, In Progress, Completed, Archived
│   │   ├── created_by (FK → user.id) - Who created the case
│   │   ├── assigned_to (FK → user.id) - Current case owner
│   │   ├── created_at (DateTime, Default=utcnow)
│   │   ├── updated_at (DateTime, Default=utcnow, Auto-update)
│   │   ├── edr_report (Text) - Full EDR/MDR report text (v1.37.0)
│   │   ├── vpn_ip_ranges (Text) - VPN IP ranges for triage (v1.43.0) - Format: "192.168.100.1-192.168.100.50, 10.10.0.0/24"
│   │   ├── archive_path (String 1000) - Full path to archive ZIP (v1.18.0)
│   │   ├── archived_at (DateTime) - When case was archived
│   │   ├── archived_by (FK → user.id) - Who archived the case
│   │   └── restored_at (DateTime) - When last restored (audit trail)
│   │
│   └── case_lock (v1.25.0)
│       ├── id (PK, Integer)
│       ├── case_id (FK → case.id, Unique, Indexed) - One lock per case
│       ├── user_id (FK → user.id, Indexed) - Who has the lock
│       ├── locked_at (DateTime, Default=utcnow) - When lock was acquired
│       ├── last_activity (DateTime, Default=utcnow) - Last user action timestamp
│       └── session_id (String 255) - Flask session ID for lock validation
│
├── 📂 FILE MANAGEMENT
│   ├── case_file
│   │   ├── id (PK, Integer)
│   │   ├── case_id (FK → case.id, Indexed) - Parent case
│   │   ├── filename (String 500) - Stored filename (UUID-based)
│   │   ├── original_filename (String 500) - User's original filename
│   │   ├── file_path (String 1000) - Full path on disk
│   │   ├── file_size (BigInteger, Default=0) - Size in bytes
│   │   ├── size_mb (Integer, Default=0) - Size in MB (rounded)
│   │   ├── file_hash (String 64, Indexed) - SHA256 hash for deduplication
│   │   ├── file_type (String 20) - EVTX, JSON, NDJSON, CSV, ZIP
│   │   ├── mime_type (String 100) - MIME type detection result
│   │   ├── indexing_status (String 50, Default='Queued') - Queued, Indexing, Completed, Failed
│   │   ├── error_message (Text) - Detailed error for failed files
│   │   ├── is_indexed (Boolean, Default=False) - Indexing completed successfully
│   │   ├── is_hidden (Boolean, Default=False) - Hide 0-event files from UI
│   │   ├── is_deleted (Boolean, Default=False) - Soft delete flag
│   │   ├── event_count (Integer, Default=0) - Actual indexed events
│   │   ├── estimated_event_count (Integer, Default=0) - Pre-index estimate
│   │   ├── violation_count (Integer, Default=0) - Active SIGMA violations
│   │   ├── ioc_event_count (Integer, Default=0) - Events matching IOCs
│   │   ├── opensearch_key (String 200, Indexed) - OpenSearch document field reference
│   │   ├── celery_task_id (String 255) - Current processing task ID
│   │   ├── upload_type (String 20, Default='http') - http, bulk, staging
│   │   ├── uploaded_by (FK → user.id) - Who uploaded the file
│   │   └── uploaded_at (DateTime, Default=utcnow)
│   │
│   ├── skipped_file
│   │   ├── id (PK, Integer)
│   │   ├── case_id (FK → case.id, Indexed) - Parent case
│   │   ├── filename (String 500) - Filename that was skipped
│   │   ├── file_size (BigInteger) - File size in bytes
│   │   ├── file_hash (String 64) - SHA256 hash
│   │   ├── skip_reason (String 100) - duplicate, zero_events, error
│   │   ├── skip_details (Text) - Additional context
│   │   ├── upload_type (String 20) - http, bulk, staging
│   │   └── created_at (DateTime, Default=utcnow)
│   │
│   └── evidence_file
│       ├── id (PK, Integer)
│       ├── case_id (FK → case.id, Indexed) - Parent case
│       ├── filename (String 500) - Stored filename (UUID-based)
│       ├── original_filename (String 500) - User's original filename
│       ├── file_path (String 1000) - Full path on disk
│       ├── file_size (BigInteger, Default=0) - Size in bytes
│       ├── size_mb (Integer, Default=0) - Size in MB (rounded)
│       ├── file_hash (String 64, Indexed) - SHA256 hash
│       ├── file_type (String 50) - Detected extension (png, jpg, pdf, docx, xlsx, zip, etc.)
│       ├── mime_type (String 100) - MIME type
│       ├── description (Text) - User-provided description
│       ├── upload_source (String 20, Default='http') - http, bulk
│       ├── uploaded_by (FK → user.id) - Who uploaded
│       ├── uploaded_at (DateTime, Default=utcnow)
│       ├── dfir_iris_synced (Boolean, Default=False) - Synced to DFIR-IRIS
│       ├── dfir_iris_file_id (String 100) - DFIR-IRIS datastore file ID
│       └── dfir_iris_sync_date (DateTime)
│
├── 🔍 SIGMA DETECTION
│   ├── sigma_rule
│   │   ├── id (PK, Integer)
│   │   ├── title (String 500) - Rule title
│   │   ├── description (Text) - Rule description
│   │   ├── rule_yaml (Text) - Full SIGMA YAML definition
│   │   ├── level (String 20) - low, medium, high, critical
│   │   ├── tags (Text) - JSON array of tags
│   │   ├── is_enabled (Boolean, Default=True, Indexed) - Active/disabled
│   │   └── created_at (DateTime, Default=utcnow)
│   │
│   └── sigma_violation
│       ├── id (PK, Integer)
│       ├── case_id (FK → case.id, Indexed) - Parent case
│       ├── file_id (FK → case_file.id, Indexed) - Source file
│       ├── rule_id (FK → sigma_rule.id) - Matching rule
│       ├── event_id (String 64, Indexed) - OpenSearch document ID
│       ├── event_data (Text) - JSON snapshot of event
│       ├── matched_fields (Text) - JSON of matched fields
│       ├── severity (String 20) - Severity level
│       └── created_at (DateTime, Default=utcnow)
│
├── 🎯 IOC MANAGEMENT
│   ├── ioc
│   │   ├── id (PK, Integer)
│   │   ├── case_id (FK → case.id, Indexed) - Parent case
│   │   ├── ioc_type (String 50) - ip, username, user_sid, hostname, fqdn, command, command_complex, filename, malware_name, hash, port, url, registry_key, email, pid, other
│   │   ├── ioc_value (String 500, Indexed) - The actual IOC value
│   │   ├── description (Text) - IOC description/context
│   │   ├── threat_level (String 20, Default='medium') - Threat severity
│   │   ├── is_active (Boolean, Default=True) - Active/disabled
│   │   ├── created_by (FK → user.id) - Who added it
│   │   ├── created_at (DateTime, Default=utcnow)
│   │   ├── opencti_enrichment (Text) - JSON enrichment data from OpenCTI
│   │   ├── opencti_enriched_at (DateTime)
│   │   ├── dfir_iris_synced (Boolean, Default=False)
│   │   ├── dfir_iris_sync_date (DateTime)
│   │   └── dfir_iris_ioc_id (String 100) - DFIR-IRIS IOC ID
│   │
│   └── ioc_match
│       ├── id (PK, Integer)
│       ├── case_id (FK → case.id, Indexed) - Parent case
│       ├── ioc_id (FK → ioc.id) - Matching IOC
│       ├── file_id (FK → case_file.id) - Source file
│       ├── index_name (String 200, Indexed) - OpenSearch index
│       ├── event_id (String 64) - OpenSearch document ID
│       ├── event_data (Text) - JSON snapshot of event
│       ├── matched_field (String 200) - Which field matched
│       └── created_at (DateTime, Default=utcnow)
│
├── 💻 SYSTEM TRACKING
│   └── system
│       ├── id (PK, Integer)
│       ├── case_id (FK → case.id, Indexed) - Parent case
│       ├── system_name (String 255, Indexed) - Hostname/system name
│       ├── ip_address (String 45) - IPv4 (15) or IPv6 (45)
│       ├── system_type (String 50, Default='workstation') - server, workstation, firewall, switch, printer, actor_system, unknown
│       ├── added_by (String 100, Default='CaseScope') - Username or 'CaseScope' for auto-detection
│       ├── created_at (DateTime, Default=utcnow)
│       ├── hidden (Boolean, Default=False) - Hide from UI
│       ├── opencti_enrichment (Text) - JSON enrichment data from OpenCTI
│       ├── opencti_enriched_at (DateTime)
│       ├── dfir_iris_synced (Boolean, Default=False)
│       ├── dfir_iris_sync_date (DateTime)
│       ├── dfir_iris_asset_id (String 100) - DFIR-IRIS Asset ID
│       └── UNIQUE(case_id, system_name) - One system name per case
│
├── 👥 KNOWN USERS (v1.20.0)
│   └── known_user
│       ├── id (PK, Integer)
│       ├── case_id (FK → case.id, Indexed) - Parent case
│       ├── username (String 255, Indexed) - Username in the environment
│       ├── user_type (String 20, Default='unknown') - domain, local, unknown, invalid (v1.21.0)
│       ├── user_sid (String 255, Indexed, Nullable) - Windows Security Identifier (v1.21.0)
│       ├── compromised (Boolean, Default=False) - Marked as compromised
│       ├── active (Boolean, Default=True) - Currently active user (v1.20.0)
│       ├── added_method (String 20) - manual, csv
│       ├── added_by (FK → user.id) - CaseScope user who added it
│       ├── created_at (DateTime, Default=utcnow)
│       └── UNIQUE(case_id, username) - One username per case
│
├── 📊 EVENT STATUS TRACKING
│   └── event_status
│       ├── id (PK, Integer)
│       ├── case_id (FK → case.id, Indexed) - Parent case
│       ├── event_id (String 150, Indexed) - OpenSearch document _id
│       ├── status (String 20, Default='new', Indexed) - new, noise, hunted, confirmed
│       │   ├── new: Fresh event, just indexed (default)
│       │   ├── noise: Flagged by known-good/noise processes, excluded from searches
│       │   ├── hunted: Tagged by Phase 3 triage as potentially interesting
│       │   └── confirmed: Analyst reviewed and confirmed as relevant
│       ├── updated_by (FK → user.id, Nullable) - Who updated (null for system)
│       ├── updated_at (DateTime, Default=utcnow, Auto-update, Indexed)
│       ├── notes (Text) - Optional analyst notes
│       └── UNIQUE(case_id, event_id) - One status per event per case
│
├── 🔖 TIMELINE & TAGGING
│   ├── timeline_tag
│   │   ├── id (PK, Integer)
│   │   ├── case_id (FK → case.id, Indexed) - Parent case
│   │   ├── user_id (FK → user.id) - Who tagged it
│   │   ├── event_id (String 64, Indexed) - OpenSearch document ID
│   │   ├── index_name (String 200, Indexed) - OpenSearch index
│   │   ├── event_data (Text) - JSON snapshot when tagged
│   │   ├── tag_color (String 20, Default='blue') - Visual identification
│   │   ├── notes (Text) - User notes about event
│   │   ├── created_at (DateTime, Default=utcnow, Indexed)
│   │   └── UNIQUE(case_id, event_id, index_name) - Prevent duplicate tags
│   │
│   └── tag_exclusion
│       ├── id (PK, Integer)
│       ├── case_id (FK → case.id, Indexed) - Parent case
│       ├── event_id (String 150, Indexed) - OpenSearch document ID
│       ├── index_name (String 200, Indexed) - OpenSearch index
│       ├── reason (String 200) - "False positive", "Not relevant", etc.
│       ├── excluded_by (FK → user.id) - Who excluded it
│       ├── excluded_at (DateTime, Default=utcnow, Indexed)
│       └── UNIQUE(case_id, event_id, index_name) - One exclusion per event
│
├── 🕐 TIMELINE GENERATION
│   └── case_timeline
│       ├── id (PK, Integer)
│       ├── case_id (FK → case.id, Indexed) - Parent case
│       ├── generated_by (FK → user.id) - Who generated it
│       ├── status (String 20, Default='pending', Indexed) - pending, generating, completed, failed, cancelled
│       ├── model_name (String 50, Default='dfir-qwen:latest') - AI model used (Qwen for timelines)
│       ├── celery_task_id (String 255, Indexed) - Celery task ID for cancellation
│       ├── timeline_title (String 500) - Timeline title
│       ├── timeline_content (Text) - Full timeline in markdown format
│       ├── timeline_json (Text) - Structured timeline data (JSON)
│       ├── prompt_sent (Text) - Full prompt sent to AI
│       ├── raw_response (Text) - Raw markdown response from AI
│       ├── generation_time_seconds (Float) - Generation duration
│       ├── version (Integer, Default=1) - Version number (increments on regenerate)
│       ├── event_count (Integer) - Event count at generation time
│       ├── ioc_count (Integer) - IOC count at generation time
│       ├── system_count (Integer) - System count at generation time
│       ├── progress_percent (Integer, Default=0) - 0-100 progress
│       ├── progress_message (String 500) - Current step description
│       ├── error_message (Text) - Error details if failed
│       ├── created_at (DateTime, Default=utcnow, Indexed)
│       └── updated_at (DateTime, Default=utcnow, Auto-update)
│
├── 🤖 AI REPORT GENERATION
│   ├── ai_report
│   │   ├── id (PK, Integer)
│   │   ├── case_id (FK → case.id, Indexed) - Parent case
│   │   ├── generated_by (FK → user.id) - Who generated it
│   │   ├── status (String 20, Default='pending', Indexed) - pending, generating, completed, failed, cancelled
│   │   ├── model_name (String 50, Default='phi3:14b') - AI model used
│   │   ├── celery_task_id (String 255, Indexed) - Celery task ID for cancellation
│   │   ├── report_title (String 500) - Report title
│   │   ├── report_content (Text) - Full report in markdown format
│   │   ├── prompt_sent (Text) - Full prompt sent to AI
│   │   ├── raw_response (Text) - Raw markdown response from AI
│   │   ├── validation_results (Text) - JSON validation results
│   │   ├── generation_time_seconds (Float) - Generation duration
│   │   ├── estimated_duration_seconds (Float) - Estimated time based on IOC/event counts
│   │   ├── tokens_per_second (Float) - Generation speed
│   │   ├── total_tokens (Integer) - Total tokens generated
│   │   ├── error_message (Text) - Error details if failed
│   │   ├── progress_percent (Integer, Default=0) - 0-100 progress
│   │   ├── progress_message (String 200) - Current step description
│   │   ├── current_stage (String 50) - Current generation stage
│   │   ├── created_at (DateTime, Default=utcnow, Indexed)
│   │   └── completed_at (DateTime)
│   │
│   └── ai_report_chat
│       ├── id (PK, Integer)
│       ├── report_id (FK → ai_report.id, Indexed) - Parent report
│       ├── user_id (FK → user.id) - Who sent message
│       ├── role (String 20) - 'user' or 'assistant'
│       ├── message (Text) - Chat message content
│       ├── applied (Boolean, Default=False) - AI suggestion applied to report
│       └── created_at (DateTime, Default=utcnow, Indexed)
│
├── 🧠 AI MODEL MANAGEMENT
│   ├── ai_model
│   │   ├── id (PK, Integer)
│   │   ├── model_name (String 100, Unique, Indexed) - 'dfir-llama:latest'
│   │   ├── display_name (String 200) - 'DFIR-Llama 3.1 8B (Forensic Profile)'
│   │   ├── description (Text) - Model description
│   │   ├── speed (String 50) - 'Fast', 'Moderate', 'Slow'
│   │   ├── quality (String 50) - 'Excellent', 'Good', etc.
│   │   ├── size (String 50) - '4.9 GB'
│   │   ├── speed_estimate (String 200) - '~25-35 tok/s GPU'
│   │   ├── time_estimate (String 200) - '3-5 minutes (GPU)'
│   │   ├── recommended (Boolean, Default=False) - Recommended model
│   │   ├── trainable (Boolean, Default=False) - Can be trained with LoRA
│   │   ├── trained (Boolean, Default=False) - Has been trained
│   │   ├── trained_date (DateTime) - Training date
│   │   ├── training_examples (Integer) - Number of reports used
│   │   ├── trained_model_path (String 500) - Path to LoRA adapter weights
│   │   ├── base_model (String 100) - Unsloth base model name
│   │   ├── installed (Boolean, Default=False) - Pulled via Ollama
│   │   ├── cpu_optimal (JSON) - CPU-optimized parameters
│   │   ├── gpu_optimal (JSON) - GPU-optimized parameters
│   │   ├── created_at (DateTime, Default=utcnow)
│   │   └── updated_at (DateTime, Default=utcnow, Auto-update)
│   │
│   └── ai_training_session
│       ├── id (PK, Integer)
│       ├── task_id (String 100, Unique, Indexed) - Celery task ID
│       ├── model_name (String 100) - Model being trained
│       ├── user_id (FK → user.id) - Who started training
│       ├── status (String 20, Default='pending', Indexed) - pending, running, completed, failed
│       ├── progress (Integer, Default=0) - 0-100
│       ├── current_step (String 200) - 'Step 3/5: Training LoRA adapter...'
│       ├── log (Text) - Full training log
│       ├── error_message (Text) - Error details if failed
│       ├── report_count (Integer) - Number of reports used
│       ├── started_at (DateTime, Default=utcnow) - Actual training start time
│       ├── completed_at (DateTime) - Training completion time
│       ├── created_at (DateTime, Default=utcnow)
│       └── updated_at (DateTime, Default=utcnow, Auto-update)
│
├── 🔧 SYSTEM TOOLS & SETTINGS
│   ├── system_tools_setting (v1.38.0, EDR tools v1.40.0)
│   │   ├── id (PK, Integer)
│   │   ├── setting_type (String 50, Indexed) - 'rmm_tool', 'remote_tool', 'edr_tool', 'known_good_ip'
│   │   ├── tool_name (String 100) - 'ConnectWise Automate', 'ScreenConnect', 'Huntress', etc.
│   │   ├── executable_pattern (String 500) - 'LTSVC.exe,LTSvcMon.exe' or 'HuntressAgent.exe'
│   │   ├── rmm_path (String 500) - RMM installation path
│   │   ├── known_good_ids (Text) - JSON list: ["id1", "id2"] (for remote tools)
│   │   ├── ip_or_cidr (String 50) - '192.168.1.0/24' or '10.0.0.50'
│   │   ├── exclude_routine (Boolean, Default=True) - Exclude routine health checks (EDR)
│   │   ├── keep_responses (Boolean, Default=True) - Keep isolation/response actions (EDR)
│   │   ├── routine_commands (Text) - JSON list: ["whoami", "systeminfo", "ipconfig"]
│   │   ├── response_patterns (Text) - JSON list: ["isolat", "quarantin", "block"]
│   │   ├── description (String 500) - Documentation
│   │   ├── created_by (FK → user.id) - Who created it
│   │   ├── created_at (DateTime, Default=utcnow)
│   │   ├── updated_at (DateTime, Default=utcnow, Auto-update)
│   │   └── is_active (Boolean, Default=True, Indexed) - Active/disabled
│   │
│   └── system_settings
│       ├── id (PK, Integer)
│       ├── setting_key (String 100, Unique) - Setting name
│       ├── setting_value (Text) - Setting value
│       ├── description (Text) - Setting description
│       └── updated_at (DateTime, Default=utcnow, Auto-update)
│
├── 📖 EVENT DESCRIPTIONS
│   └── event_description
│       ├── id (PK, Integer)
│       ├── event_id (Integer, Indexed) - Windows Event ID
│       ├── event_source (String 100) - 'Security', 'System', 'Sysmon', 'Custom'
│       ├── title (String 500) - Event title
│       ├── description (Text) - Enrichment text / additional context
│       ├── category (String 100) - Event category
│       ├── source_url (String 500) - Which site it came from
│       ├── is_custom (Boolean, Default=False, Indexed) - User-added custom event (v1.13.7)
│       ├── created_by (FK → user.id) - Who created custom event (v1.13.7)
│       ├── last_updated (DateTime, Default=utcnow, Auto-update)
│       └── UNIQUE(event_id, event_source) - One description per event + source
│
├── 🔍 SEARCH MANAGEMENT
│   └── search_history
│       ├── id (PK, Integer)
│       ├── user_id (FK → user.id, Indexed) - Who performed search
│       ├── case_id (FK → case.id, Indexed, Nullable) - Associated case
│       ├── search_query (Text) - JSON string of search parameters
│       ├── search_name (String 200) - Optional name for saved search
│       ├── is_favorite (Boolean, Default=False, Indexed) - Favorited search
│       ├── filter_type (String 50) - 'all', 'sigma', 'ioc', 'sigma_and_ioc', 'tagged'
│       ├── date_range (String 50) - '24h', '7d', '30d', 'custom'
│       ├── custom_date_start (DateTime) - Custom range start
│       ├── custom_date_end (DateTime) - Custom range end
│       ├── column_config (Text) - JSON string of column configuration
│       ├── result_count (Integer) - Number of results
│       ├── created_at (DateTime, Default=utcnow, Indexed)
│       └── last_used (DateTime, Default=utcnow, Auto-update)
│
├── 🔄 REINDEX TRACKING (v1.46.0)
│   └── reindex_progress
│       ├── id (PK, Integer)
│       ├── case_id (FK → case.id, Indexed) - Parent case
│       ├── user_id (FK → user.id) - Who started reindex
│       ├── status (String 20, Default='pending', Indexed) - pending, running, completed, failed
│       ├── celery_task_id (String 255, Indexed) - Coordinator task ID
│       ├── current_phase (Integer, Default=0) - Current phase 1-4
│       ├── current_phase_name (String 100) - Phase name
│       │
│       ├── phase1_status (String 20, Default='pending') - Index + SIGMA (per file)
│       ├── phase1_total_files (Integer, Default=0)
│       ├── phase1_completed_files (Integer, Default=0)
│       ├── phase1_events_indexed (Integer, Default=0)
│       ├── phase1_sigma_violations (Integer, Default=0)
│       │
│       ├── phase2_status (String 20, Default='pending') - Known Good Hunting (bulk)
│       ├── phase2_total_workers (Integer, Default=0)
│       ├── phase2_completed_workers (Integer, Default=0)
│       ├── phase2_events_marked (Integer, Default=0)
│       │
│       ├── phase3_status (String 20, Default='pending') - Known Noise Hunting (bulk)
│       ├── phase3_total_workers (Integer, Default=0)
│       ├── phase3_completed_workers (Integer, Default=0)
│       ├── phase3_events_marked (Integer, Default=0)
│       │
│       ├── phase4_status (String 20, Default='pending') - IOC Hunting (per file)
│       ├── phase4_total_files (Integer, Default=0)
│       ├── phase4_completed_files (Integer, Default=0)
│       ├── phase4_iocs_found (Integer, Default=0)
│       │
│       ├── statuses_deleted (Integer, Default=0) - Pre-phase data clearing
│       ├── violations_deleted (Integer, Default=0) - Pre-phase data clearing
│       ├── started_at (DateTime, Default=utcnow, Indexed)
│       ├── completed_at (DateTime)
│       └── error_message (Text)
│
├── 🎯 AI TRIAGE SEARCH (v1.39.0)
│   └── ai_triage_search
│       ├── id (PK, Integer)
│       ├── case_id (FK → case.id, Indexed) - Parent case
│       ├── generated_by (FK → user.id) - Who initiated triage
│       ├── status (String 20, Default='pending', Indexed) - pending, running, completed, failed
│       ├── celery_task_id (String 255, Indexed) - Task ID
│       ├── entry_point (String 50) - 'full_triage', 'ioc_hunt', 'tag_hunt'
│       ├── search_date (DateTime) - Date used for IOC-based hunt
│       │
│       ├── iocs_extracted_json (Text) - IOCs from report
│       ├── iocs_discovered_json (Text) - IOCs discovered via hunting
│       ├── timeline_json (Text) - Attack timeline events
│       ├── process_trees_json (Text) - Process tree structures
│       ├── mitre_techniques_json (Text) - MITRE techniques found
│       ├── summary_json (Text) - Full summary for display
│       │
│       ├── iocs_extracted_count (Integer, Default=0)
│       ├── iocs_discovered_count (Integer, Default=0)
│       ├── events_analyzed_count (Integer, Default=0)
│       ├── timeline_events_count (Integer, Default=0)
│       ├── auto_tagged_count (Integer, Default=0)
│       ├── techniques_found_count (Integer, Default=0)
│       ├── process_trees_count (Integer, Default=0)
│       │
│       ├── current_phase (Integer, Default=0) - 1-9
│       ├── current_phase_name (String 100)
│       ├── progress_message (String 500)
│       ├── progress_percent (Integer, Default=0)
│       ├── generation_time_seconds (Float)
│       ├── error_message (Text)
│       ├── created_at (DateTime, Default=utcnow, Indexed)
│       └── completed_at (DateTime)
│
└── 📝 AUDIT LOGGING
    └── audit_log
        ├── id (PK, Integer)
        ├── user_id (FK → user.id, Indexed, Nullable) - Who performed action (null for system)
        ├── username (String 80) - Username for historical reference
        ├── action (String 100, Indexed) - 'login', 'create_case', 'delete_file'
        ├── resource_type (String 50, Indexed) - 'case', 'file', 'user', 'ioc'
        ├── resource_id (Integer) - ID of affected resource
        ├── resource_name (String 500) - Name/description of resource
        ├── details (Text) - JSON or text details about action
        ├── ip_address (String 45) - IPv4 or IPv6
        ├── user_agent (String 500) - Browser/client info
        ├── status (String 20, Default='success') - success, failed, error
        └── created_at (DateTime, Default=utcnow, Indexed)
```

---

## Foreign Key Relationships Summary

### Tables with Foreign Keys to `case` table:
```
case (parent)
├── case_lock (case_id → case.id)
├── case_file (case_id → case.id)
├── skipped_file (case_id → case.id)
├── evidence_file (case_id → case.id)
├── sigma_violation (case_id → case.id)
├── ioc (case_id → case.id)
├── ioc_match (case_id → case.id)
├── system (case_id → case.id)
├── known_user (case_id → case.id)
├── event_status (case_id → case.id)
├── timeline_tag (case_id → case.id)
├── tag_exclusion (case_id → case.id)
├── case_timeline (case_id → case.id)
├── ai_report (case_id → case.id)
│   └── ai_report_chat (report_id → ai_report.id)
├── ai_triage_search (case_id → case.id)
├── reindex_progress (case_id → case.id)
└── search_history (case_id → case.id, Nullable)
```

### Tables with Foreign Keys to `user` table:
```
user (parent)
├── user (created_by → user.id) - Self-reference
├── case (created_by, assigned_to, archived_by → user.id)
├── case_lock (user_id → user.id)
├── case_file (uploaded_by → user.id)
├── ioc (created_by → user.id)
├── system_tools_setting (created_by → user.id)
├── known_user (added_by → user.id)
├── event_status (updated_by → user.id, Nullable)
├── timeline_tag (user_id → user.id)
├── tag_exclusion (excluded_by → user.id)
├── case_timeline (generated_by → user.id)
├── ai_report (generated_by → user.id)
├── ai_report_chat (user_id → user.id)
├── ai_training_session (user_id → user.id)
├── event_description (created_by → user.id)
├── search_history (user_id → user.id)
├── ai_triage_search (generated_by → user.id)
├── reindex_progress (user_id → user.id)
├── evidence_file (uploaded_by → user.id)
└── audit_log (user_id → user.id, Nullable)
```

### Other Foreign Key Relationships:
```
sigma_violation
├── file_id → case_file.id
└── rule_id → sigma_rule.id

ioc_match
├── ioc_id → ioc.id
└── file_id → case_file.id

ai_report_chat
└── report_id → ai_report.id
```

---

## Unique Constraints

| Table | Constraint | Purpose |
|-------|------------|---------|
| `user` | username (unique) | One username per system |
| `user` | email (unique) | One email per system |
| `case_lock` | case_id (unique) | One lock per case |
| `system` | (case_id, system_name) | One system name per case |
| `known_user` | (case_id, username) | One username per case |
| `event_status` | (case_id, event_id) | One status per event per case |
| `timeline_tag` | (case_id, event_id, index_name) | One tag per event per case |
| `tag_exclusion` | (case_id, event_id, index_name) | One exclusion per event per case |
| `event_description` | (event_id, event_source) | One description per event + source |
| `ai_model` | model_name (unique) | One entry per AI model |
| `ai_training_session` | task_id (unique) | One session per training task |
| `system_settings` | setting_key (unique) | One value per setting key |

---

## Index Summary

**Heavily Indexed Fields for Performance:**
- All primary keys (`id`)
- All foreign keys (`case_id`, `user_id`, `file_id`, etc.)
- Status fields (`status`, `indexing_status`, `is_enabled`, `is_active`)
- Search fields (`username`, `event_id`, `file_hash`, `ioc_value`)
- Timestamp fields (`created_at`, `updated_at`, `last_activity`)

---

## Table Sizes & Data Volume (Typical)

| Table | Typical Size | Growth Rate |
|-------|--------------|-------------|
| `event_status` | **LARGE** (millions) | High - one row per unique event |
| `sigma_violation` | **LARGE** (hundreds of thousands) | Medium - grows with SIGMA rule matches |
| `case_file` | Medium (thousands) | Medium - grows with file uploads |
| `ioc_match` | Medium (tens of thousands) | Medium - grows with IOC hunting |
| `audit_log` | Medium (tens of thousands) | Low-Medium - grows with user actions |
| `case` | Small (hundreds) | Low - one row per investigation |
| `ioc` | Small (hundreds) | Low - manually added |
| `system` | Small (tens) | Low - one row per system per case |
| `user` | Small (tens) | Very Low - only application users |
| All others | Small | Low |

---

## Data Retention & Cleanup

### Automatic Cleanup:
- **None** - All data is retained indefinitely by design

### Manual Cleanup Options:
1. **Case Archiving** - Moves case files to ZIP, marks as archived
2. **Case Deletion** - Cascades to all child tables (use with caution)
3. **Stale Lock Cleanup** - Removes locks with no activity for 4+ hours
4. **Old Audit Log Pruning** - Can be pruned periodically (optional)

### Critical Tables (DO NOT TRUNCATE):
- `user` - Application users
- `sigma_rule` - Detection rules
- `ai_model` - AI model metadata
- `system_settings` - System configuration
- `event_description` - Event enrichment data

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| v1.0.0 | 2025-12-17 | Initial comprehensive documentation |
| v1.46.0 | 2024 | Added `reindex_progress` table |
| v1.43.0 | 2024 | Added `vpn_ip_ranges` to case |
| v1.40.0 | 2024 | Added EDR tool support to `system_tools_setting` |
| v1.39.0 | 2024 | Added `ai_triage_search` table |
| v1.38.0 | 2024 | Added `system_tools_setting` table |
| v1.37.0 | 2024 | Added `edr_report` to case |
| v1.25.0 | 2024 | Added `case_lock` table |
| v1.21.0 | 2024 | Added `user_type` and `user_sid` to `known_user` |
| v1.20.0 | 2024 | Added `active` field to `known_user` |
| v1.18.0 | 2024 | Added archive fields to case |
| v1.13.7 | 2024 | Added custom event support to `event_description` |

---

## Notes

1. **OpenSearch Integration**: Event data is stored in OpenSearch (not PostgreSQL). The `event_status` table syncs status to OpenSearch's `event_status` field.

2. **Celery Task IDs**: Many tables store `celery_task_id` for background job tracking and cancellation.

3. **Soft Deletes**: `case_file` uses `is_deleted` flag for soft deletion (files remain on disk).

4. **Case Locking**: The `case_lock` table prevents concurrent edits by multiple users.

5. **Event Status Lifecycle**:
   ```
   new → noise (excluded from searches)
       → hunted (Phase 3 auto-tagged)
       → confirmed (analyst verified)
   ```

6. **Reindex Pipeline** (4 phases):
   ```
   Phase 1: Index + SIGMA (per file, parallel)
   Phase 2: Known Good Hunting (bulk, parallel)
   Phase 3: Known Noise Hunting (bulk, parallel)
   Phase 4: IOC Hunting (per file, excludes noise)
   ```

7. **AI Triage Search** (9 phases):
   ```
   1. IOC Extraction from report
   2. IOC Classification (SPECIFIC vs BROAD)
   3. Snowball Hunting (discover new IOCs)
   4. Malware/Recon Hunting
   5. SPECIFIC IOC Search (auto-tag candidates)
   6. BROAD IOC Aggregation (discovery only)
   7. Time Window Analysis (±5 min around anchors)
   8. Process Tree Building
   9. MITRE Pattern Matching + Timeline Auto-Tagging
   ```

---

**END OF DOCUMENTATION**

