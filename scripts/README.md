# CaseScope Utility Scripts

This directory contains standalone utility scripts for maintenance and administration tasks.

## Available Scripts

### `clean_all_case_data.py` ⚠️ DESTRUCTIVE
**Purpose:** Complete system reset - deletes ALL case data from PostgreSQL, OpenSearch, and disk  
**Usage:** Run when you need to start completely fresh

**⚠️ WARNING: This is DESTRUCTIVE and CANNOT be undone!**

**What it deletes:**
- All cases, files, events from PostgreSQL
- All OpenSearch indices (case_*)
- All uploaded files from `/opt/casescope/uploads/`
- All staging files from `/opt/casescope/staging/`
- All archived files from `/opt/casescope/archive/`
- All evidence files from `/opt/casescope/evidence/`

**Manual execution:**
```bash
sudo /opt/casescope/scripts/clean_all_case_data.py
```

Or with full path:
```bash
cd /opt/casescope
sudo ./scripts/clean_all_case_data.py
```

**Safety features:**
- Requires explicit confirmation: type `DELETE ALL DATA` to proceed
- Shows counts of what will be deleted before proceeding
- Reports progress and space freed

**When to use:**
- Starting fresh with a clean slate
- After testing/development work
- Clearing old demo data
- Before handing off system to new team

---

### `cleanup_stale_locks.py`
**Purpose:** Clean up stale case locks from the database  
**Usage:** Meant to run as a cron job

**Manual execution:**
```bash
cd /opt/casescope
source venv/bin/activate
python3 scripts/cleanup_stale_locks.py
```

**Cron setup (recommended - run hourly):**
```bash
# Add to crontab:
0 * * * * /opt/casescope/venv/bin/python3 /opt/casescope/scripts/cleanup_stale_locks.py >> /opt/casescope/logs/lock_cleanup.log 2>&1
```

**What it does:**
- Queries the database for case locks older than 2 hours
- Removes stale locks that may be left behind by crashed workers
- Logs results to stdout (redirect to log file in cron)

**When to use:**
- Set up as a cron job for automated maintenance
- Run manually if you suspect stale locks are preventing case access

## Adding New Scripts

When adding standalone utility scripts to this directory:
1. Add execution permissions: `chmod +x script_name.py`
2. Include proper shebang: `#!/usr/bin/env python3`
3. Add usage documentation in this README
4. Consider adding logging output for cron execution
5. Use absolute paths or `sys.path` to import from `/opt/casescope/app/`

## Script Guidelines

All scripts in this directory should:
- Be standalone executables (not imported as modules)
- Use the Flask app context when accessing database: `with app.app_context():`
- Log their actions for troubleshooting
- Handle errors gracefully
- Exit with proper exit codes (0 = success, non-zero = error)

---
*Last updated: December 17, 2025*

