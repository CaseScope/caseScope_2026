# main.py Refactoring Plan

**Created**: November 26, 2025  
**Status**: Proposed  
**Current State**: `main.py` = 5,049 lines with 73 routes

---

## Problem Statement

`main.py` is too large (5,049 lines) and mixes multiple concerns. It should be modular like the existing 15 blueprints in `routes/`.

---

## Proposed New Blueprint Structure

### 1. `routes/search.py` (NEW) - ~1,200 lines

Move all search-related routes:

| Route | Function | Lines |
|-------|----------|-------|
| `/case/<id>/search` | `search_events()` | 270 |
| `/case/<id>/search/export` | `export_search_results()` | 120 |
| `/case/<id>/search/event/<id>` | `get_event_detail_route()` | 45 |
| `/case/<id>/search/tag` | `tag_timeline_event()` | 55 |
| `/case/<id>/search/untag` | `untag_timeline_event()` | 30 |
| `/case/<id>/search/hide` | `hide_event()` | 45 |
| `/case/<id>/search/unhide` | `unhide_event()` | 35 |
| `/case/<id>/search/bulk-tag` | `bulk_tag_events()` | 65 |
| `/case/<id>/search/bulk-untag` | `bulk_untag_events()` | 50 |
| `/case/<id>/search/bulk-hide` | `bulk_hide_events()` | 35 |
| `/case/<id>/search/bulk-unhide` | `bulk_unhide_events()` | 35 |
| `/case/<id>/search/columns` | `update_search_columns()` | 30 |
| `/case/<id>/search/add_ioc` | `add_field_as_ioc()` | 55 |
| `/case/<id>/search/bulk_add_iocs` | `bulk_add_iocs()` | 70 |
| `/case/<id>/search/history/*/favorite` | `toggle_search_favorite()` | 20 |
| `/search/saved/*` | 4 routes | 120 |
| Helper: `bulk_update_hidden_status()` | | 45 |

**Total: ~1,200 lines**

---

### 2. `routes/ai_reports.py` (NEW) - ~600 lines

Move all AI report routes (distinct from AI Question/RAG in `routes/ai_search.py`):

| Route | Function | Lines |
|-------|----------|-------|
| `/ai/status` | `ai_status()` | 20 |
| `/case/<id>/ai/generate` | `generate_ai_report()` | 110 |
| `/ai/report/<id>/view` | `view_ai_report()` | 50 |
| `/ai/report/<id>` | `get_ai_report()` | 45 |
| `/ai/report/<id>/live-preview` | `get_ai_report_live_preview()` | 25 |
| `/ai/report/<id>/cancel` | `cancel_ai_report()` | 50 |
| `/ai/report/<id>/download` | `download_ai_report()` | 30 |
| `/ai/report/<id>/chat` (POST) | `ai_report_chat()` | 95 |
| `/ai/report/<id>/chat` (GET) | `get_ai_report_chat_history()` | 30 |
| `/ai/report/<id>/review` | `get_ai_report_review()` | 25 |
| `/ai/report/<id>/apply` | `apply_ai_chat_refinement()` | 40 |
| `/ai/report/<id>` (DELETE) | `delete_ai_report()` | 30 |
| `/case/<id>/ai/reports` | `list_ai_reports()` | 25 |

**Total: ~600 lines**

---

### 3. `routes/login_analysis.py` (NEW) - ~600 lines

Move specialized login analysis routes:

| Route | Function | Lines |
|-------|----------|-------|
| `/case/<id>/search/logins-ok` | `show_logins_ok()` | 75 |
| `/case/<id>/search/logins-failed` | `show_logins_failed()` | 75 |
| `/case/<id>/search/rdp-connections` | `show_rdp_connections()` | 75 |
| `/case/<id>/search/console-logins` | `show_console_logins()` | 75 |
| `/case/<id>/search/vpn-authentications` | `show_vpn_authentications()` | 80 |
| `/case/<id>/search/vpn-failed-attempts` | `show_failed_vpn_attempts()` | 80 |

**Total: ~600 lines**

---

### 4. `routes/evtx.py` (NEW) - ~350 lines

Move EVTX description management:

| Route | Function | Lines |
|-------|----------|-------|
| `/evtx_descriptions` | `evtx_descriptions()` | 130 |
| `/evtx_descriptions/update` | `evtx_descriptions_update()` | 45 |
| `/evtx_descriptions/custom` (POST) | `create_custom_event()` | 55 |
| `/evtx_descriptions/custom/<id>` (PUT) | `update_custom_event()` | 45 |
| `/evtx_descriptions/custom/<id>` (DELETE) | `delete_custom_event()` | 45 |
| `/case/<id>/refresh_descriptions` | `refresh_descriptions_case_route()` | 25 |
| `/refresh_descriptions_global` | `refresh_descriptions_global_route()` | 25 |

**Total: ~350 lines**

---

### 5. `routes/bulk_case_ops.py` (NEW) - ~500 lines

Move case-level bulk operations:

| Route | Function | Lines |
|-------|----------|-------|
| `/case/<id>/clear_files` | `clear_all_files()` | 150 |
| `/case/<id>/bulk_reindex` | `bulk_reindex_route()` | 130 |
| `/case/<id>/bulk_rechainsaw` | `bulk_rechainsaw_route()` | 35 |
| `/case/<id>/bulk_rehunt_iocs` | `bulk_rehunt_iocs_route()` | 35 |
| `/case/<id>/bulk_delete_files` | `bulk_delete_files()` | 100 |
| `/case/<id>/rehunt_iocs` | `rehunt_iocs()` | 50 |

**Total: ~500 lines**

---

### 6. Routes to Keep in `main.py` - ~800 lines

Core application routes that belong in main:

| Route | Function | Reason |
|-------|----------|--------|
| `/login`, `/logout` | Auth | Core app |
| `/`, `/cases` | Dashboard, case list | Core app |
| `/case/create` | Create case | Core app |
| `/case/<id>` | View case | Core app |
| `/select_case/<id>`, `/clear_case` | Session | Core app |
| `/case/<id>/unlock`, `/lock_status`, `/heartbeat` | Locking | Core app |
| `/health/*` | Health checks | Core app |
| `/queue/*` | Queue management | Core app |
| `/sigma` | SIGMA page | Simple redirect |
| `/case/<id>/upload*` | Upload | Core app |
| `/search-instructions` | Static page | Simple |

---

## Summary

| Component | Current Lines | After Refactor |
|-----------|---------------|----------------|
| `main.py` | 5,049 | ~800 |
| `routes/search.py` (NEW) | 0 | ~1,200 |
| `routes/ai_reports.py` (NEW) | 0 | ~600 |
| `routes/login_analysis.py` (NEW) | 0 | ~600 |
| `routes/evtx.py` (NEW) | 0 | ~350 |
| `routes/bulk_case_ops.py` (NEW) | 0 | ~500 |
| **Total** | **5,049** | **~4,050** |

**Benefits**:
- `main.py` reduced by **84%** (5,049 → 800 lines)
- Each blueprint has a single responsibility
- Easier to test, maintain, and debug
- Follows existing blueprint pattern (15 blueprints already exist)

---

## Implementation Order

### Phase 1 (Highest Impact)
1. `routes/search.py` - Largest chunk, most complex

### Phase 2 (Medium Impact)
2. `routes/ai_reports.py` - Self-contained AI report functionality
3. `routes/login_analysis.py` - Specialized analysis routes

### Phase 3 (Cleanup)
4. `routes/evtx.py` - EVTX description management
5. `routes/bulk_case_ops.py` - Case bulk operations

---

## Implementation Notes

### Blueprint Template

```python
"""
[Blueprint Name] - [Description]
Extracted from main.py during refactoring
"""

from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user
import logging

logger = logging.getLogger(__name__)

[name]_bp = Blueprint('[name]', __name__)


@[name]_bp.route('/...')
@login_required
def route_function():
    # Import dependencies inside function to avoid circular imports
    from main import db, opensearch_client
    from models import Case, CaseFile
    ...
```

### Registration in main.py

```python
# In main.py, after other blueprint imports:
from routes.search import search_bp
from routes.ai_reports import ai_reports_bp
from routes.login_analysis import login_analysis_bp
from routes.evtx import evtx_bp
from routes.bulk_case_ops import bulk_case_ops_bp

# Register blueprints
app.register_blueprint(search_bp)
app.register_blueprint(ai_reports_bp)
app.register_blueprint(login_analysis_bp)
app.register_blueprint(evtx_bp)
app.register_blueprint(bulk_case_ops_bp)
```

### Testing After Each Phase

1. Restart services: `sudo systemctl restart casescope casescope-worker`
2. Test affected routes manually
3. Check logs for errors: `tail -f /opt/casescope/logs/app.log`
4. Commit and push after each successful phase

---

## Related Files

- Existing blueprints: `app/routes/*.py` (15 files)
- Main app: `app/main.py` (5,049 lines)
- Models: `app/models.py` (540 lines)

---

## Notes

- This refactoring does NOT change functionality, only organization
- All routes will work exactly the same after refactoring
- Circular import issues are avoided by importing inside functions
- Each phase can be done independently

