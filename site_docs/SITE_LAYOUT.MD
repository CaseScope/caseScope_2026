# CaseScope 2026 - Site Layout & Organization

## File Naming Convention
**Pattern**: `Type_section_function.py`
- **Example**: `route_admin_users.py`, `task_ioc_hunt.py`, `model_case_file.py`
- **Purpose**: Immediately identify file type and purpose without opening it

## Directory Structure

### `/app` - Core Application
All Flask application code, models, configuration, and business logic.

**Key Files**:
- `main.py` - Flask app initialization, auto-loads blueprints from `/app/routes`
- `config.py` - **User-configurable settings** (web server port, SSL, database, session timeout)
- `models.py` - SQLAlchemy database models (User, Case, AuditLog)
- `audit_logger.py` - Reusable audit logging utility
- `init_db.py` - Database initialization script (creates tables, seeds default admin user)
- `wsgi.py` - Gunicorn WSGI entry point

### `/app/routes` - Flask Blueprints (Auto-loaded)
All route blueprints are automatically discovered and registered by `main.py`.

**Current Routes**:
- `auth.py` - Login/logout authentication routes
- `admin.py` - Administrator and analyst user management, audit log viewer
- `case.py` - Case management (create, edit, delete, select, dashboard)
- `dashboard.py` - Main dashboard with system stats and metrics API
- `search.py` - Event search system with boolean operators and file type filtering
- `upload.py` - File upload system (chunk-based upload, drag & drop)
- `settings.py` - System settings (Celery worker configuration, EVTX descriptions management)

**Adding New Routes**: Simply create a new file in `/app/routes` that exports a blueprint, and it will be auto-loaded on next server restart.

### `/static` - Static Assets
Frontend resources (CSS, JavaScript, images).

#### `/static/css` - Centralized Styling
- `main.css` - Global styles, CSS variables, color palette, typography
- (removed) `components.css` - Merged into main.css
- (removed) `layout.css` - Merged into main.css

**Philosophy**: All styling centralized in CSS files. **No inline styles**. **No `<style>` blocks in templates**. Modals and all UI components use consistent, reusable classes.

**CSS Architecture Compliance:**
- ✅ Zero inline styles in HTML (e.g., no `style="..."`)
- ✅ Zero `<style>` blocks in templates
- ✅ All styling in central `/static/css/main.css`
- ✅ Reusable classes with semantic names
- ✅ CSS variables for theme colors (`var(--color-primary)`, etc.)
- ✅ Utility classes for spacing (`.gap-2`, `.mb-0`, `.mt-1`, etc.)
- ✅ Component classes (`.progress`, `.progress-bar`, `.processing-card`, etc.)

**If you need to add styles:**
1. Never use inline `style="..."` attributes
2. Never add `<style>` blocks to templates
3. Always add to `/static/css/main.css`
4. Use existing CSS variables when possible
5. Follow existing naming conventions

#### `/static/js` - JavaScript
- `main.js` - Core utilities (formatNumber, formatFileSize, confirmAction, flash message handling)

### `/templates` - Jinja2 HTML Templates
All HTML templates using Jinja2 templating engine.

**Structure**:
- `base.html` - Base template with sidebar navigation, header, layout structure
- `index.html` - Dashboard/homepage with system stats
- `login.html` - Authentication page
- `error.html` - Generic error page
- `/templates/admin/` - Admin section pages:
  - `users.html` - User management (create, edit, delete users)
  - `settings.html` - System settings (Celery workers configuration)
  - `evtx_descriptions.html` - EVTX event descriptions management (scraping, viewing, searching)
  - `audit_log.html` - Audit trail viewer with detail modal
- `/templates/case/` - Case management pages:
  - `select.html` - Case selection page with table
  - `dashboard.html` - Case dashboard with details and edit modal
- `/templates/search/` - Event search pages:
  - `events.html` - Event search interface with file type filtering
- `/templates/upload/` - File upload pages:
  - `files.html` - File management UI with upload progress

### `/ai_prompts` - AI Model Prompts (User-Editable)
Template prompts for AI/LLM operations that end users can customize.

### `/bin` - External Executables
Binary tools and utilities (e.g., chainsaw, sigma tools).

### `/site_docs` - Documentation
Project documentation, architecture guides, database structure, implementation plans.

### `/migrations` - Database Migrations
SQL migration scripts for schema changes.

## Server Configuration

**Web Server**: Gunicorn with HTTPS support
- Port configurable in `app/config.py` (default: 443)
- SSL certificates configurable (default: self-signed at `/etc/ssl/certs/selfsigned.crt`)
- Start script: `start_server.sh` (dynamically reads config.py)

**Systemd Services**:
- `casescope-new.service` - Flask web application
- `casescope-celery.service` - Background task worker (if using Celery)

## Key Design Principles

1. **Modularity**: Each feature in its own file with clear naming
2. **Auto-loading**: Routes automatically discovered and registered
3. **Centralized Configuration**: One config file for all user-adjustable settings
4. **Centralized Styling**: All CSS in organized files, no inline styles
5. **User-Editable**: AI prompts and configuration exposed for customization
6. **Audit Everything**: Comprehensive logging of security-sensitive actions
