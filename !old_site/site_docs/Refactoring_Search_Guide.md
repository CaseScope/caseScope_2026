# CaseScope 2026 - Refactoring Search Guide
## How to Find All Entries That Need Adjustment

This guide provides **specific grep commands** to find every location that needs to be refactored, organized by priority.

---

## 🔍 Quick Reference Commands

```bash
# Run these from: /opt/casescope/app/

# Database query patterns
grep -rn "db.session.query(CaseFile)" --include="*.py" | wc -l  # Found: 70
grep -rn "is_deleted == False" --include="*.py" | wc -l         # Found: 32
grep -rn "is_hidden == False" --include="*.py" | wc -l          # Found: 21

# OpenSearch patterns
grep -rn "opensearch_client.search" --include="*.py" | wc -l    # Found: 19
grep -rn "opensearch_client.count" --include="*.py" | wc -l
grep -rn "opensearch_client.delete" --include="*.py" | wc -l

# Route patterns in main.py
grep -n "^@app.route" main.py | wc -l
grep -n "^def.*case_id" main.py | wc -l

# Template patterns
grep -rn "{% include 'components/pagination.html" templates/*.html | wc -l
grep -l "<div class=\"pagination\">" templates/*.html
grep -l "modal" templates/*.html
```

---

## 📋 Phase 1: Move Routes from main.py to Blueprints

### Step 1.1: Find ALL Routes in main.py

```bash
# List all routes with line numbers
grep -n "^@app.route" main.py

# Count routes
grep -c "^@app.route" main.py

# Export to file for reference
grep -n "^@app.route" main.py > /tmp/main_routes.txt
```

**What to look for**: Lines starting with `@app.route`

### Step 1.2: Identify Search Routes (Move to routes/search.py)

```bash
# Find all search-related routes
grep -n "@app.route.*search" main.py

# Specific patterns:
grep -n "/case/<int:case_id>/search" main.py
grep -n "/case/<int:case_id>/search/event" main.py
grep -n "/case/<int:case_id>/search/tag" main.py
grep -n "/case/<int:case_id>/search/bulk" main.py
grep -n "/case/<int:case_id>/search/hide" main.py
grep -n "/case/<int:case_id>/search/columns" main.py

# Get complete function definitions
grep -A 50 "@app.route.*search" main.py | grep -E "^def|^@app.route"
```

**Routes to move**:
```
Line 1737: /case/<int:case_id>/search
Line 1990: /case/<int:case_id>/search/export
Line 2113: /case/<int:case_id>/search/event/<event_id>
Line 2158: /case/<int:case_id>/search/tag
Line 2215: /case/<int:case_id>/search/untag
Line 2248: /case/<int:case_id>/search/hide
Line 2295: /case/<int:case_id>/search/unhide
Line 2331: /case/<int:case_id>/search/bulk-tag
Line 2398: /case/<int:case_id>/search/bulk-untag
Line 2563: /case/<int:case_id>/search/bulk-hide
Line 2596: /case/<int:case_id>/search/bulk-unhide
Line 2629: /case/<int:case_id>/search/columns
Line 2663: /case/<int:case_id>/search/history/<int:search_id>/favorite
```

### Step 1.3: Identify AI Routes (Move to routes/ai.py)

```bash
# Find all AI-related routes
grep -n "@app.route.*ai" main.py

# Specific patterns:
grep -n "/ai/status" main.py
grep -n "/ai/report" main.py
grep -n "/case/<int:case_id>/ai" main.py

# Export AI routes
grep -n "@app.route.*ai" main.py > /tmp/ai_routes.txt
```

**Routes to move**:
```
Line 724: /ai/status
Line 744: /case/<int:case_id>/ai/generate
Line 858: /ai/report/<int:report_id>/view
Line 908: /ai/report/<int:report_id> (GET)
Line 954: /ai/report/<int:report_id>/live-preview
Line 978: /ai/report/<int:report_id>/cancel
Line 1032: /ai/report/<int:report_id>/download
Line 1063: /ai/report/<int:report_id>/chat (POST)
Line 1160: /ai/report/<int:report_id>/chat (GET)
Line 1189: /ai/report/<int:report_id>/review
Line 1217: /ai/report/<int:report_id>/apply
Line 1258: /ai/report/<int:report_id> (DELETE)
Line 1291: /case/<int:case_id>/ai/reports
```

### Step 1.4: Identify EVTX Description Routes (Move to routes/evtx.py)

```bash
# Find EVTX description routes
grep -n "@app.route.*evtx_descriptions" main.py
grep -n "@app.route.*refresh_descriptions" main.py

# Export
grep -n "evtx_descriptions\|refresh_descriptions" main.py > /tmp/evtx_routes.txt
```

**Routes to move**:
```
Line 1317: /evtx_descriptions
Line 1449: /evtx_descriptions/update
Line 1493: /evtx_descriptions/custom
Line 1549: /evtx_descriptions/custom/<int:event_desc_id> (PUT)
Line 1597: /evtx_descriptions/custom/<int:event_desc_id> (DELETE)
Line 1643: /case/<int:case_id>/refresh_descriptions
Line 1668: /refresh_descriptions_global
```

### Step 1.5: Identify Case Routes (Move to routes/cases.py)

```bash
# Find case management routes (excluding search/ai)
grep -n "@app.route.*case" main.py | grep -v "search\|ai\|evtx"

# Specific patterns:
grep -n "@app.route('/case/<int:case_id>')" main.py
grep -n "@app.route('/cases')" main.py
grep -n "@app.route('/case/create')" main.py
```

**Routes to move**:
```
Line 545: /cases
Line 604: /case/create
Line 640: /case/<int:case_id>/status
Line 672: /case/<int:case_id>
```

### Step 1.6: Identify Auth Routes (Move to routes/auth.py)

```bash
# Find authentication routes
grep -n "@app.route('/login" main.py
grep -n "@app.route('/logout" main.py
grep -n "def login\|def logout" main.py
```

**Routes to move**:
```
Line 201: /login
Line 301: /logout
```

---

## 📋 Phase 2: Database Query Refactoring

### Step 2.1: Find All CaseFile Queries

```bash
# Find all CaseFile queries with context
grep -rn "db.session.query(CaseFile)" --include="*.py" -A 5

# Find specific patterns:
# Pattern 1: Status queries
grep -rn "CaseFile.indexing_status ==" --include="*.py"

# Pattern 2: Deleted/Hidden filters
grep -rn "CaseFile.is_deleted == False" --include="*.py"
grep -rn "CaseFile.is_hidden == False" --include="*.py"

# Pattern 3: Case filtering
grep -rn "CaseFile.case_id ==" --include="*.py"

# Generate complete list with file locations
grep -rn "db.session.query(CaseFile)" --include="*.py" > /tmp/casefile_queries.txt
```

**Files with most CaseFile queries**:
```bash
# Count by file
grep -rn "db.session.query(CaseFile)" --include="*.py" | cut -d: -f1 | sort | uniq -c | sort -rn
```

### Step 2.2: Find File Statistics Patterns

This is the MOST duplicated pattern - appears in many files.

```bash
# Find the complete statistics query pattern
grep -rn "indexing_status == 'Completed'" --include="*.py" -B 2 -A 2

# Find count() calls
grep -rn "\.count()" --include="*.py" | grep -i "casefile"

# Find specific files that calculate stats
grep -rn "completed.*queued.*failed" --include="*.py"

# Export locations
grep -rn "indexing_status == 'Completed'\|indexing_status == 'Queued'" --include="*.py" > /tmp/stats_queries.txt
```

**Common pattern to replace**:
```python
# THIS PATTERN (appears in many files):
completed = db.session.query(CaseFile).filter(
    CaseFile.case_id == case_id,
    CaseFile.indexing_status == 'Completed',
    CaseFile.is_deleted == False,
    CaseFile.is_hidden == False
).count()
```

### Step 2.3: Find IOC Queries

```bash
# Find IOC queries
grep -rn "db.session.query(IOC)" --include="*.py"
grep -rn "IOC.case_id" --include="*.py"
grep -rn "IOC.is_active" --include="*.py"

# Count by file
grep -rn "db.session.query(IOC)" --include="*.py" | cut -d: -f1 | sort | uniq -c | sort -rn
```

### Step 2.4: Find Case Queries

```bash
# Find Case queries
grep -rn "db.session.get(Case," --include="*.py"
grep -rn "db.session.query(Case)" --include="*.py"

# Find None checks (should be handled by decorator)
grep -rn "if not case:" --include="*.py" -A 2

# Export
grep -rn "db.session.get(Case," --include="*.py" > /tmp/case_queries.txt
```

---

## 📋 Phase 3: OpenSearch Query Refactoring

### Step 3.1: Find All OpenSearch Search Calls

```bash
# Find all search operations
grep -rn "opensearch_client.search" --include="*.py"

# With context (shows the query being built)
grep -rn "opensearch_client.search" --include="*.py" -B 20 -A 5

# Export with context
grep -rn "opensearch_client.search" --include="*.py" -B 20 > /tmp/opensearch_searches.txt
```

**Locations found**:
```
file_processing.py: 2 instances
login_analysis.py: 5 instances
search_utils.py: 2 instances
tasks.py: 2 instances
main.py: 8 instances
```

### Step 3.2: Find Query Construction Patterns

```bash
# Find query dict construction
grep -rn "body.*query" --include="*.py" | grep -i "opensearch"

# Find bool queries
grep -rn "\"bool\"" --include="*.py" -A 5

# Find must/must_not/should
grep -rn "\"must\":" --include="*.py"
grep -rn "\"must_not\":" --include="*.py"
grep -rn "\"should\":" --include="*.py"

# Find term queries
grep -rn "\"term\":" --include="*.py"
grep -rn "\"terms\":" --include="*.py"

# Export all query patterns
grep -rn "\"query\":" --include="*.py" -A 10 > /tmp/opensearch_query_patterns.txt
```

### Step 3.3: Find Count/Delete/Update Operations

```bash
# Count operations
grep -rn "opensearch_client.count" --include="*.py"

# Delete operations
grep -rn "opensearch_client.delete" --include="*.py"

# Update operations
grep -rn "opensearch_client.update" --include="*.py"

# Bulk operations
grep -rn "opensearch_client.bulk" --include="*.py"

# Index operations
grep -rn "opensearch_client.index" --include="*.py"
```

---

## 📋 Phase 4: Template Refactoring

### Step 4.1: Find Pagination Code

```bash
# Find templates with pagination HTML
grep -l "pagination" templates/*.html

# Find the old pattern (should be replaced)
grep -l "<div class=\"pagination\">" templates/*.html

# Find templates already using the component
grep -l "{% include 'components/pagination.html" templates/*.html

# Export list of templates needing update
grep -l "<div class=\"pagination\">" templates/*.html > /tmp/pagination_templates.txt

# Show the pagination code context
grep -rn "<div class=\"pagination\">" templates/*.html -A 10
```

**Templates that need pagination component**:
```bash
cd /home/claude/caseScope_2026/app/templates
grep -l "Page.*of.*items" *.html
```

### Step 4.2: Find Modal Dialogs

```bash
# Find templates with modals
grep -l "modal" templates/*.html

# Find modal structures
grep -rn "class=\"modal\"" templates/*.html

# Find modal-specific patterns
grep -rn "modal-content\|modal-header\|modal-footer" templates/*.html

# Count modals per file
for file in templates/*.html; do
  count=$(grep -c "class=\"modal\"" "$file" 2>/dev/null || echo 0)
  if [ "$count" -gt 0 ]; then
    echo "$count modals in $file"
  fi
done
```

### Step 4.3: Find Table Patterns

```bash
# Find tables
grep -l "<table" templates/*.html

# Find table headers
grep -rn "<thead>" templates/*.html

# Find checkbox selections in tables
grep -rn "select-all" templates/*.html

# Find sortable tables
grep -rn "sortable" templates/*.html

# Export
grep -rn "<table class=" templates/*.html > /tmp/table_templates.txt
```

### Step 4.4: Find Stat Cards

```bash
# Find stat card patterns
grep -rn "stat-card\|stat-number\|stat-label" templates/*.html

# Find specific stat patterns
grep -rn "<div class=\"stat" templates/*.html -A 5

# Count by file
grep -rn "stat-card" templates/*.html | cut -d: -f1 | sort | uniq -c | sort -rn

# Export with context
grep -rn "stat-card" templates/*.html -B 2 -A 5 > /tmp/stat_cards.txt
```

---

## 📋 Phase 5: JavaScript Refactoring

### Step 5.1: Find File Selection Logic

```bash
# Find select-all event listeners
grep -rn "select-all.*addEventListener" templates/*.html

# Find checkbox selection patterns
grep -rn "\.querySelectorAll.*file-select" templates/*.html

# Find updateBulkActionButtons functions
grep -rn "function updateBulkActionButtons" templates/*.html

# Export
grep -rn "select-all.*addEventListener\|updateBulkActionButtons" templates/*.html > /tmp/file_selection_js.txt
```

**Templates with file selection**:
```bash
grep -l "select-all" templates/*.html
```

### Step 5.2: Find Modal JavaScript

```bash
# Find modal show/hide functions
grep -rn "function showModal\|function hideModal" templates/*.html

# Find modal event listeners
grep -rn "modal-close.*addEventListener\|modal-cancel.*addEventListener" templates/*.html

# Export
grep -rn "showModal\|hideModal\|modal.*addEventListener" templates/*.html > /tmp/modal_js.txt
```

### Step 5.3: Find API Call Patterns

```bash
# Find fetch calls
grep -rn "fetch(" templates/*.html

# Find async functions with fetch
grep -rn "async function.*{" templates/*.html -A 10 | grep "fetch"

# Find error handling
grep -rn "try.*fetch\|catch.*error" templates/*.html

# Count fetch calls per template
for file in templates/*.html; do
  count=$(grep -c "fetch(" "$file" 2>/dev/null || echo 0)
  if [ "$count" -gt 0 ]; then
    echo "$count fetch calls in $file"
  fi
done > /tmp/fetch_counts.txt
```

### Step 5.4: Find Duplicate Functions

```bash
# Find common function names (likely duplicated)
grep -rn "^function\|^    function" templates/*.html | cut -d: -f2 | sort | uniq -c | sort -rn | head -20

# Find specific common patterns
grep -rn "function confirmDelete" templates/*.html
grep -rn "function reloadPage" templates/*.html
grep -rn "function showNotification" templates/*.html
```

---

## 🔧 Automated Search Scripts

### Script 1: Generate Complete Refactoring Report

```bash
#!/bin/bash
# save as: generate_refactoring_report.sh

OUTPUT_DIR="/tmp/refactoring_analysis"
mkdir -p "$OUTPUT_DIR"

echo "Generating refactoring analysis..."

# Routes in main.py
echo "=== ROUTES IN MAIN.PY ===" > "$OUTPUT_DIR/routes_report.txt"
grep -n "^@app.route" main.py >> "$OUTPUT_DIR/routes_report.txt"

# Database queries
echo "=== DATABASE QUERIES ===" > "$OUTPUT_DIR/db_queries_report.txt"
grep -rn "db.session.query(CaseFile)" --include="*.py" | cut -d: -f1 | sort | uniq -c | sort -rn >> "$OUTPUT_DIR/db_queries_report.txt"

# OpenSearch operations
echo "=== OPENSEARCH OPERATIONS ===" > "$OUTPUT_DIR/opensearch_report.txt"
grep -rn "opensearch_client\." --include="*.py" | grep -E "search|count|delete|update" >> "$OUTPUT_DIR/opensearch_report.txt"

# Template patterns
echo "=== TEMPLATE PATTERNS ===" > "$OUTPUT_DIR/template_report.txt"
echo "Pagination:" >> "$OUTPUT_DIR/template_report.txt"
grep -l "pagination" templates/*.html >> "$OUTPUT_DIR/template_report.txt"
echo -e "\nModals:" >> "$OUTPUT_DIR/template_report.txt"
grep -l "modal" templates/*.html >> "$OUTPUT_DIR/template_report.txt"

# JavaScript patterns
echo "=== JAVASCRIPT PATTERNS ===" > "$OUTPUT_DIR/javascript_report.txt"
echo "Fetch calls:" >> "$OUTPUT_DIR/javascript_report.txt"
for file in templates/*.html; do
  count=$(grep -c "fetch(" "$file" 2>/dev/null || echo 0)
  if [ "$count" -gt 0 ]; then
    echo "$count: $file" >> "$OUTPUT_DIR/javascript_report.txt"
  fi
done

echo "Reports generated in $OUTPUT_DIR/"
ls -lh "$OUTPUT_DIR/"
```

### Script 2: Find Specific Refactoring Targets

```bash
#!/bin/bash
# save as: find_refactoring_targets.sh

PATTERN="$1"
TYPE="$2"

case "$TYPE" in
  "route")
    grep -n "^@app.route.*$PATTERN" main.py
    ;;
  "db")
    grep -rn "$PATTERN" --include="*.py"
    ;;
  "opensearch")
    grep -rn "opensearch_client.*$PATTERN" --include="*.py"
    ;;
  "template")
    grep -rn "$PATTERN" templates/*.html
    ;;
  *)
    echo "Usage: $0 <pattern> <type>"
    echo "Types: route, db, opensearch, template"
    ;;
esac
```

### Script 3: Count Refactoring Opportunities

```bash
#!/bin/bash
# save as: count_refactoring_opportunities.sh

echo "=== REFACTORING OPPORTUNITY COUNTS ==="
echo

echo "Routes in main.py:"
grep -c "^@app.route" main.py

echo -e "\nCaseFile database queries:"
grep -rn "db.session.query(CaseFile)" --include="*.py" | wc -l

echo -e "\nOpenSearch search operations:"
grep -rn "opensearch_client.search" --include="*.py" | wc -l

echo -e "\nTemplates with pagination:"
grep -l "pagination" templates/*.html | wc -l

echo -e "\nTemplates with modals:"
grep -l "modal" templates/*.html | wc -l

echo -e "\nTemplates with fetch calls:"
grep -l "fetch(" templates/*.html | wc -l

echo -e "\nFile selection patterns:"
grep -rn "select-all.*addEventListener" templates/*.html | wc -l
```

---

## 📝 Step-by-Step Refactoring Process

### Example: Refactoring a Single Route

**1. Find the route:**
```bash
grep -n "@app.route('/case/<int:case_id>/search')" main.py
# Result: Line 1737
```

**2. Extract the complete function:**
```bash
# Get route decorator + function definition + body
sed -n '1737,1989p' main.py > /tmp/search_route.txt
```

**3. Identify dependencies:**
```bash
# Find imports used in the function
grep "^from\|^import" /tmp/search_route.txt

# Find database models used
grep -o "db\.session\.[^(]*\|[A-Z][a-z]*\.[a-z_]*" /tmp/search_route.txt | sort -u

# Find OpenSearch operations
grep "opensearch_client" /tmp/search_route.txt
```

**4. Move to blueprint:**
- Copy function to `routes/search.py`
- Change `@app.route` to `@search_bp.route`
- Add required imports
- Test

**5. Verify removal:**
```bash
# Check main.py no longer has this route
grep -n "def search_events" main.py
# Should return nothing
```

---

## 🎯 Priority Targets (Quick Wins)

### Immediate Actions - Can Do in 1 Hour Each

#### 1. Replace Pagination (Easiest - 15 minutes)

```bash
# Find templates NOT using component
comm -23 \
  <(grep -l "pagination" templates/*.html | sort) \
  <(grep -l "{% include 'components/pagination.html" templates/*.html | sort)

# For each template:
# REPLACE:
#   <div class="pagination">...entire pagination block...</div>
# WITH:
#   {% include 'components/pagination.html' %}
```

#### 2. Move Login/Logout Routes (30 minutes)

```bash
# Find the routes
grep -n "def login\|def logout" main.py

# Extract lines 201-300
sed -n '201,300p' main.py > /tmp/auth_routes.txt

# Move to routes/auth.py
# Change @app.route to @auth_bp.route
```

#### 3. Create OpenSearch Helper for File Events (1 hour)

```bash
# Find all file event queries
grep -rn "file_id.*opensearch" --include="*.py" -B 5 -A 5

# Create helper function that replaces these 15+ lines with 1 line
```

---

## 📊 Generate Statistics

### Count Refactoring Impact

```bash
# Count lines before
wc -l main.py routes/*.py templates/*.html

# After moving routes, count again
wc -l main.py routes/*.py

# Calculate reduction
echo "Main.py reduction: $(( $(wc -l < main.py.backup) - $(wc -l < main.py) )) lines"
```

---

## 🚀 Recommended Order

1. **Run count script first** to establish baseline
2. **Generate refactoring report** to see all targets
3. **Start with routes** (most isolated, safest)
4. **Then templates** (pagination, modals - many files, small changes)
5. **Then database helpers** (more complex, but high impact)
6. **Finally OpenSearch** (most complex, but biggest win)

---

## ⚠️ Before Making Changes

```bash
# Create backup
cp -r /opt/casescope/app /opt/casescope/app.backup.$(date +%Y%m%d)

# Create git branch (if using git)
git checkout -b refactoring-phase1

# Run tests
python -m pytest tests/

# Take note of current line counts
find . -name "*.py" -o -name "*.html" | xargs wc -l > /tmp/before_refactor.txt
```

---

## 📈 Track Progress

```bash
# Create progress tracker
cat > /tmp/refactoring_progress.txt << 'EOF'
PHASE 1: Move Routes
[ ] Search routes (13 routes)
[ ] AI routes (13 routes)
[ ] EVTX routes (7 routes)
[ ] Case routes (4 routes)
[ ] Auth routes (2 routes)

PHASE 2: Templates
[ ] Pagination (15 templates)
[ ] Modals (20 templates)
[ ] Stat cards (10 templates)
[ ] Tables (12 templates)

PHASE 3: Database Helpers
[ ] CaseFile queries (70 instances)
[ ] IOC queries (30 instances)
[ ] Case queries (25 instances)

PHASE 4: OpenSearch Helpers
[ ] Search operations (19 instances)
[ ] Count operations (? instances)
[ ] Delete operations (? instances)
EOF

# Update as you complete each item
```

Would you like me to create the actual helper files (opensearch_helpers.py, db_helpers.py, etc.) or start with moving specific routes?
