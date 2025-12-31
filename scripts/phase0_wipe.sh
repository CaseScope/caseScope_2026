#!/bin/bash
# PHASE 0: Complete Data Wipe
# Deletes ALL cases, OpenSearch indices, and files

echo "============================================================"
echo "PHASE 0: COMPLETE DATA WIPE"
echo "============================================================"
echo ""
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "WARNING: This will DELETE ALL case data permanently!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo ""
read -p "Type 'DELETE EVERYTHING' to confirm: " confirmation

if [ "$confirmation" != "DELETE EVERYTHING" ]; then
    echo ""
    echo "✗ Aborted. No changes made."
    exit 1
fi

echo ""
echo "✓ Confirmed. Beginning complete wipe..."
echo ""

# [1/8] Count existing data
echo "[1/8] Counting existing data..."
case_count=$(sudo -u postgres psql -d casescope -t -c "SELECT COUNT(*) FROM \"case\";" | tr -d ' ')
file_count=$(sudo -u postgres psql -d casescope -t -c "SELECT COUNT(*) FROM case_file;" | tr -d ' ')
task_count=$(sudo -u postgres psql -d casescope -t -c "SELECT COUNT(*) FROM active_tasks;" | tr -d ' ')
echo "  - Cases: $case_count"
echo "  - Files: $file_count"
echo "  - Active Tasks: $task_count"
echo ""

# [2/8] Get case IDs for OpenSearch cleanup
echo "[2/8] Getting case IDs for OpenSearch cleanup..."
case_ids=$(sudo -u postgres psql -d casescope -t -c "SELECT id FROM \"case\";" | tr -d ' ' | grep -v '^$')
if [ -z "$case_ids" ]; then
    echo "  - No cases found in database"
else
    echo "  - Case IDs: $case_ids"
fi
echo ""

# [3/8] Delete all case files from database
echo "[3/8] Deleting all case files from database..."
if [ "$file_count" -gt 0 ]; then
    sudo -u postgres psql -d casescope -c "DELETE FROM case_file;" > /dev/null
    echo "  ✓ Deleted $file_count case files"
else
    echo "  ✓ No case files to delete"
fi

# [4/8] Delete all cases from database
echo "[4/8] Deleting all cases from database..."
if [ "$case_count" -gt 0 ]; then
    sudo -u postgres psql -d casescope -c "DELETE FROM \"case\";" > /dev/null
    echo "  ✓ Deleted $case_count cases"
else
    echo "  ✓ No cases to delete"
fi

# [5/8] Clear active_tasks
echo "[5/8] Clearing active_tasks table..."
if [ "$task_count" -gt 0 ]; then
    sudo -u postgres psql -d casescope -c "DELETE FROM active_tasks;" > /dev/null
    echo "  ✓ Deleted $task_count active tasks"
else
    echo "  ✓ No active tasks to clear"
fi

# [6/8] Delete OpenSearch indices
echo "[6/8] Deleting OpenSearch indices..."
deleted_indices=0

# Get all case_* indices from OpenSearch
all_indices=$(curl -s 'http://localhost:9200/_cat/indices?format=json' | grep -o '"index":"case_[^"]*"' | cut -d'"' -f4 || true)

if [ -z "$all_indices" ]; then
    echo "  ✓ No OpenSearch indices found"
else
    for index_name in $all_indices; do
        curl -s -X DELETE "http://localhost:9200/${index_name}" > /dev/null
        echo "  ✓ Deleted index: $index_name"
        deleted_indices=$((deleted_indices + 1))
    done
    echo "  ✓ Deleted $deleted_indices OpenSearch indices"
fi

# [7/8] Delete filesystem directories
echo "[7/8] Deleting filesystem directories..."

# case_files (storage)
if [ -d "/opt/casescope/case_files" ]; then
    count=$(find /opt/casescope/case_files -mindepth 1 -maxdepth 1 | wc -l)
    sudo rm -rf /opt/casescope/case_files/*
    echo "  ✓ Deleted $count items from case_files/"
else
    echo "  ✓ case_files/ does not exist"
fi

# uploads/web
if [ -d "/opt/casescope/uploads/web" ]; then
    count=$(find /opt/casescope/uploads/web -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
    sudo rm -rf /opt/casescope/uploads/web/* 2>/dev/null || true
    echo "  ✓ Deleted $count items from uploads/web/"
else
    echo "  ✓ uploads/web/ does not exist"
fi

# uploads/sftp
if [ -d "/opt/casescope/uploads/sftp" ]; then
    count=$(find /opt/casescope/uploads/sftp -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
    sudo rm -rf /opt/casescope/uploads/sftp/* 2>/dev/null || true
    echo "  ✓ Deleted $count items from uploads/sftp/"
else
    echo "  ✓ uploads/sftp/ does not exist"
fi

# staging
if [ -d "/opt/casescope/staging" ]; then
    count=$(find /opt/casescope/staging -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
    sudo rm -rf /opt/casescope/staging/* 2>/dev/null || true
    echo "  ✓ Deleted $count items from staging/"
else
    echo "  ✓ staging/ does not exist"
fi

# [8/8] Log to audit trail
echo "[8/8] Logging to audit trail..."
sudo -u postgres psql -d casescope <<EOF > /dev/null
INSERT INTO audit_log (timestamp, user_id, username, action, resource_type, details, status)
VALUES (
    NOW(),
    NULL,
    'system',
    'phase0_complete_wipe',
    'system',
    '{"reason": "File upload redesign - NEW_FILE_UPLOAD.ND implementation", "phase": "PHASE 0", "wiped": ["database_cases", "database_files", "opensearch_indices", "case_files", "uploads", "staging"], "case_count": $case_count, "file_count": $file_count}',
    'success'
);
EOF
echo "  ✓ Logged complete wipe to audit trail"

echo ""
echo "============================================================"
echo "PHASE 0 COMPLETE: All data wiped successfully"
echo "============================================================"
echo ""
echo "Summary:"
echo "  - Cases deleted: $case_count"
echo "  - Files deleted: $file_count"
echo "  - OpenSearch indices deleted: $deleted_indices"
echo "  - Active tasks cleared: $task_count"
echo ""
echo "Ready for Phase 1: Database Migrations"
echo ""

