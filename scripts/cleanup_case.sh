#!/bin/bash
###############################################################################
# CaseScope Case Cleanup Script
# Resets a case to clean state (removes all files, events, and database records)
###############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root (use sudo)${NC}" 
   exit 1
fi

# Get case ID from argument or prompt
if [ -z "$1" ]; then
    echo -e "${YELLOW}Enter Case ID to clean:${NC}"
    read -p "Case ID: " CASE_ID
else
    CASE_ID=$1
fi

# Validate case ID is a number
if ! [[ "$CASE_ID" =~ ^[0-9]+$ ]]; then
    echo -e "${RED}Error: Case ID must be a number${NC}"
    exit 1
fi

# Verify case exists in database
echo -e "${YELLOW}Verifying case ${CASE_ID} exists...${NC}"
CASE_EXISTS=$(sudo -u postgres psql -d casescope -t -c "SELECT COUNT(*) FROM \"case\" WHERE id = ${CASE_ID};" 2>/dev/null | tr -d ' ')

if [ "$CASE_EXISTS" = "0" ]; then
    echo -e "${RED}Error: Case ${CASE_ID} does not exist in database${NC}"
    exit 1
fi

# Get case name
CASE_NAME=$(sudo -u postgres psql -d casescope -t -c "SELECT name FROM \"case\" WHERE id = ${CASE_ID};" 2>/dev/null | xargs)
echo -e "${GREEN}Found case: ${CASE_NAME}${NC}"

# Show current stats
echo ""
echo -e "${YELLOW}Current Stats for Case ${CASE_ID}:${NC}"
DB_COUNT=$(sudo -u postgres psql -d casescope -t -c "SELECT COUNT(*) FROM case_file WHERE case_id = ${CASE_ID};" 2>/dev/null | tr -d ' ')
OS_COUNT=$(curl -s http://localhost:9200/case_${CASE_ID}/_count 2>/dev/null | grep -oP '(?<="count":)\d+' || echo "0")
STORAGE_COUNT=$(ls /opt/casescope/storage/case_${CASE_ID}/ 2>/dev/null | wc -l)
STAGING_COUNT=$(ls /opt/casescope/staging/${CASE_ID}/ 2>/dev/null | wc -l)

echo "  Database records: ${DB_COUNT}"
echo "  OpenSearch events: ${OS_COUNT}"
echo "  Storage files: ${STORAGE_COUNT}"
echo "  Staging files: ${STAGING_COUNT}"
echo ""

# Confirm cleanup
echo -e "${RED}WARNING: This will permanently delete:${NC}"
echo "  - ${DB_COUNT} database records"
echo "  - ${OS_COUNT} OpenSearch events"
echo "  - ${STORAGE_COUNT} files from storage"
echo "  - ${STAGING_COUNT} files from staging"
echo ""
echo -e "${YELLOW}The case record itself will be preserved.${NC}"
echo ""
read -p "Are you sure you want to continue? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo -e "${YELLOW}Cleanup cancelled${NC}"
    exit 0
fi

echo ""
echo -e "${GREEN}=== Starting Case ${CASE_ID} Cleanup ===${NC}"
echo ""

# 1. Stop Celery workers
echo -e "${YELLOW}[1/6] Stopping Celery workers...${NC}"
systemctl stop casescope-workers
sleep 2
echo -e "${GREEN}✓ Workers stopped${NC}"

# 2. Delete database records
echo -e "${YELLOW}[2/6] Deleting database records...${NC}"
DELETED_ROWS=$(sudo -u postgres psql -d casescope -t -c "DELETE FROM case_file WHERE case_id = ${CASE_ID}; SELECT ROW_COUNT();" 2>/dev/null | tail -1 | tr -d ' ')
echo -e "${GREEN}✓ Deleted ${DELETED_ROWS} database records${NC}"

# 3. Delete OpenSearch index
echo -e "${YELLOW}[3/6] Deleting OpenSearch index...${NC}"
OS_RESPONSE=$(curl -s -X DELETE "http://localhost:9200/case_${CASE_ID}?ignore_unavailable=true" 2>/dev/null)
if echo "$OS_RESPONSE" | grep -q '"acknowledged":true'; then
    echo -e "${GREEN}✓ OpenSearch index deleted${NC}"
else
    echo -e "${YELLOW}! Index may not exist or already deleted${NC}"
fi

# 4. Delete filesystem storage
echo -e "${YELLOW}[4/6] Deleting storage files...${NC}"
STORAGE_PATH="/opt/casescope/storage/case_${CASE_ID}"
STAGING_PATH="/opt/casescope/staging/${CASE_ID}"
TEMP_PATH="/opt/casescope/upload_temp/${CASE_ID}"

if [ -d "$STORAGE_PATH" ]; then
    rm -rf "$STORAGE_PATH"
    echo -e "${GREEN}✓ Storage files deleted: ${STORAGE_PATH}${NC}"
else
    echo -e "${YELLOW}! Storage directory doesn't exist${NC}"
fi

if [ -d "$STAGING_PATH" ]; then
    rm -rf "$STAGING_PATH"
    echo -e "${GREEN}✓ Staging files deleted: ${STAGING_PATH}${NC}"
else
    echo -e "${YELLOW}! Staging directory doesn't exist${NC}"
fi

if [ -d "$TEMP_PATH" ]; then
    rm -rf "$TEMP_PATH"
    echo -e "${GREEN}✓ Temp files deleted: ${TEMP_PATH}${NC}"
else
    echo -e "${YELLOW}! Temp directory doesn't exist${NC}"
fi

# 5. Optional: Purge Celery tasks
echo -e "${YELLOW}[5/6] Celery task cleanup...${NC}"
read -p "Purge ALL Celery tasks (affects all cases)? (yes/no): " PURGE_CELERY
if [ "$PURGE_CELERY" = "yes" ]; then
    cd /opt/casescope
    sudo -u casescope bash -c 'source venv/bin/activate && celery -A celery_worker purge -f' 2>/dev/null || true
    echo -e "${GREEN}✓ Celery tasks purged${NC}"
else
    echo -e "${YELLOW}! Skipping Celery purge${NC}"
fi

# 6. Restart services
echo -e "${YELLOW}[6/6] Restarting services...${NC}"
systemctl start casescope-workers
sleep 2
echo -e "${GREEN}✓ Workers restarted${NC}"

# Verify cleanup
echo ""
echo -e "${GREEN}=== Cleanup Complete ===${NC}"
echo ""
echo -e "${YELLOW}Verification:${NC}"
FINAL_DB=$(sudo -u postgres psql -d casescope -t -c "SELECT COUNT(*) FROM case_file WHERE case_id = ${CASE_ID};" 2>/dev/null | tr -d ' ')
FINAL_OS=$(curl -s http://localhost:9200/case_${CASE_ID}/_count 2>/dev/null | grep -oP '(?<="count":)\d+' || echo "0")
FINAL_STORAGE=$(ls /opt/casescope/storage/case_${CASE_ID}/ 2>/dev/null | wc -l)
FINAL_STAGING=$(ls /opt/casescope/staging/${CASE_ID}/ 2>/dev/null | wc -l)

echo "  Database records: ${FINAL_DB} (expected: 0)"
echo "  OpenSearch events: ${FINAL_OS} (expected: 0)"
echo "  Storage files: ${FINAL_STORAGE} (expected: 0)"
echo "  Staging files: ${FINAL_STAGING} (expected: 0)"
echo ""

if [ "$FINAL_DB" = "0" ] && [ "$FINAL_OS" = "0" ] && [ "$FINAL_STORAGE" = "0" ] && [ "$FINAL_STAGING" = "0" ]; then
    echo -e "${GREEN}✓ Case ${CASE_ID} successfully reset to clean state${NC}"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "  1. Navigate to: https://your-server/case/${CASE_ID}/files"
    echo "  2. Verify all stats show 0"
    echo "  3. Re-upload files if needed"
else
    echo -e "${YELLOW}! Some data may remain. Check manually.${NC}"
fi

echo ""
echo -e "${GREEN}Done!${NC}"

