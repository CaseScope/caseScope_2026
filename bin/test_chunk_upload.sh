#!/bin/bash
# Quick test of chunk upload system

echo "=========================================="
echo "Chunk Upload System - Quick Test"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}1. Checking directories...${NC}"
for dir in upload_temp staging storage bulk_upload; do
    if [ -d "/opt/casescope/$dir" ]; then
        echo -e "  ${GREEN}✓${NC} /opt/casescope/$dir exists"
        ls -ld /opt/casescope/$dir | awk '{print "    " $1, $3, $4}'
    else
        echo -e "  ${RED}✗${NC} /opt/casescope/$dir missing"
    fi
done

echo ""
echo -e "${YELLOW}2. Checking Flask service...${NC}"
if systemctl is-active --quiet casescope-new.service; then
    echo -e "  ${GREEN}✓${NC} casescope-new.service is running"
else
    echo -e "  ${RED}✗${NC} casescope-new.service is not running"
fi

echo ""
echo -e "${YELLOW}3. Checking Celery workers...${NC}"
if systemctl is-active --quiet casescope-workers.service; then
    echo -e "  ${GREEN}✓${NC} casescope-workers.service is running"
    
    # Check worker count
    cd /opt/casescope/app
    source ../venv/bin/activate 2>/dev/null
    worker_count=$(celery -A celery_app.celery inspect stats 2>/dev/null | grep -c "celery@" || echo "0")
    if [ "$worker_count" -gt 0 ]; then
        echo -e "    ${GREEN}Active workers: $worker_count${NC}"
    fi
else
    echo -e "  ${RED}✗${NC} casescope-workers.service is not running"
fi

echo ""
echo -e "${YELLOW}4. Checking upload routes...${NC}"
cd /opt/casescope/app
source ../venv/bin/activate 2>/dev/null
python3 << 'PYEOF'
try:
    from routes.upload import upload_bp
    print(f"  \033[0;32m✓\033[0m Upload blueprint loaded")
    print(f"    Name: {upload_bp.name}")
    print(f"    URL prefix: {upload_bp.url_prefix}")
except Exception as e:
    print(f"  \033[0;31m✗\033[0m Failed to load: {e}")
PYEOF

echo ""
echo -e "${YELLOW}5. Checking parsers...${NC}"
python3 << 'PYEOF'
try:
    from parsers.evtx_parser import EVTX_AVAILABLE
    if EVTX_AVAILABLE:
        print(f"  \033[0;32m✓\033[0m EVTX parser (Rust) available")
    else:
        print(f"  \033[0;31m✗\033[0m EVTX parser not available")
except Exception as e:
    print(f"  \033[0;31m✗\033[0m Failed to load: {e}")

try:
    from opensearch_indexer import OpenSearchIndexer
    print(f"  \033[0;32m✓\033[0m OpenSearch indexer available")
    
    # Test connection
    indexer = OpenSearchIndexer()
    info = indexer.client.info()
    print(f"    OpenSearch version: {info['version']['number']}")
except Exception as e:
    print(f"  \033[0;33m⚠\033[0m OpenSearch: {str(e)[:50]}")
PYEOF

echo ""
echo "=========================================="
echo -e "${GREEN}System Check Complete!${NC}"
echo "=========================================="
echo ""
echo "To test chunk upload:"
echo "  1. Navigate to a case in the web UI"
echo "  2. Click 'Upload Files'"
echo "  3. Drag and drop or select a file"
echo "  4. Click 'Start Upload'"
echo "  5. Watch the progress bar"
echo ""
echo "Logs:"
echo "  Flask:  tail -f /opt/casescope/logs/error.log"
echo "  Celery: tail -f /opt/casescope/logs/celery_worker.log"
echo ""
