#!/bin/bash
# CaseScope Service Status Checker

echo "=========================================="
echo "CaseScope 2026 - Service Status"
echo "=========================================="
echo ""

# Check Flask
if systemctl is-active --quiet casescope-new.service; then
    echo "✓ Flask Web App: Running"
else
    echo "✗ Flask Web App: Stopped"
fi

# Check Celery Workers
if systemctl is-active --quiet casescope-workers.service; then
    echo "✓ Celery Workers: Running"
else
    echo "✗ Celery Workers: Stopped"
fi

# Check Redis
if systemctl is-active --quiet redis.service; then
    echo "✓ Redis: Running"
else
    echo "✗ Redis: Stopped"
fi

# Check PostgreSQL
if systemctl is-active --quiet postgresql.service; then
    echo "✓ PostgreSQL: Running"
else
    echo "✗ PostgreSQL: Stopped"
fi

# Check OpenSearch
if systemctl is-active --quiet opensearch.service 2>/dev/null; then
    echo "✓ OpenSearch: Running"
elif curl -s localhost:9200 >/dev/null 2>&1; then
    echo "✓ OpenSearch: Running (non-systemd)"
else
    echo "✗ OpenSearch: Stopped"
fi

echo ""
echo "=========================================="
echo "Task Queue Status"
echo "=========================================="
echo ""

# Check queue lengths
if redis-cli ping >/dev/null 2>&1; then
    fp_queue=$(redis-cli LLEN file_processing 2>/dev/null || echo "0")
    ing_queue=$(redis-cli LLEN ingestion 2>/dev/null || echo "0")
    def_queue=$(redis-cli LLEN default 2>/dev/null || echo "0")
    
    echo "File Processing Queue: $fp_queue tasks"
    echo "Ingestion Queue: $ing_queue tasks"
    echo "Default Queue: $def_queue tasks"
else
    echo "Cannot connect to Redis"
fi

echo ""
echo "=========================================="
echo "Quick Actions"
echo "=========================================="
echo ""
echo "Start all:   sudo systemctl start casescope-new casescope-workers"
echo "Stop all:    sudo systemctl stop casescope-new casescope-workers"
echo "Restart all: sudo systemctl restart casescope-new casescope-workers"
echo "View logs:   tail -f /opt/casescope/logs/*.log"
echo ""
