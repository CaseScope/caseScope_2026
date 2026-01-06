#!/bin/bash
# Monitor Case 4 processing with EZ Tools parsers

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║              Monitoring Case 4 - EZ Tools Processing              ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""

while true; do
    clear
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║              Case 4 Processing Monitor                            ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo ""
    
    echo "📊 File Status:"
    sudo -u postgres psql -d casescope -c "SELECT status, COUNT(*) as count FROM case_file WHERE case_id = 4 GROUP BY status ORDER BY status;" -q
    
    echo ""
    echo "📈 By File Type (Indexed):"
    sudo -u postgres psql -d casescope -c "SELECT file_type, COUNT(*) as count, SUM(event_count) as events FROM case_file WHERE case_id = 4 AND status = 'Indexed' GROUP BY file_type ORDER BY count DESC LIMIT 10;" -q
    
    echo ""
    echo "🔧 Recent Activity (last 10 from logs):"
    tail -20 /opt/casescope/logs/celery_worker.log | grep -i "parsing\|indexed\|lecmd\|jlecmd\|evtxecmd\|mftecmd\|dissect" | tail -5
    
    echo ""
    echo "📍 OpenSearch Indexes:"
    curl -s "localhost:9200/_cat/indices?v" | grep case_4 || echo "   (No indexes yet)"
    
    echo ""
    echo "⏰ Last updated: $(date)"
    echo "Press Ctrl+C to exit. Refreshing in 5 seconds..."
    
    sleep 5
done

