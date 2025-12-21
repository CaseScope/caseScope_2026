#!/bin/bash
# Safe Celery Shutdown Script
# Pauses queue and waits for active tasks to finish

echo "========================================"
echo "Safe Celery Worker Shutdown"
echo "========================================"
echo ""

cd /opt/casescope
source venv/bin/activate
cd app

# Step 1: Stop accepting new tasks (pause all consumers)
echo "🛑 Step 1: Pausing queue (no new tasks will start)..."
celery -A celery_app control cancel_consumer default

echo "✅ Queue paused - workers will finish active tasks but won't pick up new ones"
echo ""

# Step 2: Monitor active tasks
echo "⏳ Step 2: Waiting for active tasks to complete..."
echo ""

while true; do
    ACTIVE=$(python3 << 'EOF'
from celery_app import celery_app
inspect = celery_app.control.inspect()
active = inspect.active()
if active:
    total = sum(len(tasks) for tasks in active.values())
    print(total)
else:
    print(0)
EOF
)
    
    if [ "$ACTIVE" -eq 0 ]; then
        echo "✅ All active tasks completed!"
        break
    else
        echo "🔄 $ACTIVE task(s) still running... (checking again in 10 seconds)"
        sleep 10
    fi
done

echo ""
echo "========================================"
echo "✅ SAFE TO STOP WORKERS NOW"
echo "========================================"
echo ""
echo "Run: sudo systemctl stop casescope-worker.service"
echo "Then you can safely power down the VM!"
echo ""


