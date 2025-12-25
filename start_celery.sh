#!/bin/bash
# Celery Worker Startup Script

# Load environment
cd /opt/casescope
source venv/bin/activate
cd app

# Set PYTHONPATH to include app directory for imports
export PYTHONPATH="/opt/casescope/app:$PYTHONPATH"

# Load Celery settings from config.py
if [ -z "$CELERY_WORKERS" ]; then
    export CELERY_WORKERS=$(python3 -c "from config import CELERY_WORKERS; print(CELERY_WORKERS)")
fi

if [ -z "$CELERY_MAX_TASKS_PER_CHILD" ]; then
    export CELERY_MAX_TASKS_PER_CHILD=$(python3 -c "from config import CELERY_MAX_TASKS_PER_CHILD; print(CELERY_MAX_TASKS_PER_CHILD)")
fi

# Pre-load tasks to ensure they're registered
echo "Registering tasks..."
python3 -c "import register_tasks" || echo "Warning: Could not register all tasks"

# Start Celery worker
echo "Starting Celery with $CELERY_WORKERS workers, max $CELERY_MAX_TASKS_PER_CHILD tasks per child"
exec celery -A celery_app.celery worker \
    --loglevel=info \
    --concurrency=$CELERY_WORKERS \
    --max-tasks-per-child=$CELERY_MAX_TASKS_PER_CHILD \
    --queues=celery,file_processing,ingestion,default \
    --logfile=/opt/casescope/logs/celery_worker.log \
    --pidfile=/opt/casescope/logs/celery_worker.pid
