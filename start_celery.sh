#!/bin/bash
# Celery Worker Startup Script

# Load environment
cd /opt/casescope
source venv/bin/activate
cd app

# Set PYTHONPATH to include app directory for imports
export PYTHONPATH="/opt/casescope/app:$PYTHONPATH"

# Start Celery worker
exec celery -A celery_app.celery worker \
    --loglevel=info \
    --concurrency=${CELERY_WORKERS:-2} \
    --max-tasks-per-child=${CELERY_MAX_TASKS_PER_CHILD:-1000} \
    --queues=file_processing,ingestion,default \
    --logfile=/opt/casescope/logs/celery_worker.log \
    --pidfile=/opt/casescope/logs/celery_worker.pid
