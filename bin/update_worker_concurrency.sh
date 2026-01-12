#!/bin/bash
# Update Celery worker concurrency in systemd service file
# Usage: update_worker_concurrency.sh <concurrency>

CONCURRENCY=$1

if [[ ! "$CONCURRENCY" =~ ^[0-9]+$ ]] || [ "$CONCURRENCY" -lt 1 ] || [ "$CONCURRENCY" -gt 32 ]; then
    echo "Error: Invalid concurrency value (must be 1-32)"
    exit 1
fi

SERVICE_FILE="/etc/systemd/system/casescope-workers.service"

# Update the concurrency value
sed -i "s/--concurrency=[0-9]*/--concurrency=$CONCURRENCY/" "$SERVICE_FILE"

# Reload systemd
systemctl daemon-reload

echo "Updated worker concurrency to $CONCURRENCY"
