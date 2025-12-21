#!/bin/bash
# CaseScope 2026 - Server Startup Script
# Reads configuration and starts Gunicorn

cd /opt/casescope

# Read port from config.py
PORT=$(python3 -c "import sys; sys.path.insert(0, 'app'); from config import WEB_SERVER_PORT; print(WEB_SERVER_PORT)")
HOST=$(python3 -c "import sys; sys.path.insert(0, 'app'); from config import WEB_SERVER_HOST; print(WEB_SERVER_HOST)")
WORKERS=$(python3 -c "import sys; sys.path.insert(0, 'app'); from config import WEB_WORKERS; print(WEB_WORKERS)")
TIMEOUT=$(python3 -c "import sys; sys.path.insert(0, 'app'); from config import WEB_TIMEOUT; print(WEB_TIMEOUT)")
SSL_ENABLED=$(python3 -c "import sys; sys.path.insert(0, 'app'); from config import SSL_ENABLED; print(SSL_ENABLED)")
SSL_CERT=$(python3 -c "import sys; sys.path.insert(0, 'app'); from config import SSL_CERT_PATH; print(SSL_CERT_PATH)")
SSL_KEY=$(python3 -c "import sys; sys.path.insert(0, 'app'); from config import SSL_KEY_PATH; print(SSL_KEY_PATH)")

echo "Starting CaseScope 2026..."
echo "Port: $PORT"
echo "Host: $HOST"
echo "Workers: $WORKERS"
echo "SSL: $SSL_ENABLED"

# Build Gunicorn command
CMD="/opt/casescope/venv/bin/gunicorn"
CMD="$CMD --bind $HOST:$PORT"
CMD="$CMD --workers $WORKERS"
CMD="$CMD --timeout $TIMEOUT"
CMD="$CMD --access-logfile /opt/casescope/logs/access.log"
CMD="$CMD --error-logfile /opt/casescope/logs/error.log"

# Add SSL if enabled
if [ "$SSL_ENABLED" = "True" ]; then
    CMD="$CMD --certfile=$SSL_CERT"
    CMD="$CMD --keyfile=$SSL_KEY"
    echo "HTTPS enabled"
else
    echo "HTTP only (SSL disabled)"
fi

CMD="$CMD wsgi:app"

# Execute
exec $CMD
