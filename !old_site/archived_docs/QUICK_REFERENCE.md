# 🎯 CaseScope 2026 - Quick Reference Card

## 📦 Fresh Install (Nuclear Option)

```bash
# Copy script to server
scp fresh_install.sh user@server:/tmp/

# SSH and run
ssh user@server
cd /tmp
sudo bash fresh_install.sh
# Type: YES DELETE EVERYTHING
```

---

## 🔧 Essential Commands

### Service Management
```bash
# Restart everything
sudo systemctl restart casescope casescope-worker

# Stop everything
sudo systemctl stop casescope casescope-worker

# Check status
sudo systemctl status casescope casescope-worker opensearch redis
```

### View Logs
```bash
# Web application (live)
sudo journalctl -u casescope -f

# Worker (live) - watch during uploads
sudo journalctl -u casescope-worker -f

# Last 100 lines
sudo journalctl -u casescope -n 100

# All errors from last hour
sudo journalctl --since "1 hour ago" | grep ERROR
```

### Queue Management
```bash
# Check queue length (should be 0 when idle)
redis-cli LLEN celery

# Watch queue (refreshes every 1 second)
watch -n 1 'redis-cli LLEN celery'

# Clear stuck queue (DANGER!)
redis-cli DEL celery
```

### OpenSearch
```bash
# Health check
curl localhost:9200/_cluster/health?pretty

# List indices
curl localhost:9200/_cat/indices?v

# Count documents in an index
curl localhost:9200/logs-*/_count?pretty

# Delete an index (DANGER!)
curl -X DELETE localhost:9200/logs-casename-*
```

### Database
```bash
# Reinitialize database (DANGER!)
cd /opt/casescope/app
source /opt/casescope/venv/bin/activate
flask init-db
```

---

## 🚀 Quick Deploy from Mac

### Method 1: Simple Sync & Restart
```bash
# Create this script on your Mac: ~/deploy.sh
rsync -avz --exclude '.git' \
    /Users/jdube/caseScope_2026/ \
    user@server:/opt/casescope/app/

ssh user@server "sudo systemctl restart casescope casescope-worker"
```

### Method 2: With Status Check
```bash
# Create this script on your Mac: ~/deploy_status.sh
rsync -avz --exclude '.git' \
    /Users/jdube/caseScope_2026/ \
    user@server:/opt/casescope/app/

ssh user@server << 'EOF'
sudo systemctl restart casescope casescope-worker
sleep 3
echo "✅ Services restarted"
sudo systemctl status casescope --no-pager | head -3
sudo systemctl status casescope-worker --no-pager | head -3
EOF
```

---

## 🔍 Health Checks

```bash
# One-liner to check everything
echo "Redis:"; redis-cli ping; \
echo "OpenSearch:"; curl -s localhost:9200; \
echo "Web:"; curl -s -o /dev/null -w "%{http_code}\n" localhost:5000; \
echo "Queue:"; redis-cli LLEN celery

# Or create a health check script
cat > /opt/casescope/bin/health_check.sh << 'EOF'
#!/bin/bash
echo "=== CaseScope Health Check ==="
systemctl is-active opensearch && echo "✓ OpenSearch" || echo "✗ OpenSearch"
systemctl is-active redis && echo "✓ Redis" || echo "✗ Redis"
systemctl is-active casescope && echo "✓ Web" || echo "✗ Web"
systemctl is-active casescope-worker && echo "✓ Worker" || echo "✗ Worker"
echo "Queue: $(redis-cli LLEN celery) items"
EOF
chmod +x /opt/casescope/bin/health_check.sh
```

---

## 📁 Important Paths

| Purpose | Path |
|---------|------|
| Application | `/opt/casescope/app` |
| Virtual Environment | `/opt/casescope/venv` |
| Uploads | `/opt/casescope/uploads` |
| Case Data | `/opt/casescope/data` |
| Database | `/opt/casescope/data/casescope.db` |
| Logs | `journalctl -u casescope` |
| OpenSearch | `/opt/opensearch` |
| Forensic Tools | `/opt/casescope/bin/` |
| SIGMA Rules | `/opt/casescope/sigma_rules` |

---

## 🐛 Common Issues

### Issue: Worker not processing files
```bash
# Check if worker is running
sudo systemctl status casescope-worker

# Check for errors
sudo journalctl -u casescope-worker -n 50

# Restart worker
sudo systemctl restart casescope-worker

# Clear queue and restart
redis-cli DEL celery
sudo systemctl restart casescope-worker
```

### Issue: Database locked
```bash
# Find processes using the database
lsof /opt/casescope/data/casescope.db

# Stop all services
sudo systemctl stop casescope casescope-worker

# Kill any remaining celery processes
sudo pkill -9 celery

# Start services
sudo systemctl start casescope casescope-worker
```

### Issue: OpenSearch not responding
```bash
# Check if running
sudo systemctl status opensearch

# Check logs
sudo journalctl -u opensearch -n 100

# Restart
sudo systemctl restart opensearch

# Wait for it to start (can take 30-60 seconds)
sleep 30
curl localhost:9200/_cluster/health?pretty
```

### Issue: Port 5000 already in use
```bash
# Find what's using port 5000
sudo lsof -i :5000

# Kill the process (replace PID)
sudo kill -9 PID

# Or stop the service
sudo systemctl stop casescope
sudo systemctl start casescope
```

### Issue: Upload stuck in "Queued" status
```bash
# Check queue
redis-cli LLEN celery

# Check worker is running
sudo systemctl status casescope-worker

# Watch worker logs
sudo journalctl -u casescope-worker -f

# If needed, restart worker
sudo systemctl restart casescope-worker
```

---

## 🔐 Security Checklist

```bash
# Change default admin password (do this first!)
# Login to web interface → Settings → Change Password

# Update Ubuntu
sudo apt update && sudo apt upgrade -y

# Setup firewall
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 5000/tcp  # CaseScope
sudo ufw enable

# Setup reverse proxy with SSL (optional but recommended)
sudo apt install nginx certbot python3-certbot-nginx
# Configure nginx as reverse proxy
```

---

## 📊 Performance Monitoring

```bash
# Watch system resources
htop

# Check disk space
df -h /opt/casescope

# Check OpenSearch disk usage
curl localhost:9200/_cat/allocation?v

# Monitor upload processing
watch -n 1 'redis-cli LLEN celery && sudo systemctl status casescope-worker | grep Active'

# Check memory usage
free -h

# Check OpenSearch heap
curl localhost:9200/_cat/nodes?v&h=heap.percent,ram.percent
```

---

## 🧹 Cleanup Commands

```bash
# Clean old uploads (be careful!)
find /opt/casescope/uploads -type f -mtime +30 -delete

# Clean staging files
rm -rf /opt/casescope/staging/*

# Archive old logs
sudo journalctl --vacuum-time=7d

# Clean OpenSearch old indices (DANGER!)
curl -X DELETE localhost:9200/logs-*-2024-01-*
```

---

## 🔄 Update CaseScope

```bash
# Pull latest code
cd /opt/casescope/app
sudo git pull origin main

# Update Python packages
source /opt/casescope/venv/bin/activate
pip install -r requirements.txt

# Restart services
sudo systemctl restart casescope casescope-worker

# Check logs for errors
sudo journalctl -u casescope -n 50
```

---

## 📞 Emergency Recovery

### Complete Service Restart
```bash
sudo systemctl stop casescope casescope-worker opensearch redis
sleep 5
sudo systemctl start redis opensearch
sleep 30  # Wait for OpenSearch
sudo systemctl start casescope casescope-worker
```

### Nuclear Option (Fresh Install)
```bash
# Use the fresh_install.sh script
sudo bash /tmp/fresh_install.sh
```

### Backup Before Nuclear Option
```bash
# Backup database and uploads
sudo tar -czf ~/casescope_backup_$(date +%Y%m%d_%H%M%S).tar.gz \
    /opt/casescope/data \
    /opt/casescope/uploads

# Restore after fresh install
sudo tar -xzf ~/casescope_backup_*.tar.gz -C /
```

---

## 📝 Useful One-Liners

```bash
# Count total cases
sqlite3 /opt/casescope/data/casescope.db "SELECT COUNT(*) FROM cases;"

# Count total uploads
sqlite3 /opt/casescope/data/casescope.db "SELECT COUNT(*) FROM uploads;"

# List recent uploads
sqlite3 /opt/casescope/data/casescope.db "SELECT filename, status, created_at FROM uploads ORDER BY created_at DESC LIMIT 10;"

# Check all service statuses in one line
for s in redis opensearch casescope casescope-worker; do systemctl is-active --quiet $s && echo "✓ $s" || echo "✗ $s"; done

# Tail all logs at once
sudo journalctl -u casescope -u casescope-worker -f

# Count SIGMA detections
curl -s localhost:9200/logs-*/_search?q=sigma_detection:true | jq '.hits.total.value'
```

---

## 🔗 Important URLs

| Service | URL |
|---------|-----|
| Web Interface | `http://server-ip:5000` |
| OpenSearch | `http://server-ip:9200` |
| OpenSearch Health | `http://server-ip:9200/_cluster/health` |
| OpenSearch Indices | `http://server-ip:9200/_cat/indices?v` |

---

**💡 Pro Tips:**

1. Always check logs when something breaks: `sudo journalctl -u casescope-worker -f`
2. Queue should be 0 when idle: `redis-cli LLEN celery`
3. OpenSearch takes ~30 seconds to start after restart
4. Worker processes one file at a time (concurrency=2)
5. Change default admin password immediately!
6. Test with small EVTX files first (~10MB)
7. Use tmux for persistent SSH sessions
8. Set up monitoring with the health check script

---

**Last Updated:** 2025-10-27  
**Version:** CaseScope 2026 v1.0.0

