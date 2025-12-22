# ✅ Dynamic Worker Configuration - Implementation Complete

## 🎯 Feature: User-Adjustable Celery Workers

**Location:** Settings page (Administrator only)

### **What Was Implemented:**

1. **New Settings Route** (`app/routes/settings.py`)
   - Dedicated blueprint for system settings
   - Admin-only access with decorator
   - Worker count management endpoint

2. **Settings UI** (`templates/admin/settings.html`)
   - Clean, modern interface
   - Dropdown with options: 2, 4, 6, 8 workers
   - Real-time system information display
   - CPU core validation
   - Auto-disabled options that exceed limits

3. **Dynamic Configuration Updates**
   - Automatically edits `/opt/casescope/app/config.py`
   - Uses regex to update `CELERY_WORKERS` value
   - Preserves all other settings and comments

4. **Automatic Service Restart**
   - Restarts `casescope-workers` service automatically
   - No manual intervention needed
   - Sudo permissions configured for `casescope` user

5. **Comprehensive Validation**
   - CPU core detection (2/3 limit enforced)
   - Only allows 2, 4, 6, or 8 workers
   - Disables options that exceed system capacity
   - Prevents downgrade if already at limit

6. **Audit Logging**
   - Logs who changed worker count
   - Records old and new values
   - Tracks CPU limits and validation

---

## 🔧 How It Works

### **User Interface:**

```
┌─────────────────────────────────────────┐
│  🔧 Celery Workers                      │
├─────────────────────────────────────────┤
│  System CPU Cores: 16                   │
│  Maximum Allowed: 10 (2/3 of cores)     │
│  Current Workers: 2                     │
│                                          │
│  Select Worker Count:                   │
│  ┌──────────────────┐                   │
│  │ 2 Workers    ▼  │                    │
│  │ 4 Workers       │                    │
│  │ 6 Workers       │                    │
│  │ 8 Workers       │                    │
│  └──────────────────┘                   │
│                                          │
│  [ Apply Changes ]                      │
└─────────────────────────────────────────┘
```

### **Backend Process:**

1. **User selects new worker count** (e.g., 4 workers)
2. **System validates:**
   - Is it 2, 4, 6, or 8? ✓
   - Does it exceed 2/3 of CPU cores? ✗
3. **Config file updated:**
   ```python
   CELERY_WORKERS = 2  # Changed to 4
   ```
4. **Service restarted:**
   ```bash
   sudo systemctl restart casescope-workers
   ```
5. **User notified:**
   - Success message
   - Page auto-refreshes after 2 seconds
6. **Audit logged:**
   - Who changed it
   - From what to what
   - When

---

## 📊 CPU Limit Calculation

**Formula:** `max_workers = (cpu_count * 2) / 3`

**Examples:**

| CPU Cores | Max Workers | Options Available |
|-----------|-------------|-------------------|
| 4 | 2 | 2 only |
| 6 | 4 | 2, 4 |
| 12 | 8 | 2, 4, 6, 8 |
| 16 | 10 | 2, 4, 6, 8 |
| 24 | 16 | 2, 4, 6, 8 |

**Why 2/3?**
- Leaves CPU headroom for Flask, PostgreSQL, OpenSearch, Redis
- Prevents system from becoming unresponsive
- Industry best practice for worker allocation

---

## 🔐 Security

### **Sudo Permissions:**

Created `/etc/sudoers.d/casescope`:
```bash
casescope ALL=(ALL) NOPASSWD: /bin/systemctl restart casescope-workers
casescope ALL=(ALL) NOPASSWD: /bin/systemctl restart casescope-new
casescope ALL=(ALL) NOPASSWD: /bin/systemctl status casescope-workers
casescope ALL=(ALL) NOPASSWD: /bin/systemctl status casescope-new
```

**Why?**
- Web app runs as `casescope` user
- Needs to restart services without password prompt
- Restricted to only necessary commands
- No general sudo access

---

## 📝 Configuration File Update

**Before:**
```python
# Celery worker settings
CELERY_WORKERS = 2  # Number of concurrent workers
```

**After (user selects 4):**
```python
# Celery worker settings
CELERY_WORKERS = 4  # Number of concurrent workers
```

**How it's updated:**
```python
import re
pattern = r'CELERY_WORKERS\s*=\s*\d+'
replacement = f'CELERY_WORKERS = {new_value}'
new_content = re.sub(pattern, replacement, config_content)
```

**Safe:**
- Preserves comments
- Preserves formatting
- Only changes the number
- Validates before writing

---

## ✅ Features

### **1. Real-Time System Info**
- CPU core count (detected)
- Maximum allowed workers (calculated)
- Current worker count (from config)

### **2. Smart Validation**
- Options limited to 2, 4, 6, 8
- Auto-disables options exceeding CPU limit
- Shows "(Exceeds CPU limit)" for disabled options
- Rejects invalid selections with error message

### **3. User Feedback**
- Loading state while applying
- Success message with details
- Error messages with specific reasons
- Auto-refresh on success

### **4. Audit Trail**
- Who made the change
- Old and new values
- CPU limits at time of change
- Timestamp

---

## 🚀 Usage

### **For Administrators:**

1. Navigate to **Settings** (left menu)
2. View current worker count and system info
3. Select new worker count from dropdown
4. Click "Apply Changes"
5. Wait 2-5 seconds for restart
6. Page refreshes automatically

### **Recommendations:**

- **2 workers**: Most systems, light workloads
- **4 workers**: Heavy workloads, 8+ cores
- **6 workers**: High-performance, 12+ cores
- **8 workers**: Maximum, 16+ cores only

---

## 📋 API Endpoint

**POST `/settings/workers/update`**

**Request:**
```json
{
  "workers": 4
}
```

**Success Response:**
```json
{
  "success": true,
  "message": "Worker count updated from 2 to 4. Services restarted.",
  "old_value": 2,
  "new_value": 4,
  "services_restarted": ["casescope-workers"],
  "restart_needed": false
}
```

**Error Response (exceeds limit):**
```json
{
  "success": false,
  "error": "Cannot set 8 workers. Your system has 6 CPU cores. Maximum allowed: 4 workers (2/3 of cores)."
}
```

**Error Response (invalid value):**
```json
{
  "success": false,
  "error": "Invalid worker count. Must be 2, 4, 6, or 8."
}
```

---

## 🎯 Testing

**Test on your system (16 cores):**

1. Go to Settings
2. You should see:
   - CPU Cores: 16
   - Max Workers: 10
   - All options (2, 4, 6, 8) available
3. Try selecting 8 workers
4. Should succeed and restart service
5. Reload page, should show "Current Workers: 8"

**Test validation:**

If you had 4 cores:
- Max Workers: 2
- Options 4, 6, 8 would be disabled
- Selecting disabled option returns error

---

## ✨ Future Enhancements

Potential additions to Settings page:

1. **OpenSearch Bulk Chunk Size**
2. **Task Timeout Settings**
3. **Result Expiration Time**
4. **Session Timeout**
5. **Max Upload Size**
6. **Database Pool Size**

All following the same pattern:
- Dropdown or input
- Validation
- Auto-update config.py
- Auto-restart services
- Audit logging

---

## 🎉 Summary

✅ **Settings page created**
✅ **Worker configuration dropdown**
✅ **CPU limit validation (2/3 of cores)**
✅ **Auto-updates config.py**
✅ **Auto-restarts casescope-workers**
✅ **Sudo permissions configured**
✅ **Audit logging**
✅ **User-friendly UI with real-time info**

**Ready for testing!** Navigate to Settings in the left menu (Administrator only). 🚀
