# AI Toggle Implementation Guide

## Overview

AI features can be **enabled or disabled** with a single config flag. This provides deployment flexibility for systems without GPUs or when AI features aren't needed.

---

## How to Enable/Disable AI

### Option 1: Config File (Recommended)

Edit `/opt/casescope/app/config.py`:

```python
# Enable AI (default)
AI_ENABLED = True

# Disable AI
AI_ENABLED = False
```

Restart Flask:
```bash
sudo systemctl restart casescope-new
```

### Option 2: Environment Variable

```bash
export CASESCOPE_AI_ENABLED=false
sudo systemctl restart casescope-new
```

### Option 3: Admin UI (Phase 3)

In Phase 3, we'll add a toggle in the admin settings page.

---

## What Happens When AI is Disabled

### Backend Behavior

✅ **AI routes return 404**
- `/api/ai/query` → 404 Not Found
- `/api/ai/analyze` → 404 Not Found
- `/api/ai/chat` → 404 Not Found
- All other routes work normally

✅ **No AI dependencies loaded**
- Ollama not accessed
- Vector store not initialized
- Embedding models not loaded
- Saves memory and resources

✅ **Application remains functional**
- All core features work (search, upload, cases, etc.)
- No crashes or errors
- Graceful degradation

### Frontend Behavior

✅ **AI UI elements hidden**
- "AI Assistant" button hidden
- AI-related tiles not shown
- No broken UI elements

✅ **Users see message**
- "AI features not available" (if they try to access)
- Optional: Show reason (Ollama not running, etc.)

---

## Implementation Details

### 1. Config Flag

**File:** `/opt/casescope/app/config.py`

```python
# Master toggle
AI_ENABLED = True  # Set to False to disable

# Auto-detection (recommended)
AI_AUTO_DETECT = True  # Check if Ollama/models available
```

**Behavior:**
- `AI_ENABLED = False` → AI completely disabled
- `AI_ENABLED = True` + `AI_AUTO_DETECT = True` → Check components on startup
- `AI_ENABLED = True` + `AI_AUTO_DETECT = False` → Assume AI available (crash if not)

### 2. Helper Functions

**File:** `/opt/casescope/app/ai/ai_toggle.py`

```python
from app.ai.ai_toggle import is_ai_available, require_ai

# Check if AI is available
available, reason = is_ai_available()
if available:
    print("AI ready!")
else:
    print(f"AI unavailable: {reason}")

# Use decorator on routes
@ai_bp.route('/query')
@require_ai  # Returns 404 if AI not available
def ai_query():
    # This only runs if AI is available
    ...
```

### 3. Route Protection (Phase 2)

**File:** `/opt/casescope/app/routes/ai.py` (to be created)

```python
from flask import Blueprint
from app.ai.ai_toggle import require_ai

ai_bp = Blueprint('ai', __name__)

@ai_bp.route('/api/ai/query', methods=['POST'])
@login_required
@admin_required
@require_ai  # ← Returns 404 if AI disabled
def ai_query():
    # AI logic here
    ...
```

### 4. Blueprint Registration (Phase 2)

**File:** `/opt/casescope/app/main.py`

```python
from app.config import AI_ENABLED
from app.ai.ai_toggle import is_ai_available

def create_app():
    app = Flask(__name__)
    
    # Register core blueprints (always)
    app.register_blueprint(auth_bp)
    app.register_blueprint(cases_bp)
    app.register_blueprint(search_bp)
    
    # Register AI blueprint only if enabled
    if AI_ENABLED:
        try:
            from app.routes import ai
            app.register_blueprint(ai.ai_bp)
            logger.info("✅ AI routes registered")
        except Exception as e:
            logger.warning(f"⚠️  AI routes not registered: {e}")
    else:
        logger.info("ℹ️  AI features disabled")
    
    return app
```

### 5. Frontend Check (Phase 3)

**JavaScript:**
```javascript
// Check AI status
fetch('/api/ai/status')
    .then(r => r.json())
    .then(data => {
        if (data.available) {
            // Show AI button
            document.getElementById('ai-assistant-btn').style.display = 'block';
        } else {
            // Hide AI button
            document.getElementById('ai-assistant-btn').style.display = 'none';
        }
    });
```

**Template (Jinja2):**
```html
{% if config.AI_ENABLED %}
<button id="ai-assistant-btn">
    🤖 AI Assistant
</button>
{% endif %}
```

---

## Use Cases

### Scenario 1: Development/Testing
```python
AI_ENABLED = True
AI_AUTO_DETECT = True  # Gracefully disable if Ollama not running
```

**Result:** AI works if available, disabled if not. No crashes.

### Scenario 2: Production with AI
```python
AI_ENABLED = True
AI_AUTO_DETECT = False  # Assume AI is available
```

**Result:** AI always active. Crash if Ollama/models missing (fail-fast).

### Scenario 3: Production without AI
```python
AI_ENABLED = False
AI_AUTO_DETECT = False  # Not checked
```

**Result:** AI completely disabled. No resources wasted.

### Scenario 4: Gradual Rollout
```python
AI_ENABLED = True
AI_AUTO_DETECT = True

# Only enable for specific users (add to routes)
if current_user.is_beta_tester():
    # Show AI features
```

**Result:** Feature flag for beta testing.

---

## Auto-Detection Logic

When `AI_AUTO_DETECT = True`:

1. **Check Ollama**
   - Try: `ollama.list()`
   - Fail: Disable AI, log warning

2. **Check Vector Store**
   - Try: Connect to PostgreSQL + check pattern count
   - Fail: Disable AI, log warning

3. **Check Models**
   - Try: Verify configured models exist
   - Fail: Disable AI, log warning

4. **Result**
   - All pass: `AI available = True`
   - Any fail: `AI available = False`

---

## Admin Status Page (Phase 3)

**Location:** `/admin/settings` → "AI Configuration" tile

**Display:**
```
AI Status: ✅ Operational / ⚠️ Degraded / ❌ Disabled

Components:
  ✅ Ollama Service: Running
  ✅ Vector Store: 3,918 patterns loaded
  ✅ Models: qwen2.5:7b-instruct-q4_k_m
  ✅ GPU: Tesla P4 (7.6GB VRAM)

[Toggle AI On/Off]
[Test AI Performance]
```

---

## Testing

### Check Current Status

```bash
cd /opt/casescope
python3 scripts/check_ai_availability.py
```

**Output:**
```
AI Component Availability Check
=========================================
✅ Ollama service running
✅ Vector store ready (3918 patterns)
✅ FastEmbed available
✅ Model available: qwen2.5:7b-instruct-q4_k_m
✅ Model available: qwen2.5-coder:7b-instruct-q4_k_m

✅ AI can be ENABLED
   All components are ready
```

### Test with AI Disabled

1. Edit config:
   ```python
   AI_ENABLED = False
   ```

2. Restart:
   ```bash
   sudo systemctl restart casescope-new
   ```

3. Try AI endpoint:
   ```bash
   curl http://localhost:5000/api/ai/query
   # Expected: 404 Not Found
   ```

4. Check logs:
   ```bash
   sudo journalctl -u casescope-new -n 20
   # Expected: "ℹ️  AI features disabled"
   ```

---

## Migration Path

### Phase 2 (Now)
- ✅ Add `AI_ENABLED` config flag
- ✅ Add `ai_toggle.py` helper module
- ✅ Add `@require_ai` decorator
- ✅ Register AI blueprint conditionally

### Phase 3 (Future)
- Add admin UI toggle
- Add status page with component health
- Add user-level AI permissions
- Add API rate limiting for AI endpoints

---

## Resource Savings

When AI is **disabled**:

| Component | Memory Saved | Notes |
|-----------|--------------|-------|
| Ollama | 0 (separate process) | Ollama service can still run |
| Embedding model | ~500MB | FastEmbed not loaded |
| Vector store connection | ~10MB | No PostgreSQL queries |
| LLM context | Variable | No model loaded in VRAM |

**Total:** ~500MB+ RAM, 0-5GB VRAM (depending on if Ollama is stopped)

---

## Complexity Assessment

### Implementation Difficulty: ⭐⭐☆☆☆ (Easy)

**What's needed:**
1. ✅ Add config flag (1 line)
2. ✅ Create `ai_toggle.py` helper (50 lines)
3. Add conditional blueprint registration (5 lines) - Phase 2
4. Add decorator to routes (1 line per route) - Phase 2
5. Add frontend checks (10 lines) - Phase 3

**Time estimate:** 30 minutes for backend, 1 hour for frontend UI

**Risk:** Very low (no existing code affected)

---

## Summary

**Answer to "How hard would it be?"**

✅ **Very easy!** 

- Single config flag: `AI_ENABLED = True/False`
- Auto-detection: Check if components available
- Graceful degradation: 404 on AI routes, hide UI elements
- No changes to existing code
- ~1-2 hours of work for complete implementation

**Implementation already started:**
- ✅ Config flag added
- ✅ Helper module created (`ai_toggle.py`)
- ✅ Availability check script created
- 🔄 Phase 2 will use these components

**Would you like me to proceed with Phase 2 now, implementing the AI routes with toggle support built-in?**

