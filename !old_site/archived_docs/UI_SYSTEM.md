# CaseScope 2026 - Centralized UI System

**Version**: 1.0.0  
**Created**: 2025-10-27  
**Purpose**: Documentation for the centralized UI management system

---

## 🎨 Overview

CaseScope now uses a **centralized UI system** that manages all visual elements from a single location:

- **Centralized Theme**: All colors, spacing, and styles defined in one CSS file
- **Base Template**: Sidebar navigation and top bar shared across all pages
- **Reusable Components**: Stats cards, tables, and UI elements
- **Global JavaScript**: Theme switching and utility functions
- **Automatic Case Selector**: Context processor injects case list into all templates

---

## 📁 File Structure

```
/opt/casescope/app/
├── static/
│   ├── css/
│   │   └── theme.css              # ✨ CENTRALIZED THEME
│   └── js/
│       └── app.js                 # ✨ GLOBAL JAVASCRIPT
│
├── templates/
│   ├── base.html                  # ✨ BASE LAYOUT (sidebar + header)
│   ├── dashboard.html             # Dashboard page
│   ├── view_case.html             # Case details page
│   └── components/
│       └── stats_card.html        # Reusable stats card
│
└── main.py                        # Routes (now using render_template)
```

---

## 🎨 Centralized Theme System

### Location: `/opt/casescope/app/static/css/theme.css`

All visual elements are controlled via **CSS Variables**:

```css
:root {
    /* Colors */
    --color-bg-primary: #0a1929;
    --color-bg-secondary: #1e2a3a;
    --color-primary: #3b82f6;
    --color-success: #10b981;
    --color-warning: #f59e0b;
    --color-error: #ef4444;
    
    /* Spacing */
    --spacing-sm: 8px;
    --spacing-md: 16px;
    --spacing-lg: 24px;
    
    /* Layout */
    --sidebar-width: 240px;
    --header-height: 64px;
}
```

### 🎯 Key Features

1. **Single Source of Truth**: Change colors/spacing globally
2. **Dark Theme**: Navy/teal color scheme matching your screenshot
3. **Component Classes**: `.btn`, `.card`, `.stat-card`, `.status-badge`
4. **Responsive Design**: Mobile-friendly with collapsible sidebar
5. **Animations**: Pulsing status indicators, fade-in effects

### 🔧 Common Classes

| Class | Purpose | Example |
|-------|---------|---------|
| `.card` | Content card/panel | `<div class="card">...</div>` |
| `.stat-card` | Statistics display | Auto-styled in `.stats-grid` |
| `.btn-primary` | Primary action button | `<a class="btn btn-primary">Save</a>` |
| `.status-badge` | Status indicator | `<span class="status-badge status-completed">Done</span>` |
| `.table-container` | Responsive table wrapper | `<div class="table-container"><table>...</table></div>` |

---

## 🏗️ Base Template System

### Location: `/opt/casescope/app/templates/base.html`

The base template provides:

#### **Left Sidebar Navigation**
- System Dashboard
- Cases
- Upload EVTX (when case selected)
- Search
- Settings

#### **Top Header Bar**
- Case selector dropdown (auto-populated)
- Theme toggle button
- User info (username + role)
- Logout button

#### **Flash Messages**
Automatically rendered for all pages

#### **Content Block**
Pages extend base and fill `{% block content %}`

### 📝 Using the Base Template

```html
{% extends "base.html" %}

{% block title %}My Page - CaseScope 2026{% endblock %}

{% block content %}
<div class="content-header">
    <h1 class="content-title">My Page</h1>
    <div class="content-actions">
        <a href="#" class="btn btn-primary">Action</a>
    </div>
</div>

<div class="stats-grid">
    <!-- Stats cards auto-styled -->
</div>

<div class="card">
    <div class="card-header">
        <h2 class="card-title">Section Title</h2>
    </div>
    <div class="card-body">
        <!-- Content here -->
    </div>
</div>
{% endblock %}
```

---

## 🔄 Context Processor (Auto-Injection)

### Location: `main.py` - `@app.context_processor`

**Automatically injects into ALL templates:**

| Variable | Type | Description |
|----------|------|-------------|
| `available_cases` | List[Case] | All active cases for dropdown |
| `current_case` | Case or None | Current case from URL |
| `db` | SQLAlchemy | Database session |
| `CaseFile` | Model | For template queries |

**No need to pass these manually!**

```python
# ❌ OLD WAY - manually pass available_cases
return render_template('page.html', available_cases=cases, current_case=case)

# ✅ NEW WAY - auto-injected
return render_template('page.html')
```

---

## 🌐 Global JavaScript

### Location: `/opt/casescope/app/static/js/app.js`

**Global Functions Available:**

```javascript
// Theme switching
toggleTheme()

// Case navigation
switchCase(caseId)

// Utilities
formatSize(bytes)          // "1.5 MB"
formatDate(timestamp)      // "Oct 27, 2025"
showToast(message, type)   // Toast notification
copyToClipboard(text)      // Copy with feedback

// Access via window.CaseScope
window.CaseScope.formatSize(123456)
```

---

## 📊 Example Pages

### Dashboard (`dashboard.html`)

**Features:**
- 4-column stats grid
- Active cases table
- New case button
- Auto-formatted numbers

**Stats Card Example:**
```html
<div class="stat-card">
    <div style="font-size: 2rem; margin-bottom: var(--spacing-sm);">📁</div>
    <div class="stat-label">Total Cases</div>
    <div class="stat-value">{{ total_cases }}</div>
    <div class="stat-subtitle">Active investigations</div>
</div>
```

### View Case (`view_case.html`)

**Features:**
- Case info display
- File list with status badges
- Live status updates (JavaScript)
- Pulsing indicators for active processing

**Live Updates:**
```javascript
// Auto-refresh every 3 seconds
setInterval(updateStatuses, 3000);

// Fetch from /case/<id>/status API
fetch('/case/{{ case.id }}/status')
    .then(response => response.json())
    .then(data => {
        // Update DOM without page reload
    });
```

---

## 🎨 Color Scheme

### Primary Colors

| Use | Color | CSS Variable | Hex |
|-----|-------|--------------|-----|
| Background | Deep Navy | `--color-bg-primary` | `#0a1929` |
| Cards | Light Navy | `--color-bg-secondary` | `#1e2a3a` |
| Primary Action | Blue | `--color-primary` | `#3b82f6` |
| Accent | Teal | `--color-accent` | `#0ea5e9` |

### Status Colors

| Status | Color | CSS Variable | Hex |
|--------|-------|--------------|-----|
| Success/Completed | Green | `--color-success` | `#10b981` |
| Warning/Indexing | Orange | `--color-warning` | `#f59e0b` |
| Error/Failed | Red | `--color-error` | `#ef4444` |
| SIGMA | Purple | `--color-purple` | `#a855f7` |

---

## 🔧 How to Add a New Page

### Step 1: Create Template

```html
<!-- templates/my_page.html -->
{% extends "base.html" %}

{% block title %}My Page{% endblock %}

{% block content %}
<h1 class="content-title">My Page</h1>

<div class="card">
    <div class="card-body">
        <!-- Content -->
    </div>
</div>
{% endblock %}
```

### Step 2: Create Route

```python
# main.py
@app.route('/my-page')
@login_required
def my_page():
    # No need to pass available_cases or current_case - auto-injected!
    return render_template('my_page.html',
        my_data='Hello'
    )
```

### Step 3: Add to Sidebar (Optional)

Edit `templates/base.html`:

```html
<a href="{{ url_for('my_page') }}" 
   class="sidebar-nav-item {% if request.endpoint == 'my_page' %}active{% endif %}">
    <span class="sidebar-nav-icon">🔧</span>
    <span>My Page</span>
</a>
```

**That's it!** Automatic sidebar, header, theme, and case selector.

---

## 🎯 Status Badges

### Usage

```html
<span class="status-badge status-completed">Completed</span>
<span class="status-badge status-indexing pulsing">Indexing</span>
<span class="status-badge status-sigma">SIGMA</span>
<span class="status-badge status-queued">Queued</span>
<span class="status-badge status-failed">Failed</span>
```

### Available Classes

- `status-completed` - Green
- `status-indexing` - Orange
- `status-queued` - Gray
- `status-failed` - Red
- `status-sigma` - Purple
- `status-ioc` - Blue

Add `.pulsing` for animated pulse effect.

---

## 📐 Layout Grid

### Stats Grid (Auto-responsive)

```html
<div class="stats-grid">
    <!-- 4 columns on desktop, 1 on mobile -->
    <div class="stat-card">...</div>
    <div class="stat-card">...</div>
    <div class="stat-card">...</div>
    <div class="stat-card">...</div>
</div>
```

### Responsive Breakpoints

| Screen | Sidebar | Stats Grid |
|--------|---------|------------|
| Desktop (>1024px) | 240px fixed | 4 columns |
| Tablet (768-1024px) | 200px fixed | 2 columns |
| Mobile (<768px) | Collapsible | 1 column |

---

## 🔍 Debugging

### Check Theme CSS Loaded

In browser DevTools Console:
```javascript
getComputedStyle(document.documentElement).getPropertyValue('--color-primary')
// Should return: " #3b82f6"
```

### Check Available Cases Injected

In template:
```html
{{ available_cases|length }} cases available
{{ current_case.name if current_case else 'No case selected' }}
```

### View Network Requests

DevTools → Network → Filter by:
- `theme.css` - Theme loaded?
- `app.js` - JavaScript loaded?
- `/status` - Live updates working?

---

## 🚀 Benefits

✅ **Centralized Management**: Change colors once, apply everywhere  
✅ **Consistent UI**: All pages use same components  
✅ **Faster Development**: No copy-paste, just extend base  
✅ **Easier Maintenance**: One CSS file, not 10 inline styles  
✅ **Mobile Friendly**: Responsive by default  
✅ **Theme Ready**: Easy to add light mode  
✅ **Auto Context**: Case selector works everywhere  

---

## 📝 Migration Status

| Page | Status | Template | Notes |
|------|--------|----------|-------|
| Login | ❌ Old | Inline HTML | Low priority - simple page |
| Dashboard | ✅ New | `dashboard.html` | ✅ Complete |
| View Case | ✅ New | `view_case.html` | ✅ Complete |
| Upload Files | ❌ Old | Inline HTML | TODO: Migrate |
| Create Case | ❌ Old | Inline HTML | TODO: Migrate |

### Old Inline Templates

Marked with `_old_*_template()` functions in `main.py`:
- Can be deleted once all pages migrated
- Kept for reference during transition

---

## 🎓 Best Practices

1. **Always extend base.html** - Don't create standalone pages
2. **Use CSS variables** - `var(--color-primary)` not `#3b82f6`
3. **Use utility classes** - `.text-muted`, `.btn-primary`, etc.
4. **Wrap tables** - `<div class="table-container"><table>...`
5. **Use card structure** - `.card > .card-header + .card-body`
6. **Add page-specific JS** - Use `{% block extra_js %}`
7. **Flash messages work** - Use `flash('Message', 'success')`

---

## 🔮 Future Enhancements

- [ ] Light theme support
- [ ] Custom theme builder
- [ ] Additional reusable components
- [ ] Print-friendly styles
- [ ] Accessibility improvements (ARIA labels)
- [ ] Keyboard shortcuts
- [ ] Export theme as JSON

---

## 📞 Quick Reference

| Task | File | Section |
|------|------|---------|
| Change colors | `static/css/theme.css` | `:root` variables |
| Add sidebar link | `templates/base.html` | `.sidebar-nav` |
| Create new page | `templates/yourpage.html` | Extend base |
| Add global function | `static/js/app.js` | Export to `window.CaseScope` |
| Style component | `static/css/theme.css` | Add class rules |

---

**Documentation maintained by:** AI Assistant  
**Last reviewed:** 2025-10-27  
**Questions?** Check `APP_MAP.md` for workflow details

