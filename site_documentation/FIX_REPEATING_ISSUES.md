# Repeating Issues - Quick Reference

This document tracks common issues that have occurred multiple times in the codebase and their proven solutions.

---

## 1. Number Formatting Disappears After Auto-Refresh

**Symptoms:**
- Numbers display with commas initially (e.g., `1,234,567`)
- After JavaScript auto-refresh (AJAX call), commas disappear (e.g., `1234567`)
- Numbers flash with commas for a split second, then lose formatting

**Root Cause:**
PostgreSQL returns `Decimal` types from aggregate queries like `COUNT()` and `SUM()`. When Flask's `jsonify()` serializes these Decimal objects to JSON, they can:
1. Become strings: `"1234567"` instead of `1234567`
2. Lose their numeric type, preventing `.toLocaleString()` from working

**Solution:**
Explicitly convert all numeric values to `int()` before returning in JSON response:

```python
# ❌ BAD - Returns Decimal types
status_counts = get_status_counts(case_id)
return jsonify({
    'status_counts': status_counts  # Values might be Decimal objects
})

# ✅ GOOD - Convert to int
status_counts = get_status_counts(case_id)
status_counts = {k: int(v) for k, v in status_counts.items()}  # Force int conversion
return jsonify({
    'status_counts': status_counts  # Values are guaranteed integers
})
```

**JavaScript Side:**
Use `.toLocaleString()` to format numbers with commas:

```javascript
// Assuming data.status_counts.new is now a proper integer from backend
element.textContent = data.status_counts.new.toLocaleString();  // 1,234,567
```

**Files Affected (Historical):**
- `app/routes/files.py` - `/case/<id>/file-stats` endpoint (v1.11.1, v1.45.x)
- `app/templates/case_files.html` - Event status counts auto-refresh
- Any endpoint returning database COUNT/SUM results for JavaScript display

**Version History:**
- **v1.11.1:** First occurrence - System Dashboard PostgreSQL migration
- **v1.45.x:** Recurrence - Event Status Counts auto-refresh feature

**Prevention:**
- Always convert database aggregate results to `int()` before `jsonify()`
- Test auto-refresh functionality after adding new numeric displays
- Check browser console for type mismatches (`typeof` should be `number`)

---

## 2. Dropdown Styling Inconsistency

**Symptoms:**
- Different dropdowns across the application have inconsistent styling
- Some dropdowns have proper text color, others don't
- Inline styles scattered throughout templates making it hard to maintain consistent look
- Mix of hardcoded styles vs CSS classes

**Root Cause:**
Dropdown/select element styling was not properly centralized in the main CSS file. Developers were adding inline styles directly in templates, leading to:
1. Inconsistent appearance across pages
2. Difficulty maintaining a unified design
3. Text color not being explicitly set on select elements

**Solution:**
Centralize all dropdown styling in `/app/static/css/theme.css`:

```css
/* Standard form inputs and selects */
.form-group input,
.form-group textarea,
.form-group select,
.form-input,
.form-textarea,
.form-select {
    width: 100%;
    padding: var(--spacing-md);
    background: var(--color-bg-tertiary);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    color: var(--color-text-primary);  /* Explicitly set text color */
    font-size: 0.9375rem;
    transition: all var(--transition-fast);
}

/* Ensure select dropdowns have proper text color and cursor */
select.form-input,
select.form-select,
.form-group select {
    cursor: pointer;
    color: var(--color-text-primary);
}

/* Compact dropdown style for in-table or small contexts */
.dropdown-compact {
    font-size: 0.75rem;
    padding: 2px 4px;
    border-radius: 4px;
    min-width: 90px;
    background: var(--color-bg-tertiary);
    border: 1px solid var(--color-border);
    color: var(--color-text-primary);
    cursor: pointer;
}

.dropdown-compact:focus {
    outline: none;
    border-color: var(--color-primary);
}
```

**Usage in Templates:**
```html
<!-- ✅ GOOD - Regular dropdown -->
<select name="filter" class="form-input">
    <option value="all">All Events</option>
</select>

<!-- ✅ GOOD - Compact dropdown (for tables) -->
<select class="dropdown-compact">
    <option value="new">New</option>
</select>

<!-- ❌ BAD - Inline styles -->
<select style="padding: 8px; background: #f0f0f0; color: #333;">
    <option>Bad</option>
</select>
```

**Files Affected:**
- `app/static/css/theme.css` - Central CSS file with standardized dropdown styles
- `app/templates/search_events.html` - Status dropdown in events table (v1.45.x)
- All template files using `<select>` elements should use `form-input` or `dropdown-compact` classes

**Version History:**
- **v1.45.x:** Centralized dropdown styling and added explicit text color rules

**Prevention:**
- Always use `class="form-input"` for standard dropdowns
- Use `class="dropdown-compact"` for compact dropdowns in tables or tight spaces
- Never add inline styles for basic dropdown appearance
- Only use inline styles for dynamic coloring (e.g., status-based backgrounds)
- Reference the central CSS classes in code reviews

---

## 3. Button Styling Inconsistency

**Symptoms:**
- Different buttons across the application have inconsistent styling
- Inline styles with gradients, hardcoded colors scattered throughout templates
- Difficult to maintain a unified design system
- Mix of hardcoded color values vs CSS classes

**Root Cause:**
Button styling was not properly centralized in the main CSS file. Developers were adding inline styles directly in templates with gradients and custom colors, leading to:
1. Inconsistent appearance across pages
2. Difficulty maintaining a unified design
3. Hard to change colors globally when needed
4. Performance overhead from inline styles

**Solution:**
Centralize all button styling in `/app/static/css/theme.css` with clear variants:

```css
/* Base button - already defined */
.btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--spacing-sm);
    padding: 10px 20px;
    border: none;
    border-radius: var(--radius-md);
    font-size: 0.9375rem;
    font-weight: 500;
    cursor: pointer;
    transition: all var(--transition-fast);
    text-decoration: none;
    line-height: 1.5;
}

/* Standard variants */
.btn-primary { background: #3b82f6; color: white; }
.btn-secondary { background: var(--color-bg-tertiary); color: var(--color-text-primary); border: 1px solid var(--color-border); }
.btn-success { background: var(--color-success); color: white; }
.btn-warning { background: var(--color-warning); color: white; }
.btn-danger, .btn-error { background: var(--color-error); color: white; }

/* Purple button for AI features */
.btn-purple {
    background: #9b59b6;
    color: white;
}

.btn-purple:hover {
    background: #8e44ad;
    transform: translateY(-1px);
    box-shadow: 0 4px 6px -1px rgba(155, 89, 182, 0.4);
}

/* Add hover states with proper shadows and transforms */
```

**Usage in Templates:**
```html
<!-- ✅ GOOD - Use standard classes -->
<button class="btn btn-primary">Search</button>
<button class="btn btn-purple">AI Question</button>
<button class="btn btn-secondary">Cancel</button>
<button class="btn btn-sm btn-danger">Delete</button>

<!-- ❌ BAD - Inline styles with gradients -->
<button class="btn" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
    AI Question
</button>

<!-- ❌ BAD - Hardcoded colors -->
<button class="btn" style="background: #9b59b6; color: white;">Hunted</button>
<button class="btn" style="background: var(--color-success); color: white;">Export</button>
```

**Standard Button Colors:**
- **Primary (Blue):** Main actions (Search, Save, Export, Manage)
- **Secondary (Gray):** Cancel, Reset, neutral actions
- **Purple:** AI-related features only
- **Success (Green):** Confirmation actions
- **Warning (Orange):** Warning actions
- **Danger/Error (Red):** Destructive actions (Delete)

**Files Affected:**
- `app/static/css/theme.css` - Central CSS file with all button variants
- `app/templates/search_events.html` - All buttons standardized (v1.45.x)
- All template files using `<button>` elements should use standard button classes

**Version History:**
- **v1.45.x:** Centralized button styling, removed gradients, added `.btn-purple` for AI features

**Prevention:**
- Always use standard button classes: `btn-primary`, `btn-secondary`, `btn-purple`, `btn-success`, `btn-warning`, `btn-danger`
- Never use inline styles for button colors or backgrounds
- Only use `.btn-purple` for AI-related features
- Use `.btn-sm` or `.btn-lg` for size variants
- Reference the central CSS classes in code reviews

---

## 4. [Future Issue Placeholder]

When another repeating issue is identified, add it here following the same format:
- Symptoms
- Root Cause
- Solution (code examples)
- Files Affected
- Version History
- Prevention

---

## Contributing to This Document

When you encounter an issue for the **second time**:
1. Add it to this document with full details
2. Include code examples of the fix
3. Reference the version numbers where it occurred
4. Add prevention tips to avoid future occurrences

This document saves time by providing instant solutions to problems we've already solved.

