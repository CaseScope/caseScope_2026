# Info Tiles Component System

**Version:** 1.0.0  
**Date:** December 17, 2025  
**Status:** Active

## Overview

The Info Tiles component system provides standardized, reusable tiles for displaying system information, metrics, and status data across the CaseScope platform.

## Design Principles

- **Consistency:** All information tiles follow the same visual design
- **Readability:** Font sizes optimized for helper text and values
- **Flexibility:** Supports various content types and layouts
- **Responsive:** Adapts to different screen sizes automatically

## CSS Classes

### Grid Container

```html
<div class="info-tiles-grid">
    <!-- Tiles go here -->
</div>
```

**Properties:**
- Auto-fit grid layout (min: 320px, max: 1fr)
- Gap: `var(--spacing-lg)`
- Margin bottom: `var(--spacing-xl)`

### Tile Structure

```html
<div class="info-tile">
    <div class="info-tile-header">
        <span class="info-tile-icon">📊</span>
        <h2 class="info-tile-title">Tile Title</h2>
    </div>
    
    <div class="info-tile-row">
        <div class="info-tile-label">Label Text</div>
        <div class="info-tile-value">Value Text</div>
    </div>
    
    <!-- Additional rows as needed -->
</div>
```

## Typography Specifications

### Tile Header
- **Icon:** `font-size: 1.5rem`
- **Title:** `font-size: 1.125rem`, `font-weight: 600`

### Content Rows
- **Label:** `font-size: 0.875rem`, `font-weight: 500`, `color: var(--color-text-secondary)`
- **Value:** `font-size: 1.0625rem`, `font-weight: 600`, `color: var(--color-text-primary)`

These match the System Status tile design and provide optimal readability.

## Color Variants

Values can be colored using variant classes:

```html
<div class="info-tile-value success">Healthy</div>
<div class="info-tile-value warning">Warning</div>
<div class="info-tile-value error">Critical</div>
<div class="info-tile-value primary">16 cores</div>
```

**Available colors:**
- `.success` - Green (`var(--color-success)`)
- `.warning` - Orange (`var(--color-warning)`)
- `.error` - Red (`var(--color-error)`)
- `.primary` - Blue (`var(--color-primary)`)

## Compact Variant

For tiles with many rows of data:

```html
<div class="info-tile compact">
    <!-- Content -->
</div>
```

**Changes:**
- Reduced row spacing
- Label: `font-size: 0.8125rem`
- Value: `font-size: 0.9375rem`

## Complete Example

```html
<!-- System Status Dashboard -->
<div class="info-tiles-grid">
    <!-- System Status Tile -->
    <div class="info-tile">
        <div class="info-tile-header">
            <span class="info-tile-icon">📊</span>
            <h2 class="info-tile-title">System Status</h2>
        </div>
        
        <div class="info-tile-row">
            <div class="info-tile-label">OS Name & Version</div>
            <div class="info-tile-value">Linux 6.8.0-90-generic</div>
        </div>
        
        <div class="info-tile-row">
            <div class="info-tile-label">CPU Cores / Usage</div>
            <div class="info-tile-value">16 cores / 0.8%</div>
        </div>
        
        <div class="info-tile-row">
            <div class="info-tile-label">Memory Total / Used</div>
            <div class="info-tile-value">62.89 GB / 25.82 GB (41.1%)</div>
        </div>
        
        <div class="info-tile-row">
            <div class="info-tile-label">GPU</div>
            <div class="info-tile-value">Tesla P4 (7.5GB VRAM, Driver: 580.95.05)</div>
        </div>
    </div>
    
    <!-- Software Status Tile -->
    <div class="info-tile">
        <div class="info-tile-header">
            <span class="info-tile-icon">🔧</span>
            <h2 class="info-tile-title">Software Status</h2>
        </div>
        
        <div class="info-tile-row">
            <div class="info-tile-label">Python</div>
            <div class="info-tile-value">3.12.3</div>
        </div>
        
        <div class="info-tile-row">
            <div class="info-tile-label">PostgreSQL</div>
            <div class="info-tile-value">16.11</div>
        </div>
        
        <div class="info-tile-row">
            <div class="info-tile-label">OpenSearch</div>
            <div class="info-tile-value success">2.11.0</div>
        </div>
    </div>
</div>
```

## JavaScript Integration

### Dynamic Tile Creation

```javascript
function createInfoTile(icon, title, rows) {
    let rowsHtml = '';
    for (const [label, value] of Object.entries(rows)) {
        rowsHtml += `
            <div class="info-tile-row">
                <div class="info-tile-label">${label}</div>
                <div class="info-tile-value">${value}</div>
            </div>
        `;
    }
    
    return `
        <div class="info-tile">
            <div class="info-tile-header">
                <span class="info-tile-icon">${icon}</span>
                <h2 class="info-tile-title">${title}</h2>
            </div>
            ${rowsHtml}
        </div>
    `;
}

// Usage
const tileHtml = createInfoTile('📊', 'System Info', {
    'OS Version': 'Linux 6.8.0',
    'CPU Cores': '16',
    'Memory': '64 GB'
});

document.getElementById('container').innerHTML += tileHtml;
```

## Use Cases

### System Diagnostics
- Display system status, resources, and health metrics
- Show service states and monitoring data

### Case Statistics
- Display case file counts, event counts, and processing stats
- Show SIGMA violations and IOC matches

### Software Versions
- List installed software and their versions
- Display dependency information

### Resource Monitoring
- CPU, memory, disk usage
- GPU status and VRAM availability

## Migration from Old Tiles

### Old Style (diagnostics-tile)
```html
<div class="diagnostics-tile">
    <div class="tile-header">
        <h2>📊 System Status</h2>
    </div>
    <div class="status-card">
        <div class="status-card-title">Database</div>
        <div class="metric-label">Status:</div>
        <div class="metric-value">Healthy</div>
    </div>
</div>
```

### New Style (info-tile)
```html
<div class="info-tile">
    <div class="info-tile-header">
        <span class="info-tile-icon">🗄️</span>
        <h2 class="info-tile-title">Database</h2>
    </div>
    <div class="info-tile-row">
        <div class="info-tile-label">Status</div>
        <div class="info-tile-value success">Healthy</div>
    </div>
</div>
```

## Benefits

1. **Consistency:** All system information displays follow the same pattern
2. **Maintainability:** Single source of truth in `theme.css`
3. **Readability:** Optimized typography based on System Status design
4. **Flexibility:** Easy to add new tiles with consistent appearance
5. **Responsive:** Works across all screen sizes

## Files Modified

- **`app/static/css/theme.css`** - Added `.info-tile*` classes
- **`app/templates/diagnostics.html`** - Migrated to info-tile system
- Removed unused/redundant tile styles from template-specific CSS

---

**Last Updated:** December 17, 2025  
**Maintained By:** CaseScope Development Team

