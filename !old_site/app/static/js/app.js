/**
 * CaseScope 2026 - Global JavaScript
 * Version: 1.0.0
 * 
 * Centralized UI interactions and theme management
 */

// ============================================================================
// THEME SWITCHING
// ============================================================================

function toggleTheme() {
    const currentTheme = localStorage.getItem('theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    localStorage.setItem('theme', newTheme);
    document.body.classList.toggle('light-theme');
    
    // Update theme icon
    const icon = document.getElementById('themeIcon');
    if (icon) {
        icon.textContent = newTheme === 'dark' ? '🌙' : '☀️';
    }
    
    console.log(`Theme switched to: ${newTheme}`);
}

// Apply saved theme on page load
document.addEventListener('DOMContentLoaded', function() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    if (savedTheme === 'light') {
        document.body.classList.add('light-theme');
        const icon = document.getElementById('themeIcon');
        if (icon) icon.textContent = '☀️';
    }
});


// ============================================================================
// CASE SELECTOR
// ============================================================================

function switchCase(caseId) {
    if (caseId) {
        window.location.href = `/select_case/${caseId}`;
    } else {
        window.location.href = '/clear_case';
    }
}


// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Format bytes to human-readable size
 */
function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

/**
 * Format timestamp to readable date
 */
function formatDate(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        top: 80px;
        right: 24px;
        padding: 16px 24px;
        background: var(--color-bg-secondary);
        border-left: 4px solid var(--color-${type === 'success' ? 'success' : type === 'error' ? 'error' : 'info'});
        border-radius: var(--radius-md);
        box-shadow: var(--shadow-lg);
        z-index: var(--z-tooltip);
        animation: slideInRight 0.3s ease-out;
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOutRight 0.3s ease-out';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

/**
 * Copy text to clipboard
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showToast('Copied to clipboard', 'success');
    } catch (err) {
        showToast('Failed to copy', 'error');
        console.error('Copy failed:', err);
    }
}

/**
 * Confirm dialog with custom styling
 */
function confirmAction(message, callback) {
    if (confirm(message)) {
        callback();
    }
}


// ============================================================================
// MOBILE SIDEBAR TOGGLE
// ============================================================================

let sidebarOpen = false;

function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    sidebarOpen = !sidebarOpen;
    if (sidebarOpen) {
        sidebar.classList.add('open');
    } else {
        sidebar.classList.remove('open');
    }
}

// Add mobile menu button on small screens
if (window.innerWidth <= 768) {
    document.addEventListener('DOMContentLoaded', function() {
        const header = document.querySelector('.header');
        const menuBtn = document.createElement('button');
        menuBtn.className = 'btn btn-secondary btn-sm';
        menuBtn.innerHTML = '☰';
        menuBtn.onclick = toggleSidebar;
        menuBtn.style.marginRight = 'auto';
        
        const headerLeft = header.querySelector('.header-left');
        if (headerLeft) {
            headerLeft.insertBefore(menuBtn, headerLeft.firstChild);
        }
    });
}


// ============================================================================
// GLOBAL ERROR HANDLING
// ============================================================================

window.addEventListener('error', function(e) {
    console.error('Global error:', e.error);
});

window.addEventListener('unhandledrejection', function(e) {
    console.error('Unhandled promise rejection:', e.reason);
});


// ============================================================================
// ANIMATIONS (CSS KEYFRAMES FOR TOAST)
// ============================================================================

const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);


// ============================================================================
// EXPORT FOR MODULE USE
// ============================================================================

window.CaseScope = {
    toggleTheme,
    switchCase,
    formatSize,
    formatDate,
    showToast,
    copyToClipboard,
    confirmAction
};

