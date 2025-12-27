/**
 * CaseScope 2026 - Main JavaScript
 * Core functionality
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
    
    // Auto-dismiss flash messages after 5 seconds
    const flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach(msg => {
        setTimeout(() => {
            msg.style.opacity = '0';
            setTimeout(() => msg.remove(), 300);
        }, 5000);
    });
});

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// Auto-dismiss flash messages after 5 seconds (moved to DOMContentLoaded above)

// Utility: Format numbers with commas
function formatNumber(num) {
    if (!num) return '0';
    return num.toLocaleString();
}

// Utility: Format file sizes
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

// Utility: Confirm action
function confirmAction(message) {
    return confirm(message);
}
