// ZIP Expansion Functionality
// Handles expandable ZIP containers with pagination

const zipExpansionState = {}; // Track expanded ZIPs

async function toggleZipExpansion(containerId, containerName, totalFiles) {
    const row = document.querySelector(`tr[data-container-id="${containerId}"]`);
    if (!row) return;
    
    // Check if already expanded
    if (zipExpansionState[containerId]) {
        // Collapse
        const detailsRow = document.getElementById(`zip-details-${containerId}`);
        if (detailsRow) {
            detailsRow.remove();
        }
        zipExpansionState[containerId] = null;
        row.classList.remove('expanded');
        return;
    }
    
    // Expand
    row.classList.add('expanded');
    
    // Create details row
    const detailsRow = document.createElement('tr');
    detailsRow.id = `zip-details-${containerId}`;
    detailsRow.className = 'zip-details-row';
    detailsRow.innerHTML = `
        <td colspan="8" class="zip-details-cell">
            <div class="zip-details-container">
                <div class="zip-details-header">
                    <h4>📦 ${containerName} - ${totalFiles} files</h4>
                    <div class="zip-details-controls">
                        <button class="btn btn-sm btn-secondary" onclick="loadZipContents(${containerId}, 1, false)">
                            📋 Flat List
                        </button>
                        <button class="btn btn-sm btn-primary" onclick="loadZipContents(${containerId}, 1, true)">
                            🖥️ Group by System
                        </button>
                    </div>
                </div>
                <div id="zip-contents-${containerId}" class="zip-contents">
                    <div class="text-center p-4">
                        <div class="spinner-border" role="status"></div>
                        <p class="mt-2">Loading contents...</p>
                    </div>
                </div>
            </div>
        </td>
    `;
    
    row.after(detailsRow);
    
    // Load contents (default: grouped)
    await loadZipContents(containerId, 1, true);
    
    zipExpansionState[containerId] = { page: 1, grouped: true };
}

async function loadZipContents(containerId, page = 1, grouped = false) {
    const contentsDiv = document.getElementById(`zip-contents-${containerId}`);
    if (!contentsDiv) return;
    
    contentsDiv.innerHTML = `
        <div class="text-center p-4">
            <div class="spinner-border" role="status"></div>
            <p class="mt-2">Loading${grouped ? ' grouped' : ''} contents...</p>
        </div>
    `;
    
    try {
        const url = grouped 
            ? `/case/${caseId}/files/${containerId}/contents?group_by=system`
            : `/case/${caseId}/files/${containerId}/contents?page=${page}&per_page=50`;
        
        const response = await fetch(url);
        if (!response.ok) throw new Error('Failed to load contents');
        
        const data = await response.json();
        
        if (grouped) {
            renderGroupedContents(containerId, data);
        } else {
            renderPaginatedContents(containerId, data);
        }
        
        zipExpansionState[containerId] = { page, grouped };
    } catch (error) {
        console.error('Error loading ZIP contents:', error);
        contentsDiv.innerHTML = `
            <div class="alert alert-error">
                <strong>Error loading contents:</strong> ${error.message}
            </div>
        `;
    }
}

function renderGroupedContents(containerId, data) {
    const contentsDiv = document.getElementById(`zip-contents-${containerId}`);
    if (!contentsDiv) return;
    
    let html = `<div class="zip-grouped-contents">`;
    
    for (const system of data.systems) {
        html += `
            <div class="system-group">
                <div class="system-group-header" onclick="toggleSystemGroup('${containerId}-${system.system}')">
                    <span class="system-toggle" id="toggle-${containerId}-${system.system}">▶</span>
                    <strong>🖥️ ${system.system}</strong>
                    <span class="badge badge-info">${system.file_count} files</span>
                </div>
                <div class="system-group-content" id="group-${containerId}-${system.system}" style="display: none;">
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th>Filename</th>
                                <th>Type</th>
                                <th>Events</th>
                                <th>Index</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
        `;
        
        for (const file of system.files) {
            const statusBadge = getStatusBadge(file.status);
            const indexBadge = file.target_index ? `<span class="badge badge-secondary">${file.target_index}</span>` : '-';
            
            html += `
                <tr>
                    <td><span class="text-small">${file.filename}</span></td>
                    <td><span class="badge badge-info">${file.file_type}</span></td>
                    <td>${formatNumber(file.event_count || 0)}</td>
                    <td>${indexBadge}</td>
                    <td>${statusBadge}</td>
                </tr>
            `;
        }
        
        html += `
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    }
    
    html += `</div>`;
    contentsDiv.innerHTML = html;
}

function renderPaginatedContents(containerId, data) {
    const contentsDiv = document.getElementById(`zip-contents-${containerId}`);
    if (!contentsDiv) return;
    
    let html = `
        <div class="zip-flat-contents">
            <table class="table table-sm">
                <thead>
                    <tr>
                        <th>Filename</th>
                        <th>System</th>
                        <th>Type</th>
                        <th>Events</th>
                        <th>Index</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
    `;
    
    for (const file of data.files) {
        const statusBadge = getStatusBadge(file.status);
        const indexBadge = file.target_index ? `<span class="badge badge-secondary">${file.target_index}</span>` : '-';
        const system = file.source_system || '-';
        
        html += `
            <tr>
                <td><span class="text-small">${file.filename}</span></td>
                <td><span class="badge badge-secondary">${system}</span></td>
                <td><span class="badge badge-info">${file.file_type}</span></td>
                <td>${formatNumber(file.event_count || 0)}</td>
                <td>${indexBadge}</td>
                <td>${statusBadge}</td>
            </tr>
        `;
    }
    
    html += `
                </tbody>
            </table>
    `;
    
    // Add pagination controls
    if (data.total_pages > 1) {
        html += `
            <div class="pagination-controls">
                <button class="btn btn-sm btn-secondary" 
                        onclick="loadZipContents(${containerId}, ${data.page - 1}, false)"
                        ${!data.has_prev ? 'disabled' : ''}>
                    ← Previous
                </button>
                <span class="pagination-info">Page ${data.page} of ${data.total_pages}</span>
                <button class="btn btn-sm btn-secondary" 
                        onclick="loadZipContents(${containerId}, ${data.page + 1}, false)"
                        ${!data.has_next ? 'disabled' : ''}>
                    Next →
                </button>
            </div>
        `;
    }
    
    html += `</div>`;
    contentsDiv.innerHTML = html;
}

function toggleSystemGroup(groupId) {
    const content = document.getElementById(`group-${groupId}`);
    const toggle = document.getElementById(`toggle-${groupId}`);
    
    if (content.style.display === 'none') {
        content.style.display = 'block';
        toggle.textContent = '▼';
    } else {
        content.style.display = 'none';
        toggle.textContent = '▶';
    }
}

function getStatusBadge(status) {
    const badges = {
        'indexed': '<span class="badge badge-success">✓ Indexed</span>',
        'processing': '<span class="badge badge-info">Processing...</span>',
        'parsing': '<span class="badge badge-info">Parsing...</span>',
        'pending': '<span class="badge badge-secondary">Pending</span>',
        'failed': '<span class="badge badge-error">Failed</span>',
        'extracting': '<span class="badge badge-info">Extracting...</span>'
    };
    return badges[status] || `<span class="badge badge-secondary">${status}</span>`;
}

function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

