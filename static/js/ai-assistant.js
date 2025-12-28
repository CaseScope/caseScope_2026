/**
 * AI Assistant JavaScript
 * Handles all AI modal interactions
 */

let chatHistory = [];
let currentTab = 'chat';

// ============================================================================
// Modal Management
// ============================================================================

function openAiModal() {
    console.log('[AI Modal] Opening modal...');
    const modal = document.getElementById('aiModal');
    if (!modal) {
        console.error('[AI Modal] Modal element not found!');
        return;
    }
    console.log('[AI Modal] Current display:', modal.style.display);
    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
    console.log('[AI Modal] Modal opened, display set to flex');
}

function closeAiModal() {
    console.log('[AI Modal] Closing modal...');
    const modal = document.getElementById('aiModal');
    if (modal) {
        console.log('[AI Modal] Current display:', modal.style.display);
        modal.style.display = 'none';
        document.body.style.overflow = 'auto';
        console.log('[AI Modal] Modal closed');
    } else {
        console.error('[AI Modal] Modal element not found!');
    }
}

// Initialize modal event listeners once DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('[AI Modal] Initializing modal...');
    const modal = document.getElementById('aiModal');
    if (!modal) {
        console.error('[AI Modal] Modal element not found in DOM!');
        return;
    }
    
    console.log('[AI Modal] Modal found, initial display:', modal.style.display);
    
    // Close on outside click
    modal.addEventListener('click', function(event) {
        if (event.target === modal) {
            console.log('[AI Modal] Outside click detected');
            closeAiModal();
        }
    });
    
    // ESC key to close
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape' && modal.style.display === 'flex') {
            console.log('[AI Modal] ESC key pressed');
            closeAiModal();
        }
    });
    
    // Initialize tab switching
    const tabs = document.querySelectorAll('.modal-tab');
    console.log('[AI Modal] Found', tabs.length, 'tabs');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            switchTab(tab.dataset.tab);
        });
    });
    
    // Check AI status on dashboard
    if (document.getElementById('openAiAssistant')) {
        checkAIStatus();
    }
    
    console.log('[AI Modal] Initialization complete');
});

function switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.modal-tab').forEach(tab => {
        tab.classList.remove('active');
        if (tab.dataset.tab === tabName) {
            tab.classList.add('active');
        }
    });
    
    // Update tab content
    document.querySelectorAll('.modal-tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(`${tabName}-tab`).classList.add('active');
    
    currentTab = tabName;
}

// ============================================================================
// AI Status Check
// ============================================================================

async function checkAIStatus() {
    try {
        const response = await fetch('/api/ai/status');
        const data = await response.json();
        
        const indicator = document.getElementById('ai-status-indicator');
        const button = document.getElementById('openAiAssistant');
        const message = document.getElementById('ai-status-message');
        
        if (data.available && data.status === 'operational') {
            indicator.innerHTML = '<span class="badge badge-success">✓ Online</span>';
            button.disabled = false;
            button.onclick = openAiModal;
            message.textContent = 'AI features ready';
            message.className = 'text-small text-success mt-2';
        } else {
            indicator.innerHTML = '<span class="badge badge-warning">⚠ Degraded</span>';
            button.disabled = true;
            message.textContent = data.message || 'AI unavailable';
            message.className = 'text-small text-warning mt-2';
        }
    } catch (error) {
        const indicator = document.getElementById('ai-status-indicator');
        const message = document.getElementById('ai-status-message');
        indicator.innerHTML = '<span class="badge badge-danger">✗ Offline</span>';
        message.textContent = 'AI service unavailable';
        message.className = 'text-small text-danger mt-2';
    }
}

// ============================================================================
// Chat Functions
// ============================================================================

async function sendChatMessage() {
    const input = document.getElementById('chatInput');
    const message = input.value.trim();
    
    if (!message) return;
    
    // Add user message to chat
    addChatMessage('user', message);
    input.value = '';
    
    // Show loading
    const loadingId = addChatLoading();
    
    // Disable send button
    const sendBtn = document.getElementById('chatSendBtn');
    sendBtn.disabled = true;
    sendBtn.textContent = 'Thinking...';
    
    try {
        const response = await fetch('/api/ai/chat', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                message: message,
                history: chatHistory.slice(-10)
            })
        });
        
        const data = await response.json();
        
        // Remove loading
        removeChatLoading(loadingId);
        
        if (data.success) {
            // Add assistant response
            addChatMessage('assistant', data.response, data.patterns_used);
            
            // Update history
            chatHistory.push(
                {role: 'user', content: message},
                {role: 'assistant', content: data.response}
            );
        } else {
            addChatMessage('assistant', `Error: ${data.error || 'Unknown error'}`, null, true);
        }
    } catch (error) {
        removeChatLoading(loadingId);
        addChatMessage('assistant', `Error: ${error.message}`, null, true);
    } finally {
        sendBtn.disabled = false;
        sendBtn.textContent = 'Send';
    }
}

function addChatMessage(role, content, patterns = null, isError = false) {
    const messagesDiv = document.getElementById('chatMessages');
    const messageDiv = document.createElement('div');
    messageDiv.className = `chat-message ${role}`;
    
    const avatar = role === 'user' ? '👤' : '🤖';
    
    let patternsHTML = '';
    if (patterns && patterns.length > 0) {
        patternsHTML = '<div class="chat-patterns"><strong>Referenced:</strong><br>';
        patterns.forEach(p => {
            patternsHTML += `<span class="pattern-badge">[${p.source.toUpperCase()}] ${p.title}</span>`;
        });
        patternsHTML += '</div>';
    }
    
    messageDiv.innerHTML = `
        <div class="chat-avatar">${avatar}</div>
        <div class="chat-bubble ${isError ? 'text-danger' : ''}">
            ${content.replace(/\n/g, '<br>')}
            ${patternsHTML}
        </div>
    `;
    
    messagesDiv.appendChild(messageDiv);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function addChatLoading() {
    const messagesDiv = document.getElementById('chatMessages');
    const loadingDiv = document.createElement('div');
    const loadingId = 'loading-' + Date.now();
    loadingDiv.id = loadingId;
    loadingDiv.className = 'chat-loading';
    loadingDiv.innerHTML = `
        <div class="spinner-border spinner-border-sm" role="status"></div>
        <span>AI is thinking...</span>
    `;
    messagesDiv.appendChild(loadingDiv);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
    return loadingId;
}

function removeChatLoading(loadingId) {
    const loadingDiv = document.getElementById(loadingId);
    if (loadingDiv) {
        loadingDiv.remove();
    }
}

// ============================================================================
// Natural Language Query Functions
// ============================================================================

async function executeNLQuery() {
    const input = document.getElementById('queryInput');
    const question = input.value.trim();
    
    if (!question) {
        alert('Please enter a question');
        return;
    }
    
    // Easter egg check - case insensitive and punctuation insensitive
    const normalizedQuestion = question.toLowerCase().replace(/[^\w\s]/g, '');
    if (normalizedQuestion.includes('airspeed') && normalizedQuestion.includes('unladen') && normalizedQuestion.includes('swallow')) {
        showSwallowEasterEgg();
        return;
    }
    
    const resultsDiv = document.getElementById('queryResults');
    resultsDiv.style.display = 'block';
    resultsDiv.innerHTML = '<div class="text-center"><div class="spinner-border" role="status"></div><p class="mt-2">Searching events...</p></div>';
    
    try {
        const response = await fetch('/api/ai/query', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({question: question, limit: 50})
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayQueryResults(data);
        } else {
            resultsDiv.innerHTML = `<div class="alert alert-danger">Error: ${data.error || 'Query failed'}</div>`;
        }
    } catch (error) {
        resultsDiv.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
    }
}

function displayQueryResults(data) {
    // Stats
    const statsHTML = `
        <div class="card p-3 mb-3">
            <div class="grid grid-3">
                <div>
                    <div class="text-small text-muted">Events Found</div>
                    <div class="fw-bold text-large">${data.event_count}</div>
                </div>
                <div>
                    <div class="text-small text-muted">Total Matches</div>
                    <div class="fw-bold text-large">${data.total_hits}</div>
                </div>
                <div>
                    <div class="text-small text-muted">Execution Time</div>
                    <div class="fw-bold text-large">${data.execution_time_ms.toFixed(0)}ms</div>
                </div>
            </div>
        </div>
    `;
    document.getElementById('queryStats').innerHTML = statsHTML;
    
    // Patterns used
    if (data.patterns_used && data.patterns_used.length > 0) {
        let patternsHTML = '<h4>Patterns Used:</h4><div class="grid grid-2">';
        data.patterns_used.forEach(p => {
            patternsHTML += `
                <div class="pattern-card ${p.source}">
                    <div class="fw-bold">[${p.source.toUpperCase()}] ${p.title}</div>
                    <div class="text-small text-muted">Score: ${p.score.toFixed(3)}</div>
                </div>
            `;
        });
        patternsHTML += '</div>';
        document.getElementById('queryPatterns').innerHTML = patternsHTML;
    }
    
    // DSL Query
    document.getElementById('queryDSL').textContent = JSON.stringify(data.dsl_query, null, 2);
    
    // Events
    let eventsHTML = '<h4>Events:</h4>';
    if (data.events && data.events.length > 0) {
        data.events.forEach(event => {
            eventsHTML += `
                <div class="event-card">
                    <div class="grid grid-3 mb-2">
                        <div>
                            <div class="text-small text-muted">Event ID</div>
                            <div class="fw-bold">${event.event_id || event.normalized_event_id || 'N/A'}</div>
                        </div>
                        <div>
                            <div class="text-small text-muted">Computer</div>
                            <div class="fw-bold">${event.normalized_computer || 'N/A'}</div>
                        </div>
                        <div>
                            <div class="text-small text-muted">Timestamp</div>
                            <div class="fw-bold">${event.normalized_timestamp || 'N/A'}</div>
                        </div>
                    </div>
                    <div class="text-small">
                        ${(event.search_blob || '').substring(0, 200)}...
                    </div>
                </div>
            `;
        });
    } else {
        eventsHTML += '<p class="text-muted">No events found</p>';
    }
    document.getElementById('queryEvents').innerHTML = eventsHTML;
    
    // Rebuild results div
    document.getElementById('queryResults').innerHTML = `
        <h3>Results</h3>
        <div id="queryStats">${document.getElementById('queryStats').innerHTML}</div>
        <div id="queryPatterns">${document.getElementById('queryPatterns').innerHTML}</div>
        <details class="mb-3">
            <summary class="cursor-pointer">Generated OpenSearch DSL Query</summary>
            <pre class="dsl-preview">${document.getElementById('queryDSL').textContent}</pre>
        </details>
        <div id="queryEvents">${eventsHTML}</div>
    `;
}

function clearQueryResults() {
    document.getElementById('queryInput').value = '';
    document.getElementById('queryResults').style.display = 'none';
}

// ============================================================================
// Event Analysis Functions
// ============================================================================

async function analyzeEvents() {
    const input = document.getElementById('analyzeInput').value.trim();
    const question = document.getElementById('analyzeQuestion').value.trim() || 'What happened?';
    
    if (!input) {
        alert('Please paste events to analyze');
        return;
    }
    
    let events;
    try {
        events = JSON.parse(input);
        if (!Array.isArray(events)) {
            events = [events];
        }
    } catch (e) {
        alert('Invalid JSON. Please paste valid JSON array of events.');
        return;
    }
    
    const resultsDiv = document.getElementById('analyzeResults');
    resultsDiv.style.display = 'block';
    resultsDiv.innerHTML = '<div class="text-center"><div class="spinner-border" role="status"></div><p class="mt-2">Analyzing events...</p></div>';
    
    try {
        const response = await fetch('/api/ai/analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({events: events, question: question})
        });
        
        const data = await response.json();
        
        if (data.success) {
            let analysisHTML = `<h3>Analysis</h3>`;
            analysisHTML += `<div class="card p-3 mb-3">${data.analysis.replace(/\n/g, '<br>')}</div>`;
            
            if (data.patterns_referenced && data.patterns_referenced.length > 0) {
                analysisHTML += '<h4>Referenced Patterns:</h4><div class="grid grid-2">';
                data.patterns_referenced.forEach(p => {
                    analysisHTML += `
                        <div class="pattern-card ${p.source}">
                            <div class="fw-bold">[${p.source.toUpperCase()}] ${p.title}</div>
                            <div class="text-small text-muted">Score: ${p.score.toFixed(3)}</div>
                        </div>
                    `;
                });
                analysisHTML += '</div>';
            }
            
            resultsDiv.innerHTML = analysisHTML;
        } else {
            resultsDiv.innerHTML = `<div class="alert alert-danger">Error: ${data.error || 'Analysis failed'}</div>`;
        }
    } catch (error) {
        resultsDiv.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
    }
}

// ============================================================================
// IOC Extraction Functions
// ============================================================================

async function extractIOCs() {
    const input = document.getElementById('iocInput').value.trim();
    
    if (!input) {
        alert('Please paste text to extract IOCs from');
        return;
    }
    
    const resultsDiv = document.getElementById('iocResults');
    resultsDiv.style.display = 'block';
    resultsDiv.innerHTML = '<div class="text-center"><div class="spinner-border" role="status"></div><p class="mt-2">Extracting IOCs...</p></div>';
    
    try {
        const response = await fetch('/api/ai/ioc', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text: input})
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayIOCs(data.iocs, data.total_iocs);
        } else {
            resultsDiv.innerHTML = `<div class="alert alert-danger">Error: ${data.error || 'Extraction failed'}</div>`;
        }
    } catch (error) {
        resultsDiv.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
    }
}

function displayIOCs(iocs, total) {
    document.getElementById('iocCount').textContent = total;
    
    // IP Addresses
    displayIOCCategory('iocIP', 'iocIPList', iocs.ip_addresses || []);
    
    // Domains
    displayIOCCategory('iocDomain', 'iocDomainList', iocs.domains || []);
    
    // URLs
    displayIOCCategory('iocURL', 'iocURLList', iocs.urls || []);
    
    // Hashes
    const allHashes = [
        ...(iocs.file_hashes?.md5 || []),
        ...(iocs.file_hashes?.sha1 || []),
        ...(iocs.file_hashes?.sha256 || [])
    ];
    displayIOCCategory('iocHash', 'iocHashList', allHashes);
    
    // Emails
    displayIOCCategory('iocEmail', 'iocEmailList', iocs.email_addresses || []);
    
    // Files
    displayIOCCategory('iocFile', 'iocFileList', iocs.file_names || []);
    
    // Registry
    displayIOCCategory('iocRegistry', 'iocRegistryList', iocs.registry_keys || []);
    
    // CVEs
    displayIOCCategory('iocCVE', 'iocCVEList', iocs.cve_ids || []);
}

function displayIOCCategory(categoryId, listId, items) {
    const categoryDiv = document.getElementById(categoryId);
    const listDiv = document.getElementById(listId);
    
    if (items.length > 0) {
        categoryDiv.style.display = 'block';
        listDiv.innerHTML = items.map(item => 
            `<div class="ioc-badge">${item}</div>`
        ).join('');
    } else {
        categoryDiv.style.display = 'none';
    }
}

function clearIOCResults() {
    document.getElementById('iocInput').value = '';
    document.getElementById('iocResults').style.display = 'none';
}

// ============================================================================
// Easter Egg Functions
// ============================================================================

function showSwallowEasterEgg() {
    // Create modal if it doesn't exist
    let modal = document.getElementById('swallowEasterEggModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'swallowEasterEggModal';
        modal.className = 'modal-overlay';
        modal.style.display = 'none';
        modal.innerHTML = `
            <div class="modal-container" onclick="event.stopPropagation()" style="max-width: 400px;">
                <div class="modal-header">
                    <h2 class="modal-title">🦅 Airspeed Velocity</h2>
                    <button class="modal-close" onclick="closeSwallowEasterEgg(event)">×</button>
                </div>
                <div class="modal-body">
                    <p style="font-size: 20px; text-align: center; margin: 24px 0; line-height: 1.6; font-weight: 500;">
                        What do you mean? African or European?
                    </p>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-primary" onclick="closeSwallowEasterEgg(event)">I Don't Know That!</button>
                </div>
            </div>
        `;
        modal.onclick = function(event) {
            if (event.target === modal) {
                closeSwallowEasterEgg(event);
            }
        };
        document.body.appendChild(modal);
    }
    modal.style.display = 'flex';
}

function closeSwallowEasterEgg(evt) {
    if (evt) evt.stopPropagation();
    const modal = document.getElementById('swallowEasterEggModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// ESC key handler for swallow easter egg
document.addEventListener('keydown', function(evt) {
    if (evt.key === 'Escape') {
        const modal = document.getElementById('swallowEasterEggModal');
        if (modal && modal.style.display === 'flex') {
            closeSwallowEasterEgg(evt);
        }
    }
});

