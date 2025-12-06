"""
Event Details Modal Module

This module provides a clean, centralized way to fetch and display event details
in a modal dialog. Used by the search page when users click on event rows.

Author: CaseScope 2026
Version: 1.0.0
"""

from flask import jsonify, current_app
from opensearchpy import OpenSearch
import os


def get_event_details(case_id: int, event_id: str, index_name: str) -> dict:
    """
    Fetch full event details from OpenSearch and return formatted data.
    
    Args:
        case_id: The case ID
        event_id: The OpenSearch document ID
        index_name: The OpenSearch index name
        
    Returns:
        dict: {
            'event_id': str,
            'index_name': str,
            'fields': [{'field': str, 'value': str}, ...],
            'has_sigma': bool,
            'sigma_rule': str or None,
            'has_ioc': bool,
            'iocs': [str, ...]  # List of IOC values that match this event
        }
    """
    from models import IOCMatch, IOC
    from flask import current_app
    
    try:
        # Use the existing OpenSearch client from the app
        # This ensures we use the same connection settings
        from main import opensearch_client as client
        
        # Fetch event from OpenSearch
        event = client.get(index=index_name, id=event_id)
        if not event or '_source' not in event:
            return {'error': 'Event not found'}
        
        source = event['_source']
        
        # Extract SIGMA info
        has_sigma = source.get('has_sigma', False)
        sigma_rule = source.get('sigma_rule', None)
        
        # Extract IOC info
        has_ioc = source.get('has_ioc', False)
        ioc_values = []
        
        # Extract event status
        event_status = source.get('event_status', 'new')
        
        if has_ioc:
            # Fetch IOC matches for this event
            matches = IOCMatch.query.filter_by(
                case_id=case_id,
                event_id=event_id
            ).all()
            
            # Get the actual IOC values
            for match in matches:
                ioc = IOC.query.get(match.ioc_id)
                if ioc:
                    ioc_values.append(ioc.ioc_value.lower())
        
        # Keep the raw source for nested rendering
        skip_fields = {'search_blob', 'event_status'}  # Internal fields
        
        return {
            'event_id': event_id,
            'index_name': index_name,
            'source': source,
            'skip_fields': skip_fields,
            'has_sigma': has_sigma,
            'sigma_rule': sigma_rule,
            'has_ioc': has_ioc,
            'iocs': ioc_values,
            'event_status': event_status
        }
        
    except Exception as e:
        current_app.logger.error(f"Error fetching event details: {e}")
        return {'error': str(e)}


def render_event_details_html(event_data: dict) -> str:
    """
    Render event details as HTML for the modal with nested field support.
    
    Args:
        event_data: Dict from get_event_details()
        
    Returns:
        str: HTML string for modal body
    """
    import html
    import json
    
    if 'error' in event_data:
        return f'<div class="alert alert-error">{html.escape(str(event_data["error"]))}</div>'
    
    source = event_data.get('source', {})
    skip_fields = event_data.get('skip_fields', set())
    iocs = event_data.get('iocs', [])
    
    def render_value(value, path='', depth=0):
        """Recursively render a value (handles nested dicts/lists)"""
        if isinstance(value, dict):
            # Nested dictionary - render as expandable tree
            html_parts = []
            html_parts.append(f'<div class="nested-dict" style="margin-left: {depth * 20}px;">')
            for key in sorted(value.keys()):
                field_path = f'{path}.{key}' if path else key
                html_parts.append(render_field(key, value[key], field_path, depth + 1))
            html_parts.append('</div>')
            return ''.join(html_parts)
        elif isinstance(value, list):
            # List - render as expandable array
            if len(value) == 0:
                return '<span class="text-muted">[]</span>'
            elif len(value) == 1:
                # Single item - render inline
                return render_value(value[0], path, depth)
            else:
                # Multiple items - render as expandable list
                html_parts = []
                html_parts.append(f'<div class="nested-list" style="margin-left: {depth * 20}px;">')
                for idx, item in enumerate(value):
                    if isinstance(item, (dict, list)):
                        html_parts.append(f'<div class="list-item"><strong>[{idx}]</strong></div>')
                        html_parts.append(render_value(item, f'{path}[{idx}]', depth + 1))
                    else:
                        item_str = html.escape(str(item))
                        html_parts.append(f'<div class="list-item">• {item_str}</div>')
                html_parts.append('</div>')
                return ''.join(html_parts)
        elif value is None:
            return '<span class="text-muted">(null)</span>'
        else:
            # Simple value - render as string
            value_str = html.escape(str(value))
            value_lower = str(value).lower()
            is_ioc = any(ioc in value_lower for ioc in iocs)
            if is_ioc:
                return f'🚨 <span class="event-details-ioc-value">{value_str}</span>'
            return value_str
    
    def render_field(field_name, field_value, field_path, depth=0):
        """Render a single field (top-level or nested)"""
        field_name_html = html.escape(str(field_name))
        field_path_html = html.escape(field_path)
        
        # Check if this is a nested structure
        is_nested = isinstance(field_value, (dict, list))
        
        if is_nested and isinstance(field_value, dict) and len(field_value) > 0:
            # Nested dict - expandable
            unique_id = field_path.replace('.', '_').replace('[', '_').replace(']', '_')
            html_parts = []
            html_parts.append(f'''
            <tr class="nested-field-row">
                <td class="event-details-field" colspan="3">
                    <span class="nested-toggle" onclick="toggleNested('{unique_id}')" style="cursor: pointer;">
                        ▶ <strong>{field_name_html}</strong> <span class="text-muted">({len(field_value)} fields)</span>
                    </span>
                </td>
            </tr>
            <tr id="nested_{unique_id}" style="display: none;">
                <td colspan="3" style="padding: 0;">
                    <table class="table table-event-details nested-table">
            ''')
            # Render nested fields
            for key in sorted(field_value.keys()):
                nested_path = f'{field_path}.{key}'
                html_parts.append(render_field(key, field_value[key], nested_path, depth + 1))
            html_parts.append('''
                    </table>
                </td>
            </tr>
            ''')
            return ''.join(html_parts)
        elif is_nested and isinstance(field_value, list) and len(field_value) > 1:
            # List with multiple items - expandable
            unique_id = field_path.replace('.', '_').replace('[', '_').replace(']', '_')
            html_parts = []
            html_parts.append(f'''
            <tr class="nested-field-row">
                <td class="event-details-field" colspan="3">
                    <span class="nested-toggle" onclick="toggleNested('{unique_id}')" style="cursor: pointer;">
                        ▶ <strong>{field_name_html}</strong> <span class="text-muted">({len(field_value)} items)</span>
                    </span>
                </td>
            </tr>
            <tr id="nested_{unique_id}" style="display: none;">
                <td colspan="3" style="padding-left: 30px;">
            ''')
            # Render list items
            for idx, item in enumerate(field_value):
                if isinstance(item, dict):
                    html_parts.append(f'<div style="margin: 10px 0;"><strong>[{idx}]</strong></div>')
                    html_parts.append('<table class="table table-event-details nested-table">')
                    for key in sorted(item.keys()):
                        html_parts.append(render_field(key, item[key], f'{field_path}[{idx}].{key}', depth + 1))
                    html_parts.append('</table>')
                else:
                    item_str = html.escape(str(item))
                    html_parts.append(f'<div>• {item_str}</div>')
            html_parts.append('''
                </td>
            </tr>
            ''')
            return ''.join(html_parts)
        else:
            # Simple field or single-item list - render as row with actions
            value_html = render_value(field_value, field_path, depth)
            
            # For action buttons, get the string value
            if isinstance(field_value, list) and len(field_value) == 1:
                field_value_str = str(field_value[0])
            elif isinstance(field_value, (dict, list)):
                field_value_str = json.dumps(field_value)
            else:
                field_value_str = str(field_value) if field_value is not None else ''
            
            field_value_js = html.escape(field_value_str).replace('\\', '\\\\').replace("'", "\\'").replace('"', '&quot;')
            field_name_js = field_name_html.replace('\\', '\\\\').replace("'", "\\'").replace('"', '&quot;')
            
            return f'''
            <tr>
                <td class="event-details-field">{field_name_html}</td>
                <td class="event-details-value">{value_html}</td>
                <td class="event-details-actions">
                    <div class="event-details-btn-group">
                        <button class="btn-icon btn-icon-ioc" onclick="openAddIOCModal('{field_value_js}', '{field_name_js}')" title="Add as IOC">
                            📌
                        </button>
                        <button class="btn-icon btn-icon-system" onclick="openAddSystemModal('{field_value_js}')" title="Add as System">
                            💻
                        </button>
                        <button class="btn-icon btn-icon-search" onclick="addToSearch('{field_name_js}', '{field_value_js}')" title="Add to Search">
                            🔍
                        </button>
                        <button class="btn-icon btn-icon-column" onclick="addAsColumn('{field_name_js}')" title="Add Column">
                            ➕
                        </button>
                    </div>
                </td>
            </tr>
            '''
    
    # Build HTML
    html_parts = ['<table class="table table-event-details">']
    
    # Render all top-level fields
    for field_name in sorted(source.keys()):
        if field_name not in skip_fields:
            html_parts.append(render_field(field_name, source[field_name], field_name))
    
    html_parts.append('</table>')
    
    # Add JavaScript for toggle functionality
    html_parts.append('''
    <script>
    function toggleNested(id) {
        const row = document.getElementById('nested_' + id);
        const toggle = event.currentTarget.querySelector('.nested-toggle') || event.currentTarget;
        if (row.style.display === 'none') {
            row.style.display = '';
            toggle.innerHTML = toggle.innerHTML.replace('▶', '▼');
        } else {
            row.style.display = 'none';
            toggle.innerHTML = toggle.innerHTML.replace('▼', '▶');
        }
    }
    </script>
    ''')
    
    return ''.join(html_parts)


