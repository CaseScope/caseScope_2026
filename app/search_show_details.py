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
        
        # Convert source dict to field list (sorted for consistency)
        fields = []
        skip_fields = {'search_blob', 'event_status'}  # Internal fields
        
        for field_name in sorted(source.keys()):
            if field_name not in skip_fields:
                value = source[field_name]
                # Convert to string for display
                if isinstance(value, list):
                    value = ', '.join(str(v) for v in value)
                elif value is None:
                    value = ''
                else:
                    value = str(value)
                
                fields.append({
                    'field': field_name,
                    'value': value
                })
        
        return {
            'event_id': event_id,
            'index_name': index_name,
            'fields': fields,
            'has_sigma': has_sigma,
            'sigma_rule': sigma_rule,
            'has_ioc': has_ioc,
            'iocs': ioc_values
        }
        
    except Exception as e:
        current_app.logger.error(f"Error fetching event details: {e}")
        return {'error': str(e)}


def render_event_details_html(event_data: dict) -> str:
    """
    Render event details as HTML for the modal.
    
    Args:
        event_data: Dict from get_event_details()
        
    Returns:
        str: HTML string for modal body
    """
    import html
    
    if 'error' in event_data:
        return f'<div class="alert alert-error">{html.escape(str(event_data["error"]))}</div>'
    
    html_parts = ['<table class="table table-event-details">']
    
    # Event fields (SIGMA banner moved to modal header, not in table)
    iocs = event_data.get('iocs', [])
    for field in event_data['fields']:
        field_name = html.escape(str(field['field']))
        field_value = html.escape(str(field['value']))
        
        # Check if this value matches an IOC
        value_lower = field['value'].lower()
        is_ioc = any(ioc in value_lower for ioc in iocs)
        
        # Build the row
        value_class = 'event-details-ioc-value' if is_ioc else 'event-details-value'
        value_display = f'🚨 {field_value}' if is_ioc else field_value
        
        # Escape for JavaScript - replace quotes and backslashes
        field_value_js = field_value.replace('\\', '\\\\').replace("'", "\\'").replace('"', '&quot;')
        field_name_js = field_name.replace('\\', '\\\\').replace("'", "\\'").replace('"', '&quot;')
        
        html_parts.append(f'''
        <tr>
            <td class="event-details-field">{field_name}</td>
            <td class="{value_class}">{value_display}</td>
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
        ''')
    
    html_parts.append('</table>')
    return ''.join(html_parts)

