"""
Noise Filter Utilities
Apply noise filtering rules to OpenSearch queries and event searches
"""

import re
import fnmatch
from models import NoiseFilterRule, NoiseFilterCategory, NoiseFilterStats
from main import db
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def build_noise_filter_query(case_id=None):
    """
    Build OpenSearch query filters to exclude events matching noise filter rules
    
    Args:
        case_id: Optional case ID for tracking statistics
    
    Returns:
        dict: OpenSearch query dict with must_not clauses for enabled filters
    """
    try:
        # Get all enabled filter rules from enabled categories
        enabled_categories = NoiseFilterCategory.query.filter_by(is_enabled=True).all()
        category_ids = [cat.id for cat in enabled_categories]
        
        if not category_ids:
            return {'bool': {'must_not': []}}
        
        rules = NoiseFilterRule.query.filter(
            NoiseFilterRule.category_id.in_(category_ids),
            NoiseFilterRule.is_enabled == True
        ).order_by(NoiseFilterRule.priority.asc()).all()
        
        if not rules:
            return {'bool': {'must_not': []}}
        
        must_not_clauses = []
        
        for rule in rules:
            clause = _build_filter_clause(rule)
            if clause:
                must_not_clauses.append(clause)
        
        logger.info(f"Built noise filter query with {len(must_not_clauses)} rules")
        
        return {'bool': {'must_not': must_not_clauses}}
        
    except Exception as e:
        logger.error(f"Error building noise filter query: {e}")
        return {'bool': {'must_not': []}}


def _build_filter_clause(rule):
    """
    Build a single OpenSearch query clause for a noise filter rule
    
    Supports:
    - Comma-separated patterns for OR logic: "pattern1,pattern2,pattern3"
    - AND logic using &&: "pattern1&&pattern2" (both must match)
    - Field exclusions: Skip fields listed in rule.exclude_fields
    
    Args:
        rule: NoiseFilterRule object
    
    Returns:
        dict: OpenSearch query clause
    """
    # Enhanced field mapping to support both EVTX and NDJSON/ECS formats
    field_mapping = {
        'process_name': [
            # EVTX fields
            'event_data.Image',
            'event_data.ProcessName',
            'event_data.ParentImage',
            'event_data.ParentProcessName',
            # NDJSON/ECS fields
            'process.name',
            'process.executable',
            'process.parent.name',
            'process.parent.executable',
            'process.pe.original_file_name',
            'process.parent.pe.original_file_name',
            # Catch-all search field
            'search_blob'
        ],
        'file_path': [
            'event_data.Image',
            'event_data.TargetFilename',
            'file.path',
            'file.name',
            'process.executable',
            'process.pe.path',
            'search_blob'
        ],
        'command_line': [
            'event_data.CommandLine',
            'event_data.ParentCommandLine',
            'process.command_line',
            'process.parent.command_line',
            'process.args',
            'search_blob'
        ],
        'hash': [
            'event_data.Hashes',
            'file.hash.sha256',
            'file.hash.md5',
            'hash',
            'process.hash.sha256',
            'process.hash.md5'
        ],
        'guid': [
            'event_data.ProcessGuid',
            'event_data.SessionId',
            'process.entity_id',
            'session.id'
        ],
        'network_connection': [
            'event_data.DestinationIp',
            'event_data.SourceIp',
            'destination.ip',
            'source.ip',
            'network.destination.ip',
            'network.source.ip'
        ]
    }
    
    fields = field_mapping.get(rule.filter_type, [])
    if not fields:
        logger.warning(f"Unknown filter type: {rule.filter_type}")
        return None
    
    # DEBUG: Log rule exclusions
    logger.info(f"[DEBUG] Rule '{rule.name}': exclude_fields = {repr(rule.exclude_fields)}")
    
    # Filter out excluded fields if specified
    if rule.exclude_fields:
        excluded = [f.strip() for f in rule.exclude_fields.split(',')]
        # Remove excluded fields from checking (but keep search_blob for broad matching)
        # The event-level matcher will handle search_blob exclusion intelligently
        fields = [f for f in fields if f not in excluded]
        logger.debug(f"Rule '{rule.name}' excluding fields: {excluded}, remaining: {len(fields)} fields")
    
    if not fields:
        logger.warning(f"Rule '{rule.name}' has no fields left after exclusions")
        return None
    
    pattern = rule.pattern
    if not rule.is_case_sensitive:
        pattern = pattern.lower()
    
    # Check for AND logic (&&)
    if '&&' in pattern:
        # AND logic: ALL patterns must match
        and_patterns = [p.strip() for p in pattern.split('&&')]
        must_clauses = []
        
        for and_pattern in and_patterns:
            # Each AND pattern can have OR logic (comma-separated)
            or_patterns = [p.strip() for p in and_pattern.split(',')]
            
            if rule.match_mode == 'exact':
                must_clauses.append({
                    'bool': {
                        'should': [
                            {'term' if rule.is_case_sensitive else 'match_phrase': {field: p}}
                            for field in fields for p in or_patterns
                        ],
                        'minimum_should_match': 1
                    }
                })
            elif rule.match_mode == 'contains':
                must_clauses.append({
                    'bool': {
                        'should': [
                            {'wildcard': {field: {'value': f'*{p}*', 'case_insensitive': not rule.is_case_sensitive}}}
                            for field in fields for p in or_patterns
                        ],
                        'minimum_should_match': 1
                    }
                })
            elif rule.match_mode == 'starts_with':
                must_clauses.append({
                    'bool': {
                        'should': [
                            {'prefix': {field: {'value': p, 'case_insensitive': not rule.is_case_sensitive}}}
                            for field in fields for p in or_patterns
                        ],
                        'minimum_should_match': 1
                    }
                })
            elif rule.match_mode == 'ends_with':
                must_clauses.append({
                    'bool': {
                        'should': [
                            {'wildcard': {field: {'value': f'*{p}', 'case_insensitive': not rule.is_case_sensitive}}}
                            for field in fields for p in or_patterns
                        ],
                        'minimum_should_match': 1
                    }
                })
            elif rule.match_mode == 'wildcard':
                must_clauses.append({
                    'bool': {
                        'should': [
                            {'wildcard': {field: {'value': p, 'case_insensitive': not rule.is_case_sensitive}}}
                            for field in fields for p in or_patterns
                        ],
                        'minimum_should_match': 1
                    }
                })
            elif rule.match_mode == 'regex':
                must_clauses.append({
                    'bool': {
                        'should': [
                            {'regexp': {field: {'value': p, 'case_insensitive': not rule.is_case_sensitive}}}
                            for field in fields for p in or_patterns
                        ],
                        'minimum_should_match': 1
                    }
                })
        
        # Return AND of all must clauses
        return {'bool': {'must': must_clauses}}
    
    else:
        # OR logic: ANY pattern matches (comma-separated)
        patterns = [p.strip() for p in pattern.split(',')]
        
        if rule.match_mode == 'exact':
            return {
                'bool': {
                    'should': [
                        {'term' if rule.is_case_sensitive else 'match_phrase': {field: p}}
                        for field in fields for p in patterns
                    ],
                    'minimum_should_match': 1
                }
            }
        
        elif rule.match_mode == 'contains':
            return {
                'bool': {
                    'should': [
                        {'wildcard': {field: {'value': f'*{p}*', 'case_insensitive': not rule.is_case_sensitive}}}
                        for field in fields for p in patterns
                    ],
                    'minimum_should_match': 1
                }
            }
        
        elif rule.match_mode == 'starts_with':
            return {
                'bool': {
                    'should': [
                        {'prefix': {field: {'value': p, 'case_insensitive': not rule.is_case_sensitive}}}
                        for field in fields for p in patterns
                    ],
                    'minimum_should_match': 1
                }
            }
        
        elif rule.match_mode == 'ends_with':
            return {
                'bool': {
                    'should': [
                        {'wildcard': {field: {'value': f'*{p}', 'case_insensitive': not rule.is_case_sensitive}}}
                        for field in fields for p in patterns
                    ],
                    'minimum_should_match': 1
                }
            }
        
        elif rule.match_mode == 'wildcard':
            return {
                'bool': {
                    'should': [
                        {'wildcard': {field: {'value': p, 'case_insensitive': not rule.is_case_sensitive}}}
                        for field in fields for p in patterns
                    ],
                    'minimum_should_match': 1
                }
            }
        
        elif rule.match_mode == 'regex':
            return {
                'bool': {
                    'should': [
                        {'regexp': {field: {'value': p, 'case_insensitive': not rule.is_case_sensitive}}}
                        for field in fields for p in patterns
                    ],
                    'minimum_should_match': 1
                }
            }
    
    return None
    """
    Build a single OpenSearch query clause for a noise filter rule
    
    Args:
        rule: NoiseFilterRule object
    
    Returns:
        dict: OpenSearch query clause
    """
    field_mapping = {
        'process_name': ['event_data.Image', 'event_data.ProcessName', 'process.name', 'process.executable'],
        'file_path': ['event_data.Image', 'event_data.TargetFilename', 'file.path', 'file.name'],
        'command_line': ['event_data.CommandLine', 'process.command_line', 'process.args'],
        'hash': ['event_data.Hashes', 'file.hash.sha256', 'file.hash.md5', 'hash'],
        'guid': ['event_data.ProcessGuid', 'event_data.SessionId', 'process.entity_id', 'session.id'],
        'network_connection': ['event_data.DestinationIp', 'event_data.SourceIp', 'destination.ip', 'source.ip']
    }
    
    fields = field_mapping.get(rule.filter_type, [])
    if not fields:
        logger.warning(f"Unknown filter type: {rule.filter_type}")
        return None
    
    pattern = rule.pattern
    if not rule.is_case_sensitive:
        pattern = pattern.lower()
    
    # Build query based on match mode
    if rule.match_mode == 'exact':
        # Exact match - use terms query
        return {
            'bool': {
                'should': [
                    {'term' if rule.is_case_sensitive else 'match_phrase': {field: pattern}}
                    for field in fields
                ],
                'minimum_should_match': 1
            }
        }
    
    elif rule.match_mode == 'contains':
        # Contains - use wildcard or match
        return {
            'bool': {
                'should': [
                    {'wildcard': {field: {'value': f'*{pattern}*', 'case_insensitive': not rule.is_case_sensitive}}}
                    for field in fields
                ],
                'minimum_should_match': 1
            }
        }
    
    elif rule.match_mode == 'starts_with':
        # Starts with - use prefix query
        return {
            'bool': {
                'should': [
                    {'prefix': {field: {'value': pattern, 'case_insensitive': not rule.is_case_sensitive}}}
                    for field in fields
                ],
                'minimum_should_match': 1
            }
        }
    
    elif rule.match_mode == 'ends_with':
        # Ends with - use wildcard
        return {
            'bool': {
                'should': [
                    {'wildcard': {field: {'value': f'*{pattern}', 'case_insensitive': not rule.is_case_sensitive}}}
                    for field in fields
                ],
                'minimum_should_match': 1
            }
        }
    
    elif rule.match_mode == 'wildcard':
        # Wildcard - use wildcard query
        return {
            'bool': {
                'should': [
                    {'wildcard': {field: {'value': pattern, 'case_insensitive': not rule.is_case_sensitive}}}
                    for field in fields
                ],
                'minimum_should_match': 1
            }
        }
    
    elif rule.match_mode == 'regex':
        # Regular expression - use regexp query
        return {
            'bool': {
                'should': [
                    {'regexp': {field: {'value': pattern, 'case_insensitive': not rule.is_case_sensitive}}}
                    for field in fields
                ],
                'minimum_should_match': 1
            }
        }
    
    return None


def apply_noise_filters_to_query(base_query, case_id=None):
    """
    Apply noise filters to an existing OpenSearch query
    
    Args:
        base_query: Existing OpenSearch query dict
        case_id: Optional case ID for tracking statistics
    
    Returns:
        dict: Modified query with noise filters applied
    """
    noise_filters = build_noise_filter_query(case_id)
    
    if not noise_filters['bool']['must_not']:
        # No filters to apply
        return base_query
    
    # Merge with existing query
    if 'query' not in base_query:
        base_query['query'] = {'bool': {}}
    
    if 'bool' not in base_query['query']:
        base_query['query'] = {'bool': base_query['query']}
    
    # Add must_not clauses
    if 'must_not' not in base_query['query']['bool']:
        base_query['query']['bool']['must_not'] = []
    
    base_query['query']['bool']['must_not'].extend(noise_filters['bool']['must_not'])
    
    return base_query


def check_event_against_filters(event_data, return_details=False):
    """
    Check if an event matches any noise filter rules (for in-memory filtering)
    
    Args:
        event_data: Event data dict
        return_details: If True, return detailed match information
    
    Returns:
        If return_details=False: tuple (should_hide, matched_rule_name)
        If return_details=True: dict with detailed match information
    """
    try:
        # Get all enabled filter rules from enabled categories
        enabled_categories = NoiseFilterCategory.query.filter_by(is_enabled=True).all()
        category_ids = [cat.id for cat in enabled_categories]
        
        logger.info(f"[FILTER_CHECK] Found {len(category_ids)} enabled categories")
        
        if not category_ids:
            logger.info("[FILTER_CHECK] No enabled categories - returning no noise")
            if return_details:
                return {'is_noise': False, 'matched_rules': [], 'total_matches': 0}
            return False, None
        
        rules = NoiseFilterRule.query.filter(
            NoiseFilterRule.category_id.in_(category_ids),
            NoiseFilterRule.is_enabled == True
        ).order_by(NoiseFilterRule.priority.asc()).all()
        
        logger.info(f"[FILTER_CHECK] Found {len(rules)} enabled rules to check")
        
        if not rules:
            logger.info("[FILTER_CHECK] No enabled rules - returning no noise")
            if return_details:
                return {'is_noise': False, 'matched_rules': [], 'total_matches': 0}
            return False, None
        
        matched_rules = []
        
        for rule in rules:
            match_result = _event_matches_rule(event_data, rule, return_fields=return_details)
            
            if return_details and isinstance(match_result, dict) and match_result['matched']:
                matched_rules.append({
                    'rule_name': rule.name,
                    'category': rule.category.name,
                    'pattern': rule.pattern,
                    'filter_type': rule.filter_type,
                    'matched_fields': match_result['matched_fields'],
                    'priority': rule.priority
                })
            elif not return_details and match_result:
                if return_details:
                    matched_rules.append({
                        'rule_name': rule.name,
                        'category': rule.category.name,
                        'pattern': rule.pattern,
                        'filter_type': rule.filter_type
                    })
                else:
                    return True, rule.name
        
        if return_details:
            return {
                'is_noise': len(matched_rules) > 0,
                'matched_rules': matched_rules,
                'total_matches': len(matched_rules)
            }
        
        return False, None
        
    except Exception as e:
        logger.error(f"Error checking event against filters: {e}")
        if return_details:
            return {'is_noise': False, 'matched_rules': [], 'total_matches': 0, 'error': str(e)}
        return False, None


def _event_matches_rule(event_data, rule, return_fields=False):
    """
    Check if an event matches a specific noise filter rule
    
    Args:
        event_data: Event dictionary
        rule: NoiseFilterRule object
        return_fields: If True, return dict with matched fields
    
    Returns:
        If return_fields=False: bool (True if matches)
        If return_fields=True: dict {'matched': bool, 'matched_fields': [list of field paths]}
    """
    logger.info(f"[NOISE_CHECK] Checking event against rule: {rule.name}, pattern: {rule.pattern}")
    
    field_mapping = {
        'process_name': [
            'event_data.Image',
            'event_data.ProcessName',
            'event_data.ParentImage',
            'process.name',
            'process.executable',
            'process.parent.name',
            'process.parent.executable',
            'process.pe.original_file_name',
            'process.parent.pe.original_file_name',
            'search_blob'  # Added for unparsed/raw events
        ],
        'file_path': [
            'event_data.Image',
            'event_data.TargetFilename',
            'file.path',
            'file.name',
            'process.executable',
            'process.pe.path',
            'search_blob'  # Added for unparsed/raw events
        ],
        'command_line': [
            'event_data.CommandLine',
            'event_data.ParentCommandLine',
            'process.command_line',
            'process.parent.command_line',
            'process.args',
            'search_blob'  # Added for unparsed/raw events
        ],
        'hash': [
            'event_data.Hashes',
            'file.hash.sha256',
            'file.hash.md5',
            'process.hash.sha256',
            'process.hash.md5',
            'search_blob'  # Added for unparsed/raw events
        ],
        'guid': [
            'event_data.ProcessGuid',
            'event_data.SessionId',
            'process.entity_id',
            'session.id',
            'search_blob'  # Added for unparsed/raw events
        ],
        'network_connection': [
            'event_data.DestinationIp',
            'event_data.SourceIp',
            'destination.ip',
            'source.ip',
            'network.destination.ip',
            'network.source.ip',
            'search_blob'  # Added for unparsed/raw events
        ]
    }
    
    target_fields = field_mapping.get(rule.filter_type, [])
    
    # DEBUG: Log rule exclusions
    logger.info(f"[DEBUG] Rule '{rule.name}': exclude_fields = {repr(rule.exclude_fields)}")
    
    # Filter out excluded fields if specified
    if rule.exclude_fields:
        excluded = [f.strip() for f in rule.exclude_fields.split(',')]
        # Remove excluded fields from target list
        target_fields = [f for f in target_fields if f not in excluded]
        
        # For search_blob: only exclude if event has agent/metadata fields
        # (EVTX files don't have agent fields, so search_blob is safe)
        # (NDJSON from EDR has agent.url that pollutes search_blob)
        if 'search_blob' in target_fields and event_data.get('agent'):
            target_fields.remove('search_blob')
            logger.info(f"[NOISE_CHECK] Rule '{rule.name}' removed search_blob (event has agent metadata)")
        else:
            logger.info(f"[NOISE_CHECK] Rule '{rule.name}' excluding fields: {excluded}, checking {len(target_fields)} remaining fields")
    
    if not target_fields:
        logger.warning(f"[NOISE_CHECK] Rule '{rule.name}' has no fields left after exclusions")
        if return_fields:
            return {'matched': False, 'matched_fields': []}
        return False
    
    matched_fields = []
    
    logger.info(f"[NOISE_CHECK] Rule {rule.name} checking {len(target_fields)} fields")
    
    for field_path in target_fields:
        field_value = _get_nested_field(event_data, field_path)
        
        if field_value is None:
            continue
        
        logger.info(f"[NOISE_CHECK] Field {field_path} has value (length: {len(str(field_value)[:100])})")
        
        if _value_matches_pattern(field_value, rule.pattern, rule.match_mode, rule.is_case_sensitive):
            logger.info(f"✓ MATCH FOUND! Rule: {rule.name}, Field: {field_path}")
            if return_fields:
                matched_fields.append(field_path)
            else:
                return True
    
    if return_fields:
        return {'matched': len(matched_fields) > 0, 'matched_fields': matched_fields}
    
    return False


def _get_nested_field(data, field_path):
    """
    Get a nested field value using dot notation
    
    Args:
        data: Dictionary to search
        field_path: Dot-separated path (e.g., 'process.parent.name')
    
    Returns:
        Field value or None if not found
    """
    try:
        keys = field_path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        
        return value if value is not None else None
        
    except Exception:
        return None
    """
    Check if a single event matches a noise filter rule
    
    Args:
        event_data: Event data dict
        rule: NoiseFilterRule object
    
    Returns:
        bool: True if event matches the rule
    """
    field_paths = {
        'process_name': [
            ['event_data', 'Image'],
            ['event_data', 'ProcessName'],
            ['process', 'name'],
            ['process', 'executable']
        ],
        'file_path': [
            ['event_data', 'Image'],
            ['event_data', 'TargetFilename'],
            ['file', 'path'],
            ['file', 'name']
        ],
        'command_line': [
            ['event_data', 'CommandLine'],
            ['process', 'command_line'],
            ['process', 'args']
        ],
        'hash': [
            ['event_data', 'Hashes'],
            ['file', 'hash', 'sha256'],
            ['file', 'hash', 'md5'],
            ['hash']
        ],
        'guid': [
            ['event_data', 'ProcessGuid'],
            ['event_data', 'SessionId'],
            ['process', 'entity_id'],
            ['session', 'id']
        ],
        'network_connection': [
            ['event_data', 'DestinationIp'],
            ['event_data', 'SourceIp'],
            ['destination', 'ip'],
            ['source', 'ip']
        ]
    }
    
    paths = field_paths.get(rule.filter_type, [])
    
    for path in paths:
        value = _get_nested_value(event_data, path)
        if value and _value_matches_pattern(str(value), rule.pattern, rule.match_mode, rule.is_case_sensitive):
            return True
    
    return False


def _get_nested_value(data, path):
    """
    Get a value from nested dict using path list
    
    Args:
        data: Dict to search
        path: List of keys to traverse
    
    Returns:
        Value at path or None
    """
    current = data
    for key in path:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None
    return current


def _value_matches_pattern(value, pattern, match_mode, is_case_sensitive):
    """
    Check if a value matches a pattern based on match mode
    
    Supports:
    - Comma-separated patterns for OR logic: "pattern1,pattern2,pattern3"
    - AND logic using &&: "pattern1&&pattern2" (both must match)
    
    Args:
        value: Value to check
        pattern: Pattern to match (can include commas for OR, && for AND)
        match_mode: Match mode (exact, contains, starts_with, ends_with, wildcard, regex)
        is_case_sensitive: Whether match should be case sensitive
    
    Returns:
        bool: True if value matches pattern
    """
    if not is_case_sensitive:
        value = value.lower()
        pattern = pattern.lower()
    
    # Check for AND logic (&&)
    if '&&' in pattern:
        # AND logic: ALL patterns must match
        and_patterns = [p.strip() for p in pattern.split('&&')]
        for and_pattern in and_patterns:
            # Each AND pattern can have OR logic (comma-separated)
            or_patterns = [p.strip() for p in and_pattern.split(',')]
            or_matched = False
            for or_pattern in or_patterns:
                if _single_pattern_match(value, or_pattern, match_mode, True):  # Already lowercased if needed
                    or_matched = True
                    break
            if not or_matched:
                return False  # One of the AND conditions failed
        return True  # All AND conditions matched
    
    else:
        # OR logic: ANY pattern matches (comma-separated)
        patterns = [p.strip() for p in pattern.split(',')]
        for p in patterns:
            if _single_pattern_match(value, p, match_mode, True):  # Already lowercased if needed
                return True
        return False


def _single_pattern_match(value, pattern, match_mode, already_normalized):
    """
    Check if a value matches a single pattern (helper function)
    
    Args:
        value: Value to check (already normalized for case if needed)
        pattern: Single pattern to match
        match_mode: Match mode
        already_normalized: Whether case normalization already done
    
    Returns:
        bool: True if value matches pattern
    """
    if match_mode == 'exact':
        return value == pattern
    
    elif match_mode == 'contains':
        return pattern in value
    
    elif match_mode == 'starts_with':
        return value.startswith(pattern)
    
    elif match_mode == 'ends_with':
        return value.endswith(pattern)
    
    elif match_mode == 'wildcard':
        return fnmatch.fnmatch(value, pattern)
    
    elif match_mode == 'regex':
        try:
            # If already normalized, no need for flags
            return bool(re.search(pattern, value))
        except re.error:
            logger.warning(f"Invalid regex pattern: {pattern}")
            return False
    
    return False


def record_filter_match(rule_id, case_id):
    """
    Record that a filter rule matched an event (for statistics)
    
    Args:
        rule_id: ID of the matched rule
        case_id: ID of the case
    """
    try:
        stat = NoiseFilterStats.query.filter_by(
            rule_id=rule_id,
            case_id=case_id
        ).first()
        
        if stat:
            stat.events_filtered += 1
            stat.last_matched = datetime.utcnow()
        else:
            stat = NoiseFilterStats(
                rule_id=rule_id,
                case_id=case_id,
                events_filtered=1,
                last_matched=datetime.utcnow()
            )
            db.session.add(stat)
        
        db.session.commit()
        
    except Exception as e:
        logger.error(f"Error recording filter match: {e}")
        db.session.rollback()


def get_filter_stats_for_case(case_id):
    """
    Get noise filter statistics for a case
    
    Args:
        case_id: Case ID
    
    Returns:
        list: List of dicts with rule names and filter counts
    """
    try:
        stats = db.session.query(
            NoiseFilterRule.name,
            NoiseFilterStats.events_filtered,
            NoiseFilterStats.last_matched
        ).join(NoiseFilterRule).filter(
            NoiseFilterStats.case_id == case_id
        ).order_by(NoiseFilterStats.events_filtered.desc()).all()
        
        return [
            {
                'rule_name': name,
                'events_filtered': count,
                'last_matched': last_matched.isoformat() if last_matched else None
            }
            for name, count, last_matched in stats
        ]
        
    except Exception as e:
        logger.error(f"Error getting filter stats: {e}")
        return []

