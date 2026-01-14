"""Noise Filter Routes for CaseScope

Manages noise filtering rules to hide known-good software/tools from event searches.
Analysts can add/edit/toggle rules to customize filtering for their client's environment.

Uses keyword-based token matching with hasTokenCaseInsensitive() on raw_json.
"""

from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from functools import wraps
from models.database import db
from models.noise import (
    NoiseCategory, NoiseRule, NoiseRuleAudit, seed_noise_defaults
)
import logging

logger = logging.getLogger(__name__)

noise_bp = Blueprint('noise', __name__, url_prefix='/settings/noise')


def analyst_required_api(f):
    """Decorator to require at least analyst role for API endpoints (returns JSON)"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        # Check if user is analyst or administrator
        if not (current_user.is_analyst or current_user.is_administrator):
            return jsonify({'success': False, 'error': 'Analyst or Administrator access required'}), 403
        return f(*args, **kwargs)
    return decorated_function


def build_keyword_clause(keywords: list, column: str = 'raw_json') -> str:
    """Build ClickHouse hasTokenCaseInsensitive OR clause for keywords"""
    if not keywords:
        return ""
    
    clauses = []
    for keyword in keywords:
        escaped = keyword.replace("'", "''")
        clauses.append(f"hasTokenCaseInsensitive({column}, '{escaped}')")
    
    return f"({' OR '.join(clauses)})"


def build_keyword_not_clause(keywords: list, column: str = 'raw_json') -> str:
    """Build ClickHouse NOT clause for keywords"""
    if not keywords:
        return ""
    
    clauses = []
    for keyword in keywords:
        escaped = keyword.replace("'", "''")
        clauses.append(f"NOT hasTokenCaseInsensitive({column}, '{escaped}')")
    
    return " AND ".join(clauses)


# ============================================================================
# API Endpoints
# ============================================================================

@noise_bp.route('/api/categories')
@login_required
def api_list_categories():
    """List all noise filter categories with rule counts"""
    try:
        categories = NoiseCategory.get_all_ordered()
        return jsonify({
            'success': True,
            'categories': [cat.to_dict() for cat in categories]
        })
    except Exception as e:
        logger.error(f"Error listing noise categories: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@noise_bp.route('/api/categories/<int:category_id>/toggle', methods=['POST'])
@analyst_required_api
def api_toggle_category(category_id):
    """Toggle a category enabled/disabled (master switch for all rules in category)"""
    try:
        category = NoiseCategory.query.get_or_404(category_id)
        data = request.get_json() or {}
        
        is_enabled = data.get('is_enabled')
        if is_enabled is None:
            return jsonify({'success': False, 'error': 'Missing is_enabled parameter'}), 400
        
        category.is_enabled = is_enabled
        db.session.commit()
        
        logger.info(f"Noise category '{category.name}' {'enabled' if is_enabled else 'disabled'} by {current_user.username}")
        
        return jsonify({
            'success': True,
            'category': category.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error toggling noise category: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@noise_bp.route('/api/rules')
@login_required
def api_list_rules():
    """List noise filter rules with pagination and filtering"""
    try:
        # Query parameters
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(10, int(request.args.get('per_page', 50))))
        search_query = request.args.get('q', '').strip()
        category_filter = request.args.get('category', type=int)
        status_filter = request.args.get('status', '')
        
        # Build query
        query = NoiseRule.query.join(NoiseCategory)
        
        # Apply search filter (searches name, description, and keywords)
        if search_query:
            query = query.filter(
                db.or_(
                    NoiseRule.name.ilike(f'%{search_query}%'),
                    NoiseRule.description.ilike(f'%{search_query}%'),
                    NoiseRule.pattern.ilike(f'%{search_query}%'),
                    NoiseRule.pattern_and.ilike(f'%{search_query}%'),
                    NoiseRule.pattern_not.ilike(f'%{search_query}%')
                )
            )
        
        # Apply category filter
        if category_filter:
            query = query.filter(NoiseRule.category_id == category_filter)
        
        # Apply status filter
        if status_filter == 'enabled':
            query = query.filter(NoiseRule.is_enabled == True)
        elif status_filter == 'disabled':
            query = query.filter(NoiseRule.is_enabled == False)
        elif status_filter == 'system':
            query = query.filter(NoiseRule.is_system_default == True)
        elif status_filter == 'custom':
            query = query.filter(NoiseRule.is_system_default == False)
        elif status_filter == 'active':
            # Both category and rule must be enabled
            query = query.filter(
                NoiseCategory.is_enabled == True,
                NoiseRule.is_enabled == True
            )
        
        # Order by category order, then priority, then name
        query = query.order_by(
            NoiseCategory.display_order.asc(),
            NoiseRule.priority.asc(),
            NoiseRule.name.asc()
        )
        
        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'success': True,
            'rules': [rule.to_dict() for rule in pagination.items],
            'total': pagination.total,
            'page': page,
            'per_page': per_page,
            'total_pages': pagination.pages
        })
    except Exception as e:
        logger.error(f"Error listing noise rules: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@noise_bp.route('/api/rules/<int:rule_id>')
@login_required
def api_get_rule(rule_id):
    """Get a single rule by ID"""
    try:
        rule = NoiseRule.query.get_or_404(rule_id)
        return jsonify({
            'success': True,
            'rule': rule.to_dict()
        })
    except Exception as e:
        logger.error(f"Error getting noise rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@noise_bp.route('/api/rules/add', methods=['POST'])
@analyst_required_api
def api_add_rule():
    """Add a new custom noise filter rule with keyword-based matching"""
    try:
        data = request.get_json()
        
        # Validate required fields (simplified - just need category, name, and keywords)
        if not data.get('category_id'):
            return jsonify({'success': False, 'error': 'Missing required field: category_id'}), 400
        if not data.get('name'):
            return jsonify({'success': False, 'error': 'Missing required field: name'}), 400
        
        # Get keywords - accept either 'keywords' or 'pattern' for backward compat
        keywords = data.get('keywords') or data.get('pattern', '')
        if not keywords:
            return jsonify({'success': False, 'error': 'Missing required field: keywords'}), 400
        
        # Validate category exists
        category = NoiseCategory.query.get(data['category_id'])
        if not category:
            return jsonify({'success': False, 'error': 'Invalid category'}), 400
        
        # Create rule with keyword-based matching
        rule = NoiseRule(
            category_id=data['category_id'],
            name=data['name'],
            description=data.get('description', ''),
            pattern=keywords,  # OR keywords
            pattern_and=data.get('keywords_and') or data.get('pattern_and', ''),  # AND keywords
            pattern_not=data.get('keywords_not') or data.get('pattern_not', ''),  # NOT keywords
            is_enabled=data.get('is_enabled', True),
            is_system_default=False,
            priority=data.get('priority', 100),
            created_by=current_user.username
        )
        
        db.session.add(rule)
        db.session.flush()
        
        # Audit log
        NoiseRuleAudit.log_change(rule, current_user.username, 'create')
        
        db.session.commit()
        
        logger.info(f"Noise rule '{rule.name}' created by {current_user.username}")
        
        return jsonify({
            'success': True,
            'rule': rule.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding noise rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@noise_bp.route('/api/rules/<int:rule_id>/edit', methods=['POST'])
@analyst_required_api
def api_edit_rule(rule_id):
    """Edit an existing noise filter rule"""
    try:
        rule = NoiseRule.query.get_or_404(rule_id)
        data = request.get_json()
        
        # Track changes for audit
        changes = {}
        
        # Update fields
        if 'name' in data and data['name'] != rule.name:
            changes['name'] = {'old': rule.name, 'new': data['name']}
            rule.name = data['name']
        
        if 'description' in data and data['description'] != rule.description:
            changes['description'] = {'old': rule.description, 'new': data['description']}
            rule.description = data['description']
        
        if 'category_id' in data and data['category_id'] != rule.category_id:
            new_category = NoiseCategory.query.get(data['category_id'])
            if not new_category:
                return jsonify({'success': False, 'error': 'Invalid category'}), 400
            changes['category_id'] = {'old': rule.category_id, 'new': data['category_id']}
            rule.category_id = data['category_id']
        
        # Handle keywords (accept both new 'keywords' and legacy 'pattern' names)
        keywords = data.get('keywords') or data.get('pattern')
        if keywords is not None and keywords != rule.pattern:
            changes['keywords'] = {'old': rule.pattern, 'new': keywords}
            rule.pattern = keywords
        
        keywords_and = data.get('keywords_and') or data.get('pattern_and')
        if keywords_and is not None and keywords_and != (rule.pattern_and or ''):
            changes['keywords_and'] = {'old': rule.pattern_and, 'new': keywords_and}
            rule.pattern_and = keywords_and
        
        keywords_not = data.get('keywords_not') or data.get('pattern_not')
        if keywords_not is not None and keywords_not != (rule.pattern_not or ''):
            changes['keywords_not'] = {'old': rule.pattern_not, 'new': keywords_not}
            rule.pattern_not = keywords_not
        
        if 'priority' in data and data['priority'] != rule.priority:
            changes['priority'] = {'old': rule.priority, 'new': data['priority']}
            rule.priority = data['priority']
        
        if changes:
            rule.updated_by = current_user.username
            NoiseRuleAudit.log_change(rule, current_user.username, 'update', 
                                      field_name=','.join(changes.keys()))
        
        db.session.commit()
        
        logger.info(f"Noise rule '{rule.name}' updated by {current_user.username}")
        
        return jsonify({
            'success': True,
            'rule': rule.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error editing noise rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@noise_bp.route('/api/rules/<int:rule_id>/toggle', methods=['POST'])
@analyst_required_api
def api_toggle_rule(rule_id):
    """Toggle a noise filter rule enabled/disabled"""
    try:
        rule = NoiseRule.query.get_or_404(rule_id)
        data = request.get_json() or {}
        
        is_enabled = data.get('is_enabled')
        if is_enabled is None:
            return jsonify({'success': False, 'error': 'Missing is_enabled parameter'}), 400
        
        old_value = rule.is_enabled
        rule.is_enabled = is_enabled
        rule.updated_by = current_user.username
        
        # Audit log
        action = 'enable' if is_enabled else 'disable'
        NoiseRuleAudit.log_change(rule, current_user.username, action,
                                  field_name='is_enabled',
                                  old_value=old_value,
                                  new_value=is_enabled)
        
        db.session.commit()
        
        logger.info(f"Noise rule '{rule.name}' {action}d by {current_user.username}")
        
        return jsonify({
            'success': True,
            'rule': rule.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error toggling noise rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@noise_bp.route('/api/rules/<int:rule_id>/delete', methods=['POST'])
@analyst_required_api
def api_delete_rule(rule_id):
    """Delete a custom noise filter rule (system defaults cannot be deleted)"""
    try:
        rule = NoiseRule.query.get_or_404(rule_id)
        
        # Prevent deletion of system defaults
        if rule.is_system_default:
            return jsonify({
                'success': False,
                'error': 'Cannot delete system default rules. Disable them instead.'
            }), 400
        
        rule_name = rule.name
        
        # Audit log before deletion
        NoiseRuleAudit.log_change(rule, current_user.username, 'delete')
        
        db.session.delete(rule)
        db.session.commit()
        
        logger.info(f"Noise rule '{rule_name}' deleted by {current_user.username}")
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting noise rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@noise_bp.route('/api/stats')
@login_required
def api_noise_stats():
    """Get noise filter statistics"""
    try:
        total_categories = NoiseCategory.query.count()
        enabled_categories = NoiseCategory.query.filter_by(is_enabled=True).count()
        
        total_rules = NoiseRule.query.count()
        enabled_rules = NoiseRule.query.filter_by(is_enabled=True).count()
        active_rules = len(NoiseRule.get_active_rules())
        system_rules = NoiseRule.query.filter_by(is_system_default=True).count()
        custom_rules = NoiseRule.query.filter_by(is_system_default=False).count()
        
        # Stats by category
        category_stats = []
        for cat in NoiseCategory.get_all_ordered():
            category_stats.append({
                'id': cat.id,
                'name': cat.name,
                'icon': cat.icon,
                'is_enabled': cat.is_enabled,
                'total_rules': cat.rules.count(),
                'enabled_rules': cat.rules.filter_by(is_enabled=True).count()
            })
        
        return jsonify({
            'success': True,
            'total_categories': total_categories,
            'enabled_categories': enabled_categories,
            'total_rules': total_rules,
            'enabled_rules': enabled_rules,
            'active_rules': active_rules,
            'system_rules': system_rules,
            'custom_rules': custom_rules,
            'category_stats': category_stats
        })
    except Exception as e:
        logger.error(f"Error getting noise stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@noise_bp.route('/api/seed', methods=['POST'])
@analyst_required_api
def api_seed_defaults():
    """Seed default categories and rules (only if empty)"""
    try:
        seeded = seed_noise_defaults()
        if seeded:
            logger.info(f"Noise filter defaults seeded by {current_user.username}")
            return jsonify({
                'success': True,
                'message': 'Default categories and rules created'
            })
        else:
            return jsonify({
                'success': True,
                'message': 'Defaults already exist'
            })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error seeding noise defaults: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@noise_bp.route('/api/test-matching')
@login_required
def api_test_matching():
    """Test noise rules against ClickHouse events using keyword token matching
    
    Uses hasTokenCaseInsensitive() on raw_json for whole-word matching.
    """
    try:
        from utils.clickhouse import get_client
        
        client = get_client()
        
        # Get case_id filter if provided
        case_id = request.args.get('case_id', type=int)
        
        # Get active rules
        active_rules = NoiseRule.get_active_rules()
        
        if not active_rules:
            return jsonify({
                'success': True,
                'message': 'No active noise rules',
                'total_events': 0,
                'rules': []
            })
        
        # Get total events
        case_filter = f"WHERE case_id = {case_id}" if case_id else ""
        total_result = client.query(f"SELECT count() FROM events {case_filter}")
        total_events = total_result.result_rows[0][0] if total_result.result_rows else 0
        
        # Test each active rule using keyword token matching
        rule_results = []
        total_matches = 0
        
        for rule in active_rules:
            or_keywords, and_keywords, not_keywords = rule.get_keywords()
            
            if not or_keywords:
                continue
            
            # Build WHERE clause with hasTokenCaseInsensitive on raw_json
            where_parts = []
            if case_id:
                where_parts.append(f"case_id = {case_id}")
            
            # OR keywords
            or_clause = build_keyword_clause(or_keywords, 'raw_json')
            where_parts.append(or_clause)
            
            # AND keywords
            if and_keywords:
                and_clause = build_keyword_clause(and_keywords, 'raw_json')
                where_parts.append(and_clause)
            
            # NOT keywords
            if not_keywords:
                not_clause = build_keyword_not_clause(not_keywords, 'raw_json')
                where_parts.append(f"({not_clause})")
            
            where_clause = " AND ".join(where_parts)
            
            try:
                result = client.query(f"SELECT count() FROM events WHERE {where_clause}")
                match_count = result.result_rows[0][0] if result.result_rows else 0
            except Exception as e:
                logger.error(f"Error testing rule {rule.name}: {e}")
                match_count = -1  # Error indicator
            
            rule_results.append({
                'id': rule.id,
                'name': rule.name,
                'category': rule.category.name if rule.category else None,
                'category_icon': rule.category.icon if rule.category else None,
                'keywords': rule.pattern,
                'match_count': match_count,
                'percentage': round((match_count / total_events * 100), 2) if total_events > 0 and match_count > 0 else 0
            })
            
            if match_count > 0:
                total_matches += match_count
        
        # Sort by match count descending
        rule_results.sort(key=lambda x: x['match_count'], reverse=True)
        
        return jsonify({
            'success': True,
            'case_id': case_id,
            'total_events': total_events,
            'total_potential_matches': total_matches,
            'noise_percentage': round((total_matches / total_events * 100), 2) if total_events > 0 else 0,
            'active_rules_count': len(active_rules),
            'rules': rule_results
        })
        
    except Exception as e:
        logger.error(f"Error testing noise matching: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@noise_bp.route('/api/test-rule/<int:rule_id>')
@login_required  
def api_test_single_rule(rule_id):
    """Test a single rule and show sample matching events"""
    try:
        from utils.clickhouse import get_client
        
        rule = NoiseRule.query.get_or_404(rule_id)
        client = get_client()
        
        case_id = request.args.get('case_id', type=int)
        limit = min(request.args.get('limit', 10, type=int), 50)
        
        or_keywords, and_keywords, not_keywords = rule.get_keywords()
        
        if not or_keywords:
            return jsonify({
                'success': True,
                'rule': rule.to_dict(),
                'match_count': 0,
                'sample_count': 0,
                'samples': [],
                'message': 'No keywords defined'
            })
        
        # Build WHERE clause with hasTokenCaseInsensitive
        where_parts = []
        if case_id:
            where_parts.append(f"case_id = {case_id}")
        
        or_clause = build_keyword_clause(or_keywords, 'raw_json')
        where_parts.append(or_clause)
        
        if and_keywords:
            and_clause = build_keyword_clause(and_keywords, 'raw_json')
            where_parts.append(and_clause)
        
        if not_keywords:
            not_clause = build_keyword_not_clause(not_keywords, 'raw_json')
            where_parts.append(f"({not_clause})")
        
        where_clause = " AND ".join(where_parts) if where_parts else "1=1"
        
        # Get count
        count_result = client.query(f"SELECT count() FROM events WHERE {where_clause}")
        match_count = count_result.result_rows[0][0] if count_result.result_rows else 0
        
        # Get sample events
        sample_query = f"""
            SELECT timestamp, source_host, process_name, process_path, command_line
            FROM events 
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT {limit}
        """
        
        sample_result = client.query(sample_query)
        
        samples = []
        for row in sample_result.result_rows:
            samples.append({
                'timestamp': str(row[0]) if row[0] else None,
                'source_host': row[1],
                'process_name': row[2],
                'process_path': row[3],
                'command_line': row[4][:500] if row[4] else None
            })
        
        return jsonify({
            'success': True,
            'rule': rule.to_dict(),
            'match_count': match_count,
            'sample_count': len(samples),
            'samples': samples
        })
        
    except Exception as e:
        logger.error(f"Error testing single rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
