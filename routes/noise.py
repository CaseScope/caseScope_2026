"""Noise Filter Routes for CaseScope

Manages noise filtering rules to hide known-good software/tools from event searches.
Analysts can add/edit/toggle rules to customize filtering for their client's environment.
"""

from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from functools import wraps
from models.database import db
from models.noise import (
    NoiseCategory, NoiseRule, NoiseRuleAudit,
    NoiseFilterType, NoiseMatchMode, seed_noise_defaults
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
        
        old_value = category.is_enabled
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
        filter_type = request.args.get('filter_type', '')
        
        # Build query
        query = NoiseRule.query.join(NoiseCategory)
        
        # Apply search filter
        if search_query:
            query = query.filter(
                db.or_(
                    NoiseRule.name.ilike(f'%{search_query}%'),
                    NoiseRule.description.ilike(f'%{search_query}%'),
                    NoiseRule.pattern.ilike(f'%{search_query}%')
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
        
        # Apply filter type
        if filter_type:
            query = query.filter(NoiseRule.filter_type == filter_type)
        
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
    """Add a new custom noise filter rule"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['category_id', 'name', 'filter_type', 'pattern']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'Missing required field: {field}'}), 400
        
        # Validate category exists
        category = NoiseCategory.query.get(data['category_id'])
        if not category:
            return jsonify({'success': False, 'error': 'Invalid category'}), 400
        
        # Validate filter_type
        if data['filter_type'] not in NoiseFilterType.all():
            return jsonify({'success': False, 'error': f'Invalid filter type: {data["filter_type"]}'}), 400
        
        # Validate match_mode
        match_mode = data.get('match_mode', NoiseMatchMode.CONTAINS)
        if match_mode not in NoiseMatchMode.all():
            return jsonify({'success': False, 'error': f'Invalid match mode: {match_mode}'}), 400
        
        # Create rule
        rule = NoiseRule(
            category_id=data['category_id'],
            name=data['name'],
            description=data.get('description', ''),
            filter_type=data['filter_type'],
            pattern=data['pattern'],
            match_mode=match_mode,
            is_case_sensitive=data.get('is_case_sensitive', False),
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
            # Validate category exists
            new_category = NoiseCategory.query.get(data['category_id'])
            if not new_category:
                return jsonify({'success': False, 'error': 'Invalid category'}), 400
            changes['category_id'] = {'old': rule.category_id, 'new': data['category_id']}
            rule.category_id = data['category_id']
        
        if 'filter_type' in data and data['filter_type'] != rule.filter_type:
            if data['filter_type'] not in NoiseFilterType.all():
                return jsonify({'success': False, 'error': f'Invalid filter type'}), 400
            changes['filter_type'] = {'old': rule.filter_type, 'new': data['filter_type']}
            rule.filter_type = data['filter_type']
        
        if 'pattern' in data and data['pattern'] != rule.pattern:
            changes['pattern'] = {'old': rule.pattern, 'new': data['pattern']}
            rule.pattern = data['pattern']
        
        if 'match_mode' in data and data['match_mode'] != rule.match_mode:
            if data['match_mode'] not in NoiseMatchMode.all():
                return jsonify({'success': False, 'error': f'Invalid match mode'}), 400
            changes['match_mode'] = {'old': rule.match_mode, 'new': data['match_mode']}
            rule.match_mode = data['match_mode']
        
        if 'is_case_sensitive' in data and data['is_case_sensitive'] != rule.is_case_sensitive:
            changes['is_case_sensitive'] = {'old': rule.is_case_sensitive, 'new': data['is_case_sensitive']}
            rule.is_case_sensitive = data['is_case_sensitive']
        
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
        
        # Stats by filter type
        type_stats = []
        for ftype in NoiseFilterType.all():
            count = NoiseRule.query.filter_by(filter_type=ftype).count()
            enabled = NoiseRule.query.filter_by(filter_type=ftype, is_enabled=True).count()
            type_stats.append({
                'type': ftype,
                'label': NoiseFilterType.labels().get(ftype, ftype),
                'total': count,
                'enabled': enabled
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
            'category_stats': category_stats,
            'type_stats': type_stats
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


@noise_bp.route('/api/filter-types')
@login_required
def api_filter_types():
    """Get available filter types and match modes"""
    return jsonify({
        'success': True,
        'filter_types': NoiseFilterType.choices(),
        'match_modes': NoiseMatchMode.choices()
    })


@noise_bp.route('/api/test-matching')
@login_required
def api_test_matching():
    """Test noise rules against ClickHouse events and show match counts
    
    This helps analysts see how many events would be filtered by active rules.
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
        
        # Map filter types to ClickHouse columns
        filter_type_columns = {
            'process_name': 'process_name',
            'file_path': 'process_path',
            'command_line': 'command_line',
            'hash': 'file_hash_sha256',
            'service_name': 'process_name',  # Services often appear as process names
            'network': 'search_blob',  # IP/domain in search blob
            'registry': 'reg_key'
        }
        
        # Get total events
        case_filter = f"WHERE case_id = {case_id}" if case_id else ""
        total_result = client.query(f"SELECT count() FROM events {case_filter}")
        total_events = total_result.result_rows[0][0] if total_result.result_rows else 0
        
        # Test each active rule
        rule_results = []
        total_matches = 0
        
        for rule in active_rules:
            column = filter_type_columns.get(rule.filter_type, 'search_blob')
            or_patterns, and_conditions = rule.parse_pattern()
            
            # Build LIKE conditions for OR patterns
            or_clauses = []
            for pattern in or_patterns:
                # Escape pattern for SQL
                escaped = pattern.replace("'", "''").replace('%', '%%')
                if rule.is_case_sensitive:
                    or_clauses.append(f"{column} LIKE '%{escaped}%'")
                else:
                    or_clauses.append(f"lower({column}) LIKE '%{escaped.lower()}%'")
            
            if not or_clauses:
                continue
            
            # Build AND conditions (check against search_blob for full event)
            and_clauses = []
            for condition in and_conditions:
                escaped = condition.replace("'", "''").replace('%', '%%')
                if rule.is_case_sensitive:
                    and_clauses.append(f"search_blob LIKE '%{escaped}%'")
                else:
                    and_clauses.append(f"lower(search_blob) LIKE '%{escaped.lower()}%'")
            
            # Combine: (OR patterns) AND (all AND conditions)
            where_parts = []
            if case_id:
                where_parts.append(f"case_id = {case_id}")
            
            or_combined = f"({' OR '.join(or_clauses)})"
            where_parts.append(or_combined)
            
            if and_clauses:
                where_parts.extend(and_clauses)
            
            where_clause = " AND ".join(where_parts)
            
            query = f"SELECT count() FROM events WHERE {where_clause}"
            
            try:
                result = client.query(query)
                match_count = result.result_rows[0][0] if result.result_rows else 0
            except Exception as e:
                logger.error(f"Error testing rule {rule.name}: {e}")
                match_count = -1  # Error indicator
            
            rule_results.append({
                'id': rule.id,
                'name': rule.name,
                'category': rule.category.name if rule.category else None,
                'category_icon': rule.category.icon if rule.category else None,
                'filter_type': rule.filter_type,
                'pattern': rule.pattern,
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
        
        # Map filter types to columns
        filter_type_columns = {
            'process_name': 'process_name',
            'file_path': 'process_path',
            'command_line': 'command_line',
            'hash': 'file_hash_sha256',
            'service_name': 'process_name',
            'network': 'search_blob',
            'registry': 'reg_key'
        }
        
        column = filter_type_columns.get(rule.filter_type, 'search_blob')
        or_patterns, and_conditions = rule.parse_pattern()
        
        # Build query
        or_clauses = []
        for pattern in or_patterns:
            escaped = pattern.replace("'", "''").replace('%', '%%')
            if rule.is_case_sensitive:
                or_clauses.append(f"{column} LIKE '%{escaped}%'")
            else:
                or_clauses.append(f"lower({column}) LIKE '%{escaped.lower()}%'")
        
        and_clauses = []
        for condition in and_conditions:
            escaped = condition.replace("'", "''").replace('%', '%%')
            if rule.is_case_sensitive:
                and_clauses.append(f"search_blob LIKE '%{escaped}%'")
            else:
                and_clauses.append(f"lower(search_blob) LIKE '%{escaped.lower()}%'")
        
        where_parts = []
        if case_id:
            where_parts.append(f"case_id = {case_id}")
        
        if or_clauses:
            where_parts.append(f"({' OR '.join(or_clauses)})")
        
        if and_clauses:
            where_parts.extend(and_clauses)
        
        where_clause = " AND ".join(where_parts) if where_parts else "1=1"
        
        # Get count
        count_query = f"SELECT count() FROM events WHERE {where_clause}"
        count_result = client.query(count_query)
        match_count = count_result.result_rows[0][0] if count_result.result_rows else 0
        
        # Get sample events
        sample_query = f"""
            SELECT timestamp, source_host, process_name, process_path, command_line, search_blob
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
                'command_line': row[4][:500] if row[4] else None  # Truncate long command lines
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
