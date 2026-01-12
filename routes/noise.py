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


def analyst_required(f):
    """Decorator to require at least analyst role"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        from config import PermissionLevel
        if current_user.permission_level < PermissionLevel.ANALYST:
            flash('Analyst access required', 'error')
            return redirect(url_for('main.dashboard'))
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
@analyst_required
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
@analyst_required
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
@analyst_required
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
@analyst_required
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
@analyst_required
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
@analyst_required
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
