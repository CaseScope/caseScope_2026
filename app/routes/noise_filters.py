"""
Noise Filter Routes
Manages noise filtering rules to hide known good software/tools from event searches
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from main import db
from models import NoiseFilterCategory, NoiseFilterRule, NoiseFilterStats
from audit_logger import log_action
import logging
import re

logger = logging.getLogger(__name__)

noise_filters_bp = Blueprint('noise_filters', __name__, url_prefix='/settings/noise-filters')


def admin_required(f):
    """Decorator to require administrator role"""
    from functools import wraps
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'administrator':
            flash('Administrator access required', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


@noise_filters_bp.route('/')
@login_required
@admin_required
def noise_filters_page():
    """
    Noise filters management page
    """
    from sqlalchemy import func
    
    # Get statistics
    total_categories = NoiseFilterCategory.query.count()
    enabled_categories = NoiseFilterCategory.query.filter_by(is_enabled=True).count()
    
    total_rules = NoiseFilterRule.query.count()
    enabled_rules = NoiseFilterRule.query.filter_by(is_enabled=True).count()
    system_rules = NoiseFilterRule.query.filter_by(is_system_default=True).count()
    custom_rules = NoiseFilterRule.query.filter_by(is_system_default=False).count()
    
    # Get all categories with rule counts
    categories = db.session.query(
        NoiseFilterCategory,
        func.count(NoiseFilterRule.id).label('rule_count'),
        func.sum(db.case((NoiseFilterRule.is_enabled == True, 1), else_=0)).label('enabled_count')
    ).outerjoin(NoiseFilterRule).group_by(NoiseFilterCategory.id).all()
    
    return render_template('admin/noise_filters.html',
                         total_categories=total_categories,
                         enabled_categories=enabled_categories,
                         total_rules=total_rules,
                         enabled_rules=enabled_rules,
                         system_rules=system_rules,
                         custom_rules=custom_rules,
                         categories=categories)


@noise_filters_bp.route('/api/categories')
@login_required
@admin_required
def api_list_categories():
    """
    API endpoint to list all categories
    """
    try:
        from sqlalchemy import func
        
        # Get categories with rule counts
        categories = db.session.query(
            NoiseFilterCategory,
            func.count(NoiseFilterRule.id).label('rule_count'),
            func.sum(db.case((NoiseFilterRule.is_enabled == True, 1), else_=0)).label('enabled_count')
        ).outerjoin(NoiseFilterRule).group_by(NoiseFilterCategory.id).all()
        
        result = []
        for category, rule_count, enabled_count in categories:
            result.append({
                'id': category.id,
                'name': category.name,
                'description': category.description,
                'is_enabled': category.is_enabled,
                'rule_count': rule_count or 0,
                'enabled_count': enabled_count or 0,
                'created_at': category.created_at.isoformat() if category.created_at else None
            })
        
        return jsonify({'categories': result})
        
    except Exception as e:
        logger.error(f"Error listing categories: {e}")
        return jsonify({'error': str(e)}), 500


@noise_filters_bp.route('/api/rules')
@login_required
@admin_required
def api_list_rules():
    """
    API endpoint to list noise filter rules with pagination
    """
    try:
        # Get query parameters
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(10, int(request.args.get('per_page', 50))))
        search_query = request.args.get('q', '').strip()
        category_filter = request.args.get('category', type=int)
        status_filter = request.args.get('status', '')
        filter_type = request.args.get('filter_type', '')
        
        # Build query
        query = NoiseFilterRule.query
        
        # Apply search filter
        if search_query:
            query = query.filter(
                db.or_(
                    NoiseFilterRule.name.ilike(f'%{search_query}%'),
                    NoiseFilterRule.description.ilike(f'%{search_query}%'),
                    NoiseFilterRule.pattern.ilike(f'%{search_query}%')
                )
            )
        
        # Apply category filter
        if category_filter:
            query = query.filter(NoiseFilterRule.category_id == category_filter)
        
        # Apply status filter
        if status_filter == 'enabled':
            query = query.filter(NoiseFilterRule.is_enabled == True)
        elif status_filter == 'disabled':
            query = query.filter(NoiseFilterRule.is_enabled == False)
        elif status_filter == 'system':
            query = query.filter(NoiseFilterRule.is_system_default == True)
        elif status_filter == 'custom':
            query = query.filter(NoiseFilterRule.is_system_default == False)
        
        # Apply filter type
        if filter_type:
            query = query.filter(NoiseFilterRule.filter_type == filter_type)
        
        # Order by priority, then name
        query = query.order_by(NoiseFilterRule.priority.asc(), NoiseFilterRule.name.asc())
        
        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        # Format results
        rules = []
        for rule in pagination.items:
            rules.append({
                'id': rule.id,
                'category_id': rule.category_id,
                'category_name': rule.category.name if rule.category else None,
                'name': rule.name,
                'description': rule.description,
                'filter_type': rule.filter_type,
                'pattern': rule.pattern,
                'match_mode': rule.match_mode,
                'is_case_sensitive': rule.is_case_sensitive,
                'is_enabled': rule.is_enabled,
                'is_system_default': rule.is_system_default,
                'priority': rule.priority,
                'created_at': rule.created_at.isoformat() if rule.created_at else None
            })
        
        return jsonify({
            'rules': rules,
            'total': pagination.total,
            'page': page,
            'per_page': per_page,
            'total_pages': pagination.pages
        })
        
    except Exception as e:
        logger.error(f"Error listing noise filter rules: {e}")
        return jsonify({'error': str(e)}), 500


@noise_filters_bp.route('/api/rules/add', methods=['POST'])
@login_required
@admin_required
def api_add_rule():
    """
    API endpoint to add a new noise filter rule
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['category_id', 'name', 'filter_type', 'pattern']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'Missing required field: {field}'}), 400
        
        # Create new rule
        rule = NoiseFilterRule(
            category_id=data['category_id'],
            name=data['name'],
            description=data.get('description', ''),
            filter_type=data['filter_type'],
            pattern=data['pattern'],
            match_mode=data.get('match_mode', 'contains'),
            is_case_sensitive=data.get('is_case_sensitive', False),
            is_enabled=data.get('is_enabled', True),
            is_system_default=False,  # User-added rules are never system defaults
            priority=data.get('priority', 100),
            created_by=current_user.id,
            updated_by=current_user.id
        )
        
        db.session.add(rule)
        db.session.commit()
        
        # Audit log
        log_action('create_noise_filter_rule',
                   resource_type='noise_filter_rule',
                   resource_id=rule.id,
                   resource_name=rule.name,
                   details={
                       'category_id': rule.category_id,
                       'filter_type': rule.filter_type,
                       'pattern': rule.pattern,
                       'created_by': current_user.username
                   })
        
        logger.info(f"Noise filter rule '{rule.name}' created by {current_user.username}")
        
        return jsonify({'success': True, 'rule_id': rule.id})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding noise filter rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@noise_filters_bp.route('/api/rules/<int:rule_id>/edit', methods=['POST'])
@login_required
@admin_required
def api_edit_rule(rule_id):
    """
    API endpoint to edit a noise filter rule
    """
    try:
        rule = NoiseFilterRule.query.get_or_404(rule_id)
        data = request.get_json()
        
        # Track changes
        changes = {}
        
        # Update fields
        if 'name' in data and data['name'] != rule.name:
            changes['name'] = {'old': rule.name, 'new': data['name']}
            rule.name = data['name']
        
        if 'description' in data and data['description'] != rule.description:
            changes['description'] = {'old': rule.description, 'new': data['description']}
            rule.description = data['description']
        
        if 'filter_type' in data and data['filter_type'] != rule.filter_type:
            changes['filter_type'] = {'old': rule.filter_type, 'new': data['filter_type']}
            rule.filter_type = data['filter_type']
        
        if 'pattern' in data and data['pattern'] != rule.pattern:
            changes['pattern'] = {'old': rule.pattern, 'new': data['pattern']}
            rule.pattern = data['pattern']
        
        if 'match_mode' in data and data['match_mode'] != rule.match_mode:
            changes['match_mode'] = {'old': rule.match_mode, 'new': data['match_mode']}
            rule.match_mode = data['match_mode']
        
        if 'is_case_sensitive' in data and data['is_case_sensitive'] != rule.is_case_sensitive:
            changes['is_case_sensitive'] = {'old': rule.is_case_sensitive, 'new': data['is_case_sensitive']}
            rule.is_case_sensitive = data['is_case_sensitive']
        
        if 'priority' in data and data['priority'] != rule.priority:
            changes['priority'] = {'old': rule.priority, 'new': data['priority']}
            rule.priority = data['priority']
        
        rule.updated_by = current_user.id
        db.session.commit()
        
        # Audit log if changes were made
        if changes:
            log_action('modify_noise_filter_rule',
                       resource_type='noise_filter_rule',
                       resource_id=rule.id,
                       resource_name=rule.name,
                       details={
                           'changes': changes,
                           'updated_by': current_user.username
                       })
        
        logger.info(f"Noise filter rule '{rule.name}' updated by {current_user.username}")
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error editing noise filter rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@noise_filters_bp.route('/api/rules/<int:rule_id>/toggle', methods=['POST'])
@login_required
@admin_required
def api_toggle_rule(rule_id):
    """
    API endpoint to toggle a noise filter rule enabled/disabled
    """
    try:
        rule = NoiseFilterRule.query.get_or_404(rule_id)
        data = request.get_json()
        
        is_enabled = data.get('is_enabled')
        if is_enabled is None:
            return jsonify({'success': False, 'error': 'Missing is_enabled parameter'}), 400
        
        old_value = rule.is_enabled
        rule.is_enabled = is_enabled
        rule.updated_by = current_user.id
        db.session.commit()
        
        # Audit log
        log_action('toggle_noise_filter_rule',
                   resource_type='noise_filter_rule',
                   resource_id=rule.id,
                   resource_name=rule.name,
                   details={
                       'old_value': old_value,
                       'new_value': is_enabled,
                       'updated_by': current_user.username
                   })
        
        logger.info(f"Noise filter rule '{rule.name}' {'enabled' if is_enabled else 'disabled'} by {current_user.username}")
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error toggling noise filter rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@noise_filters_bp.route('/api/rules/<int:rule_id>/delete', methods=['POST'])
@login_required
@admin_required
def api_delete_rule(rule_id):
    """
    API endpoint to delete a noise filter rule
    Only custom rules can be deleted
    """
    try:
        rule = NoiseFilterRule.query.get_or_404(rule_id)
        
        # Prevent deletion of system defaults
        if rule.is_system_default:
            return jsonify({'success': False, 'error': 'Cannot delete system default rules. Disable them instead.'}), 400
        
        rule_name = rule.name
        
        db.session.delete(rule)
        db.session.commit()
        
        # Audit log
        log_action('delete_noise_filter_rule',
                   resource_type='noise_filter_rule',
                   resource_id=rule_id,
                   resource_name=rule_name,
                   details={
                       'deleted_by': current_user.username
                   })
        
        logger.info(f"Noise filter rule '{rule_name}' deleted by {current_user.username}")
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting noise filter rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@noise_filters_bp.route('/api/categories/<int:category_id>/toggle', methods=['POST'])
@login_required
@admin_required
def api_toggle_category(category_id):
    """
    API endpoint to toggle a category enabled/disabled
    """
    try:
        category = NoiseFilterCategory.query.get_or_404(category_id)
        data = request.get_json()
        
        is_enabled = data.get('is_enabled')
        if is_enabled is None:
            return jsonify({'success': False, 'error': 'Missing is_enabled parameter'}), 400
        
        old_value = category.is_enabled
        category.is_enabled = is_enabled
        db.session.commit()
        
        # Audit log
        log_action('toggle_noise_filter_category',
                   resource_type='noise_filter_category',
                   resource_id=category.id,
                   resource_name=category.name,
                   details={
                       'old_value': old_value,
                       'new_value': is_enabled,
                       'updated_by': current_user.username
                   })
        
        logger.info(f"Noise filter category '{category.name}' {'enabled' if is_enabled else 'disabled'} by {current_user.username}")
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error toggling noise filter category: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@noise_filters_bp.route('/api/stats')
@login_required
@admin_required
def api_noise_filter_stats():
    """
    API endpoint to get noise filter statistics
    """
    try:
        from sqlalchemy import func
        
        # Get overall stats
        total_rules = NoiseFilterRule.query.count()
        enabled_rules = NoiseFilterRule.query.filter_by(is_enabled=True).count()
        disabled_rules = NoiseFilterRule.query.filter_by(is_enabled=False).count()
        
        # Get stats by category
        category_stats = db.session.query(
            NoiseFilterCategory.name,
            func.count(NoiseFilterRule.id).label('total'),
            func.sum(db.case((NoiseFilterRule.is_enabled == True, 1), else_=0)).label('enabled')
        ).join(NoiseFilterRule).group_by(NoiseFilterCategory.name).all()
        
        # Get stats by filter type
        type_stats = db.session.query(
            NoiseFilterRule.filter_type,
            func.count(NoiseFilterRule.id).label('total'),
            func.sum(db.case((NoiseFilterRule.is_enabled == True, 1), else_=0)).label('enabled')
        ).group_by(NoiseFilterRule.filter_type).all()
        
        return jsonify({
            'total_rules': total_rules,
            'enabled_rules': enabled_rules,
            'disabled_rules': disabled_rules,
            'category_stats': [{'category': cat, 'total': total, 'enabled': enabled or 0} for cat, total, enabled in category_stats],
            'type_stats': [{'type': ftype, 'total': total, 'enabled': enabled or 0} for ftype, total, enabled in type_stats]
        })
        
    except Exception as e:
        logger.error(f"Error getting noise filter stats: {e}")
        return jsonify({'error': str(e)}), 500

