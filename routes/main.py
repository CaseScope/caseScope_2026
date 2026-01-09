"""Main routes for CaseScope"""
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from models.database import db
from models.case import Case, CaseStatus

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
@login_required
def index():
    """Dashboard / Home page"""
    return render_template('dashboard.html', page_title='Dashboard')


@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Dashboard page"""
    return render_template('dashboard.html', page_title='Dashboard')


@main_bp.route('/cases')
@login_required
def cases():
    """Case Selection - list all cases"""
    all_cases = Case.query.order_by(Case.created_at.desc()).all()
    return render_template(
        'cases.html',
        page_title='Case Selection',
        cases=all_cases,
        CaseStatus=CaseStatus
    )


@main_bp.route('/cases/new', methods=['GET', 'POST'])
@login_required
def case_create():
    """Create new case form"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        company = request.form.get('company', '').strip()
        description = request.form.get('description', '').strip()
        router_ips = request.form.get('router_ips', '').strip()
        vpn_ips = request.form.get('vpn_ips', '').strip()
        
        # Validate mandatory fields
        if not name:
            flash('Case name is required', 'error')
            return render_template('case_create.html', page_title='Create Case')
        
        if not company:
            flash('Company is required', 'error')
            return render_template('case_create.html', page_title='Create Case')
        
        # Create the case
        case = Case(
            name=name,
            company=company,
            description=description or None,
            router_ips=router_ips or None,
            vpn_ips=vpn_ips or None,
            created_by=current_user.username
        )
        
        db.session.add(case)
        db.session.commit()
        
        flash(f'Case "{name}" created successfully', 'success')
        return redirect(url_for('main.cases'))
    
    return render_template('case_create.html', page_title='Create Case')
