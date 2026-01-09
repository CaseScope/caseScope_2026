"""Main routes for CaseScope"""
from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
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


@main_bp.route('/cases/new')
@login_required
def case_create():
    """Create new case form"""
    return render_template('case_create.html', page_title='Create Case')
