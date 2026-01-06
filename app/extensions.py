"""
Flask Extensions
Centralized initialization of Flask extensions to avoid circular imports
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()

def init_extensions(app):
    """Initialize Flask extensions with app instance"""
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.auth_login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'

