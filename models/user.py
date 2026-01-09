"""User Model for CaseScope Authentication"""
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from models.database import db
from config import PermissionLevel, UserSettings


class User(UserMixin, db.Model):
    """User model for authentication and authorization
    
    Permission Levels:
    - Administrator: Full access to all features
    - Analyst: Can create/modify own data, cannot delete, cannot modify other users
    - Viewer: Read-only access to assigned cases only
    """
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    permission_level = db.Column(
        db.String(50), 
        nullable=False, 
        default=PermissionLevel.VIEWER
    )
    
    # Tracking fields
    created_by = db.Column(db.String(80), nullable=True)  # Username of creator
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Account status
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    # For Viewer role - assigned cases (JSON array of case IDs)
    assigned_cases = db.Column(db.JSON, default=list)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)
    
    @staticmethod
    def validate_password(password):
        """Validate password meets requirements
        
        Returns tuple (is_valid, error_message)
        """
        if len(password) < UserSettings.PASSWORD_MIN_LENGTH:
            return False, f'Password must be at least {UserSettings.PASSWORD_MIN_LENGTH} characters long'
        
        if UserSettings.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            return False, 'Password must contain at least one uppercase letter'
        
        if UserSettings.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            return False, 'Password must contain at least one lowercase letter'
        
        if UserSettings.PASSWORD_REQUIRE_DIGIT and not any(c.isdigit() for c in password):
            return False, 'Password must contain at least one digit'
        
        if UserSettings.PASSWORD_REQUIRE_SPECIAL:
            special_chars = '!@#$%^&*()_+-=[]{}|;:,.<>?'
            if not any(c in special_chars for c in password):
                return False, 'Password must contain at least one special character'
        
        return True, None
    
    @property
    def is_administrator(self):
        """Check if user is an administrator"""
        return self.permission_level == PermissionLevel.ADMINISTRATOR
    
    @property
    def is_analyst(self):
        """Check if user is an analyst"""
        return self.permission_level == PermissionLevel.ANALYST
    
    @property
    def is_viewer(self):
        """Check if user is a viewer"""
        return self.permission_level == PermissionLevel.VIEWER
    
    def can_access_case(self, case_id):
        """Check if user can access a specific case"""
        if self.is_administrator or self.is_analyst:
            return True
        # Viewers can only access assigned cases
        return case_id in (self.assigned_cases or [])
    
    def can_modify_user(self, target_user):
        """Check if this user can modify another user
        
        - Administrators can modify anyone
        - Analysts can only modify their own profile
        - Viewers cannot modify anyone (including themselves)
        """
        if self.is_administrator:
            return True
        if self.is_analyst and self.id == target_user.id:
            return True
        return False
    
    def can_delete(self):
        """Check if user can delete data
        
        Only administrators can delete
        """
        return self.is_administrator
    
    def is_account_locked(self):
        """Check if account is currently locked"""
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until
    
    def record_failed_login(self):
        """Record a failed login attempt"""
        from datetime import timedelta
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= UserSettings.MAX_LOGIN_ATTEMPTS:
            self.locked_until = datetime.utcnow() + timedelta(
                minutes=UserSettings.LOCKOUT_DURATION_MINUTES
            )
    
    def record_successful_login(self):
        """Record a successful login"""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.utcnow()
    
    def to_dict(self):
        """Convert user to dictionary for API responses"""
        return {
            'id': self.id,
            'username': self.username,
            'full_name': self.full_name,
            'email': self.email,
            'permission_level': self.permission_level,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active
        }
