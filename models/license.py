"""License Model for CaseScope

Stores license activation history and audit trail.
"""

from datetime import datetime
from models.database import db


class LicenseActivation(db.Model):
    """License activation history and current status."""
    __tablename__ = 'license_activations'
    
    id = db.Column(db.Integer, primary_key=True)
    license_id = db.Column(db.String(100), nullable=False, index=True)
    customer_id = db.Column(db.String(100), nullable=False)
    customer_name = db.Column(db.String(255), nullable=True)
    
    # License validity period
    issued_at = db.Column(db.DateTime, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    # Features enabled in this license
    features_json = db.Column(db.Text, nullable=True)  # JSON string of features dict
    
    # Activation details
    activated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    activated_by = db.Column(db.String(80), nullable=True)  # Username who activated
    
    # Fingerprint info at activation time
    fingerprint_hash = db.Column(db.String(64), nullable=True)
    fingerprint_match_count = db.Column(db.Integer, nullable=True)
    
    # Status
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    deactivated_at = db.Column(db.DateTime, nullable=True)
    deactivation_reason = db.Column(db.String(255), nullable=True)
    
    def __repr__(self):
        return f'<LicenseActivation {self.license_id} for {self.customer_name}>'
    
    @property
    def features(self):
        """Get features as dictionary."""
        if self.features_json:
            import json
            try:
                return json.loads(self.features_json)
            except (ValueError, TypeError):
                return {}
        return {}
    
    @features.setter
    def features(self, value):
        """Set features from dictionary."""
        import json
        self.features_json = json.dumps(value) if value else None
    
    @property
    def is_expired(self):
        """Check if license is expired."""
        return datetime.utcnow() > self.expires_at
    
    @property
    def days_until_expiry(self):
        """Get days until license expires."""
        if self.is_expired:
            return 0
        delta = self.expires_at - datetime.utcnow()
        return delta.days
    
    @classmethod
    def get_current(cls):
        """Get the current active license activation."""
        return cls.query.filter_by(is_active=True).order_by(cls.activated_at.desc()).first()
    
    @classmethod
    def record_activation(cls, license_data: dict, activated_by: str = None, 
                         fingerprint_hash: str = None, fingerprint_match_count: int = None):
        """
        Record a new license activation.
        
        Args:
            license_data: License data from the license file
            activated_by: Username who activated the license
            fingerprint_hash: Current machine fingerprint hash
            fingerprint_match_count: Number of fingerprint components that matched
            
        Returns:
            LicenseActivation: The new activation record
        """
        import json
        from datetime import datetime
        
        # Deactivate any existing active licenses
        existing = cls.query.filter_by(is_active=True).all()
        for existing_lic in existing:
            existing_lic.is_active = False
            existing_lic.deactivated_at = datetime.utcnow()
            existing_lic.deactivation_reason = 'Replaced by new license'
        
        # Parse dates from license data
        issued_at = datetime.fromisoformat(license_data['issued_at'].replace('Z', '+00:00'))
        expires_at = datetime.fromisoformat(license_data['expires_at'].replace('Z', '+00:00'))
        
        # Create new activation record
        activation = cls(
            license_id=license_data.get('license_id', 'unknown'),
            customer_id=license_data.get('customer_id', 'unknown'),
            customer_name=license_data.get('customer_name'),
            issued_at=issued_at.replace(tzinfo=None),
            expires_at=expires_at.replace(tzinfo=None),
            features_json=json.dumps(license_data.get('features', {})),
            activated_by=activated_by,
            fingerprint_hash=fingerprint_hash,
            fingerprint_match_count=fingerprint_match_count,
            is_active=True
        )
        
        db.session.add(activation)
        db.session.commit()
        
        return activation
    
    @classmethod
    def get_activation_history(cls, limit: int = 10):
        """Get license activation history."""
        return cls.query.order_by(cls.activated_at.desc()).limit(limit).all()
    
    def to_dict(self):
        """Convert to dictionary for API responses."""
        return {
            'id': self.id,
            'license_id': self.license_id,
            'customer_id': self.customer_id,
            'customer_name': self.customer_name,
            'issued_at': self.issued_at.isoformat() if self.issued_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'activated_at': self.activated_at.isoformat() if self.activated_at else None,
            'activated_by': self.activated_by,
            'features': self.features,
            'is_active': self.is_active,
            'is_expired': self.is_expired,
            'days_until_expiry': self.days_until_expiry,
            'deactivated_at': self.deactivated_at.isoformat() if self.deactivated_at else None,
            'deactivation_reason': self.deactivation_reason
        }


class ActivationAuditLog(db.Model):
    """Audit log for activation-related actions."""
    __tablename__ = 'activation_audit_log'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    action = db.Column(db.String(50), nullable=False)  # activate, deactivate, validate_success, validate_fail
    username = db.Column(db.String(80), nullable=True)
    license_id = db.Column(db.String(100), nullable=True)
    details = db.Column(db.Text, nullable=True)  # JSON with additional details
    ip_address = db.Column(db.String(45), nullable=True)
    
    def __repr__(self):
        return f'<ActivationAuditLog {self.action} at {self.timestamp}>'
    
    @classmethod
    def log(cls, action: str, username: str = None, license_id: str = None, 
            details: dict = None, ip_address: str = None):
        """
        Log an activation-related action.
        
        Args:
            action: Action type (activate, deactivate, validate_success, validate_fail)
            username: Username who performed the action
            license_id: License ID involved
            details: Additional details as dict
            ip_address: Client IP address
        """
        import json
        
        entry = cls(
            action=action,
            username=username,
            license_id=license_id,
            details=json.dumps(details) if details else None,
            ip_address=ip_address
        )
        
        db.session.add(entry)
        db.session.commit()
        
        return entry
    
    @classmethod
    def get_recent(cls, limit: int = 50):
        """Get recent audit log entries."""
        return cls.query.order_by(cls.timestamp.desc()).limit(limit).all()
    
    def to_dict(self):
        """Convert to dictionary for API responses."""
        import json
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'action': self.action,
            'username': self.username,
            'license_id': self.license_id,
            'details': json.loads(self.details) if self.details else None,
            'ip_address': self.ip_address
        }
