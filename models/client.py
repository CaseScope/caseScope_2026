"""Client Model for CaseScope

Clients represent organizations/companies that cases belong to.
Agents are deployed per-client to collect forensic artifacts.
"""
import uuid
from datetime import datetime
from models.database import db


class Client(db.Model):
    """Client model for organization/company management
    
    Clients are the top-level entity that cases and agents belong to.
    Uses UUID for obfuscation - no sequential IDs exposed externally.
    """
    __tablename__ = 'clients'
    
    # Primary key - internal integer for DB efficiency
    id = db.Column(db.Integer, primary_key=True)
    
    # Public UUID for external references (obfuscation)
    uuid = db.Column(db.String(36), unique=True, nullable=False, index=True, 
                     default=lambda: str(uuid.uuid4()))
    
    # Client name - full organization name
    name = db.Column(db.String(255), nullable=False, index=True)
    
    # Client code - short identifier (e.g., "ACME", "GLOBEX")
    code = db.Column(db.String(20), unique=True, nullable=False, index=True)
    
    # Default timezone for this client's cases
    timezone = db.Column(db.String(50), nullable=False, default='UTC')
    
    # Contact information
    contact_name = db.Column(db.String(255), nullable=True)
    contact_email = db.Column(db.String(255), nullable=True)
    
    # Notes/description
    notes = db.Column(db.Text, nullable=True)
    
    # Status
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    
    # Tracking fields
    created_by = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, 
                           onupdate=datetime.utcnow)
    
    # Relationships
    cases = db.relationship('Case', backref='client', lazy='dynamic',
                           foreign_keys='Case.client_id')
    agents = db.relationship('Agent', backref='client', lazy='dynamic',
                            foreign_keys='Agent.client_id')
    
    def __repr__(self):
        return f'<Client {self.code}: {self.name}>'
    
    @property
    def case_count(self):
        """Get count of cases for this client"""
        return self.cases.count()
    
    @property
    def agent_count(self):
        """Get count of agents for this client"""
        return self.agents.count()
    
    @property
    def active_agent_count(self):
        """Get count of online agents for this client"""
        return self.agents.filter_by(status='online').count()
    
    def to_dict(self):
        """Convert client to dictionary for API responses"""
        return {
            'uuid': self.uuid,
            'name': self.name,
            'code': self.code,
            'timezone': self.timezone,
            'contact_name': self.contact_name,
            'contact_email': self.contact_email,
            'notes': self.notes,
            'is_active': self.is_active,
            'case_count': self.case_count,
            'agent_count': self.agent_count,
            'active_agent_count': self.active_agent_count,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def to_dict_minimal(self):
        """Minimal dict for dropdowns and lists"""
        return {
            'uuid': self.uuid,
            'name': self.name,
            'code': self.code,
            'is_active': self.is_active
        }
    
    @staticmethod
    def get_by_uuid(client_uuid):
        """Get client by UUID"""
        return Client.query.filter_by(uuid=client_uuid).first()
    
    @staticmethod
    def get_by_code(code):
        """Get client by code"""
        return Client.query.filter_by(code=code.upper()).first()
    
    @staticmethod
    def get_active_clients():
        """Get all active clients ordered by name"""
        return Client.query.filter_by(is_active=True).order_by(Client.name).all()
    
    @staticmethod
    def generate_code_from_name(name):
        """Generate a unique code from company name
        
        Takes first letters of words, uppercase, max 10 chars.
        Appends number if code already exists.
        """
        # Extract first letter of each word
        words = name.upper().split()
        if len(words) >= 2:
            # Use first letter of first 4 words max
            code = ''.join(word[0] for word in words[:4] if word)
        else:
            # Single word - use first 4 characters
            code = name.upper()[:4]
        
        # Ensure minimum 2 characters
        if len(code) < 2:
            code = name.upper()[:4]
        
        # Remove non-alphanumeric
        code = ''.join(c for c in code if c.isalnum())[:10]
        
        # Check if exists and append number if needed
        base_code = code
        counter = 1
        while Client.query.filter_by(code=code).first() is not None:
            code = f"{base_code}{counter}"
            counter += 1
            if len(code) > 10:
                code = f"{base_code[:8]}{counter}"
        
        return code
