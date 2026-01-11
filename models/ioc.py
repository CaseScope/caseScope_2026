"""IOC (Indicators of Compromise) Models for CaseScope

Tracks IOCs discovered across cases with full audit history,
system sightings, and artifact correlation.
"""
import re
import uuid
from datetime import datetime
from models.database import db


class IOCCategory:
    """IOC Category Types"""
    NETWORK = 'Network'
    FILE = 'File'
    EMAIL = 'Email'
    REGISTRY = 'Registry'
    PROCESS = 'Process'
    AUTHENTICATION = 'Authentication'
    MALWARE = 'Malware'
    BEHAVIORAL = 'Behavioral'
    CRYPTOCURRENCY = 'Cryptocurrency'
    MOBILE = 'Mobile'
    
    @classmethod
    def all(cls):
        return [
            cls.NETWORK, cls.FILE, cls.EMAIL, cls.REGISTRY, cls.PROCESS,
            cls.AUTHENTICATION, cls.MALWARE, cls.BEHAVIORAL, 
            cls.CRYPTOCURRENCY, cls.MOBILE
        ]
    
    @classmethod
    def choices(cls):
        return [(c, c) for c in cls.all()]
    
    @classmethod
    def icons(cls):
        """Return icon for each category"""
        return {
            cls.NETWORK: '🌐',
            cls.FILE: '📄',
            cls.EMAIL: '📧',
            cls.REGISTRY: '🗂️',
            cls.PROCESS: '⚙️',
            cls.AUTHENTICATION: '🔐',
            cls.MALWARE: '🦠',
            cls.BEHAVIORAL: '📊',
            cls.CRYPTOCURRENCY: '💰',
            cls.MOBILE: '📱'
        }


# Predefined IOC types with their categories and validation patterns
IOC_TYPE_DEFINITIONS = {
    # Network
    'IP Address (IPv4)': {
        'category': IOCCategory.NETWORK,
        'regex': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    },
    'IP Address (IPv6)': {
        'category': IOCCategory.NETWORK,
        'regex': r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$'
    },
    'Hostname': {
        'category': IOCCategory.NETWORK,
        'regex': r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    },
    'FQDN': {
        'category': IOCCategory.NETWORK,
        'regex': r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    },
    'Domain': {
        'category': IOCCategory.NETWORK,
        'regex': r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    },
    'URL': {
        'category': IOCCategory.NETWORK,
        'regex': r'^https?://[^\s<>"{}|\\^`\[\]]+$'
    },
    'Port': {
        'category': IOCCategory.NETWORK,
        'regex': r'^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$'
    },
    'User-Agent': {
        'category': IOCCategory.NETWORK,
        'regex': None
    },
    'JA3 Hash': {
        'category': IOCCategory.NETWORK,
        'regex': r'^[a-fA-F0-9]{32}$'
    },
    'JA3S Hash': {
        'category': IOCCategory.NETWORK,
        'regex': r'^[a-fA-F0-9]{32}$'
    },
    'SSL Certificate Hash': {
        'category': IOCCategory.NETWORK,
        'regex': r'^[a-fA-F0-9]{40,64}$'
    },
    'ASN': {
        'category': IOCCategory.NETWORK,
        'regex': r'^AS\d+$'
    },
    
    # File
    'MD5 Hash': {
        'category': IOCCategory.FILE,
        'regex': r'^[a-fA-F0-9]{32}$'
    },
    'SHA1 Hash': {
        'category': IOCCategory.FILE,
        'regex': r'^[a-fA-F0-9]{40}$'
    },
    'SHA256 Hash': {
        'category': IOCCategory.FILE,
        'regex': r'^[a-fA-F0-9]{64}$'
    },
    'File Name': {
        'category': IOCCategory.FILE,
        'regex': None
    },
    'File Path': {
        'category': IOCCategory.FILE,
        'regex': None
    },
    'File Extension': {
        'category': IOCCategory.FILE,
        'regex': r'^\.[a-zA-Z0-9]{1,10}$'
    },
    'MIME Type': {
        'category': IOCCategory.FILE,
        'regex': r'^[a-zA-Z]+/[a-zA-Z0-9\-\+\.]+$'
    },
    'Imphash': {
        'category': IOCCategory.FILE,
        'regex': r'^[a-fA-F0-9]{32}$'
    },
    'SSDeep Hash': {
        'category': IOCCategory.FILE,
        'regex': None
    },
    'TLSH Hash': {
        'category': IOCCategory.FILE,
        'regex': r'^T1[a-fA-F0-9]{70}$'
    },
    
    # Email
    'Email Address': {
        'category': IOCCategory.EMAIL,
        'regex': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    },
    'Email Subject': {
        'category': IOCCategory.EMAIL,
        'regex': None
    },
    'Reply-To Address': {
        'category': IOCCategory.EMAIL,
        'regex': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    },
    'X-Originating-IP': {
        'category': IOCCategory.EMAIL,
        'regex': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    },
    'Message-ID': {
        'category': IOCCategory.EMAIL,
        'regex': None
    },
    
    # Registry
    'Registry Key': {
        'category': IOCCategory.REGISTRY,
        'regex': None
    },
    'Registry Value': {
        'category': IOCCategory.REGISTRY,
        'regex': None
    },
    
    # Process
    'Process Name': {
        'category': IOCCategory.PROCESS,
        'regex': None
    },
    'Process Path': {
        'category': IOCCategory.PROCESS,
        'regex': None
    },
    'Command Line': {
        'category': IOCCategory.PROCESS,
        'regex': None
    },
    'Service Name': {
        'category': IOCCategory.PROCESS,
        'regex': None
    },
    'Mutex Name': {
        'category': IOCCategory.PROCESS,
        'regex': None
    },
    
    # Authentication
    'Username': {
        'category': IOCCategory.AUTHENTICATION,
        'regex': None
    },
    'Password Hash': {
        'category': IOCCategory.AUTHENTICATION,
        'regex': None
    },
    'SSH Key Fingerprint': {
        'category': IOCCategory.AUTHENTICATION,
        'regex': None
    },
    'API Key': {
        'category': IOCCategory.AUTHENTICATION,
        'regex': None
    },
    
    # Malware
    'Malware Family': {
        'category': IOCCategory.MALWARE,
        'regex': None
    },
    'YARA Rule Name': {
        'category': IOCCategory.MALWARE,
        'regex': None
    },
    'PDB Path': {
        'category': IOCCategory.MALWARE,
        'regex': None
    },
    
    # Behavioral
    'Scheduled Task': {
        'category': IOCCategory.BEHAVIORAL,
        'regex': None
    },
    'Cron Job': {
        'category': IOCCategory.BEHAVIORAL,
        'regex': None
    },
    'Persistence Mechanism': {
        'category': IOCCategory.BEHAVIORAL,
        'regex': None
    },
    
    # Cryptocurrency
    'Bitcoin Address': {
        'category': IOCCategory.CRYPTOCURRENCY,
        'regex': r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-zA-HJ-NP-Z0-9]{39,59}$'
    },
    'Ethereum Address': {
        'category': IOCCategory.CRYPTOCURRENCY,
        'regex': r'^0x[a-fA-F0-9]{40}$'
    },
    'Monero Address': {
        'category': IOCCategory.CRYPTOCURRENCY,
        'regex': r'^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$'
    },
    
    # Mobile
    'App Package Name': {
        'category': IOCCategory.MOBILE,
        'regex': r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$'
    },
    'Device IMEI': {
        'category': IOCCategory.MOBILE,
        'regex': r'^\d{15,17}$'
    }
}


class IOC(db.Model):
    """Indicator of Compromise model
    
    Central table for tracking all IOCs with metadata about
    creation, artifact sightings, and system associations.
    """
    __tablename__ = 'iocs'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Public UUID for external references
    uuid = db.Column(db.String(36), unique=True, nullable=False, 
                     index=True, default=lambda: str(uuid.uuid4()))
    
    # IOC Classification
    category = db.Column(db.String(50), nullable=False, index=True)
    ioc_type = db.Column(db.String(100), nullable=False, index=True)
    
    # The actual IOC value
    value = db.Column(db.String(4096), nullable=False)
    value_normalized = db.Column(db.String(4096), nullable=False, index=True)
    
    # Creation metadata
    created_by = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Artifact sighting timestamps
    first_seen_in_artifacts = db.Column(db.DateTime, nullable=True)
    last_seen_in_artifacts = db.Column(db.DateTime, nullable=True)
    
    # Counts
    artifact_count = db.Column(db.Integer, nullable=False, default=0)
    
    # Analyst notes
    notes = db.Column(db.Text, nullable=True)
    
    # Status flags
    malicious = db.Column(db.Boolean, nullable=False, default=False)
    false_positive = db.Column(db.Boolean, nullable=False, default=False)
    
    # Relationships
    system_sightings = db.relationship('IOCSystemSighting', backref='ioc', 
                                       lazy='dynamic', cascade='all, delete-orphan')
    cases = db.relationship('IOCCase', backref='ioc', 
                           lazy='dynamic', cascade='all, delete-orphan')
    
    # Unique constraint: same IOC type + normalized value should be unique
    __table_args__ = (
        db.UniqueConstraint('ioc_type', 'value_normalized', name='uq_ioc_type_value'),
    )
    
    def __repr__(self):
        return f'<IOC {self.id}: {self.ioc_type}={self.value[:50]}>'
    
    @staticmethod
    def normalize_value(value, ioc_type=None):
        """Normalize IOC value for consistent storage and lookup
        
        - IP addresses: as-is (already normalized format)
        - Hashes: lowercase
        - Domains/URLs: lowercase
        - File paths: lowercase (Windows-friendly)
        - Email: lowercase
        - Other: strip whitespace
        """
        if not value:
            return ''
        
        value = str(value).strip()
        
        # Lowercase for case-insensitive types
        lowercase_types = [
            'MD5 Hash', 'SHA1 Hash', 'SHA256 Hash', 'Imphash', 'JA3 Hash', 
            'JA3S Hash', 'SSL Certificate Hash', 'TLSH Hash',
            'Domain', 'FQDN', 'URL', 'Hostname',
            'Email Address', 'Reply-To Address',
            'File Path', 'Process Path'
        ]
        
        if ioc_type in lowercase_types:
            return value.lower()
        
        return value
    
    @staticmethod
    def validate_value(value, ioc_type):
        """Validate IOC value against type-specific regex
        
        Returns: (is_valid, error_message)
        """
        if not value:
            return False, 'Value cannot be empty'
        
        type_def = IOC_TYPE_DEFINITIONS.get(ioc_type)
        if not type_def:
            return True, None  # Unknown type, allow anything
        
        regex = type_def.get('regex')
        if not regex:
            return True, None  # No validation pattern
        
        if not re.match(regex, value):
            return False, f'Value does not match expected format for {ioc_type}'
        
        return True, None
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'uuid': self.uuid,
            'category': self.category,
            'ioc_type': self.ioc_type,
            'value': self.value,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'first_seen_in_artifacts': self.first_seen_in_artifacts.isoformat() if self.first_seen_in_artifacts else None,
            'last_seen_in_artifacts': self.last_seen_in_artifacts.isoformat() if self.last_seen_in_artifacts else None,
            'artifact_count': self.artifact_count,
            'notes': self.notes,
            'malicious': self.malicious,
            'false_positive': self.false_positive,
            'system_count': self.system_sightings.count(),
            'case_count': self.cases.count(),
            'systems': [s.to_dict() for s in self.system_sightings.limit(10)],
            'case_uuids': [c.case.uuid for c in self.cases.limit(10) if c.case]
        }
    
    @staticmethod
    def find_by_value(value, ioc_type):
        """Find an IOC by its normalized value and type"""
        normalized = IOC.normalize_value(value, ioc_type)
        return IOC.query.filter_by(
            ioc_type=ioc_type,
            value_normalized=normalized
        ).first()
    
    @staticmethod
    def get_or_create(value, ioc_type, category, created_by):
        """Get existing IOC or create new one
        
        Returns: (ioc, created_bool)
        """
        normalized = IOC.normalize_value(value, ioc_type)
        
        existing = IOC.query.filter_by(
            ioc_type=ioc_type,
            value_normalized=normalized
        ).first()
        
        if existing:
            return existing, False
        
        # Validate if type has regex
        is_valid, error = IOC.validate_value(value, ioc_type)
        if not is_valid:
            raise ValueError(error)
        
        new_ioc = IOC(
            category=category,
            ioc_type=ioc_type,
            value=value,
            value_normalized=normalized,
            created_by=created_by
        )
        
        db.session.add(new_ioc)
        db.session.flush()  # Ensure ID is assigned for audit logging
        return new_ioc, True
    
    def update_artifact_stats(self, seen_at=None):
        """Update artifact sighting timestamps and count"""
        now = seen_at or datetime.utcnow()
        
        if not self.first_seen_in_artifacts:
            self.first_seen_in_artifacts = now
        
        if not self.last_seen_in_artifacts or now > self.last_seen_in_artifacts:
            self.last_seen_in_artifacts = now
        
        self.artifact_count += 1
    
    def link_to_case(self, case_id):
        """Link this IOC to a case if not already linked"""
        existing = IOCCase.query.filter_by(
            ioc_id=self.id,
            case_id=case_id
        ).first()
        
        if not existing:
            link = IOCCase(
                ioc_id=self.id,
                case_id=case_id
            )
            db.session.add(link)
            return True
        return False
    
    def add_system_sighting(self, system_id, case_id):
        """Record a sighting of this IOC on a system"""
        existing = IOCSystemSighting.query.filter_by(
            ioc_id=self.id,
            system_id=system_id,
            case_id=case_id
        ).first()
        
        if existing:
            existing.last_seen = datetime.utcnow()
            existing.sighting_count += 1
            return False
        
        sighting = IOCSystemSighting(
            ioc_id=self.id,
            system_id=system_id,
            case_id=case_id
        )
        db.session.add(sighting)
        return True


class IOCSystemSighting(db.Model):
    """Records which systems an IOC was found on
    
    Links IOCs to Known Systems with case context and timestamps.
    """
    __tablename__ = 'ioc_system_sightings'
    
    id = db.Column(db.Integer, primary_key=True)
    ioc_id = db.Column(db.Integer, db.ForeignKey('iocs.id'), nullable=False, index=True)
    system_id = db.Column(db.Integer, db.ForeignKey('known_systems.id'), nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    
    first_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    sighting_count = db.Column(db.Integer, nullable=False, default=1)
    
    # Relationship to get system details
    system = db.relationship('KnownSystem', backref='ioc_sightings')
    case = db.relationship('Case', backref='ioc_system_sightings')
    
    __table_args__ = (
        db.UniqueConstraint('ioc_id', 'system_id', 'case_id', name='uq_ioc_system_case'),
    )
    
    def __repr__(self):
        return f'<IOCSystemSighting ioc={self.ioc_id} system={self.system_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'system_id': self.system_id,
            'system_hostname': self.system.hostname if self.system else None,
            'case_id': self.case_id,
            'case_name': self.case.name if self.case else None,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'sighting_count': self.sighting_count
        }


class IOCCase(db.Model):
    """Junction table linking IOCs to cases"""
    __tablename__ = 'ioc_cases'
    
    id = db.Column(db.Integer, primary_key=True)
    ioc_id = db.Column(db.Integer, db.ForeignKey('iocs.id'), nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    first_seen_in_case = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationship
    case = db.relationship('Case', backref='iocs')
    
    __table_args__ = (
        db.UniqueConstraint('ioc_id', 'case_id', name='uq_ioc_case'),
    )
    
    def __repr__(self):
        return f'<IOCCase ioc={self.ioc_id} case={self.case_id}>'


class IOCAudit(db.Model):
    """Audit log for changes to IOCs"""
    __tablename__ = 'ioc_audit'
    
    id = db.Column(db.Integer, primary_key=True)
    ioc_id = db.Column(db.Integer, db.ForeignKey('iocs.id'), nullable=False, index=True)
    changed_on = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    changed_by = db.Column(db.String(80), nullable=False)
    field_name = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(20), nullable=False)  # create, update, delete
    old_value = db.Column(db.Text, nullable=True)
    new_value = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<IOCAudit {self.id}: {self.action} {self.field_name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'ioc_id': self.ioc_id,
            'changed_on': self.changed_on.isoformat() if self.changed_on else None,
            'changed_by': self.changed_by,
            'field_name': self.field_name,
            'action': self.action,
            'old_value': self.old_value,
            'new_value': self.new_value
        }
    
    @staticmethod
    def log_change(ioc_id, changed_by, field_name, action, old_value=None, new_value=None):
        """Create an audit log entry"""
        audit = IOCAudit(
            ioc_id=ioc_id,
            changed_by=changed_by,
            field_name=field_name,
            action=action,
            old_value=str(old_value) if old_value is not None else None,
            new_value=str(new_value) if new_value is not None else None
        )
        db.session.add(audit)
        return audit


def get_ioc_types_by_category():
    """Return IOC types organized by category for UI dropdowns"""
    result = {}
    for type_name, type_def in IOC_TYPE_DEFINITIONS.items():
        category = type_def['category']
        if category not in result:
            result[category] = []
        result[category].append(type_name)
    
    # Sort types within each category
    for category in result:
        result[category].sort()
    
    return result


def get_all_ioc_types():
    """Return list of all IOC types"""
    return sorted(IOC_TYPE_DEFINITIONS.keys())


def get_category_for_type(ioc_type):
    """Get the category for a given IOC type"""
    type_def = IOC_TYPE_DEFINITIONS.get(ioc_type)
    if type_def:
        return type_def['category']
    return None
