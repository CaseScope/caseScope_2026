"""Case Model for CaseScope"""
import uuid
from datetime import datetime
from models.database import db

# Common IANA timezones for dropdown selection
COMMON_TIMEZONES = [
    ('UTC', 'UTC (Coordinated Universal Time)'),
    ('America/New_York', 'US Eastern (New York)'),
    ('America/Chicago', 'US Central (Chicago)'),
    ('America/Denver', 'US Mountain (Denver)'),
    ('America/Los_Angeles', 'US Pacific (Los Angeles)'),
    ('America/Anchorage', 'US Alaska'),
    ('Pacific/Honolulu', 'US Hawaii'),
    ('America/Toronto', 'Canada Eastern (Toronto)'),
    ('America/Vancouver', 'Canada Pacific (Vancouver)'),
    ('Europe/London', 'UK (London)'),
    ('Europe/Paris', 'Central Europe (Paris)'),
    ('Europe/Berlin', 'Central Europe (Berlin)'),
    ('Europe/Amsterdam', 'Central Europe (Amsterdam)'),
    ('Europe/Zurich', 'Central Europe (Zurich)'),
    ('Europe/Rome', 'Central Europe (Rome)'),
    ('Europe/Madrid', 'Central Europe (Madrid)'),
    ('Europe/Stockholm', 'Northern Europe (Stockholm)'),
    ('Europe/Helsinki', 'Northern Europe (Helsinki)'),
    ('Europe/Warsaw', 'Eastern Europe (Warsaw)'),
    ('Europe/Moscow', 'Russia (Moscow)'),
    ('Asia/Dubai', 'Gulf (Dubai)'),
    ('Asia/Kolkata', 'India (Kolkata)'),
    ('Asia/Singapore', 'Singapore'),
    ('Asia/Hong_Kong', 'Hong Kong'),
    ('Asia/Shanghai', 'China (Shanghai)'),
    ('Asia/Tokyo', 'Japan (Tokyo)'),
    ('Asia/Seoul', 'Korea (Seoul)'),
    ('Australia/Sydney', 'Australia Eastern (Sydney)'),
    ('Australia/Melbourne', 'Australia Eastern (Melbourne)'),
    ('Australia/Perth', 'Australia Western (Perth)'),
    ('Pacific/Auckland', 'New Zealand (Auckland)'),
]


class CaseStatus:
    """Case Status Options"""
    NEW = 'new'
    ASSIGNED = 'assigned'
    IN_PROGRESS = 'in_progress'
    IN_REVIEW = 'in_review'
    FINISHED = 'finished'
    ARCHIVED = 'archived'
    
    @classmethod
    def choices(cls):
        """Return list of status choices for forms"""
        return [
            (cls.NEW, 'New'),
            (cls.ASSIGNED, 'Assigned'),
            (cls.IN_PROGRESS, 'In Progress'),
            (cls.IN_REVIEW, 'In Review'),
            (cls.FINISHED, 'Finished'),
            (cls.ARCHIVED, 'Archived')
        ]
    
    @classmethod
    def all(cls):
        """Return all status values"""
        return [cls.NEW, cls.ASSIGNED, cls.IN_PROGRESS, cls.IN_REVIEW, cls.FINISHED, cls.ARCHIVED]


class Case(db.Model):
    """Case model for forensic case management
    
    Uses UUID for obfuscation - no sequential IDs exposed.
    """
    __tablename__ = 'cases'
    
    # Primary key - internal integer for DB efficiency
    id = db.Column(db.Integer, primary_key=True)
    
    # Public UUID for external references (obfuscation)
    uuid = db.Column(db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
    
    # Case name - mandatory
    name = db.Column(db.String(255), nullable=False, index=True)
    
    # Company - mandatory
    company = db.Column(db.String(255), nullable=False, index=True)
    
    # Description
    description = db.Column(db.Text, nullable=True)
    
    # EDR Report
    edr_report = db.Column(db.Text, nullable=True)
    
    # Network information
    router_ips = db.Column(db.Text, nullable=True)  # Single IP or comma-separated IPs
    vpn_ips = db.Column(db.Text, nullable=True)  # IPs, ranges (192.168.1.150-160), or CIDR (192.168.0.0/24)
    
    # Timezone for artifact display and time window queries
    # IANA timezone identifier (e.g., 'America/New_York', 'UTC')
    timezone = db.Column(db.String(50), nullable=False, default='UTC')
    
    # Status
    status = db.Column(
        db.String(50),
        nullable=False,
        default=CaseStatus.NEW,
        index=True
    )
    
    # Tracking fields
    created_by = db.Column(db.String(80), nullable=False)  # Username of creator
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Assignment
    assigned_to = db.Column(db.String(80), nullable=True, index=True)  # Username assigned to
    assigned_at = db.Column(db.DateTime, nullable=True)  # When assignment was made
    
    # Noise detection tracking
    noise_last_scan = db.Column(db.DateTime, nullable=True)  # Last noise scan timestamp
    
    # Remediation documentation fields (for final reports)
    containment_actions = db.Column(db.Text, nullable=True)  # Isolation, blocks, account disables
    eradication_actions = db.Column(db.Text, nullable=True)  # Malware removal, cleanup
    recovery_actions = db.Column(db.Text, nullable=True)     # Credential resets, system restoration
    lessons_learned = db.Column(db.Text, nullable=True)      # What to prevent next time
    
    def __repr__(self):
        return f'<Case {self.uuid}: {self.name}>'
    
    def assign_to(self, username):
        """Assign case to a user"""
        self.assigned_to = username
        self.assigned_at = datetime.utcnow()
        if self.status == CaseStatus.NEW:
            self.status = CaseStatus.ASSIGNED
    
    def to_dict(self):
        """Convert case to dictionary for API responses"""
        return {
            'uuid': self.uuid,
            'name': self.name,
            'company': self.company,
            'description': self.description,
            'edr_report': self.edr_report,
            'router_ips': self.router_ips,
            'vpn_ips': self.vpn_ips,
            'timezone': self.timezone,
            'status': self.status,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'assigned_to': self.assigned_to,
            'assigned_at': self.assigned_at.isoformat() if self.assigned_at else None,
            'containment_actions': self.containment_actions,
            'eradication_actions': self.eradication_actions,
            'recovery_actions': self.recovery_actions,
            'lessons_learned': self.lessons_learned
        }
    
    @staticmethod
    def get_by_uuid(case_uuid):
        """Get case by UUID"""
        return Case.query.filter_by(uuid=case_uuid).first()
    
    @staticmethod
    def get_status_display(status):
        """Get display name for status"""
        status_map = dict(CaseStatus.choices())
        return status_map.get(status, status)
