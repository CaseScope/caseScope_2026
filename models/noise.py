"""Noise Filter Models for CaseScope

Tracks known-good software/tools to filter out during hunting.
Opposite of IOCs - these are things we want to IGNORE, not hunt.

Keyword-Based Matching:
    Uses ClickHouse hasTokenCaseInsensitive() for whole-word matching on raw_json.
    This ensures 'ltsvc' matches 'c:\\windows\\ltsvc\\agent.exe' but NOT 'altsvc'.
    
    Keywords are matched as tokens (split by non-alphanumeric chars):
    - OR keywords: If ANY keyword is found → noise
    - AND keywords: Must ALSO find at least one of these → noise  
    - NOT keywords: If ANY of these found → NOT noise (exclusion)
"""
import uuid
from datetime import datetime
from models.database import db


# Legacy classes kept for backward compatibility with existing DB records
class NoiseFilterType:
    """DEPRECATED - No longer used. Kept for DB compatibility."""
    ANY_FIELD = 'any_field'
    
    @classmethod
    def all(cls):
        return [cls.ANY_FIELD]


class NoiseMatchMode:
    """DEPRECATED - No longer used. Kept for DB compatibility."""
    CONTAINS = 'contains'
    
    @classmethod
    def all(cls):
        return [cls.CONTAINS]


class NoiseCategory(db.Model):
    """Categories for organizing noise filter rules
    
    Examples: RMM Tools, EDR Platforms, Remote Access, Backup Software
    Categories are for organization - individual rules are toggled independently.
    Category toggle acts as master switch for all rules within.
    """
    __tablename__ = 'noise_categories'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False,
                     index=True, default=lambda: str(uuid.uuid4()))
    
    name = db.Column(db.String(100), nullable=False, unique=True, index=True)
    description = db.Column(db.Text)
    icon = db.Column(db.String(10), default='🔇')  # Emoji icon
    
    is_enabled = db.Column(db.Boolean, default=True, index=True)
    display_order = db.Column(db.Integer, default=100)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    rules = db.relationship('NoiseRule', backref='category', 
                           cascade='all, delete-orphan', lazy='dynamic')
    
    def __repr__(self):
        return f'<NoiseCategory {self.name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'uuid': self.uuid,
            'name': self.name,
            'description': self.description,
            'icon': self.icon,
            'is_enabled': self.is_enabled,
            'display_order': self.display_order,
            'rule_count': self.rules.count(),
            'enabled_rule_count': self.rules.filter_by(is_enabled=True).count(),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    @staticmethod
    def get_by_uuid(uuid_str):
        return NoiseCategory.query.filter_by(uuid=uuid_str).first()
    
    @staticmethod
    def get_all_ordered():
        return NoiseCategory.query.order_by(NoiseCategory.display_order).all()


class NoiseRule(db.Model):
    """Individual noise filter rules for known-good software/tools
    
    Keyword-Based Token Matching:
        Uses hasTokenCaseInsensitive() on raw_json for whole-word matching.
        Keywords are split by non-alphanumeric characters as tokens.
        
        Example: 'ltsvc' matches 'c:\\windows\\ltsvc\\agent.exe' but NOT 'altsvc'
        
    Keyword Fields:
        - pattern (OR keywords): Comma-separated. Match if ANY keyword found.
        - pattern_and (AND keywords): Must ALSO find at least one of these.
        - pattern_not (NOT keywords): Exclude if ANY of these found.
        
    Logic: (OR1 or OR2) AND (AND1 or AND2) AND NOT (NOT1 or NOT2)
    
    Rule is only active if: category.is_enabled AND rule.is_enabled
    """
    __tablename__ = 'noise_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False,
                     index=True, default=lambda: str(uuid.uuid4()))
    
    category_id = db.Column(db.Integer, db.ForeignKey('noise_categories.id', ondelete='CASCADE'), 
                           nullable=False, index=True)
    
    # Rule identification
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    
    # Keyword configuration (column names kept for DB compatibility)
    # filter_type and match_mode are legacy - always use token matching on raw_json now
    filter_type = db.Column(db.String(50), nullable=False, index=True, default='any_field')
    pattern = db.Column(db.String(2000), nullable=False)  # OR keywords (comma-separated)
    pattern_and = db.Column(db.String(2000), default='')  # AND keywords (comma-separated)
    pattern_not = db.Column(db.String(2000), default='')  # NOT keywords (comma-separated)
    match_mode = db.Column(db.String(20), default='contains')  # Legacy, ignored
    is_case_sensitive = db.Column(db.Boolean, default=False)  # Legacy, always case-insensitive
    
    # Status and metadata
    is_enabled = db.Column(db.Boolean, default=True, index=True)
    is_system_default = db.Column(db.Boolean, default=False, index=True)
    priority = db.Column(db.Integer, default=100, index=True)
    
    # Audit fields
    created_by = db.Column(db.String(80), nullable=False)
    updated_by = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<NoiseRule {self.name}>'
    
    def is_active(self):
        """Check if rule is actually active (both category and rule enabled)"""
        return self.is_enabled and self.category.is_enabled
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'uuid': self.uuid,
            'category_id': self.category_id,
            'category_name': self.category.name if self.category else None,
            'category_icon': self.category.icon if self.category else None,
            'name': self.name,
            'description': self.description,
            # Keywords (using pattern column names for compatibility)
            'keywords': self.pattern,  # OR keywords
            'keywords_and': self.pattern_and or '',  # AND keywords
            'keywords_not': self.pattern_not or '',  # NOT keywords
            # Legacy fields (kept for backward compatibility)
            'pattern': self.pattern,
            'pattern_and': self.pattern_and or '',
            'pattern_not': self.pattern_not or '',
            # Status
            'is_enabled': self.is_enabled,
            'is_active': self.is_active(),
            'is_system_default': self.is_system_default,
            'priority': self.priority,
            'created_by': self.created_by,
            'updated_by': self.updated_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    @staticmethod
    def get_by_uuid(uuid_str):
        return NoiseRule.query.filter_by(uuid=uuid_str).first()
    
    @staticmethod
    def get_active_rules():
        """Get all rules that are actually active (category + rule both enabled)"""
        return NoiseRule.query.join(NoiseCategory).filter(
            NoiseCategory.is_enabled == True,
            NoiseRule.is_enabled == True
        ).order_by(NoiseRule.priority.asc()).all()
    
    def get_keywords(self):
        """Parse keyword fields into OR, AND, and NOT keyword lists
        
        Keyword fields:
        - pattern: OR keywords (comma-separated) - match if ANY keyword found as token
        - pattern_and: AND keywords (comma-separated) - must ALSO find ANY of these
        - pattern_not: NOT keywords (comma-separated) - exclude if ANY found
        
        Returns: (or_keywords: list, and_keywords: list, not_keywords: list)
        """
        # Parse OR keywords from main pattern field
        or_keywords = [k.strip() for k in self.pattern.split(',') if k.strip()]
        
        # Parse AND keywords (must also find any of these)
        and_keywords = []
        if self.pattern_and:
            and_keywords = [k.strip() for k in self.pattern_and.split(',') if k.strip()]
        
        # Parse NOT keywords (exclude if any found)
        not_keywords = []
        if self.pattern_not:
            not_keywords = [k.strip() for k in self.pattern_not.split(',') if k.strip()]
        
        return or_keywords, and_keywords, not_keywords
    
    # Legacy method name for backward compatibility
    def parse_pattern(self):
        """Legacy method - use get_keywords() instead"""
        return self.get_keywords()


class NoiseRuleAudit(db.Model):
    """Audit log for changes to noise rules"""
    __tablename__ = 'noise_rule_audit'
    
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('noise_rules.id', ondelete='SET NULL'), 
                       nullable=True, index=True)
    rule_name = db.Column(db.String(255))  # Store name in case rule is deleted
    
    changed_on = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    changed_by = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(20), nullable=False)  # create, update, delete, enable, disable
    field_name = db.Column(db.String(100))
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    
    def __repr__(self):
        return f'<NoiseRuleAudit {self.id}: {self.action} {self.rule_name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'changed_on': self.changed_on.isoformat() if self.changed_on else None,
            'changed_by': self.changed_by,
            'action': self.action,
            'field_name': self.field_name,
            'old_value': self.old_value,
            'new_value': self.new_value
        }
    
    @staticmethod
    def log_change(rule, changed_by, action, field_name=None, old_value=None, new_value=None):
        """Create an audit log entry"""
        audit = NoiseRuleAudit(
            rule_id=rule.id if rule else None,
            rule_name=rule.name if rule else None,
            changed_by=changed_by,
            action=action,
            field_name=field_name,
            old_value=str(old_value) if old_value is not None else None,
            new_value=str(new_value) if new_value is not None else None
        )
        db.session.add(audit)
        return audit


# Default categories and rules to seed
DEFAULT_NOISE_CATEGORIES = [
    {
        'name': 'RMM Tools',
        'description': 'Remote Monitoring and Management software used by MSPs',
        'icon': '🔧',
        'display_order': 10
    },
    {
        'name': 'EDR/MDR Platforms',
        'description': 'Endpoint Detection and Response / Managed Detection and Response tools',
        'icon': '🛡️',
        'display_order': 20
    },
    {
        'name': 'Remote Access',
        'description': 'Remote desktop and access tools',
        'icon': '🖥️',
        'display_order': 30
    },
    {
        'name': 'Backup Software',
        'description': 'Backup and disaster recovery solutions',
        'icon': '💾',
        'display_order': 40
    },
    {
        'name': 'System Utilities',
        'description': 'Windows system processes and utilities',
        'icon': '⚙️',
        'display_order': 50
    },
    {
        'name': 'Antivirus/Security',
        'description': 'Antivirus and endpoint security software',
        'icon': '🔒',
        'display_order': 60
    }
]

# Default rules - all start DISABLED so users enable what's relevant to their client
# Uses keyword-based token matching on raw_json via hasTokenCaseInsensitive()
DEFAULT_NOISE_RULES = [
    # RMM Tools - keywords match as whole tokens (ltsvc won't match 'altsvc')
    {'category': 'RMM Tools', 'name': 'ConnectWise Automate (LabTech)', 'pattern': 'ltsvc,ltservice,lttray,labtech,ltagent', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'ConnectWise ScreenConnect', 'pattern': 'screenconnect', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'Datto RMM', 'pattern': 'aemagent,daboremotemanagement,datto', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'NinjaRMM', 'pattern': 'ninjarmm,ninjaone,ninjarmmagent', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'Syncro', 'pattern': 'syncro,kabuto,syncromsp', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'Atera', 'pattern': 'atera,ateraagent', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'N-able (SolarWinds)', 'pattern': 'nable,solarwinds,advanced_monitoring_agent', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'Kaseya VSA', 'pattern': 'kaseya,agentmon,kaseyaagent', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'Pulseway', 'pattern': 'pulseway,pcmonitor', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'Action1', 'pattern': 'action1', 'is_enabled': False},
    
    # EDR/MDR Platforms
    {'category': 'EDR/MDR Platforms', 'name': 'Huntress Agent', 'pattern': 'huntress,huntressagent,huntressupdater', 'is_enabled': False},
    {'category': 'EDR/MDR Platforms', 'name': 'CrowdStrike Falcon', 'pattern': 'csfalconservice,crowdstrike,csagent,csfalconcontainer', 'is_enabled': False},
    {'category': 'EDR/MDR Platforms', 'name': 'SentinelOne', 'pattern': 'sentinelone,sentinelagent,sentinelhelper', 'is_enabled': False},
    {'category': 'EDR/MDR Platforms', 'name': 'Carbon Black', 'pattern': 'carbonblack,cbdefense,cbagent,cbcomms', 'is_enabled': False},
    {'category': 'EDR/MDR Platforms', 'name': 'Microsoft Defender ATP', 'pattern': 'mssense,sensecncproxy,mssensee', 'is_enabled': False},
    {'category': 'EDR/MDR Platforms', 'name': 'Cybereason', 'pattern': 'cybereason,activeprobe,crexe', 'is_enabled': False},
    {'category': 'EDR/MDR Platforms', 'name': 'Sophos Intercept X', 'pattern': 'sophoshealth,hmpalert,sophosservice,sophosui', 'is_enabled': False},
    {'category': 'EDR/MDR Platforms', 'name': 'Trend Micro', 'pattern': 'trendmicro,coreserviceshell,ntrtscan,tmbmsrv', 'is_enabled': False},
    
    # Remote Access
    {'category': 'Remote Access', 'name': 'TeamViewer', 'pattern': 'teamviewer', 'is_enabled': False},
    {'category': 'Remote Access', 'name': 'AnyDesk', 'pattern': 'anydesk', 'is_enabled': False},
    {'category': 'Remote Access', 'name': 'LogMeIn', 'pattern': 'logmein,lmi_rescue,logmeinrescue', 'is_enabled': False},
    {'category': 'Remote Access', 'name': 'Splashtop', 'pattern': 'splashtop,strwinclt,srsservice', 'is_enabled': False},
    {'category': 'Remote Access', 'name': 'GoToMyPC', 'pattern': 'gotomypc,g2maipc,gotoresolveit', 'is_enabled': False},
    {'category': 'Remote Access', 'name': 'BeyondTrust (Bomgar)', 'pattern': 'bomgar,beyondtrust,bomgarjumpclient', 'is_enabled': False},
    
    # Backup Software
    {'category': 'Backup Software', 'name': 'Veeam', 'pattern': 'veeam,veeamagent,veeambackup', 'is_enabled': False},
    {'category': 'Backup Software', 'name': 'Acronis', 'pattern': 'acronis,acronisagent,acronisscheduler', 'is_enabled': False},
    {'category': 'Backup Software', 'name': 'Datto SIRIS/ALTO', 'pattern': 'shadowsnap,dattoprovider', 'is_enabled': False},
    {'category': 'Backup Software', 'name': 'StorageCraft', 'pattern': 'storagecraft,sbsvc,imagemanager', 'is_enabled': False},
    {'category': 'Backup Software', 'name': 'Carbonite', 'pattern': 'carbonite,carboniteservice', 'is_enabled': False},
    {'category': 'Backup Software', 'name': 'Axcient', 'pattern': 'axcient,replibit', 'is_enabled': False},
    
    # Antivirus/Security
    {'category': 'Antivirus/Security', 'name': 'Windows Defender', 'pattern': 'msmpeng,nissrv,mpcmdrun,mpdefendercoreservice', 'is_enabled': False},
    {'category': 'Antivirus/Security', 'name': 'Webroot', 'pattern': 'wrsa,webroot,wrsvc', 'is_enabled': False},
    {'category': 'Antivirus/Security', 'name': 'Bitdefender', 'pattern': 'bitdefender,bdagent,vsserv,bdservicehost', 'is_enabled': False},
    {'category': 'Antivirus/Security', 'name': 'ESET', 'pattern': 'eset,ekrn,egui,esets_proxy', 'is_enabled': False},
    {'category': 'Antivirus/Security', 'name': 'Malwarebytes', 'pattern': 'malwarebytes,mbam,mbamservice', 'is_enabled': False},
    {'category': 'Antivirus/Security', 'name': 'Norton', 'pattern': 'norton,nsservice,nswscsvc,navapsvc', 'is_enabled': False},
    
    # System Utilities - common Windows noise
    {'category': 'System Utilities', 'name': 'Windows Update', 'pattern': 'wuauclt,usoclient,musnotification,wuauserv', 'is_enabled': False},
    {'category': 'System Utilities', 'name': 'Windows Telemetry', 'pattern': 'compattelrunner,devicecensus,diagtrack', 'is_enabled': False},
]


def seed_noise_defaults():
    """Seed default categories and rules if they don't exist
    
    Call this during app initialization or via migration.
    """
    from models.database import db
    
    # Check if categories already exist
    if NoiseCategory.query.count() > 0:
        return False  # Already seeded
    
    # Create categories
    category_map = {}
    for cat_data in DEFAULT_NOISE_CATEGORIES:
        category = NoiseCategory(
            name=cat_data['name'],
            description=cat_data['description'],
            icon=cat_data['icon'],
            display_order=cat_data['display_order'],
            is_enabled=True
        )
        db.session.add(category)
        db.session.flush()  # Get ID
        category_map[cat_data['name']] = category.id
    
    # Create rules with keyword-based matching
    for rule_data in DEFAULT_NOISE_RULES:
        rule = NoiseRule(
            category_id=category_map[rule_data['category']],
            name=rule_data['name'],
            pattern=rule_data['pattern'],  # OR keywords
            pattern_and=rule_data.get('pattern_and', ''),  # AND keywords
            pattern_not=rule_data.get('pattern_not', ''),  # NOT keywords
            is_enabled=rule_data.get('is_enabled', False),
            is_system_default=True,
            created_by='system'
        )
        db.session.add(rule)
    
    db.session.commit()
    return True
