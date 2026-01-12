"""Noise Filter Models for CaseScope

Tracks known-good software/tools to filter out during hunting.
Opposite of IOCs - these are things we want to IGNORE, not hunt.
"""
import uuid
from datetime import datetime
from models.database import db


class NoiseFilterType:
    """Filter type options for noise rules"""
    ANY_FIELD = 'any_field'
    PROCESS_NAME = 'process_name'
    FILE_PATH = 'file_path'
    COMMAND_LINE = 'command_line'
    HASH = 'hash'
    SERVICE_NAME = 'service_name'
    NETWORK = 'network'
    REGISTRY = 'registry'
    
    @classmethod
    def all(cls):
        return [
            cls.ANY_FIELD, cls.PROCESS_NAME, cls.FILE_PATH, cls.COMMAND_LINE,
            cls.HASH, cls.SERVICE_NAME, cls.NETWORK, cls.REGISTRY
        ]
    
    @classmethod
    def choices(cls):
        return [
            (cls.ANY_FIELD, 'Any Field (Full Text)'),
            (cls.PROCESS_NAME, 'Process Name'),
            (cls.FILE_PATH, 'File Path'),
            (cls.COMMAND_LINE, 'Command Line'),
            (cls.HASH, 'Hash (MD5/SHA256)'),
            (cls.SERVICE_NAME, 'Service Name'),
            (cls.NETWORK, 'Network (IP/Domain)'),
            (cls.REGISTRY, 'Registry Key/Value')
        ]
    
    @classmethod
    def labels(cls):
        return {choice[0]: choice[1] for choice in cls.choices()}


class NoiseMatchMode:
    """Match mode options for noise rules"""
    EXACT = 'exact'
    CONTAINS = 'contains'
    STARTS_WITH = 'starts_with'
    ENDS_WITH = 'ends_with'
    WILDCARD = 'wildcard'
    REGEX = 'regex'
    
    @classmethod
    def all(cls):
        return [
            cls.EXACT, cls.CONTAINS, cls.STARTS_WITH,
            cls.ENDS_WITH, cls.WILDCARD, cls.REGEX
        ]
    
    @classmethod
    def choices(cls):
        return [
            (cls.EXACT, 'Exact Match'),
            (cls.CONTAINS, 'Contains'),
            (cls.STARTS_WITH, 'Starts With'),
            (cls.ENDS_WITH, 'Ends With'),
            (cls.WILDCARD, 'Wildcard (* and ?)'),
            (cls.REGEX, 'Regular Expression')
        ]
    
    @classmethod
    def labels(cls):
        return {choice[0]: choice[1] for choice in cls.choices()}


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
    
    Each rule defines a pattern to match against event data.
    Rules can be enabled/disabled independently.
    Rule is only active if: category.is_enabled AND rule.is_enabled
    
    Pattern Syntax:
        - Comma (,) = OR matching: "screenconnect,control" matches either
        - Plus (+) = AND condition: "screenconnect+abc123" must contain both
        - Combined: "screenconnect,control+clientUID" = (screenconnect OR control) AND clientUID
        
    The AND conditions apply to ALL OR patterns. This is useful for:
        - ScreenConnect with client-specific UIDs
        - Any tool where multiple executables share a common identifier
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
    
    # Filter configuration
    filter_type = db.Column(db.String(50), nullable=False, index=True)
    pattern = db.Column(db.String(2000), nullable=False)  # OR patterns (comma-separated)
    pattern_and = db.Column(db.String(2000), default='')  # AND patterns (comma-separated, OR within)
    pattern_not = db.Column(db.String(2000), default='')  # NOT patterns (comma-separated, exclude if any match)
    match_mode = db.Column(db.String(20), default=NoiseMatchMode.CONTAINS)
    is_case_sensitive = db.Column(db.Boolean, default=False)
    
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
        return {
            'id': self.id,
            'uuid': self.uuid,
            'category_id': self.category_id,
            'category_name': self.category.name if self.category else None,
            'category_icon': self.category.icon if self.category else None,
            'name': self.name,
            'description': self.description,
            'filter_type': self.filter_type,
            'filter_type_label': NoiseFilterType.labels().get(self.filter_type, self.filter_type),
            'pattern': self.pattern,
            'pattern_and': self.pattern_and or '',
            'pattern_not': self.pattern_not or '',
            'match_mode': self.match_mode,
            'match_mode_label': NoiseMatchMode.labels().get(self.match_mode, self.match_mode),
            'is_case_sensitive': self.is_case_sensitive,
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
    
    @staticmethod
    def get_active_rules_by_type(filter_type):
        """Get active rules for a specific filter type"""
        return NoiseRule.query.join(NoiseCategory).filter(
            NoiseCategory.is_enabled == True,
            NoiseRule.is_enabled == True,
            NoiseRule.filter_type == filter_type
        ).order_by(NoiseRule.priority.asc()).all()
    
    def parse_pattern(self):
        """Parse pattern fields into OR, AND, and NOT pattern lists
        
        Pattern fields:
        - pattern: OR patterns (comma-separated) - match if ANY matches
        - pattern_and: AND patterns (comma-separated) - must ALSO match ANY of these
        - pattern_not: NOT patterns (comma-separated) - must NOT match ANY of these
        
        Returns: (or_patterns: list, and_patterns: list, not_patterns: list)
        """
        # Parse OR patterns from main pattern field
        or_patterns = [p.strip() for p in self.pattern.split(',') if p.strip()]
        
        # Parse AND patterns (must also contain any of these)
        and_patterns = []
        if self.pattern_and:
            and_patterns = [p.strip() for p in self.pattern_and.split(',') if p.strip()]
        
        # Parse NOT patterns (must not contain any of these)
        not_patterns = []
        if self.pattern_not:
            not_patterns = [p.strip() for p in self.pattern_not.split(',') if p.strip()]
        
        return or_patterns, and_patterns, not_patterns
    
    def matches(self, value, full_event_text=None):
        """Check if value matches this rule's pattern
        
        Logic: (OR1 or OR2) AND (AND1 or AND2) AND NOT (NOT1 or NOT2)
        
        Args:
            value: The specific field value to check against OR patterns
            full_event_text: Full event text/data to check AND/NOT conditions against
                            (if None, uses value for both)
        
        Returns: True if matches, False otherwise
        """
        import re
        import fnmatch
        
        if not value:
            return False
        
        or_patterns, and_patterns, not_patterns = self.parse_pattern()
        
        # Normalize for case-insensitive matching
        check_value = value if self.is_case_sensitive else value.lower()
        check_full = (full_event_text or value) if self.is_case_sensitive else (full_event_text or value).lower()
        
        # Check OR patterns - at least one must match
        or_matched = False
        for pattern in or_patterns:
            check_pattern = pattern if self.is_case_sensitive else pattern.lower()
            
            if self._pattern_matches(check_value, check_pattern):
                or_matched = True
                break
        
        if not or_matched:
            return False
        
        # Check AND patterns - if any specified, at least one must match in full event
        if and_patterns:
            and_matched = False
            for pattern in and_patterns:
                check_pattern = pattern if self.is_case_sensitive else pattern.lower()
                if check_pattern in check_full:
                    and_matched = True
                    break
            if not and_matched:
                return False
        
        # Check NOT patterns - if any match, exclude this event
        for pattern in not_patterns:
            check_pattern = pattern if self.is_case_sensitive else pattern.lower()
            if check_pattern in check_full:
                return False  # Excluded
        
        return True
    
    def _pattern_matches(self, value, pattern):
        """Check if value matches pattern based on match_mode"""
        import re
        import fnmatch
        
        if self.match_mode == NoiseMatchMode.EXACT:
            return value == pattern
        elif self.match_mode == NoiseMatchMode.CONTAINS:
            return pattern in value
        elif self.match_mode == NoiseMatchMode.STARTS_WITH:
            return value.startswith(pattern)
        elif self.match_mode == NoiseMatchMode.ENDS_WITH:
            return value.endswith(pattern)
        elif self.match_mode == NoiseMatchMode.WILDCARD:
            return fnmatch.fnmatch(value, pattern)
        elif self.match_mode == NoiseMatchMode.REGEX:
            try:
                return bool(re.search(pattern, value))
            except re.error:
                return False
        else:
            return pattern in value  # Default to contains


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
DEFAULT_NOISE_RULES = [
    # RMM Tools
    {'category': 'RMM Tools', 'name': 'ConnectWise Automate (LabTech)', 'filter_type': 'process_name', 'pattern': 'ltsvc,ltservice,lttray,labtech', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'ConnectWise ScreenConnect', 'filter_type': 'process_name', 'pattern': 'screenconnect', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'Datto RMM', 'filter_type': 'process_name', 'pattern': 'aem,aemagent,datto', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'NinjaRMM', 'filter_type': 'process_name', 'pattern': 'ninjarmm,ninjaone', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'Syncro', 'filter_type': 'process_name', 'pattern': 'syncro,kabuto', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'Atera', 'filter_type': 'process_name', 'pattern': 'atera', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'N-able (SolarWinds)', 'filter_type': 'process_name', 'pattern': 'n-able,n-central,nable,solarwinds', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'Kaseya VSA', 'filter_type': 'process_name', 'pattern': 'kaseya,agentmon', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'Pulseway', 'filter_type': 'process_name', 'pattern': 'pulseway,pcmonitor', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'RMM Tools', 'name': 'Action1', 'filter_type': 'process_name', 'pattern': 'action1', 'match_mode': 'contains', 'is_enabled': False},
    
    # EDR/MDR Platforms
    {'category': 'EDR/MDR Platforms', 'name': 'Huntress Agent', 'filter_type': 'process_name', 'pattern': 'huntress', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'EDR/MDR Platforms', 'name': 'CrowdStrike Falcon', 'filter_type': 'process_name', 'pattern': 'csfalcon,crowdstrike,csagent', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'EDR/MDR Platforms', 'name': 'SentinelOne', 'filter_type': 'process_name', 'pattern': 'sentinelone,sentinelagent', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'EDR/MDR Platforms', 'name': 'Carbon Black', 'filter_type': 'process_name', 'pattern': 'carbonblack,cbdefense,cbagent', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'EDR/MDR Platforms', 'name': 'Microsoft Defender ATP', 'filter_type': 'process_name', 'pattern': 'mssense,sensecncproxy', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'EDR/MDR Platforms', 'name': 'Cybereason', 'filter_type': 'process_name', 'pattern': 'cybereason', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'EDR/MDR Platforms', 'name': 'Sophos Intercept X', 'filter_type': 'process_name', 'pattern': 'sophoshealth,hmpalert,sophos', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'EDR/MDR Platforms', 'name': 'Trend Micro', 'filter_type': 'process_name', 'pattern': 'trendmicro,coreserviceshell,ntrtscan', 'match_mode': 'contains', 'is_enabled': False},
    
    # Remote Access
    {'category': 'Remote Access', 'name': 'TeamViewer', 'filter_type': 'process_name', 'pattern': 'teamviewer', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'Remote Access', 'name': 'AnyDesk', 'filter_type': 'process_name', 'pattern': 'anydesk', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'Remote Access', 'name': 'LogMeIn', 'filter_type': 'process_name', 'pattern': 'logmein', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'Remote Access', 'name': 'Splashtop', 'filter_type': 'process_name', 'pattern': 'splashtop,strwinclt', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'Remote Access', 'name': 'GoToMyPC', 'filter_type': 'process_name', 'pattern': 'gotomypc,g2maipc', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'Remote Access', 'name': 'BeyondTrust (Bomgar)', 'filter_type': 'process_name', 'pattern': 'bomgar,beyondtrust', 'match_mode': 'contains', 'is_enabled': False},
    
    # Backup Software
    {'category': 'Backup Software', 'name': 'Veeam', 'filter_type': 'process_name', 'pattern': 'veeam', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'Backup Software', 'name': 'Acronis', 'filter_type': 'process_name', 'pattern': 'acronis', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'Backup Software', 'name': 'Datto SIRIS/ALTO', 'filter_type': 'process_name', 'pattern': 'datto,shadowsnap', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'Backup Software', 'name': 'StorageCraft', 'filter_type': 'process_name', 'pattern': 'storagecraft,sbsvc', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'Backup Software', 'name': 'Carbonite', 'filter_type': 'process_name', 'pattern': 'carbonite', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'Backup Software', 'name': 'Axcient', 'filter_type': 'process_name', 'pattern': 'axcient,replibit', 'match_mode': 'contains', 'is_enabled': False},
    
    # Antivirus/Security
    {'category': 'Antivirus/Security', 'name': 'Windows Defender', 'filter_type': 'process_name', 'pattern': 'msmpeng,nissrv,mpcmdrun', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'Antivirus/Security', 'name': 'Webroot', 'filter_type': 'process_name', 'pattern': 'wrsa,webroot', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'Antivirus/Security', 'name': 'Bitdefender', 'filter_type': 'process_name', 'pattern': 'bitdefender,bdagent,vsserv', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'Antivirus/Security', 'name': 'ESET', 'filter_type': 'process_name', 'pattern': 'eset,ekrn,egui', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'Antivirus/Security', 'name': 'Malwarebytes', 'filter_type': 'process_name', 'pattern': 'malwarebytes,mbam', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'Antivirus/Security', 'name': 'Norton', 'filter_type': 'process_name', 'pattern': 'norton,nsservice,nswscsvc', 'match_mode': 'contains', 'is_enabled': False},
    
    # System Utilities - these are more specific patterns to avoid false negatives
    {'category': 'System Utilities', 'name': 'Windows Update', 'filter_type': 'process_name', 'pattern': 'wuauclt,usoclient,musnotification', 'match_mode': 'contains', 'is_enabled': False},
    {'category': 'System Utilities', 'name': 'Windows Telemetry', 'filter_type': 'process_name', 'pattern': 'compattelrunner,devicecensus', 'match_mode': 'contains', 'is_enabled': False},
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
    
    # Create rules
    for rule_data in DEFAULT_NOISE_RULES:
        rule = NoiseRule(
            category_id=category_map[rule_data['category']],
            name=rule_data['name'],
            filter_type=rule_data['filter_type'],
            pattern=rule_data['pattern'],
            match_mode=rule_data['match_mode'],
            is_enabled=rule_data.get('is_enabled', False),
            is_system_default=True,
            created_by='system'
        )
        db.session.add(rule)
    
    db.session.commit()
    return True
