"""IOC (Indicators of Compromise) Models for CaseScope

Tracks IOCs discovered across cases with full audit history,
system sightings, and artifact correlation.

Match Types:
    - token: Uses hasTokenCaseInsensitive() for whole-word matching (hashes, IPs, unique names)
    - substring: Uses LIKE for partial matching (file paths, registry, URLs)
    - regex: Uses regex matching for complex patterns
"""
import re
import uuid
from datetime import datetime
from models.database import db


class IOCMatchType:
    """Match type options for IOC searching"""
    TOKEN = 'token'          # Whole-word token matching (hasTokenCaseInsensitive)
    SUBSTRING = 'substring'  # Partial/contains matching (LIKE)
    REGEX = 'regex'          # Regular expression matching
    
    @classmethod
    def all(cls):
        return [cls.TOKEN, cls.SUBSTRING, cls.REGEX]
    
    @classmethod
    def choices(cls):
        return [
            (cls.TOKEN, 'Token (Whole Word) - Best for hashes, IPs, unique identifiers'),
            (cls.SUBSTRING, 'Substring (Contains) - Best for paths, registry, URLs'),
            (cls.REGEX, 'Regex (Pattern) - For complex matching patterns')
        ]
    
    @classmethod
    def labels(cls):
        return {
            cls.TOKEN: 'Token',
            cls.SUBSTRING: 'Substring',
            cls.REGEX: 'Regex'
        }


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
    VULNERABILITY = 'Vulnerability'
    THREAT_INTEL = 'Threat Intel'
    
    @classmethod
    def all(cls):
        return [
            cls.NETWORK, cls.FILE, cls.EMAIL, cls.REGISTRY, cls.PROCESS,
            cls.AUTHENTICATION, cls.MALWARE, cls.BEHAVIORAL, 
            cls.CRYPTOCURRENCY, cls.MOBILE, cls.VULNERABILITY, cls.THREAT_INTEL
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
    'SID': {
        'category': IOCCategory.AUTHENTICATION,
        'regex': r'^S-1-\d+-\d+(-\d+)*$'  # Windows Security Identifier
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
    },
    
    # Vulnerability
    'CVE': {
        'category': IOCCategory.VULNERABILITY,
        'regex': r'^CVE-\d{4}-\d{4,7}$'
    },
    
    # Threat Intel
    'Threat Name': {
        'category': IOCCategory.THREAT_INTEL,
        'regex': None
    },
    
    # Authentication - Password (visible in commands)
    'Password': {
        'category': IOCCategory.AUTHENTICATION,
        'regex': None
    },
}


class IOC(db.Model):
    """Indicator of Compromise model
    
    Case-specific IOCs with metadata about creation, artifact sightings,
    and system associations. Each IOC belongs to a single case.
    
    Match Types:
        - token: hasTokenCaseInsensitive() - whole-word matching for hashes, IPs
        - substring: LIKE matching - for paths, registry, URLs
        - regex: Pattern matching - for complex indicators
    """
    __tablename__ = 'iocs'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Case-specific - each case has its own set of IOCs
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    
    # Public UUID for external references
    uuid = db.Column(db.String(36), unique=True, nullable=False, 
                     index=True, default=lambda: str(uuid.uuid4()))
    
    # IOC Classification
    category = db.Column(db.String(50), nullable=False, index=True)
    ioc_type = db.Column(db.String(100), nullable=False, index=True)
    
    # The actual IOC value
    value = db.Column(db.String(4096), nullable=False)
    value_normalized = db.Column(db.String(4096), nullable=False, index=True)
    
    # Match type for searching (token, substring, regex)
    # If null, auto-detected based on ioc_type and value
    match_type = db.Column(db.String(20), nullable=True, default=None)
    
    # Creation metadata
    created_by = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Artifact sighting timestamps
    first_seen_in_artifacts = db.Column(db.DateTime, nullable=True)
    last_seen_in_artifacts = db.Column(db.DateTime, nullable=True)
    
    # Counts
    artifact_count = db.Column(db.Integer, nullable=False, default=0)
    
    # Aliases for contextual matching (e.g., full command line for a cmd.exe IOC)
    # Stored as JSON array of strings
    aliases = db.Column(db.JSON, nullable=True, default=list)
    
    # Analyst notes
    notes = db.Column(db.Text, nullable=True)
    
    # Status flags
    malicious = db.Column(db.Boolean, nullable=False, default=False)
    false_positive = db.Column(db.Boolean, nullable=False, default=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    hidden = db.Column(db.Boolean, nullable=False, default=False)  # Exclude from reports
    
    # OpenCTI integration
    opencti_enrichment = db.Column(db.Text, nullable=True)  # JSON: enriched data from OpenCTI
    opencti_enriched_at = db.Column(db.DateTime, nullable=True)
    
    # Data sources that contributed to this IOC (manual, ai_extraction, stix_import, etc.)
    sources = db.Column(db.JSON, nullable=False, default=list)
    
    # Relationships
    case = db.relationship('Case', backref=db.backref('iocs_direct', lazy='dynamic'))
    system_sightings = db.relationship('IOCSystemSighting', backref='ioc', 
                                       lazy='dynamic', cascade='all, delete-orphan')
    
    # Unique constraint: same IOC type + normalized value should be unique WITHIN a case
    __table_args__ = (
        db.UniqueConstraint('case_id', 'ioc_type', 'value_normalized', name='uq_ioc_case_type_value'),
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
            'File Path', 'Process Path',
            'File Name', 'Process Name',
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
    
    def get_effective_match_type(self):
        """Get the effective match type (explicit or auto-detected)"""
        if self.match_type:
            return self.match_type
        return detect_match_type(self.value, self.ioc_type)
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        import json
        
        # Parse OpenCTI enrichment if available
        opencti_data = None
        if self.opencti_enrichment:
            try:
                opencti_data = json.loads(self.opencti_enrichment)
            except (json.JSONDecodeError, TypeError):
                opencti_data = None

        opencti_legacy_unverified = False
        if opencti_data:
            try:
                from utils.opencti import is_legacy_unverified_enrichment
                opencti_legacy_unverified = is_legacy_unverified_enrichment(opencti_data)
            except Exception:
                opencti_legacy_unverified = bool(
                    opencti_data.get('found') and not opencti_data.get('schema_version')
                )

        aliases = self.aliases or []
        derived_context = any(
            isinstance(alias, str) and ('\\' in alias or '/' in alias or ' ' in alias)
            for alias in aliases
        )
        
        effective_match_type = self.get_effective_match_type()
        
        return {
            'id': self.id,
            'case_id': self.case_id,
            'uuid': self.uuid,
            'category': self.category,
            'ioc_type': self.ioc_type,
            'value': self.value,
            'aliases': aliases,
            'derived_from_context': derived_context,
            'alias_preview': aliases[0] if aliases else None,
            'match_type': self.match_type,  # Explicit setting (may be null)
            'effective_match_type': effective_match_type,  # What will actually be used
            'match_type_label': IOCMatchType.labels().get(effective_match_type, effective_match_type),
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'first_seen_in_artifacts': self.first_seen_in_artifacts.isoformat() if self.first_seen_in_artifacts else None,
            'last_seen_in_artifacts': self.last_seen_in_artifacts.isoformat() if self.last_seen_in_artifacts else None,
            'artifact_count': self.artifact_count,
            'notes': self.notes,
            'malicious': self.malicious,
            'false_positive': self.false_positive,
            'active': self.active,
            'hidden': self.hidden,
            'opencti_enrichment': opencti_data,
            'opencti_legacy_unverified': opencti_legacy_unverified,
            'opencti_enriched_at': self.opencti_enriched_at.isoformat() if self.opencti_enriched_at else None,
            'sources': self.sources or [],
            'system_count': self.system_sightings.count(),
            'systems': [s.to_dict() for s in self.system_sightings.limit(10)]
        }
    
    @staticmethod
    def find_by_value(value, ioc_type, case_id=None):
        """Find an IOC by its normalized value and type within a case
        
        Args:
            value: The IOC value to search for
            ioc_type: Type of IOC
            case_id: Required - the case to search within
        """
        normalized = IOC.normalize_value(value, ioc_type)
        query = IOC.query.filter_by(
            ioc_type=ioc_type,
            value_normalized=normalized
        )
        if case_id:
            query = query.filter_by(case_id=case_id)
        return query.first()
    
    @staticmethod
    def get_or_create(value, ioc_type, category, created_by, case_id, aliases=None, match_type=None, source=None):
        """Get existing IOC or create new one within a case
        
        Args:
            value: Primary IOC value (e.g., 'cmd.exe')
            ioc_type: Type of IOC (e.g., 'File Name', 'Command Line')
            category: Category (e.g., 'File', 'Process')
            created_by: Username who created this
            case_id: Required - the case this IOC belongs to
            aliases: List of contextual aliases (e.g., full command lines)
            match_type: Explicit match type ('token', 'substring', 'regex') or None for auto
            source: Data source (e.g., 'manual', 'ai_extraction', 'stix_import', 'bulk_import')
        
        Returns: (ioc, created_bool)
        """
        if not case_id:
            raise ValueError("case_id is required")
        
        normalized = IOC.normalize_value(value, ioc_type)
        
        existing = IOC.query.filter_by(
            case_id=case_id,
            ioc_type=ioc_type,
            value_normalized=normalized
        ).first()
        
        if existing:
            # Merge any new aliases with existing ones
            if aliases:
                existing_aliases = existing.aliases or []
                new_aliases = [a.lower() for a in aliases if a]
                merged = list(set(existing_aliases + new_aliases))
                if merged != existing_aliases:
                    existing.aliases = merged
            # Update match_type if provided and not already set
            if match_type and not existing.match_type:
                existing.match_type = match_type
            # Add source if provided
            if source:
                existing.add_source(source)
            return existing, False
        
        # Validate if type has regex
        is_valid, error = IOC.validate_value(value, ioc_type)
        if not is_valid:
            raise ValueError(error)
        
        # Normalize aliases
        normalized_aliases = []
        if aliases:
            normalized_aliases = list(set([a.lower() for a in aliases if a]))
        
        # Initialize sources list
        sources_list = [source.lower()] if source else []
        
        new_ioc = IOC(
            case_id=case_id,
            category=category,
            ioc_type=ioc_type,
            value=value,
            value_normalized=normalized,
            created_by=created_by,
            aliases=normalized_aliases if normalized_aliases else None,
            match_type=match_type,  # Can be None - will use auto-detection
            sources=sources_list
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
    
    def add_alias(self, alias):
        """Add an alias to this IOC if not already present"""
        if not alias:
            return False
        
        alias_lower = alias.lower()
        current_aliases = self.aliases or []
        
        if alias_lower not in current_aliases:
            self.aliases = current_aliases + [alias_lower]
            return True
        return False
    
    def remove_alias(self, alias):
        """Remove an alias from this IOC"""
        if not alias or not self.aliases:
            return False
        
        alias_lower = alias.lower()
        if alias_lower in self.aliases:
            self.aliases = [a for a in self.aliases if a != alias_lower]
            return True
        return False
    
    def link_to_case(self, case_id):
        """Link this IOC to a case - DEPRECATED
        
        IOCs are now case-specific via the case_id column.
        This method is kept for backward compatibility and returns True only
        when the IOC already belongs to the requested case.
        """
        return self.case_id == case_id
    
    def add_source(self, source):
        """Add a data source if not already present
        
        Valid sources: manual, ai_extraction, stix_import, bulk_import, tag_artifacts, etc.
        """
        from sqlalchemy.orm.attributes import flag_modified
        
        if not source:
            return False
        
        source = source.lower()
        current_sources = list(self.sources or [])  # Create a new list copy
        
        if source not in current_sources:
            current_sources.append(source)
            self.sources = current_sources
            flag_modified(self, 'sources')  # Tell SQLAlchemy the column changed
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


def can_use_token_match(value: str) -> bool:
    """Check if a value can be used with ClickHouse hasTokenCaseInsensitive().
    
    ClickHouse token functions treat certain characters as separators and will
    reject values containing them. The separator characters include:
    - Dot (.)
    - Comma (,)
    - Colon (:)
    - Semicolon (;)
    - Space and other whitespace
    - Various punctuation
    
    Returns True if the value can be used with token matching.
    """
    if not value:
        return False
    
    # Characters that ClickHouse treats as separators in hasTokenCaseInsensitive
    # These will cause the query to fail if present in the needle
    separator_chars = {'.', ',', ':', ';', ' ', '\t', '\n', '\r', '!', '?', 
                       '@', '#', '$', '%', '^', '&', '*', '(', ')', '[', ']',
                       '{', '}', '<', '>', '/', '\\', '|', '~', '`', '"', "'"}
    
    for char in value:
        if char in separator_chars:
            return False
    
    return True


def detect_match_type(value: str, ioc_type: str) -> str:
    """Auto-detect the best match type for an IOC based on its value and type.
    
    Token matching (hasTokenCaseInsensitive):
        - Best for unique identifiers that should match as whole words
        - Hashes (hex-only), unique names without dots/separators
        - Example: 'ltsvc' matches 'c:\\ltsvc\\' but NOT 'altsvc'
        - NOTE: Cannot contain dots, colons, or other separator characters!
    
    Substring matching (LIKE):
        - Best for paths, registry, URLs, file names with extensions
        - Used as fallback when token matching isn't possible
        - Example: 'c:\\windows\\malware.exe' or 'd.bat'
    
    Regex matching:
        - For complex patterns with wildcards, alternatives, etc.
    
    Returns: 'token', 'substring', or 'regex'
    """
    if not value:
        return IOCMatchType.SUBSTRING
    
    value = value.strip()
    
    # Substring matching types - paths and structured data (always substring)
    substring_types = {
        'File Path', 'Process Path', 'PDB Path',
        'Registry Key', 'Registry Value',
        'URL', 'Command Line',
        'Scheduled Task', 'Cron Job', 'Persistence Mechanism',
        'File Name', 'Process Name',  # File names have dots - use substring
        'IP Address (IPv4)', 'IP Address (IPv6)',  # IPs have dots - use substring
        'Domain', 'FQDN', 'Hostname',  # Domains have dots - use substring
        'Email Address', 'Reply-To Address',  # Emails have @ and . - use substring
    }
    
    if ioc_type in substring_types:
        return IOCMatchType.SUBSTRING
    
    # Token matching types - but ONLY if value has no separators
    token_types = {
        'MD5 Hash', 'SHA1 Hash', 'SHA256 Hash', 'Imphash', 'TLSH Hash',
        'JA3 Hash', 'JA3S Hash', 'SSL Certificate Hash',
        'Bitcoin Address', 'Ethereum Address', 'Monero Address',
        'SID', 'ASN',
        'Malware Family', 'YARA Rule Name',
        'Mutex Name', 'Username', 'Service Name',
    }
    
    if ioc_type in token_types:
        # Check if value can actually use token matching
        if can_use_token_match(value):
            return IOCMatchType.TOKEN
        else:
            # Fallback to substring if value contains separators
            return IOCMatchType.SUBSTRING
    
    # Value-based detection for ambiguous types
    # Check for path indicators
    if '\\' in value or '/' in value:
        return IOCMatchType.SUBSTRING
    
    # Check for registry hive prefixes
    if value.upper().startswith(('HKLM', 'HKCU', 'HKEY_', 'HKU')):
        return IOCMatchType.SUBSTRING
    
    # Check for URL patterns
    if value.startswith(('http://', 'https://', 'ftp://')):
        return IOCMatchType.SUBSTRING
    
    # Check for command line patterns (has spaces + quotes or switches)
    if ' ' in value and ('"' in value or value.startswith('-') or ' -' in value or ' /' in value):
        return IOCMatchType.SUBSTRING
    
    # Check if it looks like a pure hex hash (no separators)
    if re.match(r'^[a-fA-F0-9]{32}$', value):  # MD5
        return IOCMatchType.TOKEN
    if re.match(r'^[a-fA-F0-9]{40}$', value):  # SHA1
        return IOCMatchType.TOKEN
    if re.match(r'^[a-fA-F0-9]{64}$', value):  # SHA256
        return IOCMatchType.TOKEN
    
    # For any value containing separators, use substring
    if not can_use_token_match(value):
        return IOCMatchType.SUBSTRING
    
    # Default to substring for safety (catches everything, may have more false positives)
    return IOCMatchType.SUBSTRING


def detect_ioc_type_from_value(value: str) -> str:
    """Auto-detect IOC type based on value pattern analysis.
    
    Used when user creates IOC without specifying type.
    Returns the most likely IOC type.
    """
    if not value:
        return 'Unknown'
    
    value = value.strip()
    
    # Check for hash patterns
    if re.match(r'^[a-fA-F0-9]{32}$', value):
        return 'MD5 Hash'
    if re.match(r'^[a-fA-F0-9]{40}$', value):
        return 'SHA1 Hash'
    if re.match(r'^[a-fA-F0-9]{64}$', value):
        return 'SHA256 Hash'
    
    # Check for IP addresses
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
        return 'IP Address (IPv4)'
    if ':' in value and re.match(r'^[0-9a-fA-F:]+$', value):
        return 'IP Address (IPv6)'
    
    # Check for email
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
        return 'Email Address'
    
    # Check for URL
    if value.startswith(('http://', 'https://', 'ftp://')):
        return 'URL'
    
    # Check for domain/FQDN
    if re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', value):
        return 'Domain'
    
    # Check for registry paths
    if value.upper().startswith(('HKLM', 'HKCU', 'HKEY_', 'HKU')):
        return 'Registry Key'
    
    # Check for file paths (Windows or Unix)
    if '\\' in value or (value.startswith('/') and '/' in value[1:]):
        if value.lower().endswith(('.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js')):
            return 'Process Path'
        return 'File Path'
    
    # Check for Windows SID
    if re.match(r'^S-1-\d+-\d+(-\d+)*$', value):
        return 'SID'
    
    # Check for cryptocurrency
    if re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', value) or re.match(r'^bc1[a-zA-HJ-NP-Z0-9]{39,59}$', value):
        return 'Bitcoin Address'
    if re.match(r'^0x[a-fA-F0-9]{40}$', value):
        return 'Ethereum Address'
    
    # Check for common executables
    if value.lower().endswith(('.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.msi')):
        return 'File Name'
    
    # Default - if short could be username, if longer could be command line
    if ' ' in value or len(value) > 50:
        return 'Command Line'
    
    return 'File Name'  # Default for short strings


def get_match_type_recommendation(value: str, ioc_type: str) -> dict:
    """Get a match type recommendation with explanation.
    
    Used when user creates an IOC manually without setting match_type.
    
    Returns:
        {
            'recommended': 'token' | 'substring' | 'regex',
            'reason': str,
            'examples': list of example matches
        }
    """
    detected = detect_match_type(value, ioc_type)
    
    # Build explanation based on detection
    reasons = {
        IOCMatchType.TOKEN: [],
        IOCMatchType.SUBSTRING: [],
    }
    
    # Analyze the value
    is_hash = bool(re.match(r'^[a-fA-F0-9]{32,64}$', value))
    is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value))
    has_path_sep = '\\' in value or '/' in value
    has_spaces = ' ' in value
    is_url = value.startswith(('http://', 'https://'))
    is_registry = value.upper().startswith(('HKLM', 'HKCU', 'HKEY_', 'HKU'))
    
    if is_hash:
        reasons[IOCMatchType.TOKEN].append('Hash values are unique identifiers')
    if is_ip:
        reasons[IOCMatchType.TOKEN].append('IP addresses are unique identifiers')
    if has_path_sep:
        reasons[IOCMatchType.SUBSTRING].append('Contains path separators - needs exact path matching')
    if is_url:
        reasons[IOCMatchType.SUBSTRING].append('URLs need substring matching for full path')
    if is_registry:
        reasons[IOCMatchType.SUBSTRING].append('Registry paths need substring matching')
    if has_spaces and not is_url:
        reasons[IOCMatchType.SUBSTRING].append('Contains spaces - likely a command or complex pattern')
    
    # Type-based reasons
    if ioc_type in ('File Name', 'Process Name'):
        reasons[IOCMatchType.TOKEN].append(f'{ioc_type} should match as whole word to avoid partial matches')
    if ioc_type in ('Domain', 'FQDN'):
        reasons[IOCMatchType.TOKEN].append('Domains match well as tokens')
    
    # Build the recommendation
    if detected == IOCMatchType.TOKEN:
        reason = '; '.join(reasons[IOCMatchType.TOKEN]) if reasons[IOCMatchType.TOKEN] else 'Unique identifier - best matched as whole word'
        examples = [
            f"✓ '{value}' in raw data will match",
            f"✗ Partial matches like 'x{value}' or '{value}x' will NOT match"
        ]
    else:
        reason = '; '.join(reasons[IOCMatchType.SUBSTRING]) if reasons[IOCMatchType.SUBSTRING] else 'Complex value - needs substring matching'
        examples = [
            f"✓ Any occurrence of '{value[:30]}...' in raw data will match",
            f"⚠ May also match unrelated contexts containing this string"
        ]
    
    return {
        'recommended': detected,
        'recommended_label': IOCMatchType.labels().get(detected, detected),
        'reason': reason,
        'examples': examples,
        'ioc_type': ioc_type,
        'value_preview': value[:50] + ('...' if len(value) > 50 else '')
    }
