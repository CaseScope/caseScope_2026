"""Known System Models for CaseScope

Tracks known systems discovered across cases with deduplication
and full audit history.
"""
import re
from datetime import datetime
from models.database import db


class OSType:
    """Operating System Types"""
    WINDOWS = 'Windows'
    LINUX = 'Linux'
    MAC = 'Mac'
    OTHER = 'Other'
    
    @classmethod
    def choices(cls):
        return [
            (cls.WINDOWS, 'Windows'),
            (cls.LINUX, 'Linux'),
            (cls.MAC, 'Mac'),
            (cls.OTHER, 'Other')
        ]
    
    @classmethod
    def all(cls):
        return [cls.WINDOWS, cls.LINUX, cls.MAC, cls.OTHER]


class SystemType:
    """System Types"""
    WORKSTATION = 'Workstation'
    SERVER = 'Server'
    ROUTER = 'Router'
    SWITCH = 'Switch'
    PRINTER = 'Printer'
    OTHER = 'Other'
    
    @classmethod
    def choices(cls):
        return [
            (cls.WORKSTATION, 'Workstation'),
            (cls.SERVER, 'Server'),
            (cls.ROUTER, 'Router'),
            (cls.SWITCH, 'Switch'),
            (cls.PRINTER, 'Printer'),
            (cls.OTHER, 'Other')
        ]
    
    @classmethod
    def all(cls):
        return [cls.WORKSTATION, cls.SERVER, cls.ROUTER, cls.SWITCH, cls.PRINTER, cls.OTHER]


class KnownSystem(db.Model):
    """Known System model for tracking discovered systems
    
    Stores normalized NETBIOS hostname with related tables for
    IPs, aliases, shares, and case associations.
    """
    __tablename__ = 'known_systems'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Hostname - NETBIOS name only (e.g., ATN12345, not ATN12345.domain.local)
    hostname = db.Column(db.String(255), nullable=False, unique=True, index=True)
    
    # OS Information
    os_type = db.Column(db.String(50), nullable=True)  # Windows, Linux, Mac, Other
    os_version = db.Column(db.String(255), nullable=True)
    
    # System Type
    system_type = db.Column(db.String(50), nullable=True)  # Workstation, Server, Router, Switch, Printer, Other
    
    # Artifact count - incremented when artifacts reference this system
    artifacts_with_hostname = db.Column(db.Integer, nullable=False, default=0)
    
    # Timestamps
    added_on = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, nullable=True)
    
    # Analyst notes
    notes = db.Column(db.Text, nullable=True)
    
    # Compromised flag
    compromised = db.Column(db.Boolean, nullable=False, default=False)
    
    # Data sources that contributed to this system (evtx, ndjson, case_files, logon_events, unc_paths)
    sources = db.Column(db.JSON, nullable=False, default=list)
    
    # Relationships
    ip_addresses = db.relationship('KnownSystemIP', backref='system', lazy='dynamic', cascade='all, delete-orphan')
    mac_addresses = db.relationship('KnownSystemMAC', backref='system', lazy='dynamic', cascade='all, delete-orphan')
    aliases = db.relationship('KnownSystemAlias', backref='system', lazy='dynamic', cascade='all, delete-orphan')
    shares = db.relationship('KnownSystemShare', backref='system', lazy='dynamic', cascade='all, delete-orphan')
    cases = db.relationship('KnownSystemCase', backref='system', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<KnownSystem {self.id}: {self.hostname}>'
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'hostname': self.hostname,
            'os_type': self.os_type,
            'os_version': self.os_version,
            'system_type': self.system_type,
            'artifacts_with_hostname': self.artifacts_with_hostname,
            'added_on': self.added_on.isoformat() if self.added_on else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'notes': self.notes,
            'compromised': self.compromised,
            'sources': self.sources or [],
            'ip_addresses': [ip.ip_address for ip in self.ip_addresses],
            'mac_addresses': [mac.mac_address for mac in self.mac_addresses],
            'aliases': [alias.alias for alias in self.aliases],
            'shares': [share.to_dict() for share in self.shares],
            'case_count': self.cases.count()
        }
    
    @staticmethod
    def extract_netbios_name(hostname):
        """Extract NETBIOS name from a hostname
        
        ATN12345.domain.local -> ATN12345
        ATN12345 -> ATN12345
        
        Returns tuple: (netbios_name, full_hostname_if_different)
        """
        if not hostname:
            return None, None
        
        hostname = hostname.strip().upper()
        
        # Check if it contains a domain suffix
        if '.' in hostname:
            netbios = hostname.split('.')[0]
            return netbios, hostname
        
        return hostname, None
    
    @staticmethod
    def find_by_hostname_or_alias(hostname):
        """Find a system by hostname or any of its aliases
        
        Implements the deduplication workflow:
        1. Check if exists as hostname
        2. Check if exists in aliases
        3. Strip to NETBIOS and check again
        
        Returns: (KnownSystem or None, match_type)
        match_type: 'hostname', 'alias', 'netbios_hostname', 'netbios_alias', None
        """
        if not hostname:
            return None, None
        
        hostname_upper = hostname.strip().upper()
        netbios, fqdn = KnownSystem.extract_netbios_name(hostname_upper)
        
        # 1. Check exact hostname match
        system = KnownSystem.query.filter(
            db.func.upper(KnownSystem.hostname) == hostname_upper
        ).first()
        if system:
            return system, 'hostname'
        
        # 2. Check aliases for exact match
        alias_match = KnownSystemAlias.query.filter(
            db.func.upper(KnownSystemAlias.alias) == hostname_upper
        ).first()
        if alias_match:
            return alias_match.system, 'alias'
        
        # 3. Strip to NETBIOS and check hostname
        if netbios and netbios != hostname_upper:
            system = KnownSystem.query.filter(
                db.func.upper(KnownSystem.hostname) == netbios
            ).first()
            if system:
                return system, 'netbios_hostname'
            
            # 4. Check aliases for NETBIOS match
            alias_match = KnownSystemAlias.query.filter(
                db.func.upper(KnownSystemAlias.alias) == netbios
            ).first()
            if alias_match:
                return alias_match.system, 'netbios_alias'
        
        return None, None
    
    def add_ip_address(self, ip_address):
        """Add an IP address if not already present
        
        NOTE: Only use for IPs that belong TO this system (from host_ip in EDR data),
        NOT IPs from src_ip which could be remote systems accessing this machine.
        """
        if not ip_address:
            return False
        
        ip_address = ip_address.strip()
        existing = KnownSystemIP.query.filter_by(
            system_id=self.id,
            ip_address=ip_address
        ).first()
        
        if not existing:
            new_ip = KnownSystemIP(
                system_id=self.id,
                ip_address=ip_address,
                first_seen=datetime.utcnow()
            )
            db.session.add(new_ip)
            return True
        return False
    
    def add_mac_address(self, mac_address):
        """Add a MAC address if not already present
        
        NOTE: Only use for MACs that belong TO this system (from host_mac in EDR data).
        """
        if not mac_address:
            return False
        
        # Normalize MAC address to uppercase with colons
        mac_address = mac_address.strip().upper()
        # Handle different formats: aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff, aabbccddeeff
        mac_address = mac_address.replace('-', ':')
        if ':' not in mac_address and len(mac_address) == 12:
            # Convert aabbccddeeff to aa:bb:cc:dd:ee:ff
            mac_address = ':'.join(mac_address[i:i+2] for i in range(0, 12, 2))
        
        existing = KnownSystemMAC.query.filter_by(
            system_id=self.id,
            mac_address=mac_address
        ).first()
        
        if not existing:
            new_mac = KnownSystemMAC(
                system_id=self.id,
                mac_address=mac_address,
                first_seen=datetime.utcnow()
            )
            db.session.add(new_mac)
            return True
        return False
    
    def add_alias(self, alias):
        """Add an alias if not already present"""
        if not alias:
            return False
        
        alias = alias.strip().upper()
        
        # Don't add if it's the same as hostname
        if alias == self.hostname.upper():
            return False
        
        existing = KnownSystemAlias.query.filter_by(
            system_id=self.id
        ).filter(db.func.upper(KnownSystemAlias.alias) == alias).first()
        
        if not existing:
            new_alias = KnownSystemAlias(
                system_id=self.id,
                alias=alias,
                first_seen=datetime.utcnow()
            )
            db.session.add(new_alias)
            return True
        return False
    
    def add_share(self, share_name, share_path=None):
        """Add a share if not already present"""
        if not share_name:
            return False
        
        share_name = share_name.strip()
        existing = KnownSystemShare.query.filter_by(
            system_id=self.id,
            share_name=share_name
        ).first()
        
        if not existing:
            new_share = KnownSystemShare(
                system_id=self.id,
                share_name=share_name,
                share_path=share_path,
                first_seen=datetime.utcnow()
            )
            db.session.add(new_share)
            return True
        return False
    
    def link_to_case(self, case_id):
        """Link this system to a case"""
        existing = KnownSystemCase.query.filter_by(
            system_id=self.id,
            case_id=case_id
        ).first()
        
        if not existing:
            new_link = KnownSystemCase(
                system_id=self.id,
                case_id=case_id,
                first_seen_in_case=datetime.utcnow()
            )
            db.session.add(new_link)
            return True
        return False
    
    def add_source(self, source):
        """Add a data source if not already present
        
        Valid sources: case_files, evtx, ndjson, logon_events, unc_paths, firewall
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


class KnownSystemIP(db.Model):
    """IP addresses associated with a known system
    
    NOTE: Only stores IPs that belong TO this system (from host_ip in EDR data),
    NOT IPs from src_ip which could be remote systems accessing this machine.
    """
    __tablename__ = 'known_system_ips'
    
    id = db.Column(db.Integer, primary_key=True)
    system_id = db.Column(db.Integer, db.ForeignKey('known_systems.id'), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv6 max length
    first_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    __table_args__ = (
        db.UniqueConstraint('system_id', 'ip_address', name='uq_system_ip'),
    )
    
    def __repr__(self):
        return f'<KnownSystemIP {self.ip_address}>'


class KnownSystemMAC(db.Model):
    """MAC addresses associated with a known system
    
    NOTE: Only stores MACs that belong TO this system (from host_mac in EDR data).
    """
    __tablename__ = 'known_system_macs'
    
    id = db.Column(db.Integer, primary_key=True)
    system_id = db.Column(db.Integer, db.ForeignKey('known_systems.id'), nullable=False, index=True)
    mac_address = db.Column(db.String(17), nullable=False)  # aa:bb:cc:dd:ee:ff format
    first_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    __table_args__ = (
        db.UniqueConstraint('system_id', 'mac_address', name='uq_system_mac'),
    )
    
    def __repr__(self):
        return f'<KnownSystemMAC {self.mac_address}>'


class KnownSystemAlias(db.Model):
    """Aliases for a known system (FQDN variants, etc.)"""
    __tablename__ = 'known_system_aliases'
    
    id = db.Column(db.Integer, primary_key=True)
    system_id = db.Column(db.Integer, db.ForeignKey('known_systems.id'), nullable=False, index=True)
    alias = db.Column(db.String(255), nullable=False, index=True)
    first_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    __table_args__ = (
        db.UniqueConstraint('system_id', 'alias', name='uq_system_alias'),
    )
    
    def __repr__(self):
        return f'<KnownSystemAlias {self.alias}>'


class KnownSystemShare(db.Model):
    """Network shares found on a known system"""
    __tablename__ = 'known_system_shares'
    
    id = db.Column(db.Integer, primary_key=True)
    system_id = db.Column(db.Integer, db.ForeignKey('known_systems.id'), nullable=False, index=True)
    share_name = db.Column(db.String(255), nullable=False)
    share_path = db.Column(db.String(1024), nullable=True)
    first_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    __table_args__ = (
        db.UniqueConstraint('system_id', 'share_name', name='uq_system_share'),
    )
    
    def __repr__(self):
        return f'<KnownSystemShare {self.share_name}>'
    
    def to_dict(self):
        return {
            'share_name': self.share_name,
            'share_path': self.share_path,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None
        }


class KnownSystemCase(db.Model):
    """Junction table linking systems to cases"""
    __tablename__ = 'known_system_cases'
    
    id = db.Column(db.Integer, primary_key=True)
    system_id = db.Column(db.Integer, db.ForeignKey('known_systems.id'), nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    first_seen_in_case = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    __table_args__ = (
        db.UniqueConstraint('system_id', 'case_id', name='uq_system_case'),
    )
    
    def __repr__(self):
        return f'<KnownSystemCase system={self.system_id} case={self.case_id}>'


class KnownSystemAudit(db.Model):
    """Audit log for changes to known systems
    
    Tracks all changes except artifacts_with_hostname counter updates.
    """
    __tablename__ = 'known_systems_audit'
    
    id = db.Column(db.Integer, primary_key=True)
    system_id = db.Column(db.Integer, db.ForeignKey('known_systems.id'), nullable=False, index=True)
    changed_on = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    changed_by = db.Column(db.String(80), nullable=False)  # Username
    field_name = db.Column(db.String(100), nullable=False)  # Field or table that changed
    action = db.Column(db.String(20), nullable=False)  # create, update, delete
    old_value = db.Column(db.Text, nullable=True)
    new_value = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<KnownSystemAudit {self.id}: {self.action} {self.field_name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'system_id': self.system_id,
            'changed_on': self.changed_on.isoformat() if self.changed_on else None,
            'changed_by': self.changed_by,
            'field_name': self.field_name,
            'action': self.action,
            'old_value': self.old_value,
            'new_value': self.new_value
        }
    
    @staticmethod
    def log_change(system_id, changed_by, field_name, action, old_value=None, new_value=None):
        """Create an audit log entry"""
        audit = KnownSystemAudit(
            system_id=system_id,
            changed_by=changed_by,
            field_name=field_name,
            action=action,
            old_value=str(old_value) if old_value is not None else None,
            new_value=str(new_value) if new_value is not None else None
        )
        db.session.add(audit)
        return audit
