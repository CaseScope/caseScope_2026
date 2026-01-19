"""Memory Forensics Data Models for CaseScope

Stores parsed Volatility 3 output for cross-memory correlation and analysis.
Each table links to a memory_job which provides case/hostname context.
"""
from datetime import datetime
from models.database import db


class MemoryProcess(db.Model):
    """Parsed process data from pslist/pstree/cmdline plugins"""
    __tablename__ = 'memory_processes'
    
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('memory_jobs.id', ondelete='CASCADE'), nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, index=True)
    hostname = db.Column(db.String(100), nullable=False, index=True)
    
    # Process identifiers
    pid = db.Column(db.Integer, nullable=False, index=True)
    ppid = db.Column(db.Integer, index=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    name_lower = db.Column(db.String(255), index=True)  # For case-insensitive search
    
    # Extended info from cmdline/pstree
    path = db.Column(db.Text)
    cmdline = db.Column(db.Text)
    audit_path = db.Column(db.Text)  # From pstree Audit field
    
    # Process metadata
    offset_v = db.Column(db.BigInteger)
    session_id = db.Column(db.Integer)
    threads = db.Column(db.Integer)
    handles = db.Column(db.Integer)
    wow64 = db.Column(db.Boolean, default=False)
    
    # Timestamps
    create_time = db.Column(db.DateTime)
    exit_time = db.Column(db.DateTime)
    
    # Cross-reference counts (cached for performance)
    cross_memory_count = db.Column(db.Integer, default=0)  # Found in N other memory dumps
    cross_events_count = db.Column(db.Integer, default=0)  # Found in N events
    
    # Tracking
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Indexes for common queries
    __table_args__ = (
        db.Index('idx_memproc_case_name', 'case_id', 'name_lower'),
        db.Index('idx_memproc_job_pid', 'job_id', 'pid'),
    )
    
    def to_dict(self):
        return {
            'id': self.id,
            'job_id': self.job_id,
            'hostname': self.hostname,
            'pid': self.pid,
            'ppid': self.ppid,
            'name': self.name,
            'path': self.path,
            'cmdline': self.cmdline,
            'session_id': self.session_id,
            'threads': self.threads,
            'handles': self.handles,
            'wow64': self.wow64,
            'create_time': self.create_time.isoformat() if self.create_time else None,
            'exit_time': self.exit_time.isoformat() if self.exit_time else None,
            'cross_memory_count': self.cross_memory_count,
            'cross_events_count': self.cross_events_count,
        }


class MemoryNetwork(db.Model):
    """Parsed network connections from netscan/netstat plugins"""
    __tablename__ = 'memory_network'
    
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('memory_jobs.id', ondelete='CASCADE'), nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, index=True)
    hostname = db.Column(db.String(100), nullable=False, index=True)
    
    # Connection details
    protocol = db.Column(db.String(20))  # TCPv4, TCPv6, UDPv4, UDPv6
    local_addr = db.Column(db.String(50), index=True)
    local_port = db.Column(db.Integer)
    foreign_addr = db.Column(db.String(50), index=True)
    foreign_port = db.Column(db.Integer)
    state = db.Column(db.String(30))  # LISTENING, ESTABLISHED, CLOSE_WAIT, etc.
    
    # Process info
    pid = db.Column(db.Integer, index=True)
    owner = db.Column(db.String(255))  # Process name
    
    # Metadata
    offset = db.Column(db.BigInteger)
    created_time = db.Column(db.DateTime)
    
    # Cross-reference
    cross_memory_count = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        db.Index('idx_memnet_case_foreign', 'case_id', 'foreign_addr'),
        db.Index('idx_memnet_case_local', 'case_id', 'local_addr'),
    )
    
    def to_dict(self):
        return {
            'id': self.id,
            'job_id': self.job_id,
            'hostname': self.hostname,
            'protocol': self.protocol,
            'local_addr': self.local_addr,
            'local_port': self.local_port,
            'foreign_addr': self.foreign_addr,
            'foreign_port': self.foreign_port,
            'state': self.state,
            'pid': self.pid,
            'owner': self.owner,
            'created_time': self.created_time.isoformat() if self.created_time else None,
            'cross_memory_count': self.cross_memory_count,
        }


class MemoryService(db.Model):
    """Parsed Windows services from svcscan plugin"""
    __tablename__ = 'memory_services'
    
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('memory_jobs.id', ondelete='CASCADE'), nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, index=True)
    hostname = db.Column(db.String(100), nullable=False, index=True)
    
    # Service details
    name = db.Column(db.String(255), nullable=False, index=True)
    name_lower = db.Column(db.String(255), index=True)
    display_name = db.Column(db.String(500))
    binary_path = db.Column(db.Text)
    binary_path_registry = db.Column(db.Text)
    dll = db.Column(db.Text)
    
    # Service state
    state = db.Column(db.String(50))  # SERVICE_RUNNING, SERVICE_STOPPED, etc.
    start_type = db.Column(db.String(50))  # SERVICE_AUTO_START, SERVICE_DEMAND_START, etc.
    service_type = db.Column(db.String(100))  # SERVICE_WIN32_OWN_PROCESS, etc.
    
    # Metadata
    pid = db.Column(db.Integer)
    offset = db.Column(db.BigInteger)
    order = db.Column(db.Integer)
    
    # Cross-reference
    cross_memory_count = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        db.Index('idx_memsvc_case_name', 'case_id', 'name_lower'),
    )
    
    def to_dict(self):
        return {
            'id': self.id,
            'job_id': self.job_id,
            'hostname': self.hostname,
            'name': self.name,
            'display_name': self.display_name,
            'binary_path': self.binary_path or self.binary_path_registry,
            'dll': self.dll,
            'state': self.state,
            'start_type': self.start_type,
            'service_type': self.service_type,
            'pid': self.pid,
            'cross_memory_count': self.cross_memory_count,
        }


class MemoryMalfind(db.Model):
    """Suspicious memory regions from malfind plugin"""
    __tablename__ = 'memory_malfind'
    
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('memory_jobs.id', ondelete='CASCADE'), nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, index=True)
    hostname = db.Column(db.String(100), nullable=False, index=True)
    
    # Process info
    pid = db.Column(db.Integer, nullable=False, index=True)
    process_name = db.Column(db.String(255), index=True)
    
    # Memory region details
    protection = db.Column(db.String(50))  # PAGE_EXECUTE_READWRITE, etc.
    start_vpn = db.Column(db.BigInteger)
    end_vpn = db.Column(db.BigInteger)
    tag = db.Column(db.String(20))  # VadS, etc.
    commit_charge = db.Column(db.Integer)
    private_memory = db.Column(db.Boolean)
    
    # Content (first 64 bytes typically)
    hexdump = db.Column(db.Text)
    disasm = db.Column(db.Text)
    
    # Notes
    notes = db.Column(db.Text)
    
    # Cross-reference
    cross_memory_count = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'job_id': self.job_id,
            'hostname': self.hostname,
            'pid': self.pid,
            'process_name': self.process_name,
            'protection': self.protection,
            'start_vpn': self.start_vpn,
            'end_vpn': self.end_vpn,
            'hexdump': self.hexdump,
            'disasm': self.disasm,
            'cross_memory_count': self.cross_memory_count,
        }


class MemoryModule(db.Model):
    """Loaded modules/DLLs from ldrmodules plugin"""
    __tablename__ = 'memory_modules'
    
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('memory_jobs.id', ondelete='CASCADE'), nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, index=True)
    hostname = db.Column(db.String(100), nullable=False, index=True)
    
    # Process info
    pid = db.Column(db.Integer, nullable=False, index=True)
    process_name = db.Column(db.String(255))
    
    # Module details
    base_address = db.Column(db.BigInteger)
    mapped_path = db.Column(db.Text, index=True)
    
    # Link status (hidden DLL detection)
    in_init = db.Column(db.Boolean, default=False)
    in_load = db.Column(db.Boolean, default=False)
    in_mem = db.Column(db.Boolean, default=False)
    
    # Cross-reference
    cross_memory_count = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        db.Index('idx_memmod_case_path', 'case_id', 'mapped_path'),
    )
    
    def to_dict(self):
        # Derive suspicion level from link status
        unlinked = not (self.in_init or self.in_load or self.in_mem)
        return {
            'id': self.id,
            'job_id': self.job_id,
            'hostname': self.hostname,
            'pid': self.pid,
            'process_name': self.process_name,
            'base_address': hex(self.base_address) if self.base_address else None,
            'mapped_path': self.mapped_path,
            'in_init': self.in_init,
            'in_load': self.in_load,
            'in_mem': self.in_mem,
            'unlinked': unlinked,
            'cross_memory_count': self.cross_memory_count,
        }


class MemoryCredential(db.Model):
    """Extracted credentials from hashdump/cachedump/lsadump plugins"""
    __tablename__ = 'memory_credentials'
    
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('memory_jobs.id', ondelete='CASCADE'), nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, index=True)
    hostname = db.Column(db.String(100), nullable=False, index=True)
    
    # Credential type
    source_plugin = db.Column(db.String(50), nullable=False)  # hashdump, cachedump, lsadump
    
    # User info
    username = db.Column(db.String(255), index=True)
    domain = db.Column(db.String(255))
    rid = db.Column(db.Integer)  # For hashdump
    
    # Hash/secret data (stored securely - could encrypt in future)
    lm_hash = db.Column(db.String(100))
    nt_hash = db.Column(db.String(100))
    cached_hash = db.Column(db.String(200))
    lsa_key = db.Column(db.String(100))
    lsa_secret_hex = db.Column(db.Text)
    
    # Cross-reference
    cross_memory_count = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        db.Index('idx_memcred_case_user', 'case_id', 'username'),
    )
    
    def to_dict(self, mask_secrets=True):
        result = {
            'id': self.id,
            'job_id': self.job_id,
            'hostname': self.hostname,
            'source_plugin': self.source_plugin,
            'username': self.username,
            'domain': self.domain,
            'rid': self.rid,
            'cross_memory_count': self.cross_memory_count,
        }
        
        if mask_secrets:
            # Show partial hash for identification
            if self.nt_hash:
                result['nt_hash'] = self.nt_hash[:8] + '...' if len(self.nt_hash) > 8 else self.nt_hash
            if self.lm_hash:
                result['lm_hash'] = self.lm_hash[:8] + '...' if len(self.lm_hash) > 8 else self.lm_hash
            if self.cached_hash:
                result['cached_hash'] = self.cached_hash[:16] + '...' if len(self.cached_hash) > 16 else self.cached_hash
            if self.lsa_key:
                result['lsa_key'] = self.lsa_key
            result['has_secret'] = bool(self.lsa_secret_hex)
        else:
            result['nt_hash'] = self.nt_hash
            result['lm_hash'] = self.lm_hash
            result['cached_hash'] = self.cached_hash
            result['lsa_key'] = self.lsa_key
            result['lsa_secret_hex'] = self.lsa_secret_hex
        
        return result


class MemorySID(db.Model):
    """Process SIDs from getsids plugin"""
    __tablename__ = 'memory_sids'
    
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('memory_jobs.id', ondelete='CASCADE'), nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, index=True)
    hostname = db.Column(db.String(100), nullable=False, index=True)
    
    # Process info
    pid = db.Column(db.Integer, nullable=False, index=True)
    process_name = db.Column(db.String(255))
    
    # SID info
    sid = db.Column(db.String(200), index=True)
    sid_name = db.Column(db.String(255))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'job_id': self.job_id,
            'hostname': self.hostname,
            'pid': self.pid,
            'process_name': self.process_name,
            'sid': self.sid,
            'sid_name': self.sid_name,
        }


class MemoryInfo(db.Model):
    """System information from windows.info plugin"""
    __tablename__ = 'memory_info'
    
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('memory_jobs.id', ondelete='CASCADE'), nullable=False, index=True, unique=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, index=True)
    hostname = db.Column(db.String(100), nullable=False)
    
    # System details
    kernel_base = db.Column(db.String(50))
    dtb = db.Column(db.String(50))
    symbols = db.Column(db.Text)
    is_64bit = db.Column(db.Boolean)
    is_pae = db.Column(db.Boolean)
    
    # Version info
    major_minor = db.Column(db.String(20))  # e.g., "15.19041"
    nt_major = db.Column(db.Integer)
    nt_minor = db.Column(db.Integer)
    machine_type = db.Column(db.Integer)
    num_processors = db.Column(db.Integer)
    nt_product_type = db.Column(db.String(50))
    nt_system_root = db.Column(db.String(255))
    
    # Timestamps
    system_time = db.Column(db.DateTime)  # When the memory was captured
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'job_id': self.job_id,
            'hostname': self.hostname,
            'is_64bit': self.is_64bit,
            'major_minor': self.major_minor,
            'nt_major': self.nt_major,
            'nt_minor': self.nt_minor,
            'num_processors': self.num_processors,
            'nt_product_type': self.nt_product_type,
            'nt_system_root': self.nt_system_root,
            'system_time': self.system_time.isoformat() if self.system_time else None,
        }
