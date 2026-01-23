"""Agent Model for CaseScope

Agents are deployed on remote systems to collect forensic artifacts.
Each agent belongs to a client and can receive collection tasks.
"""
import uuid
from datetime import datetime
from models.database import db
from sqlalchemy.dialects.postgresql import JSONB


class AgentStatus:
    """Agent Status Options"""
    OFFLINE = 'offline'
    ONLINE = 'online'
    COLLECTING = 'collecting'
    ERROR = 'error'
    MAINTENANCE = 'maintenance'
    
    @classmethod
    def choices(cls):
        """Return list of status choices for forms"""
        return [
            (cls.OFFLINE, 'Offline'),
            (cls.ONLINE, 'Online'),
            (cls.COLLECTING, 'Collecting'),
            (cls.ERROR, 'Error'),
            (cls.MAINTENANCE, 'Maintenance')
        ]
    
    @classmethod
    def all(cls):
        """Return all status values"""
        return [cls.OFFLINE, cls.ONLINE, cls.COLLECTING, cls.ERROR, cls.MAINTENANCE]


class AgentOS:
    """Agent Operating System Options"""
    WINDOWS = 'windows'
    LINUX = 'linux'
    MACOS = 'macos'
    
    @classmethod
    def choices(cls):
        """Return list of OS choices for forms"""
        return [
            (cls.WINDOWS, 'Windows'),
            (cls.LINUX, 'Linux'),
            (cls.MACOS, 'macOS')
        ]
    
    @classmethod
    def all(cls):
        """Return all OS values"""
        return [cls.WINDOWS, cls.LINUX, cls.MACOS]


class Agent(db.Model):
    """Agent model for deployed collection agents
    
    Agents are installed on remote systems and can:
    - Send heartbeats with system status
    - Receive and execute collection tasks
    - Upload collected artifacts (CyDR, memory dumps, PCAPs)
    
    Uses UUID for obfuscation - no sequential IDs exposed externally.
    """
    __tablename__ = 'agents'
    
    # Primary key - internal integer for DB efficiency
    id = db.Column(db.Integer, primary_key=True)
    
    # Public UUID for external references (obfuscation)
    uuid = db.Column(db.String(36), unique=True, nullable=False, index=True,
                     default=lambda: str(uuid.uuid4()))
    
    # Client relationship
    client_id = db.Column(db.Integer, db.ForeignKey('clients.id'), nullable=False, index=True)
    
    # Agent identification
    name = db.Column(db.String(255), nullable=True)  # Friendly name (optional)
    hostname = db.Column(db.String(255), nullable=False, index=True)
    
    # System information
    os = db.Column(db.String(50), nullable=False, default=AgentOS.WINDOWS)
    os_version = db.Column(db.String(100), nullable=True)  # e.g., "Windows 10 22H2"
    architecture = db.Column(db.String(20), nullable=True)  # x64, x86, arm64
    
    # Agent software version
    agent_version = db.Column(db.String(20), nullable=True)
    
    # Status tracking
    status = db.Column(db.String(20), nullable=False, default=AgentStatus.OFFLINE, index=True)
    last_seen = db.Column(db.DateTime, nullable=True, index=True)
    last_ip = db.Column(db.String(45), nullable=True)  # IPv4 or IPv6
    
    # Capabilities - what this agent can collect
    # Example: {"cydr": true, "memory": true, "pcap": true, "custom_scripts": false}
    capabilities = db.Column(JSONB, nullable=True)
    
    # System resources (from last heartbeat)
    # Example: {"cpu_percent": 25.5, "memory_percent": 60.2, "disk_free_gb": 120.5}
    system_info = db.Column(JSONB, nullable=True)
    
    # Registration tracking
    registered_at = db.Column(db.DateTime, nullable=True)  # When agent first connected
    
    # Auth token hash for agent authentication (future use)
    auth_token_hash = db.Column(db.String(255), nullable=True)
    
    # Notes
    notes = db.Column(db.Text, nullable=True)
    
    # Tracking fields
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                           onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Agent {self.uuid[:8]}: {self.hostname}>'
    
    @property
    def display_name(self):
        """Get display name (friendly name or hostname)"""
        return self.name or self.hostname
    
    @property
    def is_online(self):
        """Check if agent is considered online"""
        return self.status == AgentStatus.ONLINE
    
    @property
    def is_available(self):
        """Check if agent can accept new tasks"""
        return self.status in [AgentStatus.ONLINE]
    
    def update_heartbeat(self, ip_address, system_info=None):
        """Update agent status from heartbeat
        
        Args:
            ip_address: Current IP address of the agent
            system_info: Optional dict with CPU, memory, disk info
        """
        self.last_seen = datetime.utcnow()
        self.last_ip = ip_address
        self.status = AgentStatus.ONLINE
        if system_info:
            self.system_info = system_info
    
    def mark_collecting(self):
        """Mark agent as currently collecting data"""
        self.status = AgentStatus.COLLECTING
    
    def mark_offline(self):
        """Mark agent as offline"""
        self.status = AgentStatus.OFFLINE
    
    def mark_error(self, error_note=None):
        """Mark agent as having an error"""
        self.status = AgentStatus.ERROR
        if error_note:
            current_notes = self.notes or ''
            timestamp = datetime.utcnow().isoformat()
            self.notes = f"{current_notes}\n[{timestamp}] ERROR: {error_note}".strip()
    
    def to_dict(self):
        """Convert agent to dictionary for API responses"""
        return {
            'uuid': self.uuid,
            'client_id': self.client_id,
            'name': self.name,
            'hostname': self.hostname,
            'display_name': self.display_name,
            'os': self.os,
            'os_version': self.os_version,
            'architecture': self.architecture,
            'agent_version': self.agent_version,
            'status': self.status,
            'is_online': self.is_online,
            'is_available': self.is_available,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'last_ip': self.last_ip,
            'capabilities': self.capabilities,
            'system_info': self.system_info,
            'registered_at': self.registered_at.isoformat() if self.registered_at else None,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def to_dict_minimal(self):
        """Minimal dict for lists and dropdowns"""
        return {
            'uuid': self.uuid,
            'display_name': self.display_name,
            'hostname': self.hostname,
            'os': self.os,
            'status': self.status,
            'is_online': self.is_online
        }
    
    @staticmethod
    def get_by_uuid(agent_uuid):
        """Get agent by UUID"""
        return Agent.query.filter_by(uuid=agent_uuid).first()
    
    @staticmethod
    def get_by_hostname(hostname, client_id=None):
        """Get agent by hostname, optionally filtered by client"""
        query = Agent.query.filter_by(hostname=hostname)
        if client_id:
            query = query.filter_by(client_id=client_id)
        return query.first()
    
    @staticmethod
    def get_online_agents(client_id=None):
        """Get all online agents, optionally filtered by client"""
        query = Agent.query.filter_by(status=AgentStatus.ONLINE)
        if client_id:
            query = query.filter_by(client_id=client_id)
        return query.order_by(Agent.hostname).all()
    
    @staticmethod
    def get_agents_for_client(client_id):
        """Get all agents for a specific client"""
        return Agent.query.filter_by(client_id=client_id).order_by(Agent.hostname).all()
