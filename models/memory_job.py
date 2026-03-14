"""Memory Forensics Job Model for CaseScope"""
import enum
from datetime import datetime
from models.database import db


class MemoryOS(enum.Enum):
    """Operating system types for memory analysis"""
    WINDOWS = 'windows'
    LINUX = 'linux'
    MACOS = 'macos'
    
    @classmethod
    def choices(cls):
        return [
            (cls.WINDOWS.value, 'Windows'),
            (cls.LINUX.value, 'Linux'),
            (cls.MACOS.value, 'macOS')
        ]


class MemoryType(enum.Enum):
    """Memory dump types"""
    RAW = 'raw'
    DMP = 'dmp'
    VMWARE = 'vmware'
    LIME = 'lime'
    HIBERNATION = 'hibernation'
    PAGEFILE = 'pagefile'
    ENCASE = 'encase'
    AFF = 'aff'
    OTHER = 'other'
    
    @classmethod
    def choices(cls):
        return [
            (cls.RAW.value, 'Raw Memory (.raw, .mem)'),
            (cls.DMP.value, 'Windows Dump (.dmp)'),
            (cls.VMWARE.value, 'VMware Memory (.vmem)'),
            (cls.LIME.value, 'LiME Dump (.lime)'),
            (cls.HIBERNATION.value, 'Hibernation File'),
            (cls.PAGEFILE.value, 'Page/Swap File'),
            (cls.ENCASE.value, 'EnCase Image (.E01)'),
            (cls.AFF.value, 'AFF Image (.aff)'),
            (cls.OTHER.value, 'Other')
        ]


class JobStatus(enum.Enum):
    """Job processing status"""
    PENDING = 'pending'
    RUNNING = 'running'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'


# Plugin definitions by category
VOLATILITY_PLUGINS = {
    'windows': {
        'essential': [
            {'name': 'windows.info', 'description': 'System info and timestamp', 'default': True},
            {'name': 'windows.pslist', 'description': 'List running processes', 'default': True},
            {'name': 'windows.psscan', 'description': 'Find hidden/unlinked processes', 'default': True},
            {'name': 'windows.pstree', 'description': 'Process tree with parent-child relationships', 'default': True},
            {'name': 'windows.cmdline', 'description': 'Command line arguments for each process', 'default': True},
            {'name': 'windows.netscan', 'description': 'Network connections (active and closed)', 'default': True},
            {'name': 'windows.malfind', 'description': 'Find injected code (RWX memory)', 'default': True},
            {'name': 'windows.ldrmodules', 'description': 'Detect unlinked/hidden DLLs', 'default': True},
            {'name': 'windows.svcscan', 'description': 'Windows services', 'default': True},
            {'name': 'windows.getsids', 'description': 'SIDs per process (user context)', 'default': True},
        ],
        'recommended': [
            {'name': 'windows.hollowprocesses', 'description': 'Detect process hollowing', 'default': False},
            {'name': 'windows.handles', 'description': 'Open handles per process', 'default': False},
            {'name': 'windows.dlllist', 'description': 'Loaded DLLs per process', 'default': False},
            {'name': 'windows.netstat', 'description': 'Active network connections only', 'default': False},
            {'name': 'windows.registry.hivelist', 'description': 'List registry hives in memory', 'default': False},
            {'name': 'windows.registry.userassist', 'description': 'UserAssist (program execution)', 'default': False},
            {'name': 'windows.modules', 'description': 'Kernel modules (rootkit detection)', 'default': False},
            {'name': 'windows.callbacks', 'description': 'Kernel callbacks (persistence)', 'default': False},
            {'name': 'windows.scheduled_tasks', 'description': 'Scheduled tasks', 'default': False},
        ],
        'credentials': [
            {'name': 'windows.hashdump', 'description': 'Extract password hashes (SAM)', 'default': False, 'sensitive': True},
            {'name': 'windows.lsadump', 'description': 'LSA secrets', 'default': False, 'sensitive': True},
            {'name': 'windows.cachedump', 'description': 'Cached domain credentials', 'default': False, 'sensitive': True},
        ],
        'advanced': [
            {'name': 'windows.filescan', 'description': 'Scan for file objects (SLOW)', 'default': False, 'slow': True},
            {'name': 'windows.mftscan', 'description': 'MFT entries in memory (SLOW)', 'default': False, 'slow': True},
            {'name': 'windows.vadinfo', 'description': 'Virtual Address Descriptor analysis', 'default': False},
            {'name': 'windows.modscan', 'description': 'Scan for hidden kernel modules', 'default': False},
            {'name': 'windows.ssdt', 'description': 'SSDT hooking detection', 'default': False},
        ],
    },
    'linux': {
        'essential': [
            {'name': 'linux.pslist', 'description': 'List running processes', 'default': True},
            {'name': 'linux.pstree', 'description': 'Process tree', 'default': True},
            {'name': 'linux.bash', 'description': 'Bash command history', 'default': True},
            {'name': 'linux.lsof', 'description': 'Open files per process', 'default': True},
            {'name': 'linux.sockstat', 'description': 'Network sockets', 'default': True},
            {'name': 'linux.elfs', 'description': 'ELF binaries in memory', 'default': True},
            {'name': 'linux.malfind', 'description': 'Find injected code', 'default': True},
        ],
        'recommended': [
            {'name': 'linux.psaux', 'description': 'Process listing with arguments', 'default': False},
            {'name': 'linux.lsmod', 'description': 'Loaded kernel modules', 'default': False},
            {'name': 'linux.tty_check', 'description': 'TTY hijacking detection', 'default': False},
            {'name': 'linux.check_syscall', 'description': 'Syscall table hooks', 'default': False},
        ],
        'credentials': [
            {'name': 'linux.proc.maps', 'description': 'Process memory maps', 'default': False},
        ],
        'advanced': [
            {'name': 'linux.check_idt', 'description': 'IDT hooking detection', 'default': False},
            {'name': 'linux.hidden_modules', 'description': 'Hidden kernel modules', 'default': False},
        ],
    },
    'macos': {
        'essential': [
            {'name': 'mac.pslist', 'description': 'List running processes', 'default': True},
            {'name': 'mac.pstree', 'description': 'Process tree', 'default': True},
            {'name': 'mac.bash', 'description': 'Bash command history', 'default': True},
            {'name': 'mac.lsof', 'description': 'Open files per process', 'default': True},
            {'name': 'mac.netstat', 'description': 'Network connections', 'default': True},
            {'name': 'mac.malfind', 'description': 'Find injected code', 'default': True},
        ],
        'recommended': [
            {'name': 'mac.psaux', 'description': 'Process listing with arguments', 'default': False},
            {'name': 'mac.lsmod', 'description': 'Loaded kernel extensions', 'default': False},
            {'name': 'mac.socket_filters', 'description': 'Socket filter hooks', 'default': False},
        ],
        'credentials': [],
        'advanced': [
            {'name': 'mac.check_syscall', 'description': 'Syscall hooking detection', 'default': False},
            {'name': 'mac.check_sysctl', 'description': 'Sysctl hooking detection', 'default': False},
        ],
    }
}


def get_default_plugins(os_type: str) -> list:
    """Get list of default plugin names for an OS"""
    plugins = []
    os_plugins = VOLATILITY_PLUGINS.get(os_type, {})
    for category, plugin_list in os_plugins.items():
        for plugin in plugin_list:
            if plugin.get('default', False):
                plugins.append(plugin['name'])
    return plugins


class MemoryJob(db.Model):
    """Track memory forensics processing jobs"""
    __tablename__ = 'memory_jobs'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False)
    
    # Source file info
    source_file = db.Column(db.String(500), nullable=False)  # Retained source file used for processing
    original_source_file = db.Column(db.String(500), nullable=True)  # Original upload path for custody tracking
    source_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.BigInteger)
    
    # User-provided metadata
    hostname = db.Column(db.String(100), nullable=False)
    os_type = db.Column(db.String(20), nullable=False)  # windows, linux, macos
    memory_type = db.Column(db.String(50), nullable=False)  # raw, dmp, vmware, etc.
    
    # Selected plugins (JSON array of plugin names)
    selected_plugins = db.Column(db.JSON, default=list)
    
    # Processing results
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed, cancelled
    progress = db.Column(db.Integer, default=0)  # 0-100
    current_plugin = db.Column(db.String(100))
    
    # Output paths
    output_folder = db.Column(db.String(500))
    extracted_file_path = db.Column(db.String(500))
    
    # Timestamps extracted from memory
    memory_timestamp = db.Column(db.DateTime)  # System time from memory image
    
    # Results summary
    plugins_completed = db.Column(db.JSON, default=list)
    plugins_failed = db.Column(db.JSON, default=list)
    error_message = db.Column(db.Text)
    
    # Tracking
    created_by = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    # Celery task ID for tracking
    celery_task_id = db.Column(db.String(100))
    
    # Relationships
    case = db.relationship('Case', backref=db.backref('memory_jobs', lazy='dynamic'))

    def plugin_results(self):
        """Return normalized plugin execution and ingestion results."""
        results = []
        selected_order = {
            name: idx for idx, name in enumerate(self.selected_plugins or [])
        }

        for item in self.plugins_completed or []:
            if not isinstance(item, dict) or not item.get('name'):
                continue
            entry = dict(item)
            entry.setdefault('selected', entry.get('name') in selected_order)
            entry['auto_added'] = bool(entry.get('auto_added', False))
            entry.setdefault('execution_status', 'completed')
            entry.setdefault('state', entry.get('ingest_status') or 'completed')
            results.append(entry)

        for item in self.plugins_failed or []:
            if not isinstance(item, dict) or not item.get('name'):
                continue
            entry = dict(item)
            entry.setdefault('selected', entry.get('name') in selected_order)
            entry['auto_added'] = bool(entry.get('auto_added', False))
            entry['execution_status'] = 'failed'
            entry['state'] = 'failed'
            results.append(entry)

        def _sort_key(entry):
            plugin_name = entry.get('name')
            return (
                0 if plugin_name in selected_order else 1,
                selected_order.get(plugin_name, 10**6),
                entry.get('timestamp') or '',
                plugin_name or '',
            )

        return sorted(results, key=_sort_key)

    def plugin_summary(self):
        """Return aggregate plugin-state counts for UI and API consumers."""
        summary = {
            'selected_total': len(self.selected_plugins or []),
            'execution_total': 0,
            'completed_total': 0,
            'failed_total': 0,
            'ingested_total': 0,
            'zero_row_total': 0,
            'unsupported_total': 0,
            'unknown_total': 0,
            'auto_added_total': 0,
            'has_partial_results': False,
            'has_ingested_results': False,
        }

        for entry in self.plugin_results():
            summary['execution_total'] += 1
            if entry.get('auto_added'):
                summary['auto_added_total'] += 1

            state = entry.get('state')
            if state == 'failed':
                summary['failed_total'] += 1
                summary['has_partial_results'] = True
            elif state == 'completed_ingested':
                summary['completed_total'] += 1
                summary['ingested_total'] += 1
                summary['has_ingested_results'] = True
            elif state == 'completed_zero_rows':
                summary['completed_total'] += 1
                summary['zero_row_total'] += 1
                summary['has_partial_results'] = True
            elif state == 'completed_unsupported':
                summary['completed_total'] += 1
                summary['unsupported_total'] += 1
                summary['has_partial_results'] = True
            else:
                summary['completed_total'] += 1
                summary['unknown_total'] += 1

        return summary
    
    def to_dict(self):
        return {
            'id': self.id,
            'case_id': self.case_id,
            'source_file': self.source_file,
            'original_source_file': self.original_source_file,
            'source_filename': self.source_filename,
            'file_size': self.file_size,
            'hostname': self.hostname,
            'os_type': self.os_type,
            'memory_type': self.memory_type,
            'selected_plugins': self.selected_plugins or [],
            'status': self.status,
            'progress': self.progress,
            'current_plugin': self.current_plugin,
            'output_folder': self.output_folder,
            'extracted_file_path': self.extracted_file_path,
            'memory_timestamp': self.memory_timestamp.isoformat() if self.memory_timestamp else None,
            'plugins_completed': self.plugins_completed or [],
            'plugins_failed': self.plugins_failed or [],
            'plugin_results': self.plugin_results(),
            'plugin_summary': self.plugin_summary(),
            'error_message': self.error_message,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
        }
