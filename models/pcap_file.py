"""PCAP File Model for tracking network capture file uploads"""
import os
import hashlib
from datetime import datetime
from models.database import db


class PcapFileStatus:
    """PCAP file processing status"""
    NEW = 'new'              # File uploaded, not yet processed
    QUEUED = 'queued'        # Queued for parsing
    PROCESSING = 'processing' # Currently being parsed with zeek
    ERROR = 'error'          # Error during processing
    DONE = 'done'            # Processing complete
    
    @classmethod
    def all(cls):
        return [cls.NEW, cls.QUEUED, cls.PROCESSING, cls.ERROR, cls.DONE]
    
    @classmethod
    def choices(cls):
        return [
            (cls.NEW, 'New'),
            (cls.QUEUED, 'Queued'),
            (cls.PROCESSING, 'Processing'),
            (cls.ERROR, 'Error'),
            (cls.DONE, 'Done')
        ]


class PcapFile(db.Model):
    """Model for tracking PCAP files associated with a case
    
    Tracks uploaded PCAP/PCAPNG files for Zeek analysis.
    Uses parent_id to link extracted files from ZIP archives.
    """
    __tablename__ = 'pcap_files'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Foreign key to case (by UUID for consistency)
    case_uuid = db.Column(db.String(36), nullable=False, index=True)
    
    # Parent file ID (for extracted files from zip)
    parent_id = db.Column(db.Integer, db.ForeignKey('pcap_files.id'), nullable=True, index=True)
    
    # File information
    filename = db.Column(db.String(512), nullable=False)
    original_filename = db.Column(db.String(512), nullable=False)  # Original name before any renaming
    file_path = db.Column(db.String(1024), nullable=True)  # Full path to file
    file_size = db.Column(db.BigInteger, nullable=False, default=0)
    sha256_hash = db.Column(db.String(64), nullable=False, index=True)
    
    # User-provided metadata
    hostname = db.Column(db.String(255), nullable=True, index=True)  # Source host/network device
    description = db.Column(db.Text, nullable=True)  # User description
    
    # Upload source tracking
    upload_source = db.Column(db.String(20), nullable=False, default='web')  # web, folder
    is_archive = db.Column(db.Boolean, nullable=False, default=False)  # True if this is a zip archive
    is_extracted = db.Column(db.Boolean, nullable=False, default=False)  # True if extracted from archive
    
    # Archive extraction status
    extraction_status = db.Column(db.String(20), nullable=False, default='n/a')  # n/a, pending, full, partial, fail
    
    # Processing status (workflow state)
    status = db.Column(db.String(50), nullable=False, default='new')
    
    # PCAP file type detection
    pcap_type = db.Column(db.String(50), nullable=True)  # pcap, pcapng, other
    
    # Zeek processing results
    zeek_output_path = db.Column(db.String(1024), nullable=True)  # Path to zeek logs output directory
    logs_generated = db.Column(db.Integer, nullable=False, default=0)  # Number of log files generated
    
    # ClickHouse indexing results
    indexed_at = db.Column(db.DateTime, nullable=True)  # When logs were indexed to ClickHouse
    logs_indexed = db.Column(db.Integer, nullable=False, default=0)  # Total log entries indexed
    
    # Error message if parsing failed
    error_message = db.Column(db.Text, nullable=True)
    
    # Timestamps
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime, nullable=True)
    
    # Who uploaded
    uploaded_by = db.Column(db.String(80), nullable=False)
    
    # Relationship for parent/child files
    parent = db.relationship('PcapFile', remote_side=[id], backref='extracted_files', foreign_keys=[parent_id])
    
    def __repr__(self):
        return f'<PcapFile {self.id}: {self.filename}>'
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'case_uuid': self.case_uuid,
            'parent_id': self.parent_id,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'sha256_hash': self.sha256_hash,
            'hostname': self.hostname,
            'description': self.description,
            'upload_source': self.upload_source,
            'is_archive': self.is_archive,
            'is_extracted': self.is_extracted,
            'extraction_status': self.extraction_status,
            'status': self.status,
            'pcap_type': self.pcap_type,
            'zeek_output_path': self.zeek_output_path,
            'logs_generated': self.logs_generated,
            'indexed_at': self.indexed_at.isoformat() if self.indexed_at else None,
            'logs_indexed': self.logs_indexed,
            'error_message': self.error_message,
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None,
            'processed_at': self.processed_at.isoformat() if self.processed_at else None,
            'uploaded_by': self.uploaded_by,
            'parent_filename': self.parent.filename if self.parent else None
        }
    
    @property
    def size_display(self):
        """Human-readable file size"""
        size = self.file_size
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.2f} GB"
    
    @staticmethod
    def get_stats(case_uuid):
        """Get file statistics for a case"""
        # Exclude archives from stats - they are containers
        base_query = PcapFile.query.filter_by(case_uuid=case_uuid, is_archive=False)
        
        total = base_query.count()
        done_count = base_query.filter_by(status=PcapFileStatus.DONE).count()
        error_count = base_query.filter_by(status=PcapFileStatus.ERROR).count()
        pending_count = base_query.filter(
            PcapFile.status.in_([PcapFileStatus.NEW, PcapFileStatus.QUEUED, PcapFileStatus.PROCESSING])
        ).count()
        
        # Total logs generated
        total_logs = db.session.query(db.func.sum(PcapFile.logs_generated)).filter(
            PcapFile.case_uuid == case_uuid,
            PcapFile.is_archive == False
        ).scalar() or 0
        
        return {
            'total': total,
            'done': done_count,
            'error': error_count,
            'pending': pending_count,
            'total_logs': total_logs
        }
    
    @staticmethod
    def calculate_sha256(filepath):
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    @staticmethod
    def detect_pcap_type(filepath):
        """Detect PCAP file type by magic bytes"""
        try:
            with open(filepath, 'rb') as f:
                magic = f.read(4)
                # PCAP magic bytes (little and big endian)
                if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
                    return 'pcap'
                # PCAPNG magic bytes
                if magic == b'\x0a\x0d\x0d\x0a':
                    return 'pcapng'
                # Also check for nanosecond pcap
                if magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
                    return 'pcap'
        except Exception:
            pass
        return None
    
    @staticmethod
    def is_pcap_file(filepath):
        """Check if file is a PCAP/PCAPNG file"""
        pcap_type = PcapFile.detect_pcap_type(filepath)
        if pcap_type:
            return True
        # Also check by extension if magic detection fails
        ext = os.path.splitext(filepath)[1].lower()
        return ext in ('.pcap', '.pcapng', '.cap')
    
    @staticmethod
    def is_zip_file(filepath):
        """Check if file is a zip archive by magic bytes"""
        try:
            with open(filepath, 'rb') as f:
                magic = f.read(4)
                # ZIP magic bytes: PK\x03\x04
                return magic[:2] == b'PK' and magic[2:4] in (b'\x03\x04', b'\x05\x06', b'\x07\x08')
        except Exception:
            return False
    
    @staticmethod
    def get_by_case(case_uuid, include_archives=True):
        """Get all files for a case"""
        query = PcapFile.query.filter_by(case_uuid=case_uuid)
        if not include_archives:
            query = query.filter_by(is_archive=False)
        return query.order_by(PcapFile.uploaded_at.desc()).all()
    
    @staticmethod
    def find_by_hash(sha256_hash, case_uuid=None):
        """Find existing file by hash, optionally within a specific case"""
        query = PcapFile.query.filter_by(sha256_hash=sha256_hash)
        if case_uuid:
            query = query.filter_by(case_uuid=case_uuid)
        return query.first()
    
    @staticmethod
    def find_by_filename(filename, case_uuid=None):
        """Find existing file by filename, optionally within a specific case"""
        query = PcapFile.query.filter_by(original_filename=filename)
        if case_uuid:
            query = query.filter_by(case_uuid=case_uuid)
        return query.first()
