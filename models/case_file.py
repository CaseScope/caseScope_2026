"""CaseFile Model for tracking uploaded/ingested files"""
import os
import hashlib
from datetime import datetime
from models.database import db


class ExtractionStatus:
    """Extraction status for archive files"""
    NA = 'n/a'          # Not an archive
    PENDING = 'pending'  # Not yet extracted
    FULL = 'full'        # Fully extracted successfully
    PARTIAL = 'partial'  # Partially extracted (some files failed)
    FAIL = 'fail'        # Failed to extract at all
    
    @classmethod
    def all(cls):
        return [cls.NA, cls.PENDING, cls.FULL, cls.PARTIAL, cls.FAIL]


class CaseFile(db.Model):
    """Model for tracking files associated with a case
    
    Tracks both uploaded files and extracted files from archives.
    Uses parent_id to link extracted files to their source archive.
    """
    __tablename__ = 'case_files'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Foreign key to case (by UUID for consistency)
    case_uuid = db.Column(db.String(36), nullable=False, index=True)
    
    # Parent file ID (for extracted files from zip)
    parent_id = db.Column(db.Integer, db.ForeignKey('case_files.id'), nullable=True, index=True)
    
    # File information
    filename = db.Column(db.String(512), nullable=False)
    original_filename = db.Column(db.String(512), nullable=False)  # Original name before any renaming
    file_path = db.Column(db.String(1024), nullable=True)  # Full path in staging (null if deleted/not kept)
    file_size = db.Column(db.BigInteger, nullable=False, default=0)
    sha256_hash = db.Column(db.String(64), nullable=False, index=True)
    
    # User-provided metadata
    hostname = db.Column(db.String(255), nullable=True, index=True)
    file_type = db.Column(db.String(50), nullable=True)  # CyLR, Huntress NDJSON, IIS Log, etc.
    
    # Upload source tracking
    upload_source = db.Column(db.String(20), nullable=False, default='web')  # web, folder
    is_archive = db.Column(db.Boolean, nullable=False, default=False)  # True if this is a zip/archive
    is_extracted = db.Column(db.Boolean, nullable=False, default=False)  # True if extracted from archive
    
    # Archive extraction status
    extraction_status = db.Column(db.String(20), nullable=False, default='n/a')  # n/a, pending, full, partial, fail
    
    # Processing status
    status = db.Column(db.String(50), nullable=False, default='pending')  # pending, processing, completed, error
    
    # Timestamps
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime, nullable=True)
    
    # Who uploaded
    uploaded_by = db.Column(db.String(80), nullable=False)
    
    # Relationship for parent/child files
    parent = db.relationship('CaseFile', remote_side=[id], backref='extracted_files')
    
    def __repr__(self):
        return f'<CaseFile {self.id}: {self.filename}>'
    
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
            'file_type': self.file_type,
            'upload_source': self.upload_source,
            'is_archive': self.is_archive,
            'is_extracted': self.is_extracted,
            'extraction_status': self.extraction_status,
            'status': self.status,
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None,
            'processed_at': self.processed_at.isoformat() if self.processed_at else None,
            'uploaded_by': self.uploaded_by
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
    def get_by_case(case_uuid):
        """Get all files for a case"""
        return CaseFile.query.filter_by(case_uuid=case_uuid).order_by(CaseFile.uploaded_at.desc()).all()
    
    @staticmethod
    def get_parent_files(case_uuid):
        """Get only parent files (not extracted) for a case"""
        return CaseFile.query.filter_by(
            case_uuid=case_uuid,
            is_extracted=False
        ).order_by(CaseFile.uploaded_at.desc()).all()
