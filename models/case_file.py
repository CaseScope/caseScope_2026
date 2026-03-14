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


class FileStatus:
    """File processing status"""
    NEW = 'new'              # File uploaded, not yet processed
    QUEUED = 'queued'        # Queued for parsing
    INGESTING = 'ingesting'  # Currently being parsed
    ERROR = 'error'          # Error during processing
    DONE = 'done'            # Processing complete
    DUPLICATE = 'duplicate'  # Duplicate of another file in this case
    
    @classmethod
    def all(cls):
        return [cls.NEW, cls.QUEUED, cls.INGESTING, cls.ERROR, cls.DONE, cls.DUPLICATE]
    
    @classmethod
    def choices(cls):
        return [
            (cls.NEW, 'New'),
            (cls.QUEUED, 'Queued'),
            (cls.INGESTING, 'Ingesting'),
            (cls.ERROR, 'Error'),
            (cls.DONE, 'Done'),
            (cls.DUPLICATE, 'Duplicate')
        ]


class IngestionStatus:
    """Ingestion/parsing result status"""
    NOT_DONE = 'not_done'      # Not yet processed
    FULL = 'full'              # Fully indexed
    PARTIAL = 'partial'        # Partially indexed
    NO_PARSER = 'no_parser'    # No parser available for this file type
    PARSE_ERROR = 'parse_error'  # Parser exists but failed
    ERROR = 'error'            # General error (can't read file, etc.)
    
    @classmethod
    def all(cls):
        return [cls.NOT_DONE, cls.FULL, cls.PARTIAL, cls.NO_PARSER, cls.PARSE_ERROR, cls.ERROR]
    
    @classmethod
    def choices(cls):
        return [
            (cls.NOT_DONE, 'Not Done'),
            (cls.FULL, 'Full'),
            (cls.PARTIAL, 'Partial'),
            (cls.NO_PARSER, 'No Parser'),
            (cls.PARSE_ERROR, 'Parse Error'),
            (cls.ERROR, 'Error')
        ]


class CaseFile(db.Model):
    """Model for tracking files associated with a case
    
    Tracks both uploaded files and extracted files from archives.
    Uses parent_id to link extracted files to their source archive.
    """
    __tablename__ = 'case_files'

    EXPECTED_SIDECAR_EXTENSIONS = {
        '.blf', '.cdp', '.cdpresource', '.chk', '.db-shm', '.db-wal', '.etl',
        '.ini', '.jfm', '.jrs', '.log', '.log1', '.log2', '.regtrans-ms',
        '.sst', '.tmp'
    }
    EXPECTED_SIDECAR_FILENAMES = {
        'desktop.ini',
    }
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Foreign key to case (by UUID for consistency)
    case_uuid = db.Column(db.String(36), nullable=False, index=True)
    
    # Parent file ID (for extracted files from zip)
    parent_id = db.Column(db.Integer, db.ForeignKey('case_files.id'), nullable=True, index=True)
    
    # Duplicate tracking - references the original file this is a duplicate of
    duplicate_of_id = db.Column(db.Integer, db.ForeignKey('case_files.id'), nullable=True, index=True)
    
    # File information
    filename = db.Column(db.String(512), nullable=False)
    original_filename = db.Column(db.String(512), nullable=False)  # Original name before any renaming
    file_path = db.Column(db.String(1024), nullable=True)  # Current retained path
    source_path = db.Column(db.String(1024), nullable=True)  # Original upload/staging path for custody tracking
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
    
    # Processing status (workflow state)
    status = db.Column(db.String(50), nullable=False, default='new')  # new, queued, ingesting, error, done
    
    # Ingestion result status
    ingestion_status = db.Column(db.String(50), nullable=False, default='not_done')  # not_done, full, partial, no_parser, parse_error, error
    retention_state = db.Column(db.String(50), nullable=False, default='retained')  # retained, duplicate_retained, archived, failed_retained
    
    # Parser type used (e.g., EVTX, HuntressNDJSON, Registry, etc.)
    parser_type = db.Column(db.String(50), nullable=True)
    
    # Event counts from parsing
    events_indexed = db.Column(db.Integer, nullable=False, default=0)
    
    # Error message if parsing failed
    error_message = db.Column(db.Text, nullable=True)
    
    # Timestamps
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime, nullable=True)
    
    # Who uploaded
    uploaded_by = db.Column(db.String(80), nullable=False)
    
    # Relationship for parent/child files
    parent = db.relationship('CaseFile', remote_side=[id], backref='extracted_files', foreign_keys=[parent_id])
    
    # Relationship for duplicate tracking
    duplicate_of = db.relationship('CaseFile', remote_side=[id], foreign_keys=[duplicate_of_id])
    
    def __repr__(self):
        return f'<CaseFile {self.id}: {self.filename}>'
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        review_status = self.derive_review_status(
            filename=self.original_filename or self.filename,
            status=self.status,
            ingestion_status=self.ingestion_status,
            is_archive=self.is_archive,
            retention_state=self.retention_state,
        )
        return {
            'id': self.id,
            'case_uuid': self.case_uuid,
            'parent_id': self.parent_id,
            'duplicate_of_id': self.duplicate_of_id,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'file_path': self.file_path,
            'source_path': self.source_path,
            'file_size': self.file_size,
            'sha256_hash': self.sha256_hash,
            'hostname': self.hostname,
            'file_type': self.file_type,
            'upload_source': self.upload_source,
            'is_archive': self.is_archive,
            'is_extracted': self.is_extracted,
            'extraction_status': self.extraction_status,
            'status': self.status,
            'ingestion_status': self.ingestion_status,
            'retention_state': self.retention_state,
            'parser_type': self.parser_type,
            'events_indexed': self.events_indexed,
            'error_message': self.error_message,
            'review_status': review_status,
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None,
            'processed_at': self.processed_at.isoformat() if self.processed_at else None,
            'uploaded_by': self.uploaded_by
        }
    
    @staticmethod
    def get_stats(case_uuid):
        """Get file statistics for a case"""
        from sqlalchemy import func
        
        # Exclude archives and duplicates from stats - they are containers/duplicates, not files to process
        base_query = CaseFile.query.filter_by(case_uuid=case_uuid, is_archive=False).filter(
            CaseFile.status != FileStatus.DUPLICATE
        )
        
        total = base_query.count()
        
        # Status counts
        done_count = base_query.filter_by(status=FileStatus.DONE).count()
        error_count = base_query.filter_by(status=FileStatus.ERROR).count()
        pending_count = base_query.filter(
            CaseFile.status.in_([FileStatus.NEW, FileStatus.QUEUED, FileStatus.INGESTING])
        ).count()
        
        # Ingestion status counts
        full_count = base_query.filter_by(ingestion_status=IngestionStatus.FULL).count()
        partial_count = base_query.filter_by(ingestion_status=IngestionStatus.PARTIAL).count()
        no_parser_count = base_query.filter_by(ingestion_status=IngestionStatus.NO_PARSER).count()
        parse_error_count = base_query.filter_by(ingestion_status=IngestionStatus.PARSE_ERROR).count()
        ingestion_error_count = base_query.filter_by(ingestion_status=IngestionStatus.ERROR).count()
        
        # Completed = done + error (files that have been processed)
        completed = done_count + error_count
        
        return {
            'total': total,
            'completed': completed,
            'pending': pending_count,
            'fully_indexed': full_count,
            'partially_indexed': partial_count,
            'no_parser': no_parser_count,
            'parse_error': parse_error_count,
            'error': ingestion_error_count
        }

    @classmethod
    def is_expected_sidecar(cls, filename):
        """Return True when a filename is an expected retained-only sidecar."""
        if not filename:
            return False

        normalized = filename.replace('\\', '/').split('/')[-1].lower()
        if normalized in cls.EXPECTED_SIDECAR_FILENAMES:
            return True

        return any(normalized.endswith(ext) for ext in cls.EXPECTED_SIDECAR_EXTENSIONS)

    @classmethod
    def derive_review_status(cls, filename, status, ingestion_status,
                             is_archive=False, retention_state='retained'):
        """Return an analyst-friendly review classification for a file."""
        if is_archive:
            return {'code': 'archived', 'label': 'Archived ZIP', 'tone': 'info'}

        if status == FileStatus.DUPLICATE or retention_state == 'duplicate_retained':
            return {'code': 'duplicate_retained', 'label': 'Duplicate Retained', 'tone': 'muted'}

        if status == FileStatus.NEW:
            return {'code': 'new', 'label': 'New', 'tone': 'info'}
        if status == FileStatus.QUEUED:
            return {'code': 'queued', 'label': 'Queued', 'tone': 'warning'}
        if status == FileStatus.INGESTING:
            return {'code': 'ingesting', 'label': 'Ingesting', 'tone': 'warning'}

        if status == FileStatus.ERROR or ingestion_status in (IngestionStatus.PARSE_ERROR, IngestionStatus.ERROR):
            return {'code': 'failed', 'label': 'Parser Failed', 'tone': 'danger'}

        if ingestion_status == IngestionStatus.FULL:
            return {'code': 'indexed', 'label': 'Indexed', 'tone': 'success'}

        if ingestion_status == IngestionStatus.PARTIAL:
            return {'code': 'partial', 'label': 'Partially Indexed', 'tone': 'warning'}

        if ingestion_status == IngestionStatus.NO_PARSER:
            if cls.is_expected_sidecar(filename):
                return {'code': 'retained_only', 'label': 'Retained Only', 'tone': 'muted'}
            return {'code': 'unsupported', 'label': 'Unsupported', 'tone': 'muted'}

        return {'code': 'unknown', 'label': 'Unknown', 'tone': 'muted'}

    @classmethod
    def get_review_stats(cls, case_uuid):
        """Get analyst-oriented review counts for a case."""
        rows = cls.query.filter_by(case_uuid=case_uuid).with_entities(
            cls.original_filename,
            cls.filename,
            cls.status,
            cls.ingestion_status,
            cls.is_archive,
            cls.retention_state,
        ).all()

        stats = {
            'archived': 0,
            'duplicate_retained': 0,
            'indexed': 0,
            'partial': 0,
            'retained_only': 0,
            'unsupported': 0,
            'failed': 0,
            'pending': 0,
        }

        for row in rows:
            review = cls.derive_review_status(
                filename=row.original_filename or row.filename,
                status=row.status,
                ingestion_status=row.ingestion_status,
                is_archive=row.is_archive,
                retention_state=row.retention_state,
            )
            code = review['code']
            if code in ('new', 'queued', 'ingesting'):
                stats['pending'] += 1
            elif code in stats:
                stats[code] += 1

        return stats
    
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
    def get_by_case(case_uuid, include_duplicates=False):
        """Get all files for a case
        
        Args:
            case_uuid: Case UUID
            include_duplicates: If True, include duplicate files. Default False.
        """
        query = CaseFile.query.filter_by(case_uuid=case_uuid)
        if not include_duplicates:
            query = query.filter(CaseFile.status != FileStatus.DUPLICATE)
        return query.order_by(CaseFile.uploaded_at.desc()).all()
    
    @staticmethod
    def get_parent_files(case_uuid, include_duplicates=False):
        """Get only parent files (not extracted) for a case
        
        Args:
            case_uuid: Case UUID
            include_duplicates: If True, include duplicate files. Default False.
        """
        query = CaseFile.query.filter_by(
            case_uuid=case_uuid,
            is_extracted=False
        )
        if not include_duplicates:
            query = query.filter(CaseFile.status != FileStatus.DUPLICATE)
        return query.order_by(CaseFile.uploaded_at.desc()).all()
    
    @staticmethod
    def find_by_hash(sha256_hash, case_uuid=None):
        """Find existing file by hash, optionally within a specific case"""
        query = CaseFile.query.filter_by(sha256_hash=sha256_hash)
        if case_uuid:
            query = query.filter_by(case_uuid=case_uuid)
        return query.first()
    
    @staticmethod
    def find_duplicates_by_hashes(hash_list, case_uuid=None):
        """Find all existing files matching a list of hashes
        
        Returns dict mapping hash -> CaseFile record
        """
        query = CaseFile.query.filter(CaseFile.sha256_hash.in_(hash_list))
        if case_uuid:
            query = query.filter_by(case_uuid=case_uuid)
        
        results = {}
        for cf in query.all():
            results[cf.sha256_hash] = cf
        return results
    
    @staticmethod
    def find_by_filename(filename, case_uuid=None):
        """Find existing file by filename, optionally within a specific case
        
        Note: Uses original_filename for comparison (without zip prefix)
        """
        query = CaseFile.query.filter_by(original_filename=filename)
        if case_uuid:
            query = query.filter_by(case_uuid=case_uuid)
        return query.first()
    
    @staticmethod
    def check_duplicate_type(filename, sha256_hash, case_uuid):
        """Check if a file is a duplicate and what type
        
        Returns:
            tuple: (duplicate_type, existing_file)
            - ('true', CaseFile) - exact duplicate: same filename AND hash
            - ('hash_only', CaseFile) - same hash, different filename
            - ('name_only', CaseFile) - same filename, different hash (NOT a duplicate for storage)
            - (None, None) - not a duplicate
        """
        # Check for hash match first (more specific)
        hash_match = CaseFile.find_by_hash(sha256_hash, case_uuid=case_uuid)
        
        if hash_match:
            # Hash matches - check if filename also matches
            if hash_match.original_filename == filename:
                return ('true', hash_match)  # True duplicate
            else:
                return ('hash_only', hash_match)  # Same content, different name
        
        # No hash match - check filename only
        name_match = CaseFile.find_by_filename(filename, case_uuid=case_uuid)
        if name_match:
            return ('name_only', name_match)  # Different content, same name
        
        return (None, None)  # New file