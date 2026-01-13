"""FileAuditLog Model for tracking file operations (deletes, etc.)"""
from datetime import datetime
from models.database import db


class FileAction:
    """File action types for audit logging"""
    DELETED_DUPLICATE = 'deleted_duplicate'  # True duplicate (same filename + hash) deleted
    # Future actions can be added here:
    # UPLOADED = 'uploaded'
    # MOVED = 'moved'
    # DELETED_MANUAL = 'deleted_manual'
    
    @classmethod
    def all(cls):
        return [cls.DELETED_DUPLICATE]
    
    @classmethod
    def choices(cls):
        return [
            (cls.DELETED_DUPLICATE, 'Deleted (Duplicate)'),
        ]


class FileAuditLog(db.Model):
    """Audit log for file operations
    
    Tracks file deletions and other significant file actions.
    Designed to be lightweight for high-volume logging.
    """
    __tablename__ = 'file_audit_log'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Case reference
    case_uuid = db.Column(db.String(36), nullable=False, index=True)
    
    # File information at time of action
    filename = db.Column(db.String(512), nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False, index=True)
    file_path = db.Column(db.String(1024), nullable=True)  # Original path before action
    file_size = db.Column(db.BigInteger, nullable=True)
    
    # Action details
    action = db.Column(db.String(50), nullable=False, index=True)
    
    # Who and when
    performed_by = db.Column(db.String(80), nullable=False)
    performed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    # Optional notes (e.g., "duplicate of CaseFile id: 123")
    notes = db.Column(db.Text, nullable=True)
    
    # Composite index for common queries
    __table_args__ = (
        db.Index('ix_file_audit_case_action_time', 'case_uuid', 'action', 'performed_at'),
    )
    
    def __repr__(self):
        return f'<FileAuditLog {self.id}: {self.action} {self.filename}>'
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'case_uuid': self.case_uuid,
            'filename': self.filename,
            'sha256_hash': self.sha256_hash,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'action': self.action,
            'performed_by': self.performed_by,
            'performed_at': self.performed_at.isoformat() if self.performed_at else None,
            'notes': self.notes
        }
    
    @classmethod
    def log_deleted_duplicate(cls, case_uuid: str, filename: str, sha256_hash: str,
                              file_path: str, file_size: int, performed_by: str,
                              original_file_id: int = None):
        """Log a deleted duplicate file
        
        Args:
            case_uuid: Case UUID
            filename: Name of the deleted file
            sha256_hash: Hash of the deleted file
            file_path: Path where file was before deletion
            file_size: Size of the deleted file
            performed_by: Username who triggered the deletion
            original_file_id: ID of the original file this was a duplicate of
        
        Returns:
            FileAuditLog entry
        """
        notes = None
        if original_file_id:
            notes = f"Duplicate of CaseFile id: {original_file_id}"
        
        entry = cls(
            case_uuid=case_uuid,
            filename=filename,
            sha256_hash=sha256_hash,
            file_path=file_path,
            file_size=file_size,
            action=FileAction.DELETED_DUPLICATE,
            performed_by=performed_by,
            notes=notes
        )
        db.session.add(entry)
        return entry
    
    @classmethod
    def get_by_case(cls, case_uuid: str, action: str = None, limit: int = None):
        """Get audit log entries for a case
        
        Args:
            case_uuid: Case UUID
            action: Optional filter by action type
            limit: Optional limit on number of results
        
        Returns:
            List of FileAuditLog entries
        """
        query = cls.query.filter_by(case_uuid=case_uuid)
        if action:
            query = query.filter_by(action=action)
        query = query.order_by(cls.performed_at.desc())
        if limit:
            query = query.limit(limit)
        return query.all()
    
    @classmethod
    def count_by_case(cls, case_uuid: str, action: str = None):
        """Count audit log entries for a case"""
        query = cls.query.filter_by(case_uuid=case_uuid)
        if action:
            query = query.filter_by(action=action)
        return query.count()
