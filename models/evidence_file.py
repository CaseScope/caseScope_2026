"""Evidence File Model

Stores evidence files that are NOT processed/parsed.
Used for screenshots, exports, and other archival items.
"""
from datetime import datetime
from models.database import db


class EvidenceFile(db.Model):
    """Evidence files - archival storage (NOT processed/indexed)"""
    __tablename__ = 'evidence_file'
    
    id = db.Column(db.Integer, primary_key=True)
    case_uuid = db.Column(db.String(36), db.ForeignKey('cases.uuid'), nullable=False, index=True)
    duplicate_of_id = db.Column(db.Integer, db.ForeignKey('evidence_file.id'), index=True)
    filename = db.Column(db.String(500), nullable=False)
    original_filename = db.Column(db.String(500), nullable=False)
    file_path = db.Column(db.String(1000), nullable=False)
    source_path = db.Column(db.String(1000))
    file_size = db.Column(db.BigInteger, default=0)  # bytes
    size_mb = db.Column(db.Integer, default=0)  # MB rounded
    file_hash = db.Column(db.String(64), index=True)  # SHA256
    file_type = db.Column(db.String(50))  # Detected extension (png, jpg, pdf, docx, xlsx, zip, etc.)
    mime_type = db.Column(db.String(100))
    description = db.Column(db.Text)  # User-provided description of evidence
    
    # Upload metadata
    upload_source = db.Column(db.String(20), default='http')  # http, bulk
    retention_state = db.Column(db.String(50), default='retained')
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    case = db.relationship('Case', backref=db.backref('evidence_files', lazy='dynamic'))
    uploader = db.relationship('User', foreign_keys=[uploaded_by], backref='uploaded_evidence')
    duplicate_of = db.relationship('EvidenceFile', remote_side=[id], foreign_keys=[duplicate_of_id])
    
    def __repr__(self):
        return f'<EvidenceFile {self.id}: {self.original_filename}>'
    
    @property
    def size_display(self):
        """Human-readable file size"""
        if self.file_size < 1024:
            return f"{self.file_size} B"
        elif self.file_size < 1024 * 1024:
            return f"{self.file_size / 1024:.1f} KB"
        elif self.file_size < 1024 * 1024 * 1024:
            return f"{self.file_size / (1024 * 1024):.2f} MB"
        else:
            return f"{self.file_size / (1024 * 1024 * 1024):.2f} GB"
    
    @classmethod
    def get_case_stats(cls, case_uuid):
        """Get evidence statistics for a case"""
        from sqlalchemy import func
        
        total_files = cls.query.filter_by(case_uuid=case_uuid).count()
        total_size_raw = db.session.query(func.sum(cls.file_size)).filter_by(case_uuid=case_uuid).scalar() or 0
        total_size = int(total_size_raw)  # Convert Decimal to int for JSON serialization
        
        # File type breakdown
        file_types = db.session.query(
            cls.file_type,
            func.count(cls.id)
        ).filter_by(case_uuid=case_uuid).group_by(cls.file_type).all()
        
        return {
            'total_files': total_files,
            'total_size': total_size,
            'total_size_gb': float(total_size / (1024 * 1024 * 1024)),
            'file_types': {ft or 'UNKNOWN': int(count) for ft, count in file_types}
        }
