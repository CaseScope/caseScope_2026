"""Archive Job Model for CaseScope

Tracks case archive and restore operations with progress monitoring.
"""
import enum
from datetime import datetime
from models.database import db


class ArchiveJobType(enum.Enum):
    """Type of archive operation"""
    ARCHIVE = 'archive'
    RESTORE = 'restore'


class ArchiveJobStatus(enum.Enum):
    """Job processing status"""
    PENDING = 'pending'
    RUNNING = 'running'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'


class ArchiveStage(enum.Enum):
    """Archive operation stages"""
    VALIDATING = 'validating'
    COMPRESSING_STORAGE = 'compressing_storage'
    COMPRESSING_EVIDENCE = 'compressing_evidence'
    CREATING_MANIFEST = 'creating_manifest'
    VERIFYING = 'verifying'
    CLEANUP = 'cleanup'
    COMPLETE = 'complete'
    
    # Restore stages
    EXTRACTING_STORAGE = 'extracting_storage'
    EXTRACTING_EVIDENCE = 'extracting_evidence'
    VERIFYING_EXTRACTION = 'verifying_extraction'
    DELETING_ARCHIVE = 'deleting_archive'


# Stage descriptions for UI
STAGE_DESCRIPTIONS = {
    ArchiveStage.VALIDATING.value: 'Validating archive path',
    ArchiveStage.COMPRESSING_STORAGE.value: 'Compressing storage files',
    ArchiveStage.COMPRESSING_EVIDENCE.value: 'Compressing evidence files',
    ArchiveStage.CREATING_MANIFEST.value: 'Creating manifest',
    ArchiveStage.VERIFYING.value: 'Verifying archive integrity',
    ArchiveStage.CLEANUP.value: 'Cleaning up original files',
    ArchiveStage.COMPLETE.value: 'Complete',
    ArchiveStage.EXTRACTING_STORAGE.value: 'Extracting storage files',
    ArchiveStage.EXTRACTING_EVIDENCE.value: 'Extracting evidence files',
    ArchiveStage.VERIFYING_EXTRACTION.value: 'Verifying extraction',
    ArchiveStage.DELETING_ARCHIVE.value: 'Deleting archive',
}

# Archive stages in order
ARCHIVE_STAGES = [
    ArchiveStage.VALIDATING.value,
    ArchiveStage.COMPRESSING_STORAGE.value,
    ArchiveStage.COMPRESSING_EVIDENCE.value,
    ArchiveStage.CREATING_MANIFEST.value,
    ArchiveStage.VERIFYING.value,
    ArchiveStage.CLEANUP.value,
    ArchiveStage.COMPLETE.value,
]

# Restore stages in order
RESTORE_STAGES = [
    ArchiveStage.VALIDATING.value,
    ArchiveStage.EXTRACTING_STORAGE.value,
    ArchiveStage.EXTRACTING_EVIDENCE.value,
    ArchiveStage.VERIFYING_EXTRACTION.value,
    ArchiveStage.DELETING_ARCHIVE.value,  # Optional
    ArchiveStage.CLEANUP.value,
    ArchiveStage.COMPLETE.value,
]


class ArchiveJob(db.Model):
    """Track case archive and restore operations"""
    __tablename__ = 'archive_jobs'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False)
    case_uuid = db.Column(db.String(36), nullable=False, index=True)
    
    # Job type and status
    job_type = db.Column(db.String(20), nullable=False)  # archive, restore
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed, cancelled
    
    # Progress tracking
    current_stage = db.Column(db.String(50))
    stage_number = db.Column(db.Integer, default=0)
    total_stages = db.Column(db.Integer, default=6)
    
    # File progress within current stage
    current_file_count = db.Column(db.Integer, default=0)
    total_file_count = db.Column(db.Integer, default=0)
    current_file_name = db.Column(db.String(255))
    
    # Size tracking
    storage_size_bytes = db.Column(db.BigInteger, default=0)
    evidence_size_bytes = db.Column(db.BigInteger, default=0)
    compressed_size_bytes = db.Column(db.BigInteger, default=0)
    
    # File counts
    storage_file_count = db.Column(db.Integer, default=0)
    evidence_file_count = db.Column(db.Integer, default=0)
    
    # Archive paths
    archive_path = db.Column(db.String(500))  # Base archive path from settings
    archive_folder = db.Column(db.String(500))  # Full path: {archive_path}/{case_uuid}/
    
    # Restore options
    delete_archive_after_restore = db.Column(db.Boolean, default=False)
    
    # Status before archive (for manifest)
    original_status = db.Column(db.String(50))
    
    # Error handling
    error_message = db.Column(db.Text)
    error_stage = db.Column(db.String(50))
    
    # Tracking
    created_by = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    # Celery task ID for tracking
    celery_task_id = db.Column(db.String(100))
    
    # Relationships
    case = db.relationship('Case', backref=db.backref('archive_jobs', lazy='dynamic'))
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        stages = ARCHIVE_STAGES if self.job_type == 'archive' else RESTORE_STAGES
        
        return {
            'id': self.id,
            'case_id': self.case_id,
            'case_uuid': self.case_uuid,
            'job_type': self.job_type,
            'status': self.status,
            'current_stage': self.current_stage,
            'stage_description': STAGE_DESCRIPTIONS.get(self.current_stage, self.current_stage),
            'stage_number': self.stage_number,
            'total_stages': self.total_stages,
            'stages': stages,
            'current_file_count': self.current_file_count,
            'total_file_count': self.total_file_count,
            'current_file_name': self.current_file_name,
            'storage_size_bytes': self.storage_size_bytes,
            'evidence_size_bytes': self.evidence_size_bytes,
            'compressed_size_bytes': self.compressed_size_bytes,
            'storage_file_count': self.storage_file_count,
            'evidence_file_count': self.evidence_file_count,
            'archive_path': self.archive_path,
            'archive_folder': self.archive_folder,
            'delete_archive_after_restore': self.delete_archive_after_restore,
            'original_status': self.original_status,
            'error_message': self.error_message,
            'error_stage': self.error_stage,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'celery_task_id': self.celery_task_id,
        }
    
    def get_progress_percent(self):
        """Calculate overall progress percentage"""
        if self.status == 'completed':
            return 100
        if self.status == 'pending':
            return 0
        
        # Stage-based progress
        stages = ARCHIVE_STAGES if self.job_type == 'archive' else RESTORE_STAGES
        if self.current_stage not in stages:
            return 0
        
        stage_index = stages.index(self.current_stage)
        stage_progress = (stage_index / len(stages)) * 100
        
        # Add file progress within stage
        if self.total_file_count > 0:
            file_progress = (self.current_file_count / self.total_file_count) * (100 / len(stages))
            return int(stage_progress + file_progress)
        
        return int(stage_progress)
    
    def update_stage(self, stage, file_count=0, total_files=0):
        """Update current stage and file counts"""
        stages = ARCHIVE_STAGES if self.job_type == 'archive' else RESTORE_STAGES
        
        self.current_stage = stage
        self.stage_number = stages.index(stage) + 1 if stage in stages else 0
        self.current_file_count = file_count
        self.total_file_count = total_files
        self.current_file_name = None
    
    def update_file_progress(self, current, total, filename=None):
        """Update file progress within current stage"""
        self.current_file_count = current
        self.total_file_count = total
        if filename:
            self.current_file_name = filename[:255]  # Truncate if needed
    
    def mark_failed(self, error_message, stage=None):
        """Mark job as failed with error details"""
        self.status = ArchiveJobStatus.FAILED.value
        self.error_message = error_message
        self.error_stage = stage or self.current_stage
        self.completed_at = datetime.utcnow()
    
    def mark_completed(self):
        """Mark job as completed"""
        self.status = ArchiveJobStatus.COMPLETED.value
        self.current_stage = ArchiveStage.COMPLETE.value
        self.completed_at = datetime.utcnow()
