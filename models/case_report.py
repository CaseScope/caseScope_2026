"""Case Report Model for CaseScope

Tracks generated reports for cases with file sync, notes, and audit logging.
Reports are stored as .docx files in /storage/{case_uuid}/reports/
"""
import os
import re
from datetime import datetime
from typing import List, Dict, Optional

from models.database import db
from config import Config


class CaseReport(db.Model):
    """Tracks generated reports for a case
    
    Syncs with filesystem to track report files, allowing notes/annotations
    and providing audit trail for report management.
    """
    __tablename__ = 'case_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Case relationship
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # File information
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(1024), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=True)
    
    # Report type (extracted from filename prefix, e.g., "DFIR_Report" -> "DFIR Report")
    report_type = db.Column(db.String(100), nullable=True)
    
    # User-editable notes/annotations
    notes = db.Column(db.Text, nullable=True)
    
    # Tracking fields
    file_created_at = db.Column(db.DateTime, nullable=True)  # File mtime when first discovered
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.String(80), nullable=True)  # User who generated/discovered it
    
    # Unique constraint: one filename per case
    __table_args__ = (
        db.UniqueConstraint('case_id', 'filename', name='uq_case_report_filename'),
        db.Index('ix_case_report_case_created', 'case_id', 'file_created_at'),
    )
    
    # Relationship
    case = db.relationship('Case', backref=db.backref('reports', lazy='dynamic', cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f'<CaseReport {self.id}: {self.filename}>'
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'case_id': self.case_id,
            'filename': self.filename,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'file_size_human': self._format_size(self.file_size) if self.file_size else None,
            'report_type': self.report_type,
            'notes': self.notes,
            'file_created_at': self.file_created_at.isoformat() if self.file_created_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_by': self.created_by
        }
    
    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format file size in human-readable format"""
        if size_bytes is None:
            return 'Unknown'
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"
    
    @staticmethod
    def extract_report_type(filename: str) -> str:
        """Extract report type from filename
        
        Examples:
            DFIR_Report_20260121_143052.docx -> "DFIR Report"
            CaseReport_2026-01-21_143052.docx -> "Case Report"
            Monthly_Summary_Report_Jan.docx -> "Monthly Summary Report"
        """
        # Remove extension
        name = os.path.splitext(filename)[0]
        
        # Try to find prefix before timestamp pattern (YYYYMMDD or YYYY-MM-DD)
        # Pattern: prefix followed by timestamp
        match = re.match(r'^(.+?)_(\d{8}|\d{4}-\d{2}-\d{2}).*$', name)
        if match:
            prefix = match.group(1)
        else:
            # No timestamp pattern, use the whole name
            prefix = name
        
        # Convert underscores/hyphens to spaces and title case
        report_type = prefix.replace('_', ' ').replace('-', ' ')
        return report_type.title()
    
    @staticmethod
    def get_reports_folder(case_uuid: str) -> str:
        """Get the reports folder path for a case"""
        return os.path.join(Config.STORAGE_FOLDER, case_uuid, 'reports')
    
    @classmethod
    def sync_reports_for_case(cls, case_uuid: str, case_id: int, username: str = None) -> Dict:
        """Sync filesystem reports with database
        
        Scans the reports folder and:
        - Adds new files to database (with audit log)
        - Removes missing files from database (with audit log)
        
        Args:
            case_uuid: The case UUID
            case_id: The case ID (integer)
            username: Username performing the sync (for audit)
            
        Returns:
            Dict with 'added', 'removed', 'existing', 'total' counts
        """
        from models.audit_log import AuditLog, AuditAction, AuditEntityType
        
        reports_folder = cls.get_reports_folder(case_uuid)
        
        # Get files on disk
        disk_files = set()
        if os.path.isdir(reports_folder):
            for f in os.listdir(reports_folder):
                if f.lower().endswith('.docx') and not f.startswith('~$'):
                    disk_files.add(f)
        
        # Get files in database
        db_reports = {r.filename: r for r in cls.query.filter_by(case_id=case_id).all()}
        
        added = 0
        existing = 0
        removed = 0
        
        # Add new files found on disk
        for filename in disk_files:
            if filename not in db_reports:
                filepath = os.path.join(reports_folder, filename)
                try:
                    stat = os.stat(filepath)
                    file_size = stat.st_size
                    file_mtime = datetime.fromtimestamp(stat.st_mtime)
                except OSError:
                    file_size = None
                    file_mtime = None
                
                report = cls(
                    case_id=case_id,
                    filename=filename,
                    file_path=filepath,
                    file_size=file_size,
                    report_type=cls.extract_report_type(filename),
                    file_created_at=file_mtime,
                    created_by=username or 'system'
                )
                db.session.add(report)
                db.session.flush()  # Get the ID
                
                # Audit log for new report
                AuditLog.log(
                    entity_type=AuditEntityType.CASE_REPORT,
                    entity_id=report.id,
                    action=AuditAction.CREATED,
                    entity_name=filename,
                    case_uuid=case_uuid,
                    username=username,
                    details={'file_size': file_size, 'report_type': report.report_type}
                )
                
                added += 1
            else:
                # Update file size if changed
                report = db_reports[filename]
                filepath = os.path.join(reports_folder, filename)
                try:
                    stat = os.stat(filepath)
                    if report.file_size != stat.st_size:
                        report.file_size = stat.st_size
                except OSError:
                    pass
                existing += 1
        
        # Remove files no longer on disk
        for filename, report in db_reports.items():
            if filename not in disk_files:
                # Audit log before deletion
                AuditLog.log(
                    entity_type=AuditEntityType.CASE_REPORT,
                    entity_id=report.id,
                    action=AuditAction.DELETED,
                    entity_name=filename,
                    case_uuid=case_uuid,
                    username=username or 'system',
                    details={'reason': 'file_not_found', 'last_notes': report.notes}
                )
                
                db.session.delete(report)
                removed += 1
        
        db.session.commit()
        
        return {
            'added': added,
            'removed': removed,
            'existing': existing,
            'total': added + existing
        }
    
    @classmethod
    def get_reports_for_case(cls, case_id: int) -> List['CaseReport']:
        """Get all reports for a case, sorted by creation date descending"""
        return cls.query.filter_by(case_id=case_id).order_by(cls.file_created_at.desc()).all()
    
    @classmethod
    def get_by_id(cls, report_id: int) -> Optional['CaseReport']:
        """Get a report by ID"""
        return cls.query.get(report_id)
    
    def update_notes(self, notes: str, username: str = None, case_uuid: str = None) -> None:
        """Update notes with audit logging
        
        Args:
            notes: New notes content
            username: Username making the change
            case_uuid: Case UUID for audit context
        """
        from models.audit_log import AuditLog, AuditAction, AuditEntityType
        
        old_notes = self.notes
        self.notes = notes
        self.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        # Audit log
        AuditLog.log(
            entity_type=AuditEntityType.CASE_REPORT,
            entity_id=self.id,
            action=AuditAction.UPDATED,
            entity_name=self.filename,
            field_name='notes',
            old_value=old_notes,
            new_value=notes,
            case_uuid=case_uuid,
            username=username
        )
    
    def delete_report(self, username: str = None, case_uuid: str = None, delete_file: bool = True) -> bool:
        """Delete report with audit logging
        
        Args:
            username: Username performing deletion
            case_uuid: Case UUID for audit context
            delete_file: Whether to delete the file from disk
            
        Returns:
            True if successful, False otherwise
        """
        from models.audit_log import AuditLog, AuditAction, AuditEntityType
        import shutil
        
        # Try to delete file from disk
        file_deleted = False
        if delete_file and self.file_path and os.path.isfile(self.file_path):
            try:
                os.remove(self.file_path)
                file_deleted = True
            except OSError as e:
                # Log but continue with DB deletion
                pass
        
        # Audit log before deletion
        AuditLog.log(
            entity_type=AuditEntityType.CASE_REPORT,
            entity_id=self.id,
            action=AuditAction.DELETED,
            entity_name=self.filename,
            case_uuid=case_uuid,
            username=username,
            details={
                'file_deleted': file_deleted,
                'file_path': self.file_path,
                'notes': self.notes,
                'report_type': self.report_type
            }
        )
        
        # Delete from database
        db.session.delete(self)
        db.session.commit()
        
        return True
