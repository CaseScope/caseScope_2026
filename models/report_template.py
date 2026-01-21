"""Report Template Model for CaseScope

Stores metadata for Word document report templates used in AI-powered report generation.
Templates are stored as .docx files in /static/templates/report_templates/
"""
import os
from datetime import datetime
from models.database import db
from config import Config


class ReportTemplate(db.Model):
    """Report template metadata for Word document templates
    
    Templates are .docx files stored on disk. This model tracks:
    - Which templates exist and are available for use
    - Admin-assigned friendly names and descriptions
    - Default template selection
    """
    __tablename__ = 'report_templates'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # The actual filename on disk (e.g., "case_report_template.docx")
    filename = db.Column(db.String(255), unique=True, nullable=False, index=True)
    
    # Admin-assigned friendly name (e.g., "Default Case Report")
    display_name = db.Column(db.String(255), nullable=False)
    
    # Optional description of what this template is for
    description = db.Column(db.Text, nullable=True)
    
    # Whether this template is available for use
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    # Default template - only one can be true at a time
    is_default = db.Column(db.Boolean, default=False, nullable=False)
    
    # Whether the file exists on disk (updated by scanner)
    file_exists = db.Column(db.Boolean, default=True, nullable=False)
    
    # Tracking fields
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.String(80), nullable=True)
    
    def __repr__(self):
        return f'<ReportTemplate {self.filename}: {self.display_name}>'
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'filename': self.filename,
            'display_name': self.display_name,
            'description': self.description,
            'is_active': self.is_active,
            'is_default': self.is_default,
            'file_exists': self.file_exists,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'updated_by': self.updated_by
        }
    
    @staticmethod
    def get_template_folder():
        """Get the path to the report templates folder"""
        return os.path.join(Config.BASE_DIR, 'static', 'templates', 'report_templates')
    
    @staticmethod
    def get_template_path(filename):
        """Get the full path to a template file"""
        return os.path.join(ReportTemplate.get_template_folder(), filename)
    
    @staticmethod
    def get_default_template():
        """Get the default template, or None if none set"""
        return ReportTemplate.query.filter_by(is_default=True, is_active=True, file_exists=True).first()
    
    @staticmethod
    def get_active_templates():
        """Get all active templates that exist on disk"""
        return ReportTemplate.query.filter_by(is_active=True, file_exists=True).order_by(
            ReportTemplate.is_default.desc(),
            ReportTemplate.display_name
        ).all()
    
    @staticmethod
    def set_as_default(template_id):
        """Set a template as the default, unsetting any existing default"""
        # Unset all defaults
        ReportTemplate.query.update({ReportTemplate.is_default: False})
        
        # Set the new default
        template = ReportTemplate.query.get(template_id)
        if template:
            template.is_default = True
            db.session.commit()
            return True
        return False
    
    @staticmethod
    def scan_templates(updated_by=None):
        """Scan the templates folder and sync with database
        
        Returns:
            dict with 'added', 'removed', 'existing' counts
        """
        template_folder = ReportTemplate.get_template_folder()
        
        # Ensure folder exists
        os.makedirs(template_folder, exist_ok=True)
        
        # Get all .docx files in folder
        disk_templates = set()
        if os.path.isdir(template_folder):
            for f in os.listdir(template_folder):
                if f.lower().endswith('.docx') and not f.startswith('~$'):
                    disk_templates.add(f)
        
        # Get all templates from database
        db_templates = {t.filename: t for t in ReportTemplate.query.all()}
        
        added = 0
        existing = 0
        
        # Add new templates found on disk
        for filename in disk_templates:
            if filename not in db_templates:
                # New template - create with filename as display name
                display_name = os.path.splitext(filename)[0].replace('_', ' ').replace('-', ' ').title()
                template = ReportTemplate(
                    filename=filename,
                    display_name=display_name,
                    is_active=True,
                    file_exists=True,
                    updated_by=updated_by
                )
                db.session.add(template)
                added += 1
            else:
                # Existing template - mark as exists
                db_templates[filename].file_exists = True
                existing += 1
        
        # Mark templates not on disk
        removed = 0
        for filename, template in db_templates.items():
            if filename not in disk_templates:
                template.file_exists = False
                removed += 1
        
        db.session.commit()
        
        return {
            'added': added,
            'removed': removed,
            'existing': existing,
            'total_on_disk': len(disk_templates)
        }
