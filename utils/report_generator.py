"""Report Generator Utility for CaseScope

Generates Word documents from templates using docxtpl.
Templates can contain Jinja2-style placeholders that get replaced with case data.

Common placeholders:
    {{ case_name }}
    {{ case_company }}
    {{ report_date }}
    {{ executive_summary }}
    {{ findings }}
    {{ recommendations }}
    {{ analyst_name }}
"""
import os
import shutil
from datetime import datetime
from typing import Dict, Any, Optional

from docxtpl import DocxTemplate

from config import Config
from utils.logger import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """Generates Word document reports from templates"""
    
    def __init__(self, template_path: str):
        """Initialize with a template file path
        
        Args:
            template_path: Full path to the .docx template file
        """
        if not os.path.exists(template_path):
            raise FileNotFoundError(f"Template not found: {template_path}")
        
        self.template_path = template_path
        self.template = DocxTemplate(template_path)
    
    def get_available_placeholders(self) -> list:
        """Get list of placeholder variables in the template
        
        Returns:
            List of variable names found in the template
        """
        try:
            return list(self.template.get_undeclared_template_variables())
        except Exception as e:
            logger.warning(f"Could not extract placeholders: {e}")
            return []
    
    def generate(self, context: Dict[str, Any], output_path: str) -> str:
        """Generate a report with the given context
        
        Args:
            context: Dictionary of placeholder values
            output_path: Full path for the output file
            
        Returns:
            Path to the generated file
        """
        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        os.makedirs(output_dir, exist_ok=True)
        
        # Set permissions on directory
        try:
            shutil.chown(output_dir, user='casescope', group='casescope')
        except (PermissionError, LookupError):
            pass
        
        # Render and save
        self.template.render(context)
        self.template.save(output_path)
        
        # Set permissions on file
        try:
            shutil.chown(output_path, user='casescope', group='casescope')
        except (PermissionError, LookupError):
            pass
        
        logger.info(f"Generated report: {output_path}")
        return output_path


def get_case_reports_folder(case_uuid: str) -> str:
    """Get the reports folder path for a case
    
    Args:
        case_uuid: The case UUID
        
    Returns:
        Path to /storage/{case_uuid}/reports/
    """
    return os.path.join(Config.STORAGE_FOLDER, case_uuid, 'reports')


def ensure_reports_folder(case_uuid: str) -> str:
    """Ensure the reports folder exists for a case
    
    Args:
        case_uuid: The case UUID
        
    Returns:
        Path to the created/existing folder
    """
    folder = get_case_reports_folder(case_uuid)
    os.makedirs(folder, exist_ok=True)
    
    try:
        shutil.chown(folder, user='casescope', group='casescope')
    except (PermissionError, LookupError):
        pass
    
    return folder


def generate_report_filename(prefix: str = "CaseReport") -> str:
    """Generate a unique report filename with timestamp
    
    Args:
        prefix: Filename prefix
        
    Returns:
        Filename like "CaseReport_2026-01-21_143052.docx"
    """
    timestamp = datetime.now().strftime('%Y-%m-%d_%H%M%S')
    return f"{prefix}_{timestamp}.docx"


def generate_case_report(
    case_uuid: str,
    template_id: int,
    context: Dict[str, Any],
    filename_prefix: str = "CaseReport"
) -> Optional[str]:
    """Generate a report for a case using a template
    
    Args:
        case_uuid: The case UUID
        template_id: ID of the ReportTemplate to use
        context: Dictionary of placeholder values
        filename_prefix: Prefix for the output filename
        
    Returns:
        Path to the generated report, or None on error
    """
    from models.report_template import ReportTemplate
    
    # Get the template
    template = ReportTemplate.query.get(template_id)
    if not template:
        logger.error(f"Template not found: {template_id}")
        return None
    
    if not template.file_exists:
        logger.error(f"Template file missing on disk: {template.filename}")
        return None
    
    template_path = ReportTemplate.get_template_path(template.filename)
    
    try:
        # Create generator
        generator = ReportGenerator(template_path)
        
        # Ensure output folder exists
        reports_folder = ensure_reports_folder(case_uuid)
        
        # Generate output filename
        output_filename = generate_report_filename(filename_prefix)
        output_path = os.path.join(reports_folder, output_filename)
        
        # Generate the report
        return generator.generate(context, output_path)
        
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        return None


def get_base_case_context(case) -> Dict[str, Any]:
    """Get base context dictionary with case information
    
    Args:
        case: Case model instance
        
    Returns:
        Dictionary with common case placeholders
    """
    from flask_login import current_user
    
    return {
        'case_name': case.name,
        'case_company': case.client.name if case.client else case.company,
        'case_description': case.description or '',
        'case_status': case.status,
        'case_timezone': case.timezone,
        'case_created_by': case.created_by,
        'case_created_at': case.created_at.strftime('%Y-%m-%d %H:%M') if case.created_at else '',
        'case_assigned_to': case.assigned_to or '',
        'report_date': datetime.now().strftime('%Y-%m-%d'),
        'report_datetime': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'analyst_name': current_user.full_name if current_user and current_user.is_authenticated else '',
        'analyst_username': current_user.username if current_user and current_user.is_authenticated else '',
    }


def list_case_reports(case_uuid: str) -> list:
    """List all generated reports for a case
    
    Args:
        case_uuid: The case UUID
        
    Returns:
        List of dicts with report info (filename, path, size, created_at)
    """
    reports_folder = get_case_reports_folder(case_uuid)
    
    if not os.path.isdir(reports_folder):
        return []
    
    reports = []
    for filename in os.listdir(reports_folder):
        if filename.lower().endswith('.docx') and not filename.startswith('~$'):
            filepath = os.path.join(reports_folder, filename)
            stat = os.stat(filepath)
            reports.append({
                'filename': filename,
                'path': filepath,
                'size': stat.st_size,
                'size_human': _format_size(stat.st_size),
                'created_at': datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
    
    # Sort by created_at descending (newest first)
    reports.sort(key=lambda x: x['created_at'], reverse=True)
    return reports


def _format_size(size_bytes: int) -> str:
    """Format file size in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"
