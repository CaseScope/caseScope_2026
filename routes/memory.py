"""Memory Forensics API routes for CaseScope"""
import os
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from datetime import datetime

from models.database import db
from models.case import Case
from config import Config

memory_bp = Blueprint('memory', __name__, url_prefix='/api/memory')


def ensure_memory_dir(case_uuid):
    """Ensure the memory upload directory exists for a case
    
    Uses the same folder structure as file uploads: /opt/casescope/uploads/sftp/{case_uuid}/memory/
    """
    case_memory_path = os.path.join(Config.UPLOAD_FOLDER_SFTP, case_uuid, 'memory')
    os.makedirs(case_memory_path, exist_ok=True)
    return case_memory_path


@memory_bp.route('/folder/<case_uuid>', methods=['GET'])
@login_required
def get_memory_folder(case_uuid):
    """Get the memory upload folder path for a case"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        folder_path = ensure_memory_dir(case_uuid)
        
        return jsonify({
            'success': True,
            'folder_path': folder_path
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/scan/<case_uuid>', methods=['GET'])
@login_required
def scan_memory_folder(case_uuid):
    """Scan the memory upload folder for files"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        folder_path = ensure_memory_dir(case_uuid)
        
        files = []
        if os.path.exists(folder_path):
            for root, dirs, filenames in os.walk(folder_path):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    try:
                        stat = os.stat(filepath)
                        # Get relative path from the case folder
                        rel_path = os.path.relpath(filepath, folder_path)
                        
                        files.append({
                            'name': filename,
                            'path': filepath,
                            'relative_path': rel_path,
                            'size': stat.st_size,
                            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'type': detect_memory_type(filename)
                        })
                    except (OSError, IOError) as e:
                        # Skip files we can't access
                        continue
        
        # Sort by name
        files.sort(key=lambda x: x['name'].lower())
        
        return jsonify({
            'success': True,
            'files': files,
            'folder_path': folder_path,
            'total_count': len(files)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/clear/<case_uuid>', methods=['POST'])
@login_required
def clear_memory_folder(case_uuid):
    """Clear all files from the memory upload folder"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        folder_path = ensure_memory_dir(case_uuid)
        
        deleted_count = 0
        errors = []
        
        if os.path.exists(folder_path):
            for root, dirs, filenames in os.walk(folder_path, topdown=False):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    try:
                        os.remove(filepath)
                        deleted_count += 1
                    except Exception as e:
                        errors.append(f"{filename}: {str(e)}")
                
                # Remove empty directories (but not the case root)
                for dirname in dirs:
                    dirpath = os.path.join(root, dirname)
                    try:
                        os.rmdir(dirpath)
                    except:
                        pass  # Directory not empty or can't be removed
        
        return jsonify({
            'success': True,
            'deleted_count': deleted_count,
            'errors': errors
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


def detect_memory_type(filename):
    """Detect the type of memory dump from filename"""
    filename_lower = filename.lower()
    
    # Memory dump types
    if filename_lower.endswith('.dmp') or filename_lower.endswith('.dump'):
        if 'mini' in filename_lower:
            return 'Minidump'
        elif 'kernel' in filename_lower:
            return 'Kernel Dump'
        elif 'complete' in filename_lower or 'full' in filename_lower:
            return 'Complete Dump'
        return 'Memory Dump'
    
    if filename_lower.endswith('.raw') or filename_lower.endswith('.mem'):
        return 'Raw Memory'
    
    if filename_lower.endswith('.vmem'):
        return 'VMware Memory'
    
    if filename_lower.endswith('.lime'):
        return 'LiME Dump'
    
    if filename_lower.endswith('.elf') or filename_lower.endswith('.core'):
        return 'ELF Core Dump'
    
    if 'hiberfil' in filename_lower:
        return 'Hibernation File'
    
    if 'pagefile' in filename_lower:
        return 'Page File'
    
    if 'swapfile' in filename_lower:
        return 'Swap File'
    
    if filename_lower.endswith('.e01') or filename_lower.endswith('.ex01'):
        return 'EnCase Image'
    
    if filename_lower.endswith('.aff') or filename_lower.endswith('.aff4'):
        return 'AFF Image'
    
    # Common related files
    if filename_lower.endswith('.json'):
        return 'JSON Data'
    
    if filename_lower.endswith('.txt') or filename_lower.endswith('.log'):
        return 'Log/Text'
    
    if filename_lower.endswith('.csv'):
        return 'CSV Data'
    
    if filename_lower.endswith('.zip') or filename_lower.endswith('.gz') or filename_lower.endswith('.7z'):
        return 'Archive'
    
    return 'Unknown'
