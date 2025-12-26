"""
File Hash Utility
Calculate SHA256 hashes for existing files (on-demand)
"""

import os
import hashlib
import logging

logger = logging.getLogger(__name__)


def calculate_file_hash(file_path, chunk_size=8388608):
    """
    Calculate SHA256 hash of a file using streaming (memory-safe)
    
    Args:
        file_path: Path to file
        chunk_size: Chunk size for streaming (default 8MB)
    
    Returns:
        str: SHA256 hash (64 hex characters) or None on error
    """
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return None
    
    try:
        hash_obj = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                hash_obj.update(chunk)
        
        file_hash = hash_obj.hexdigest()
        logger.info(f"Calculated hash for {os.path.basename(file_path)}: {file_hash[:16]}...")
        return file_hash
        
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {e}")
        return None


def backfill_file_hashes(case_id=None, limit=None):
    """
    Calculate hashes for existing files that don't have them
    
    Args:
        case_id: Optional case ID to limit scope
        limit: Optional limit on number of files to process
    
    Returns:
        dict: Statistics about hashing operation
    """
    from main import app, db
    from models import CaseFile
    
    stats = {
        'processed': 0,
        'updated': 0,
        'skipped': 0,
        'errors': 0,
        'error_details': []
    }
    
    with app.app_context():
        # Query files without hashes
        query = CaseFile.query.filter(
            (CaseFile.file_hash == None) | (CaseFile.file_hash == '')
        )
        
        if case_id:
            query = query.filter_by(case_id=case_id)
        
        if limit:
            query = query.limit(limit)
        
        files = query.all()
        
        logger.info(f"Found {len(files)} files without hashes")
        
        for case_file in files:
            stats['processed'] += 1
            
            try:
                if not case_file.file_path or not os.path.exists(case_file.file_path):
                    logger.warning(f"File not found: {case_file.filename}")
                    stats['skipped'] += 1
                    continue
                
                # Calculate hash
                file_hash = calculate_file_hash(case_file.file_path)
                
                if file_hash:
                    case_file.file_hash = file_hash
                    db.session.commit()
                    stats['updated'] += 1
                    logger.info(f"Updated hash for {case_file.filename}")
                else:
                    stats['errors'] += 1
                    stats['error_details'].append(f"Failed to hash: {case_file.filename}")
                    
            except Exception as e:
                stats['errors'] += 1
                error_msg = f"Error processing {case_file.filename}: {e}"
                stats['error_details'].append(error_msg)
                logger.error(error_msg)
                db.session.rollback()
        
        logger.info(f"Hash backfill complete: {stats['updated']} updated, {stats['skipped']} skipped, {stats['errors']} errors")
        
        return stats

