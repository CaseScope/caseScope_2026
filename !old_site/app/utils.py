#!/usr/bin/env python3
"""
CaseScope 2026 v1.0.0 - Utility Functions
"""

import re
import hashlib


def sanitize_filename(filename):
    """
    Sanitize filename for safe filesystem and OpenSearch index usage
    
    Rules:
    - Convert to lowercase
    - Replace spaces with underscores
    - Remove special characters (keep alphanumeric, underscore, hyphen, dot)
    - Strip leading/trailing dots and underscores
    """
    # Convert to lowercase
    name = filename.lower()
    
    # Replace spaces with underscores
    name = name.replace(' ', '_')
    
    # Remove special characters
    name = re.sub(r'[^a-z0-9_\-.]', '', name)
    
    # Remove multiple consecutive underscores
    name = re.sub(r'_+', '_', name)
    
    # Strip leading/trailing dots and underscores
    name = name.strip('._')
    
    return name


def make_index_name(case_id, filename=None):
    """
    Create OpenSearch index name - ONE INDEX PER CASE (not per file)
    
    OLD: case_{case_id}_{filename} → 10,458 indices = 10,458 shards
    NEW: case_{case_id} → 7 indices = 7 shards
    
    This fixes scaling issues:
    - Reduces shard count from 10K+ to <100
    - Reduces heap from 16GB+ to 2-4GB
    - Allows millions of files per case
    - Filter by source_file field instead of index name
    
    Format: case_{case_id}
    Example: case_1, case_2, case_3
    
    Args:
        case_id: Case ID
        filename: IGNORED (kept for backward compatibility)
    """
    return f"case_{case_id}"


def hash_file(file_path, algorithm='sha256'):
    """
    Calculate file hash
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm (default: sha256)
    
    Returns:
        str: Hex digest of file hash
    """
    hasher = hashlib.new(algorithm)
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    
    return hasher.hexdigest()

