"""
Prefetch Parser (Phase 3)
==========================
Parses Windows Prefetch files (.pf)
Routes to: case_X_execution index

Extracts:
- Executable name
- Run count
- Last execution times
- File references
"""

import os
import sys
import logging
from datetime import datetime

# Add system dist-packages for pyscca
sys.path.append('/usr/lib/python3/dist-packages')

logger = logging.getLogger(__name__)

try:
    import pyscca
    SCCA_AVAILABLE = True
except ImportError:
    logger.warning("pyscca not available - Prefetch parsing will be skipped")
    SCCA_AVAILABLE = False

# Windows FILETIME epoch
FILETIME_EPOCH = datetime(1601, 1, 1)

def filetime_to_datetime(filetime):
    """Convert Windows FILETIME to Python datetime"""
    try:
        if not filetime or filetime == 0:
            return None
        from datetime import timedelta
        return FILETIME_EPOCH + timedelta(microseconds=filetime / 10)
    except:
        return None


def parse_prefetch_file(file_path):
    """
    Parse Windows Prefetch file (.pf)
    
    Yields execution events from prefetch
    """
    if not SCCA_AVAILABLE:
        logger.error("pyscca not available - cannot parse Prefetch")
        return
    
    if not os.path.exists(file_path):
        logger.error(f"Prefetch file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        # Open prefetch file
        pf_file = pyscca.file()
        pf_file.open(file_path)
        
        # Get executable name
        executable_name = pf_file.executable_filename or filename.replace('.pf', '')
        run_count = pf_file.run_count
        
        logger.info(f"Parsing Prefetch: {executable_name} (run_count={run_count})")
        
        # Get last run times
        last_run_times = []
        for i in range(min(8, pf_file.number_of_last_run_times)):  # Prefetch stores up to 8 times
            try:
                filetime = pf_file.get_last_run_time(i)
                dt = filetime_to_datetime(filetime)
                if dt:
                    last_run_times.append(dt.isoformat())
            except:
                pass
        
        # Get file references (files accessed by executable)
        file_references = []
        try:
            for i in range(min(100, pf_file.number_of_file_metrics)):  # Limit to 100
                try:
                    file_metric = pf_file.get_file_metric(i)
                    file_ref = file_metric.filename
                    if file_ref:
                        file_references.append(file_ref)
                except:
                    pass
        except:
            pass
        
        # Create event for most recent execution
        if last_run_times:
            event = {
                '@timestamp': last_run_times[0],  # Most recent
                'event_type': 'prefetch_execution',
                'executable': executable_name,
                'run_count': run_count,
                'last_run_times': last_run_times,
                'file_references': file_references[:20],  # Limit to 20 for indexing
                'file_reference_count': len(file_references),
                'source_file': filename,
                'artifact_type': 'prefetch'
            }
            yield event
        
        pf_file.close()
    
    except Exception as e:
        logger.error(f"Error parsing Prefetch {file_path}: {e}")
        import traceback
        traceback.print_exc()

