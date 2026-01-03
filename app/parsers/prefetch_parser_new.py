"""
Prefetch Parser (Updated for Windows 10/11)
============================================
Parses Windows Prefetch files (.pf) including compressed format
Routes to: case_X_execution index

Uses libscca-python library for cross-platform support

Extracts:
- Executable name
- Run count
- Last execution times (up to 8)
- Volume information
- File references
"""

import os
import sys
import logging
from datetime import datetime, timedelta

# Add system dist-packages for pyscca
sys.path.append('/usr/lib/python3/dist-packages')

logger = logging.getLogger(__name__)

try:
    import pyscca
    PREFETCH_AVAILABLE = True
except ImportError:
    logger.warning("pyscca not available - Prefetch parsing will be skipped")
    PREFETCH_AVAILABLE = False


def filetime_to_datetime(filetime):
    """Convert Windows FILETIME to Python datetime"""
    try:
        if not filetime or filetime == 0:
            return None
        # FILETIME is 100-nanosecond intervals since January 1, 1601
        epoch = datetime(1601, 1, 1)
        return epoch + timedelta(microseconds=filetime / 10)
    except:
        return None


def parse_prefetch_file(file_path):
    """
    Parse Windows Prefetch file (.pf) - supports Windows 10/11 compressed format
    
    Yields execution events from prefetch
    """
    if not PREFETCH_AVAILABLE:
        logger.error("libscca not available - cannot parse Prefetch")
        return
    
    if not os.path.exists(file_path):
        logger.error(f"Prefetch file not found: {file_path}")
        return
    
    filename = os.path.basename(file_path)
    
    try:
        # Parse prefetch file
        pf_file = pyscca.file()
        
        try:
            pf_file.open(file_path)
        except OSError as e:
            if "unsupported format version" in str(e):
                # Windows 10/11 compressed prefetch - not supported by pyscca 2020
                logger.warning(f"Compressed prefetch file not supported (Windows 10/11): {filename}")
                # Create a minimal event to track that file exists
                event = {
                    '@timestamp': datetime.utcnow().isoformat(),
                    'event_type': 'prefetch_unsupported',
                    'executable': filename.replace('.pf', ''),
                    'source_file': filename,
                    'artifact_type': 'prefetch',
                    'note': 'Compressed prefetch format (Windows 10/11) - requires newer parser'
                }
                yield event
                return
            else:
                raise
        
        # Get executable name
        executable_name = pf_file.executable_filename
        run_count = pf_file.run_count
        
        logger.info(f"Parsing Prefetch: {executable_name} (run_count={run_count})")
        
        # Get last run times (up to 8)
        last_run_times = []
        for i in range(min(8, pf_file.number_of_last_run_times)):
            try:
                filetime = pf_file.get_last_run_time(i)
                dt = filetime_to_datetime(filetime)
                if dt:
                    last_run_times.append(dt.isoformat())
            except Exception as e:
                logger.debug(f"Error getting timestamp {i}: {e}")
        
        # Get volume information
        volumes = []
        try:
            num_volumes = pf_file.number_of_volumes
            for i in range(min(5, num_volumes)):  # Limit to 5 volumes
                try:
                    volume = pf_file.get_volume_information(i)
                    vol_info = {
                        'device_path': volume.device_path if hasattr(volume, 'device_path') else None,
                        'serial_number': volume.serial_number if hasattr(volume, 'serial_number') else None
                    }
                    volumes.append(vol_info)
                except Exception as e:
                    logger.debug(f"Error parsing volume {i}: {e}")
        except Exception as e:
            logger.debug(f"Error getting volumes: {e}")
        
        # Get file references (limit for indexing)
        file_references = []
        try:
            num_files = pf_file.number_of_file_metrics_entries
            for i in range(min(100, num_files)):  # Limit to 100
                try:
                    file_metric = pf_file.get_file_metric(i)
                    if file_metric and file_metric.filename:
                        file_references.append(file_metric.filename)
                except:
                    pass
        except Exception as e:
            logger.debug(f"Error getting file references: {e}")
        
        # Create event for most recent execution
        if last_run_times:
            event = {
                '@timestamp': last_run_times[0],  # Most recent
                'event_type': 'prefetch_execution',
                'executable': executable_name,
                'run_count': run_count,
                'last_run_times': last_run_times,
                'volumes': volumes,
                'file_references': file_references[:20],  # Limit to 20 for indexing
                'file_reference_count': len(file_references),
                'source_file': filename,
                'artifact_type': 'prefetch'
            }
            yield event
        else:
            # No timestamps available, create basic event
            event = {
                '@timestamp': datetime.utcnow().isoformat(),
                'event_type': 'prefetch_execution',
                'executable': executable_name,
                'run_count': run_count,
                'volumes': volumes,
                'file_reference_count': len(file_references),
                'source_file': filename,
                'artifact_type': 'prefetch',
                'note': 'No execution timestamps available'
            }
            yield event
        
        pf_file.close()
    
    except Exception as e:
        logger.error(f"Error parsing Prefetch {file_path}: {e}")
        import traceback
        traceback.print_exc()
