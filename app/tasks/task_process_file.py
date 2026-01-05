"""
Individual File Processing Task
================================
Processes a single file in parallel with other workers

This task is queued for each file after ZIP extraction,
allowing all 8 workers to process files simultaneously
"""

import os
import sys
import logging
from datetime import datetime

# Add app directory to path
app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

logger = logging.getLogger(__name__)

from celery_app import celery


@celery.task(name='tasks.process_individual_file', bind=True, queue='ingestion')
def process_individual_file(self, case_id, file_id, file_path):
    """
    Process a single file: parse, index, move to storage
    
    Args:
        case_id: Case ID
        file_id: CaseFile record ID  
        file_path: Path to file in staging
    
    Returns:
        dict: Processing results
    """
    from main import app, db
    from models import CaseFile
    from opensearch_indexer import OpenSearchIndexer
    from config import Config
    from utils.event_normalization import normalize_event_computer
    import gzip
    import shutil
    
    # Import all parsers
    try:
        from parsers.eztools_lnk_parser import parse_lnk_file as parse_lnk_eztools, LECMD_AVAILABLE
        parse_lnk_file = parse_lnk_eztools if LECMD_AVAILABLE else None
    except:
        LECMD_AVAILABLE = False
        parse_lnk_file = None
    
    try:
        from parsers.eztools_evtx_parser import parse_evtx_file as parse_evtx_eztools, EVTXECMD_AVAILABLE
        parse_evtx_eztools_fn = parse_evtx_eztools if EVTXECMD_AVAILABLE else None
    except:
        EVTXECMD_AVAILABLE = False
        parse_evtx_eztools_fn = None
    
    from parsers.evtx_parser import parse_evtx_file as parse_evtx_python, EVTX_AVAILABLE
    from parsers.ndjson_parser import parse_ndjson_file
    from parsers.firewall_csv_parser import parse_firewall_csv
    from parsers.prefetch_parser_dissect import parse_prefetch_file as parse_prefetch_dissect, DISSECT_AVAILABLE as PREFETCH_AVAILABLE
    from parsers.eztools_jumplist_parser import parse_jumplist_file, JLECMD_AVAILABLE
    from parsers.eztools_mft_parser import parse_mft_file as parse_mft_eztools, MFTECMD_AVAILABLE
    from parsers.browser_history_parser import parse_browser_history_file
    from parsers.webcache_parser import parse_webcache_file, ESE_AVAILABLE
    from parsers.srum_parser import parse_srum_file
    
    with app.app_context():
        try:
            # Get file record
            file_record = CaseFile.query.get(file_id)
            if not file_record:
                logger.error(f"File record {file_id} not found")
                return {'success': False, 'error': 'File record not found'}
            
            filename = os.path.basename(file_path)
            file_ext = os.path.splitext(filename)[1].lower()
            
            # Update task state with current file
            self.update_state(
                state='PROCESSING',
                meta={
                    'file_id': file_id,
                    'filename': filename,
                    'status': 'parsing'
                }
            )
            
            logger.info(f"[Worker {self.request.id[:8]}] Processing {filename}")
            
            indexer = OpenSearchIndexer()
            index_name = f'case_{case_id}'
            
            event_count = 0
            parse_success = False
            source_system = None
            
            # Parse based on file type (same logic as before, extracted from task_ingest_files.py)
            # EVTX
            if file_ext == '.evtx':
                if EVTXECMD_AVAILABLE and parse_evtx_eztools_fn:
                    logger.info(f"Using EvtxECmd for {filename}")
                    events = list(parse_evtx_eztools_fn(file_path))
                elif EVTX_AVAILABLE:
                    logger.info(f"Using Python EVTX parser for {filename}")
                    events = list(parse_evtx_python(file_path))
                else:
                    raise ImportError("No EVTX parser available")
                
                if events:
                    source_system = normalize_event_computer(events[0])
                
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(
                        index_name=index_name,
                        events=iter(chunk),
                        chunk_size=chunk_size,
                        case_id=case_id,
                        source_file=filename
                    )
                
                event_count = len(events)
                parse_success = True
            
            # NDJSON
            elif file_ext in ['.json', '.ndjson', '.jsonl']:
                events = list(parse_ndjson_file(file_path))
                if events:
                    source_system = normalize_event_computer(events[0])
                
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(
                        index_name=index_name,
                        events=iter(chunk),
                        chunk_size=chunk_size,
                        case_id=case_id,
                        source_file=filename
                    )
                
                event_count = len(events)
                parse_success = True
            
            # CSV
            elif file_ext == '.csv':
                events = list(parse_firewall_csv(file_path))
                if events:
                    source_system = normalize_event_computer(events[0])
                
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(
                        index_name=index_name,
                        events=iter(chunk),
                        chunk_size=chunk_size,
                        case_id=case_id,
                        source_file=filename
                    )
                
                event_count = len(events)
                parse_success = True
            
            # Prefetch (dissect for Win10/11)
            elif file_ext == '.pf':
                if not PREFETCH_AVAILABLE:
                    raise ImportError("dissect.util not available")
                
                logger.info(f"Using dissect for {filename}")
                events = list(parse_prefetch_dissect(file_path))
                if events:
                    source_system = events[0].get('machine_id') or normalize_event_computer(events[0])
                
                execution_index = f'case_{case_id}_execution'
                chunk_size = 100
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(
                        index_name=execution_index,
                        events=iter(chunk),
                        chunk_size=chunk_size,
                        case_id=case_id,
                        source_file=filename
                    )
                
                event_count = len(events)
                parse_success = True
            
            # LNK (LECmd)
            elif file_ext == '.lnk':
                if LECMD_AVAILABLE and parse_lnk_file:
                    logger.info(f"Using LECmd for {filename}")
                    events = list(parse_lnk_file(file_path))
                else:
                    from parsers.lnk_parser import parse_lnk_file as parse_lnk_python
                    logger.info(f"Using Python LNK parser for {filename}")
                    events = list(parse_lnk_python(file_path))
                
                if events:
                    source_system = events[0].get('machine_id') or normalize_event_computer(events[0])
                
                execution_index = f'case_{case_id}_execution'
                chunk_size = 100
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(
                        index_name=execution_index,
                        events=iter(chunk),
                        chunk_size=chunk_size,
                        case_id=case_id,
                        source_file=filename
                    )
                
                event_count = len(events)
                parse_success = True
            
            # JumpLists
            elif filename.lower().endswith('destinations-ms'):
                if not JLECMD_AVAILABLE:
                    logger.warning(f"JLECmd not available for {filename}")
                    raise ImportError("JLECmd not available")
                
                logger.info(f"Using JLECmd for {filename}")
                events = list(parse_jumplist_file(file_path))
                if events:
                    source_system = events[0].get('machine_id') or normalize_event_computer(events[0])
                
                execution_index = f'case_{case_id}_execution'
                chunk_size = 100
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(
                        index_name=execution_index,
                        events=iter(chunk),
                        chunk_size=chunk_size,
                        case_id=case_id,
                        source_file=filename
                    )
                
                event_count = len(events)
                parse_success = True
            
            # MFT
            elif filename in ['$MFT', '$MFT.gz'] or filename.startswith('$MFT'):
                if not MFTECMD_AVAILABLE:
                    logger.warning(f"MFTECmd not available for {filename}")
                    raise ImportError("MFTECmd not available")
                
                logger.info(f"Using MFTECmd for {filename}")
                events = list(parse_mft_eztools(file_path))
                
                # Extract hostname from first event (if available)
                if events:
                    source_system = events[0].get('computer') or normalize_event_computer(events[0])
                    if source_system:
                        logger.info(f"MFT hostname: {source_system}")
                
                filesystem_index = f'case_{case_id}_filesystem'
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(
                        index_name=filesystem_index,
                        events=iter(chunk),
                        chunk_size=chunk_size,
                        case_id=case_id,
                        source_file=filename
                    )
                    if i % 50000 == 0 and i > 0:
                        logger.info(f"MFT progress: {i}/{len(events)}")
                
                event_count = len(events)
                parse_success = True
            
            # Browser History
            elif 'history' in filename.lower() or 'places.sqlite' in filename.lower():
                events = list(parse_browser_history_file(file_path))
                if events:
                    source_system = normalize_event_computer(events[0])
                
                browser_index = f'case_{case_id}_browser'
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(
                        index_name=browser_index,
                        events=iter(chunk),
                        chunk_size=chunk_size,
                        case_id=case_id,
                        source_file=filename
                    )
                
                event_count = len(events)
                parse_success = True
            
            # WebCache
            elif 'webcache' in filename.lower() and file_ext in ['.dat', '.edb']:
                if not ESE_AVAILABLE:
                    raise ImportError("pyesedb not available")
                
                events = list(parse_webcache_file(file_path))
                if events:
                    source_system = normalize_event_computer(events[0])
                
                browser_index = f'case_{case_id}_browser'
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(
                        index_name=browser_index,
                        events=iter(chunk),
                        chunk_size=chunk_size,
                        case_id=case_id,
                        source_file=filename
                    )
                
                event_count = len(events)
                parse_success = True
            
            # SRUM
            elif 'srudb' in filename.lower() and file_ext == '.dat':
                if not ESE_AVAILABLE:
                    raise ImportError("pyesedb not available")
                
                events = list(parse_srum_file(file_path))
                if events:
                    source_system = normalize_event_computer(events[0])
                
                network_index = f'case_{case_id}_network'
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(
                        index_name=network_index,
                        events=iter(chunk),
                        chunk_size=chunk_size,
                        case_id=case_id,
                        source_file=filename
                    )
                
                event_count = len(events)
                parse_success = True
            
            # Thumbcache (Windows thumbnail cache)
            elif 'thumbcache' in filename.lower() and file_ext == '.db':
                from parsers.thumbcache_parser import parse_thumbcache_file
                logger.info(f"Parsing thumbcache: {filename}")
                events = list(parse_thumbcache_file(file_path))
                if events:
                    source_system = normalize_event_computer(events[0])
                
                filesystem_index = f'case_{case_id}_filesystem'
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(filesystem_index, iter(chunk), chunk_size, case_id, filename)
                
                event_count = len(events)
                parse_success = True
            
            # BITS (Background Intelligent Transfer Service)
            elif filename.lower() in ['qmgr.db', 'qmgr0.dat', 'qmgr1.dat']:
                from parsers.bits_parser import parse_bits_file
                logger.info(f"Parsing BITS database: {filename}")
                events = list(parse_bits_file(file_path))
                if events:
                    source_system = normalize_event_computer(events[0])
                
                network_index = f'case_{case_id}_network'
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(network_index, iter(chunk), chunk_size, case_id, filename)
                
                event_count = len(events)
                parse_success = True
            
            # Windows Search (Windows.edb)
            elif filename.lower() == 'windows.edb':
                from parsers.winsearch_parser import parse_windows_search_file
                logger.info(f"Parsing Windows Search: {filename}")
                events = list(parse_windows_search_file(file_path))
                if events:
                    source_system = normalize_event_computer(events[0])
                
                filesystem_index = f'case_{case_id}_filesystem'
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(filesystem_index, iter(chunk), chunk_size, case_id, filename)
                
                event_count = len(events)
                parse_success = True
            
            # Activities Cache (Windows Timeline)
            elif 'activitiescache' in filename.lower() and file_ext == '.db':
                from parsers.activities_parser import parse_activities_cache_file
                logger.info(f"Parsing Activities Cache: {filename}")
                events = list(parse_activities_cache_file(file_path))
                if events:
                    source_system = normalize_event_computer(events[0])
                
                execution_index = f'case_{case_id}_execution'
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(execution_index, iter(chunk), chunk_size, case_id, filename)
                
                event_count = len(events)
                parse_success = True
            
            # Windows Notifications
            elif 'wpndatabase' in filename.lower() and file_ext == '.db':
                from parsers.notifications_parser import parse_notifications_file
                logger.info(f"Parsing Notifications: {filename}")
                events = list(parse_notifications_file(file_path))
                if events:
                    source_system = normalize_event_computer(events[0])
                
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(index_name, iter(chunk), chunk_size, case_id, filename)
                
                event_count = len(events)
                parse_success = True
            
            # RDP Cache
            elif (filename.lower().startswith('cache') and file_ext == '.bin') or file_ext == '.bmc':
                from parsers.rdp_cache_parser import parse_rdp_cache_file
                logger.info(f"Parsing RDP Cache: {filename}")
                events = list(parse_rdp_cache_file(file_path))
                if events:
                    source_system = normalize_event_computer(events[0])
                
                filesystem_index = f'case_{case_id}_filesystem'
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(filesystem_index, iter(chunk), chunk_size, case_id, filename)
                
                event_count = len(events)
                parse_success = True
            
            # WMI Persistence
            elif filename.lower() in ['objects.data', 'index.btr']:
                from parsers.wmi_parser import parse_wmi_file
                logger.info(f"Parsing WMI: {filename}")
                events = list(parse_wmi_file(file_path))
                if events:
                    source_system = normalize_event_computer(events[0])
                
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(index_name, iter(chunk), chunk_size, case_id, filename)
                
                event_count = len(events)
                parse_success = True
            
            # PST/OST Email
            elif file_ext in ['.pst', '.ost']:
                from parsers.pst_parser import parse_pst_file
                logger.info(f"Parsing PST/OST: {filename}")
                events = list(parse_pst_file(file_path))
                if events:
                    source_system = normalize_event_computer(events[0])
                
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(index_name, iter(chunk), chunk_size, case_id, filename)
                
                event_count = len(events)
                parse_success = True
            
            # Scheduled Tasks
            elif 'tasks' in file_path.lower() and (file_ext == '.xml' or not file_ext):
                from parsers.schtasks_parser import parse_scheduled_task_file
                logger.info(f"Parsing Scheduled Task: {filename}")
                events = list(parse_scheduled_task_file(file_path))
                if events:
                    source_system = normalize_event_computer(events[0])
                
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(index_name, iter(chunk), chunk_size, case_id, filename)
                
                event_count = len(events)
                parse_success = True
            
            # Teams/Skype
            elif ('skype' in file_path.lower() or 'teams' in file_path.lower()) and filename.lower() == 'main.db':
                from parsers.teams_skype_parser import parse_teams_skype_file
                logger.info(f"Parsing Teams/Skype: {filename}")
                events = list(parse_teams_skype_file(file_path))
                if events:
                    source_system = normalize_event_computer(events[0])
                
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(index_name, iter(chunk), chunk_size, case_id, filename)
                
                event_count = len(events)
                parse_success = True
            
            # USB History
            elif 'setupapi' in filename.lower() and 'log' in filename.lower():
                from parsers.usb_history_parser import parse_usb_file
                logger.info(f"Parsing USB History: {filename}")
                events = list(parse_usb_file(file_path))
                if events:
                    source_system = normalize_event_computer(events[0])
                
                devices_index = f'case_{case_id}_devices'
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(devices_index, iter(chunk), chunk_size, case_id, filename)
                
                event_count = len(events)
                parse_success = True
            
            # OneDrive
            elif 'onedrive' in file_path.lower() or filename.lower().endswith(('.odl', '.odlgz')):
                from parsers.onedrive_parser import parse_onedrive_file
                logger.info(f"Parsing OneDrive: {filename}")
                events = list(parse_onedrive_file(file_path))
                if events:
                    source_system = normalize_event_computer(events[0])
                
                cloud_index = f'case_{case_id}_cloud'
                chunk_size = 500
                for i in range(0, len(events), chunk_size):
                    chunk = events[i:i + chunk_size]
                    indexer.bulk_index(cloud_index, iter(chunk), chunk_size, case_id, filename)
                
                event_count = len(events)
                parse_success = True
            
            else:
                # Unsupported file type
                logger.warning(f"No parser for {filename} (ext: {file_ext})")
                file_record.status = 'ParseFail'
                file_record.error_message = f'Unsupported file type: {file_ext}'
                db.session.commit()
                return {'success': False, 'error': 'Unsupported file type'}
            
            # Update file record with results
            if parse_success:
                if event_count == 0:
                    file_record.status = 'ZeroEvents'
                else:
                    file_record.status = 'Indexed'
                    file_record.indexed_at = datetime.utcnow()
            else:
                file_record.status = 'ParseFail'
            
            file_record.event_count = event_count
            file_record.source_system = source_system
            
            # Move to storage and compress
            storage_path = f'/opt/casescope/storage/case_{case_id}'
            os.makedirs(storage_path, exist_ok=True)
            
            if file_record.status == 'Indexed' and os.path.exists(file_path):
                compressed_filename = filename + '.gz'
                compressed_path = os.path.join(storage_path, compressed_filename)
                
                with open(file_path, 'rb') as f_in:
                    with gzip.open(compressed_path, 'wb', compresslevel=6) as f_out:
                        shutil.copyfileobj(f_in, f_out)
                
                file_record.file_path = compressed_path
                os.remove(file_path)
                logger.info(f"Moved to storage: {filename} → {compressed_filename}")
            
            db.session.commit()
            
            logger.info(f"[Worker {self.request.id[:8]}] Completed {filename}: {event_count} events")
            
            return {
                'success': True,
                'file_id': file_id,
                'filename': filename,
                'event_count': event_count,
                'status': file_record.status
            }
            
        except OSError as e:
            logger.warning(f"Unable to parse {filename}: {e}")
            file_record.status = 'UnableToParse'
            file_record.error_message = str(e)[:500]
            db.session.commit()
            return {'success': False, 'error': str(e)}
            
        except Exception as e:
            logger.error(f"Error processing {filename}: {e}", exc_info=True)
            file_record.status = 'ParseFail'
            file_record.error_message = str(e)[:500]
            db.session.commit()
            return {'success': False, 'error': str(e)}


# Export for Celery autodiscovery
__all__ = ['process_individual_file']

