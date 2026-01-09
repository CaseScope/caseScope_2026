"""
Individual File Processing Task - V2 with Parser Factory
=========================================================
Processes a single file in parallel with other workers

This version uses the parser factory system for automatic parser detection and routing
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


@celery.task(name='tasks.process_individual_file_v2', bind=True, queue='ingestion')
def process_individual_file_v2(self, case_id, file_id, file_path):
    """
    Process a single file: parse, index, move to storage
    
    Uses parser factory for automatic detection and routing
    
    Args:
        case_id: Case ID
        file_id: CaseFile record ID  
        file_path: Path to file in staging
    
    Returns:
        dict: Processing results
    """
    from main import app, db
    from models import CaseFile
    from utils.event_store import get_event_store
    from utils.event_normalization import normalize_event_computer
    from utils.parser_routing import get_index_name
    from parsers import detect_parser_type, get_parser
    import gzip
    import shutil
    
    with app.app_context():
        try:
            # Get file record
            file_record = CaseFile.query.get(file_id)
            if not file_record:
                logger.error(f"File record {file_id} not found")
                return {'success': False, 'error': 'File record not found'}
            
            filename = os.path.basename(file_path)
            parent_dir = os.path.basename(os.path.dirname(file_path))
            
            # Update task state
            self.update_state(
                state='PROCESSING',
                meta={
                    'file_id': file_id,
                    'filename': filename,
                    'status': 'parsing'
                }
            )
            
            logger.info(f"[Worker {self.request.id[:8]}] Processing {filename}")
            
            # Auto-detect parser type
            parser_type = detect_parser_type(filename, parent_dir)
            
            if parser_type == 'unknown':
                logger.warning(f"No parser available for {filename}")
                file_record.status = 'UnableToParse'
                file_record.error_message = f'No parser available for this file type'
                db.session.commit()
                return {'success': False, 'error': 'No parser available'}
            
            # Get parser function
            parser_func = get_parser(parser_type)
            if not parser_func:
                logger.error(f"Failed to load parser {parser_type} for {filename}")
                file_record.status = 'UnableToParse'
                file_record.parser_type = parser_type
                file_record.error_message = f'Parser {parser_type} not available or failed to load'
                db.session.commit()
                return {'success': False, 'error': 'Parser load failed'}
            
            logger.info(f"Using {parser_type} parser for {filename}")
            
            # Parse file directly (no decompression needed)
            try:
                events = list(parser_func(file_path))
            except OSError as e:
                # File system errors (file not accessible, permissions, etc.)
                logger.warning(f"Unable to parse {filename}: {e}")
                file_record.status = 'UnableToParse'
                file_record.parser_type = parser_type
                file_record.error_message = str(e)[:500]
                db.session.commit()
                return {'success': False, 'error': str(e)}
            except Exception as e:
                # Parser exists but failed to parse the file
                logger.error(f"Parser {parser_type} failed for {filename}: {e}")
                file_record.status = 'ParseFail'
                file_record.parser_type = parser_type
                file_record.error_message = str(e)[:500]
                db.session.commit()
                return {'success': False, 'error': str(e)}
            
            if not events:
                logger.info(f"No events extracted from {filename}")
                file_record.status = 'ZeroEvents'
                file_record.parser_type = parser_type
                file_record.event_count = 0
                db.session.commit()
                return {'success': True, 'file_id': file_id, 'filename': filename, 'event_count': 0, 'status': 'ZeroEvents'}
            
            # Extract hostname/computer from first event with refinement logic
            extracted_hostname = None
            extraction_method = None
            confidence = 'low'
            
            if events:
                extracted_hostname = events[0].get('computer') or events[0].get('ComputerName') or normalize_event_computer(events[0])
                if extracted_hostname:
                    extraction_method = 'evtx' if parser_type == 'evtx' else parser_type
                    confidence = 'high'
                    logger.info(f"Extracted hostname from {parser_type}: {extracted_hostname}")
            
            # Check for machine_id in LNK and JumpList files
            if not extracted_hostname and events and parser_type in ('lnk', 'jumplist'):
                extracted_hostname = events[0].get('machine_id')
                if extracted_hostname:
                    extraction_method = parser_type
                    confidence = 'high'
                    logger.info(f"Extracted hostname from {parser_type} machine_id: {extracted_hostname}")
            
            # Refine source_system based on extraction
            source_system = file_record.source_system  # Initial value from upload
            
            if extracted_hostname:
                # Found hostname in artifacts
                if file_record.source_system_confidence == 'pending':
                    # Was waiting for extraction - use it
                    source_system = extracted_hostname
                    file_record.source_system_method = extraction_method
                    file_record.source_system_confidence = confidence
                    file_record.needs_review = False
                    logger.info(f"Refined source_system from 'pending' to '{source_system}'")
                    
                elif file_record.source_system and file_record.source_system != extracted_hostname:
                    # Mismatch between initial guess and extracted
                    logger.warning(f"Hostname mismatch: file_record={file_record.source_system}, extracted={extracted_hostname}")
                    file_record.suggested_source_system = extracted_hostname
                    file_record.needs_review = True
                    # Keep using the initially specified one for now
                    
                elif not file_record.source_system:
                    # No initial value, use extracted
                    source_system = extracted_hostname
                    file_record.source_system_method = extraction_method
                    file_record.source_system_confidence = confidence
                    
            else:
                # Couldn't extract from artifacts
                if file_record.source_system_confidence == 'pending':
                    # Fall back to whatever we have (likely filename)
                    file_record.source_system_confidence = 'medium'
                    file_record.source_system_method = 'filename'
                    file_record.needs_review = True  # User should confirm
                    logger.info(f"No hostname in artifacts, using initial value: {source_system}")
            
            logger.info(f"Final source_system: {source_system} (confidence: {file_record.source_system_confidence})")
            
            # Get target index (for logging, ClickHouse uses single table)
            index_name = get_index_name(parser_type, case_id)
            logger.info(f"Indexing {len(events)} events (type={parser_type})")
            
            # Index events using event store abstraction
            event_store = get_event_store()
            chunk_size = 5000  # ClickHouse handles larger chunks efficiently
            
            for i in range(0, len(events), chunk_size):
                chunk = events[i:i + chunk_size]
                event_store.bulk_index(
                    case_id=case_id,
                    events=iter(chunk),
                    chunk_size=chunk_size,
                    source_file=filename,
                    file_type=parser_type,
                    source_system=source_system
                )
                
                # Progress logging for large files
                if parser_type == 'mft' and i % 50000 == 0 and i > 0:
                    logger.info(f"MFT progress: {i}/{len(events)}")
            
            event_count = len(events)
            
            # Update file record
            file_record.status = 'Indexed'
            file_record.parser_type = parser_type
            file_record.indexed_at = datetime.utcnow()
            file_record.event_count = event_count
            file_record.source_system = source_system
            
            # Move to storage (no compression - keep original format)
            storage_path = f'/opt/casescope/storage/case_{case_id}'
            os.makedirs(storage_path, exist_ok=True)
            
            if os.path.exists(file_path):
                storage_file_path = os.path.join(storage_path, filename)
                shutil.move(file_path, storage_file_path)
                file_record.file_path = storage_file_path
                logger.info(f"Moved to storage: {filename}")
            
            db.session.commit()
            
            logger.info(f"[Worker {self.request.id[:8]}] Completed {filename}: {event_count} events")
            
            return {
                'success': True,
                'file_id': file_id,
                'filename': filename,
                'event_count': event_count,
                'status': file_record.status,
                'parser_type': parser_type,
                'index': index_name
            }
            
        except Exception as e:
            # Catch-all for unexpected errors (indexing errors, storage errors, etc.)
            logger.error(f"Error processing {filename}: {e}", exc_info=True)
            file_record.status = 'Error'
            file_record.error_message = str(e)[:500]
            db.session.commit()
            return {'success': False, 'error': str(e)}


# Export for Celery autodiscovery
__all__ = ['process_individual_file_v2']

