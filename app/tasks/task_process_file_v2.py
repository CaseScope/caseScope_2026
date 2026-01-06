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
    from opensearch_indexer import OpenSearchIndexer
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
                file_record.status = 'ParseFail'
                file_record.error_message = f'No parser available for this file type'
                db.session.commit()
                return {'success': False, 'error': 'No parser available'}
            
            # Get parser function
            parser_func = get_parser(parser_type)
            if not parser_func:
                logger.error(f"Failed to load parser {parser_type} for {filename}")
                file_record.status = 'ParseFail'
                file_record.error_message = f'Parser {parser_type} failed to load'
                db.session.commit()
                return {'success': False, 'error': 'Parser load failed'}
            
            logger.info(f"Using {parser_type} parser for {filename}")
            
            # Parse file
            try:
                events = list(parser_func(file_path))
            except Exception as e:
                logger.error(f"Parser {parser_type} failed for {filename}: {e}")
                raise
            
            if not events:
                logger.info(f"No events extracted from {filename}")
                file_record.status = 'ZeroEvents'
                file_record.event_count = 0
                db.session.commit()
                return {'success': True, 'file_id': file_id, 'filename': filename, 'event_count': 0, 'status': 'ZeroEvents'}
            
            # Extract hostname/computer from first event
            source_system = None
            if events:
                source_system = events[0].get('computer') or events[0].get('ComputerName') or normalize_event_computer(events[0])
                if source_system:
                    logger.info(f"Source system: {source_system}")
            
            # Get target index
            index_name = get_index_name(parser_type, case_id)
            logger.info(f"Indexing {len(events)} events to {index_name}")
            
            # Index events
            indexer = OpenSearchIndexer()
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
                
                # Progress logging for large files
                if parser_type == 'mft' and i % 50000 == 0 and i > 0:
                    logger.info(f"MFT progress: {i}/{len(events)}")
            
            event_count = len(events)
            
            # Update file record
            file_record.status = 'Indexed'
            file_record.indexed_at = datetime.utcnow()
            file_record.event_count = event_count
            file_record.source_system = source_system
            
            # Move to storage and compress
            storage_path = f'/opt/casescope/storage/case_{case_id}'
            os.makedirs(storage_path, exist_ok=True)
            
            if os.path.exists(file_path):
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
                'status': file_record.status,
                'parser_type': parser_type,
                'index': index_name
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
__all__ = ['process_individual_file_v2']

