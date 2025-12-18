#!/usr/bin/env python3
"""
Index EVTX Module - Phase 1 of Reindex Pipeline
Handles ONLY indexing - no auto-hide, no SIGMA, no IOCs
"""

import os
import logging
import subprocess
import tempfile
import json
from typing import Dict, Optional

logger = logging.getLogger(__name__)


def index_file_simple(db, opensearch_client, file_id: int, case_id: int) -> Dict:
    """
    Index a single EVTX file - ONLY indexing, no detection/filtering.
    
    Phase 1 Step 1: Convert EVTX → JSON → OpenSearch
    - All events marked as event_status='new'
    - NO auto-hide for known-good or noise
    - NO IOC hunting
    - NO SIGMA detection
    
    Args:
        db: Database session
        opensearch_client: OpenSearch client
        file_id: CaseFile ID
        case_id: Case ID
    
    Returns:
        Dict with status, events_indexed count
    """
    from models import CaseFile, Case
    from opensearchpy.helpers import bulk as opensearch_bulk
    from event_normalization import normalize_event
    from utils import make_index_name
    
    case_file = db.session.get(CaseFile, file_id)
    if not case_file:
        return {'status': 'error', 'message': 'File not found', 'events_indexed': 0}
    
    case = db.session.get(Case, case_id)
    if not case:
        return {'status': 'error', 'message': 'Case not found', 'events_indexed': 0}
    
    file_path = case_file.file_path
    filename = case_file.original_filename
    
    logger.info(f"[INDEX] Starting Phase 1 indexing: {filename} (file_id={file_id})")
    
    # Only process EVTX files
    if not filename.lower().endswith('.evtx'):
        case_file.indexing_status = 'Completed'
        case_file.is_indexed = True
        case_file.event_count = 0
        db.session.commit()
        return {'status': 'success', 'message': 'Not EVTX, skipped', 'events_indexed': 0}
    
    # Check if file exists
    if not os.path.exists(file_path):
        case_file.indexing_status = 'Failed: File not found'
        case_file.error_message = f'File not found: {file_path}'
        db.session.commit()
        return {'status': 'error', 'message': 'File not found', 'events_indexed': 0}
    
    case_file.indexing_status = 'Indexing'
    db.session.commit()
    
    try:
        # STEP 1: Convert EVTX to JSONL (Rust evtx library - 2-5x faster)
        logger.info(f"[INDEX] Converting EVTX to JSON (Rust evtx library)...")
        json_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl')
        json_path = json_file.name
        json_file.close()
        
        # Use Rust evtx library (v2.2.0 - 2-5x faster than subprocess evtx_dump)
        try:
            from evtx import PyEvtxParser
            import json
            
            parser = PyEvtxParser(file_path)
            records_written = 0
            
            with open(json_path, 'w') as f:
                for record in parser.records_json():
                    # record is already a Python dict (not an object with .data)
                    json_line = json.dumps(record)
                    f.write(json_line + '\n')
                    records_written += 1
            
            output_path = json_path
            logger.info(f"[INDEX] ✓ EVTX converted to JSONL: {records_written:,} records")
            
        except Exception as e:
            error_msg = f'Rust evtx parsing failed: {str(e)[:100]}'
            logger.error(f"[INDEX] {error_msg}")
            logger.warning(f"[INDEX] Falling back to legacy evtx_dump...")
            
            # FALLBACK: Use legacy evtx_dump
            cmd = ['/opt/casescope/bin/evtx_dump', '-o', 'jsonl', file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode != 0:
                error_msg = f'evtx_dump fallback also failed: {result.stderr[:200]}'
                logger.error(f"[INDEX] {error_msg}")
                case_file.indexing_status = 'Failed: EVTX parsing failed'
                case_file.error_message = error_msg
                db.session.commit()
                if os.path.exists(json_path):
                    os.unlink(json_path)
                return {'status': 'error', 'message': error_msg, 'events_indexed': 0}
            
            # Move output to proper location
            output_path = json_path.replace('.jsonl', '.json')
            if os.path.exists(f"{file_path}.json"):
                output_path = f"{file_path}.json"
            elif os.path.exists(json_path):
                import shutil
                shutil.move(json_path, output_path)
        
        if not os.path.exists(output_path):
            error_msg = 'EVTX parsing produced no output'
            case_file.indexing_status = 'Failed: No output'
            case_file.error_message = error_msg
            db.session.commit()
            return {'status': 'error', 'message': error_msg, 'events_indexed': 0}
        
        # STEP 2: Parse and prepare for OpenSearch
        logger.info(f"[INDEX] Parsing events...")
        index_name = make_index_name(case_id)
        bulk_data = []
        event_count = 0
        
        with open(output_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    event = json.loads(line)
                    
                    # Normalize event fields
                    event = normalize_event(event)
                    
                    # Add case metadata
                    event['case_id'] = case_id
                    event['file_id'] = file_id
                    event['case_name'] = case.name
                    event['source_file'] = filename
                    
                    # Phase 1: ALL events marked as 'new' (NO auto-hide)
                    event['event_status'] = 'new'
                    event['status_reason'] = ''
                    
                    # Add to bulk queue
                    bulk_data.append({
                        '_index': index_name,
                        '_source': event
                    })
                    
                    event_count += 1
                    
                    # Bulk index every 1000 events
                    if len(bulk_data) >= 1000:
                        success, errors = opensearch_bulk(opensearch_client, bulk_data, raise_on_error=False)
                        logger.debug(f"[INDEX] Indexed batch: {success} events")
                        bulk_data = []
                
                except json.JSONDecodeError as e:
                    logger.warning(f"[INDEX] Invalid JSON line: {e}")
                    continue
                except Exception as e:
                    logger.warning(f"[INDEX] Error processing event: {e}")
                    continue
        
        # Index remaining events
        if bulk_data:
            success, errors = opensearch_bulk(opensearch_client, bulk_data, raise_on_error=False)
            logger.debug(f"[INDEX] Indexed final batch: {success} events")
        
        # STEP 3: Update file record
        case_file.event_count = event_count
        case_file.is_indexed = True
        case_file.indexing_status = 'Indexed (waiting for SIGMA)'
        case_file.opensearch_key = f"case{case_id}_{filename.replace('.evtx', '')}"
        db.session.commit()
        
        logger.info(f"[INDEX] ✓ Indexed {event_count:,} events for {filename}")
        
        # Cleanup temp file
        if os.path.exists(output_path) and output_path.startswith('/tmp'):
            os.unlink(output_path)
        
        return {
            'status': 'success',
            'message': 'Indexing completed',
            'events_indexed': event_count,
            'file_id': file_id
        }
    
    except Exception as e:
        logger.error(f"[INDEX] Failed to index file {file_id}: {e}", exc_info=True)
        case_file.indexing_status = f'Failed: {str(e)[:200]}'
        case_file.error_message = str(e)[:500]
        db.session.commit()
        
        # Cleanup
        if 'json_path' in locals() and os.path.exists(json_path):
            os.unlink(json_path)
        if 'output_path' in locals() and os.path.exists(output_path) and output_path.startswith('/tmp'):
            os.unlink(output_path)
        
        return {'status': 'error', 'message': str(e), 'events_indexed': 0}


