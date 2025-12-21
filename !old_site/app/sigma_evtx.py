#!/usr/bin/env python3
"""
SIGMA EVTX Module - Phase 1 (Part 2) of Reindex Pipeline
Handles ONLY SIGMA detection on already-indexed events
"""

import os
import logging
import subprocess
import tempfile
import json
from typing import Dict

logger = logging.getLogger(__name__)


def sigma_file_simple(db, opensearch_client, file_id: int, case_id: int) -> Dict:
    """
    Run SIGMA detection on already-indexed file events.
    
    Phase 1 Step 2: Query OpenSearch → Run Chainsaw → Store violations
    - Assumes events already indexed in OpenSearch
    - Updates has_sigma flags in OpenSearch
    - Stores violations in database
    
    Args:
        db: Database session
        opensearch_client: OpenSearch client
        file_id: CaseFile ID
        case_id: Case ID
    
    Returns:
        Dict with status, violations_found count
    """
    from models import CaseFile, SigmaRule, SigmaViolation
    from opensearchpy.helpers import scan, bulk as opensearch_bulk
    from utils import make_index_name
    
    case_file = db.session.get(CaseFile, file_id)
    if not case_file:
        return {'status': 'error', 'message': 'File not found', 'violations_found': 0}
    
    filename = case_file.original_filename
    
    # Only process EVTX files
    if not filename.lower().endswith('.evtx'):
        logger.info(f"[SIGMA] Skipping {filename} (not EVTX)")
        return {'status': 'success', 'message': 'Not EVTX, skipped', 'violations_found': 0}
    
    logger.info(f"[SIGMA] Starting SIGMA detection: {filename} (file_id={file_id})")
    
    case_file.indexing_status = 'SIGMA Testing'
    db.session.commit()
    
    try:
        # STEP 1: Export events from OpenSearch to temp JSONL
        index_name = make_index_name(case_id)
        temp_jsonl = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl', encoding='utf-8')
        temp_jsonl_path = temp_jsonl.name
        
        logger.info(f"[SIGMA] Exporting events from OpenSearch...")
        event_count = 0
        
        query = {"query": {"term": {"file_id": file_id}}}
        
        for hit in scan(opensearch_client, index=index_name, query=query):
            event = hit['_source']
            temp_jsonl.write(json.dumps(event) + '\n')
            event_count += 1
        
        temp_jsonl.close()
        
        if event_count == 0:
            logger.warning(f"[SIGMA] No events found for file {file_id}")
            os.unlink(temp_jsonl_path)
            case_file.violation_count = 0
            case_file.indexing_status = 'Completed'
            db.session.commit()
            return {'status': 'success', 'message': 'No events found', 'violations_found': 0}
        
        logger.info(f"[SIGMA] Exported {event_count:,} events, running Chainsaw...")
        
        # STEP 2: Run Chainsaw on temp JSONL
        output_json = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        output_path = output_json.name
        output_json.close()
        
        cmd = [
            '/opt/casescope/bin/chainsaw',
            'hunt', temp_jsonl_path,
            '-s', '/opt/casescope/chainsaw_rules/',
            '--json',
            '--output', output_path
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        # STEP 3: Parse Chainsaw results
        violations = []
        violation_count = 0
        
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            try:
                with open(output_path, 'r', encoding='utf-8') as f:
                    chainsaw_data = json.load(f)
                
                for detection in chainsaw_data:
                    rule_name = detection.get('name', 'Unknown')
                    rule_level = detection.get('level', 'low')
                    
                    # Get event timestamp for matching
                    event_time = detection.get('timestamp', '')
                    
                    violations.append({
                        'rule_name': rule_name,
                        'rule_level': rule_level,
                        'event_time': event_time,
                        'detection': detection
                    })
                    violation_count += 1
            
            except Exception as e:
                logger.warning(f"[SIGMA] Failed to parse Chainsaw output: {e}")
        
        logger.info(f"[SIGMA] Found {violation_count} violations")
        
        # STEP 4: Store violations in database
        event_ids_with_sigma = set()
        
        if violations:
            # Clear existing violations for this file
            SigmaViolation.query.filter_by(file_id=file_id).delete()
            
            for v in violations:
                # Store in database
                violation = SigmaViolation(
                    case_id=case_id,
                    file_id=file_id,
                    event_id='',  # Will be updated if we match event
                    rule_name=v['rule_name'],
                    rule_level=v['rule_level'],
                    event_timestamp=v['event_time'],
                    details=json.dumps(v['detection'])
                )
                db.session.add(violation)
                event_ids_with_sigma.add(v['event_time'])  # Use timestamp as proxy
            
            db.session.commit()
            logger.info(f"[SIGMA] Stored {violation_count} violations in database")
            
            # STEP 5: Update OpenSearch events with has_sigma flag
            # Query events and set has_sigma=True for matching events
            update_body = []
            for hit in scan(opensearch_client, index=index_name, query={"query": {"term": {"file_id": file_id}}}):
                event_time = hit['_source'].get('@timestamp', '')
                if event_time in event_ids_with_sigma:
                    update_body.append({"update": {"_id": hit['_id'], "_index": index_name}})
                    update_body.append({"doc": {"has_sigma": True}})
                
                if len(update_body) >= 2000:  # Batch of 1000 updates
                    opensearch_client.bulk(body=update_body)
                    update_body = []
            
            if update_body:
                opensearch_client.bulk(body=update_body)
            
            logger.info(f"[SIGMA] Updated OpenSearch events with has_sigma flags")
        
        # STEP 6: Update file record
        case_file.violation_count = violation_count
        case_file.indexing_status = 'Completed'
        db.session.commit()
        
        # Cleanup
        if os.path.exists(temp_jsonl_path):
            os.unlink(temp_jsonl_path)
        if os.path.exists(output_path):
            os.unlink(output_path)
        
        logger.info(f"[SIGMA] ✓ Completed SIGMA for {filename}: {violation_count} violations")
        
        return {
            'status': 'success',
            'message': 'SIGMA completed',
            'violations_found': violation_count,
            'file_id': file_id
        }
    
    except Exception as e:
        logger.error(f"[SIGMA] Failed for file {file_id}: {e}", exc_info=True)
        case_file.indexing_status = f'Failed: {str(e)[:200]}'
        case_file.error_message = str(e)[:500]
        db.session.commit()
        
        # Cleanup
        if 'temp_jsonl_path' in locals() and os.path.exists(temp_jsonl_path):
            os.unlink(temp_jsonl_path)
        if 'output_path' in locals() and os.path.exists(output_path):
            os.unlink(output_path)
        
        return {'status': 'error', 'message': str(e), 'violations_found': 0}


