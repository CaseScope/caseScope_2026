"""
Celery task for Sigma rule hunting using Chainsaw
Based on the old system's approach: Export from OpenSearch → Run Chainsaw on JSONL
"""

import os
import logging
import tempfile
import subprocess
import json
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# Paths
CHAINSAW_BIN = '/opt/casescope/bin/chainsaw'
SIGMA_RULES = '/opt/casescope/rules/sigma/rules'


def hunt_sigma(case_id, user_id, clear_previous=True):
    """
    Hunt for Sigma rule violations across all EVTX files in a case
    
    This uses the OLD SYSTEM approach:
    1. Export events from OpenSearch to JSONL
    2. Run Chainsaw on JSONL (NOT on raw EVTX)
    3. Match detections back to OpenSearch doc IDs
    4. Store in event_sigma_hits table
    
    Args:
        case_id: Case ID to hunt
        user_id: User initiating the hunt
        clear_previous: Clear previous Sigma hits before hunting
    
    Returns:
        dict: Hunt statistics
    """
    from celery import current_task
    
    # Import inside function to avoid circular imports
    from main import app
    
    with app.app_context():
        from models import db, CaseFile, EventSigmaHit
        from opensearchpy import OpenSearch
        from config import OPENSEARCH_HOST, OPENSEARCH_PORT, OPENSEARCH_USE_SSL, OPENSEARCH_INDEX_PREFIX
        
        logger.info(f"Starting Sigma hunt for case {case_id}, user {user_id}, clear_previous={clear_previous}")
        
        # Initialize OpenSearch
        os_client = OpenSearch(
            hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
            use_ssl=OPENSEARCH_USE_SSL,
            verify_certs=False,
            ssl_show_warn=False
        )
        
        index_name = f"{OPENSEARCH_INDEX_PREFIX}{case_id}"
        
        # Clear previous hits if requested
        if clear_previous:
            logger.info(f"Clearing previous Sigma hits for case {case_id}")
            deleted = EventSigmaHit.query.filter_by(case_id=case_id).delete()
            db.session.commit()
            logger.info(f"Cleared {deleted} previous Sigma hits")
        
        # Get all EVTX files for this case that are indexed and not hidden
        evtx_files = CaseFile.query.filter_by(
            case_id=case_id,
            file_type='evtx',  # lowercase!
            status='indexed',
            is_hidden=False
        ).all()
        
        if not evtx_files:
            logger.warning(f"No EVTX files found for case {case_id}")
            return {
                'success': True,
                'files_checked': 0,
                'files_ignored': 0,
                'events_tagged': 0,
                'total_hits': 0,
                'rules_matched': {}
            }
        
        total_files = len(evtx_files)
        files_checked = 0
        files_ignored = 0
        events_tagged = 0
        total_hits = 0
        rules_matched = {}
        
        for idx, case_file in enumerate(evtx_files, 1):
            try:
                logger.info(f"Processing file {idx}/{total_files}: {case_file.original_filename}")
                
                # Get the EVTX file path
                evtx_path = case_file.file_path
                if not evtx_path or not os.path.exists(evtx_path):
                    logger.warning(f"EVTX file not found: {evtx_path}")
                    continue
                
                # Update progress at start of processing
                if current_task:
                    current_task.update_state(
                        state='PROGRESS',
                        meta={
                            'current': idx,
                            'total': total_files,
                            'current_file': case_file.original_filename,
                            'files_checked': files_checked,
                            'files_ignored': files_ignored,
                            'events_tagged': events_tagged,
                            'total_hits': total_hits,
                            'percent': int((idx - 1) / total_files * 100)
                        }
                    )
                
                # Run Chainsaw directly on EVTX file (this works!)
                detections = run_chainsaw_on_evtx_file(
                    evtx_path=evtx_path,
                    case_id=case_id,
                    os_client=os_client,
                    index_name=index_name,
                    filename=case_file.original_filename
                )
                
                logger.info(f"Chainsaw found {len(detections)} detections in {case_file.original_filename}")
                
                if detections:
                    # Store detections in database
                    stats = store_sigma_detections(
                        detections=detections,
                        case_id=case_id,
                        file_id=case_file.id,
                        user_id=user_id
                    )
                    
                    events_tagged += stats['events_tagged']
                    total_hits += stats['total_hits']
                    
                    # Merge rules_matched (use rule_title, not rule_id)
                    for rule_title, count in stats['rules_matched'].items():
                        rules_matched[rule_title] = rules_matched.get(rule_title, 0) + count
                
                files_checked += 1
                
                # Update progress after processing file
                if current_task:
                    current_task.update_state(
                        state='PROGRESS',
                        meta={
                            'current': idx,
                            'total': total_files,
                            'current_file': case_file.original_filename,
                            'files_checked': files_checked,
                            'files_ignored': files_ignored,
                            'events_tagged': events_tagged,
                            'total_hits': total_hits,
                            'percent': int(idx / total_files * 100)
                        }
                    )
                
            except Exception as e:
                logger.error(f"Error processing file {case_file.original_filename}: {e}", exc_info=True)
                continue
        
        logger.info(f"Sigma hunt complete for case {case_id}: {files_checked} files, {events_tagged} events, {total_hits} hits")
        
        return {
            'success': True,
            'files_checked': files_checked,
            'files_ignored': files_ignored,
            'events_tagged': events_tagged,
            'total_hits': total_hits,
            'rules_matched': rules_matched
        }


def run_chainsaw_on_evtx_file(evtx_path, case_id, os_client, index_name, filename):
    """
    Run Chainsaw directly on EVTX file (this works!),
    then match detections back to OpenSearch documents.
    
    Args:
        evtx_path: Path to EVTX file
        case_id: Case ID
        os_client: OpenSearch client
        index_name: OpenSearch index name
        filename: Original filename
    
    Returns:
        list: Detections with _opensearch_doc_id added
    """
    from opensearchpy.helpers import scan
    
    try:
        # STEP 1: Run Chainsaw on raw EVTX
        output_json = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        output_path = output_json.name
        output_json.close()
        
        cmd = [
            CHAINSAW_BIN,
            'hunt', evtx_path,
            '-s', SIGMA_RULES,
            '--mapping', '/opt/casescope/rules/mappings/sigma-event-logs-all.yml',
            '--json',
            '--output', output_path
        ]
        
        logger.debug(f"Running Chainsaw: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        
        if result.returncode != 0 and result.returncode != 1:
            logger.warning(f"Chainsaw exit code {result.returncode}")
        
        # STEP 2: Parse Chainsaw results
        detections = []
        
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            try:
                with open(output_path, 'r', encoding='utf-8') as f:
                    chainsaw_data = json.load(f)
                    if not isinstance(chainsaw_data, list):
                        chainsaw_data = [chainsaw_data]
                
                logger.info(f"Chainsaw found {len(chainsaw_data)} detections")
                
                # STEP 3: Match detections to OpenSearch doc IDs
                # For each detection, find matching event in OpenSearch
                for detection in chainsaw_data:
                    timestamp = detection.get('timestamp', '')
                    
                    # Extract event details from Chainsaw output
                    try:
                        event_system = detection.get('document', {}).get('data', {}).get('Event', {}).get('System', {})
                        event_record_id = event_system.get('EventRecordID')
                        event_id = str(event_system.get('EventID', ''))
                        computer = event_system.get('Computer', '')
                    except:
                        event_record_id = None
                        event_id = ''
                        computer = ''
                    
                    # Find matching document in OpenSearch
                    doc_id = find_matching_opensearch_doc(
                        os_client=os_client,
                        index_name=index_name,
                        filename=filename,
                        timestamp=timestamp,
                        event_record_id=event_record_id,
                        event_id=event_id,
                        computer=computer
                    )
                    
                    if doc_id:
                        detection['_opensearch_doc_id'] = doc_id
                        detection['_event_record_id'] = event_record_id
                        detection['_event_id'] = event_id
                        detection['_computer'] = computer
                        detections.append(detection)
                    else:
                        logger.debug(f"Could not match detection: record_id={event_record_id}, event_id={event_id}")
            
            except Exception as e:
                logger.error(f"Failed to parse Chainsaw output: {e}", exc_info=True)
        else:
            logger.warning(f"Chainsaw output file empty or missing: {output_path}")
        
        # Cleanup
        if os.path.exists(output_path):
            os.unlink(output_path)
        
        logger.info(f"Matched {len(detections)} detections to OpenSearch documents")
        return detections
        
    except subprocess.TimeoutExpired:
        logger.error(f"Chainsaw timed out processing {evtx_path}")
        return []
    except Exception as e:
        logger.error(f"Error running Chainsaw on {evtx_path}: {e}", exc_info=True)
        return []


def find_matching_opensearch_doc(os_client, index_name, filename, timestamp, event_record_id, event_id, computer):
    """
    Find OpenSearch document matching Chainsaw detection
    
    Args:
        os_client: OpenSearch client
        index_name: Index name
        filename: Source filename
        timestamp: Event timestamp
        event_record_id: Event record ID (most reliable)
        event_id: Event ID
        computer: Computer name
    
    Returns:
        str: Document ID or None
    """
    try:
        must_filters = [
            {'term': {'source_file': filename}}
        ]
        
        # Try to match by event_record_id (most reliable)
        if event_record_id:
            must_filters.append({'term': {'event_record_id': event_record_id}})
            
            query = {
                'query': {'bool': {'must': must_filters}},
                'size': 1,
                '_source': False
            }
            
            result = os_client.search(index=index_name, body=query)
            
            if result['hits']['total']['value'] > 0:
                return result['hits']['hits'][0]['_id']
        
        # Fallback: match by timestamp + event_id
        if timestamp and event_id:
            # Parse timestamp
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                ts_ms = int(dt.timestamp() * 1000)
                
                must_filters = [
                    {'term': {'source_file': filename}},
                    {'term': {'event_id': event_id}},
                    {'range': {
                        'timestamp': {
                            'gte': ts_ms - 5000,  # ±5 seconds
                            'lte': ts_ms + 5000
                        }
                    }}
                ]
                
                query = {
                    'query': {'bool': {'must': must_filters}},
                    'size': 1,
                    '_source': False
                }
                
                result = os_client.search(index=index_name, body=query)
                
                if result['hits']['total']['value'] > 0:
                    return result['hits']['hits'][0]['_id']
            except:
                pass
        
        return None
        
    except Exception as e:
        logger.error(f"Error finding matching doc: {e}")
        return None


def store_sigma_detections(detections, case_id, file_id, user_id):
    """
    Store Sigma detections in database
    
    Args:
        detections: List of detection objects with _opensearch_doc_id
        case_id: Case ID
        file_id: CaseFile ID
        user_id: User ID
    
    Returns:
        dict: Statistics
    """
    from models import db, EventSigmaHit
    
    events_tagged = set()
    total_hits = 0
    rules_matched = {}
    
    batch_size = 100
    hits_batch = []
    
    for detection in detections:
        try:
            doc_id = detection.get('_opensearch_doc_id')
            if not doc_id:
                continue
            
            rule_id = detection.get('id', 'unknown')
            rule_name = detection.get('name', 'Unknown')
            rule_level = (detection.get('level', 'medium') or 'medium').lower()
            
            # Extract MITRE tags
            tags = detection.get('tags', [])
            if isinstance(tags, list):
                mitre_tags = ','.join([t for t in tags if t.startswith('attack.')])
            else:
                mitre_tags = ''
            
            # Create hit record
            hit = EventSigmaHit(
                case_id=case_id,
                opensearch_doc_id=doc_id,
                file_id=file_id,
                sigma_rule_id=rule_id,
                rule_title=rule_name,
                rule_level=rule_level,
                mitre_tags=mitre_tags,
                detected_by=user_id
            )
            
            hits_batch.append(hit)
            events_tagged.add(doc_id)
            total_hits += 1
            # Use rule_title (readable name) instead of rule_id (UUID)
            rules_matched[rule_name] = rules_matched.get(rule_name, 0) + 1
            
            # Batch insert
            if len(hits_batch) >= batch_size:
                db.session.bulk_save_objects(hits_batch)
                db.session.commit()
                hits_batch = []
        
        except Exception as e:
            logger.error(f"Error storing detection: {e}", exc_info=True)
            continue
    
    # Insert remaining hits
    if hits_batch:
        db.session.bulk_save_objects(hits_batch)
        db.session.commit()
    
    return {
        'events_tagged': len(events_tagged),
        'total_hits': total_hits,
        'rules_matched': rules_matched
    }


# Make hunt_sigma available as Celery task
try:
    from celery_app import celery
    hunt_sigma = celery.task(name='tasks.task_hunt_sigma.hunt_sigma')(hunt_sigma)
except ImportError:
    # Not running as Celery worker
    pass
