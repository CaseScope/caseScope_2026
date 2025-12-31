"""
Celery task for Sigma rule hunting using Chainsaw
Based on the old system's approach: Export from OpenSearch → Run Chainsaw on JSONL
"""

import os
import logging
import tempfile
import subprocess
import json
import shutil
from datetime import datetime
from pathlib import Path
from celery import group

logger = logging.getLogger(__name__)

from celery_app import celery

# Paths
CHAINSAW_BIN = '/opt/casescope/bin/chainsaw'
SIGMA_RULES = '/opt/casescope/rules/sigma/rules'


@celery.task(bind=False, name='tasks.process_single_evtx')
def process_single_evtx(task_id, file_id, case_id, user_id, evtx_path, original_filename, zip_filename):
    """
    Process a single EVTX file with Chainsaw in parallel.
    Updates ActiveTask progress directly.
    """
    from main import app
    
    with app.app_context():
        from models import db, ActiveTask
        from opensearchpy import OpenSearch
        from config import OPENSEARCH_HOST, OPENSEARCH_PORT, OPENSEARCH_USE_SSL, OPENSEARCH_INDEX_PREFIX
        
        try:
            # Update currently processing file
            if task_id:
                try:
                    from sqlalchemy import text
                    db.session.execute(text("""
                        UPDATE active_tasks 
                        SET result_data = jsonb_set(
                                jsonb_set(result_data, '{current_zip}', to_jsonb(:zip_name::text)),
                                '{current_evtx}', 
                                to_jsonb(:evtx_name::text)
                            )
                        WHERE task_id = :task_id
                    """), {'task_id': task_id, 'zip_name': zip_filename, 'evtx_name': original_filename})
                    db.session.commit()
                except Exception as e:
                    logger.warning(f"Failed to update current file: {e}")
                    db.session.rollback()
            
            os_client = OpenSearch(
                hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
                use_ssl=OPENSEARCH_USE_SSL,
                verify_certs=False,
                ssl_show_warn=False
            )
            
            index_name = f"{OPENSEARCH_INDEX_PREFIX}{case_id}"
            
            detections = run_chainsaw_on_evtx_file(
                evtx_path=evtx_path,
                case_id=case_id,
                os_client=os_client,
                index_name=index_name,
                filename=original_filename
            )
            
            result = {'success': True, 'file_id': file_id, 'filename': original_filename, 'events_tagged': 0, 'total_hits': 0, 'rules_matched': {}}
            
            if detections:
                stats = store_sigma_detections(detections, case_id, file_id, user_id)
                result.update(stats)
            
            # Increment progress in ActiveTask using atomic SQL updates
            if task_id:
                try:
                    from sqlalchemy import text
                    # Atomic increment of counters using PostgreSQL JSONB operations
                    db.session.execute(text("""
                        UPDATE active_tasks 
                        SET 
                            result_data = jsonb_set(
                                jsonb_set(
                                    jsonb_set(
                                        result_data,
                                        '{files_checked}',
                                        to_jsonb(COALESCE((result_data->>'files_checked')::int, 0) + 1)
                                    ),
                                    '{events_tagged}',
                                    to_jsonb(COALESCE((result_data->>'events_tagged')::int, 0) + :events_tagged)
                                ),
                                '{total_hits}',
                                to_jsonb(COALESCE((result_data->>'total_hits')::int, 0) + :total_hits)
                            ),
                            progress_percent = LEAST(100, (COALESCE((result_data->>'files_checked')::int, 0) + 1) * 100 / GREATEST((result_data->>'total_files')::int, 1)),
                            progress_message = 'Processing ' || (COALESCE((result_data->>'files_checked')::int, 0) + 1)::text || '/' || (result_data->>'total_files')::text
                        WHERE task_id = :task_id
                    """), {
                        'task_id': task_id,
                        'events_tagged': result['events_tagged'],
                        'total_hits': result['total_hits']
                    })
                    db.session.commit()
                except Exception as e:
                    logger.warning(f"Failed to update progress: {e}")
                    db.session.rollback()
            
            return result
                
        except Exception as e:
            logger.error(f"Error processing {original_filename}: {e}", exc_info=True)
            # Increment ignored count
            if task_id:
                try:
                    active_task = ActiveTask.query.filter_by(task_id=task_id).first()
                    if active_task:
                        rd = active_task.result_data or {}
                        rd['files_ignored'] = rd.get('files_ignored', 0) + 1
                        active_task.result_data = rd
                        db.session.commit()
                except:
                    pass
            return {'success': False, 'file_id': file_id, 'filename': original_filename, 'error': str(e)}


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
    
    task_id = current_task.request.id if current_task else None
    
    with app.app_context():
        from models import db, CaseFile, EventSigmaHit, ActiveTask
        from opensearchpy import OpenSearch
        from config import OPENSEARCH_HOST, OPENSEARCH_PORT, OPENSEARCH_USE_SSL, OPENSEARCH_INDEX_PREFIX
        
        logger.info(f"Starting Sigma hunt for case {case_id}, user {user_id}, task_id={task_id}, clear_previous={clear_previous}")
        
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
            file_type='evtx',
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
        
        # Group files by parent ZIP
        files_by_zip = {}
        standalone_files = []
        
        for case_file in evtx_files:
            if case_file.parent_file_id:
                if case_file.parent_file_id not in files_by_zip:
                    files_by_zip[case_file.parent_file_id] = []
                files_by_zip[case_file.parent_file_id].append(case_file)
            else:
                standalone_files.append(case_file)
        
        total_files = len(evtx_files)
        files_checked = 0
        files_ignored = 0
        events_tagged = 0
        total_hits = 0
        rules_matched = {}
        files_processed = 0
        
        # Create ActiveTask record
        if task_id:
            active_task = ActiveTask(
                case_id=case_id,
                task_type='sigma_hunt',
                task_id=task_id,
                user_id=user_id,
                status='running',
                progress_percent=0,
                progress_message='Initializing...',
                result_data={'total_files': total_files, 'files_checked': 0, 'events_tagged': 0, 'total_hits': 0}
            )
            db.session.add(active_task)
            db.session.commit()
        
        def update_progress(current_zip=None, current_evtx=None):
            if not task_id:
                return
            try:
                percent = int((files_processed / total_files) * 100) if total_files > 0 else 0
                ActiveTask.query.filter_by(task_id=task_id).update({
                    'progress_percent': percent,
                    'progress_message': f'Processing {files_processed}/{total_files}',
                    'result_data': {
                        'total_files': total_files,
                        'files_checked': files_checked,
                        'files_ignored': files_ignored,
                        'events_tagged': events_tagged,
                        'total_hits': total_hits,
                        'current_zip': current_zip,
                        'current_evtx': current_evtx
                    }
                })
                db.session.commit()
            except Exception as e:
                logger.warning(f"Failed to update progress: {e}")
        
        # Process standalone files (those with direct paths)
        for case_file in standalone_files:
            files_processed += 1
            try:
                if case_file.file_path and os.path.exists(case_file.file_path):
                    logger.info(f"Processing standalone file {files_processed}/{total_files}: {case_file.original_filename}")
                    
                    if current_task:
                        current_task.update_state(
                            state='PROGRESS',
                            meta={
                                'current': files_processed,
                                'total': total_files,
                                'current_file': case_file.original_filename,
                                'files_checked': files_checked,
                                'files_ignored': files_ignored,
                                'events_tagged': events_tagged,
                                'total_hits': total_hits,
                                'percent': int(files_processed / total_files * 100)
                            }
                        )
                    
                    detections = run_chainsaw_on_evtx_file(
                        evtx_path=case_file.file_path,
                        case_id=case_id,
                        os_client=os_client,
                        index_name=index_name,
                        filename=case_file.original_filename
                    )
                    
                    if detections:
                        stats = store_sigma_detections(detections, case_id, case_file.id, user_id)
                        events_tagged += stats['events_tagged']
                        total_hits += stats['total_hits']
                        for rule_title, count in stats['rules_matched'].items():
                            rules_matched[rule_title] = rules_matched.get(rule_title, 0) + count
                    
                    files_checked += 1
                else:
                    files_ignored += 1
            except Exception as e:
                logger.error(f"Error processing standalone file {case_file.original_filename}: {e}", exc_info=True)
                files_ignored += 1
        
        # Process files grouped by ZIP
        for parent_id, zip_files in files_by_zip.items():
            temp_dir = None
            try:
                # Get parent ZIP
                parent_zip = db.session.get(CaseFile, parent_id)
                if not parent_zip or not parent_zip.file_path or not os.path.exists(parent_zip.file_path):
                    logger.warning(f"Parent ZIP not found for {len(zip_files)} files")
                    files_ignored += len(zip_files)
                    files_processed += len(zip_files)
                    continue
                
                logger.info(f"Extracting {len(zip_files)} EVTX files from {parent_zip.original_filename}")
                update_progress(current_zip=parent_zip.original_filename, current_evtx='Extracting...')
                
                # Create temp directory for this ZIP's files
                temp_dir = tempfile.mkdtemp(prefix='sigma_batch_')
                
                # Extract all EVTX files from this ZIP at once
                import zipfile
                extracted_files = {}
                
                with zipfile.ZipFile(parent_zip.file_path, 'r') as zf:
                    for case_file in zip_files:
                        file_in_zip = case_file.original_filename
                        for name in zf.namelist():
                            if name.replace('\\', '/') == file_in_zip.replace('\\', '/'):
                                # Extract to temp dir with safe filename
                                safe_name = os.path.basename(name)
                                temp_path = os.path.join(temp_dir, f"{case_file.id}_{safe_name}")
                                with zf.open(name) as source, open(temp_path, 'wb') as target:
                                    target.write(source.read())
                                extracted_files[case_file.id] = (case_file, temp_path)
                                break
                
                logger.info(f"Extracted {len(extracted_files)} files, processing in parallel with {len(extracted_files)} workers...")
                
                # Create parallel tasks for all extracted files
                tasks = []
                for file_id, (case_file, temp_path) in extracted_files.items():
                    tasks.append(
                        process_single_evtx.s(
                            task_id=task_id,
                            file_id=case_file.id,
                            case_id=case_id,
                            user_id=user_id,
                            evtx_path=temp_path,
                            original_filename=case_file.original_filename,
                            zip_filename=parent_zip.original_filename
                        )
                    )
                
                # Execute tasks in parallel and wait for completion
                job = group(tasks)
                result = job.apply_async()
                results = result.get()  # Blocks until all complete
                
                # Aggregate results (progress already updated by subtasks)
                for res in results:
                    if res.get('success'):
                        files_checked += 1
                        events_tagged += res.get('events_tagged', 0)
                        total_hits += res.get('total_hits', 0)
                        for rule_title, count in res.get('rules_matched', {}).items():
                            rules_matched[rule_title] = rules_matched.get(rule_title, 0) + count
                    else:
                        files_ignored += 1
                files_processed += len(extracted_files)
                
            except Exception as e:
                logger.error(f"Error processing ZIP batch: {e}", exc_info=True)
                files_ignored += len(zip_files)
                files_processed += len(zip_files)
            finally:
                # Clean up entire temp directory
                if temp_dir and os.path.exists(temp_dir):
                    try:
                        shutil.rmtree(temp_dir)
                        logger.info(f"Cleaned up temp directory: {temp_dir}")
                    except Exception as e:
                        logger.warning(f"Failed to clean up temp dir {temp_dir}: {e}")
        
        # Mark as completed (subtasks already updated counters in result_data)
        if task_id:
            try:
                # Get current values from database (updated by subtasks)
                active_task = ActiveTask.query.filter_by(task_id=task_id).first()
                if active_task:
                    final_data = active_task.result_data or {}
                    logger.info(f"Sigma hunt complete for case {case_id}: {final_data.get('files_checked', 0)} files, {final_data.get('events_tagged', 0)} events, {final_data.get('total_hits', 0)} hits")
                    
                    # Just update status, leave counters as-is (already updated by subtasks)
                    ActiveTask.query.filter_by(task_id=task_id).update({
                        'status': 'completed',
                        'progress_percent': 100,
                        'progress_message': 'Complete',
                        'completed_at': datetime.utcnow()
                    })
                    db.session.commit()
                    
                    # Return values from database (updated by subtasks)
                    return {
                        'success': True,
                        'files_checked': final_data.get('files_checked', 0),
                        'files_ignored': final_data.get('files_ignored', 0),
                        'events_tagged': final_data.get('events_tagged', 0),
                        'total_hits': final_data.get('total_hits', 0),
                        'rules_matched': final_data.get('rules_matched', {})
                    }
            except Exception as e:
                logger.warning(f"Failed to mark complete: {e}")
        
        # Fallback return if task_id not found
        return {
            'success': True,
            'files_checked': 0,
            'files_ignored': 0,
            'events_tagged': 0,
            'total_hits': 0,
            'rules_matched': {}
        }


def run_chainsaw_on_evtx_file(evtx_path, case_id, os_client, index_name, filename):
    """
    Run Chainsaw directly on EVTX file (this works!),
    then match detections back to OpenSearch documents.
    
    ONLY uses enabled SIGMA rules from the database.
    
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
        # Get list of enabled rules only
        from models import SigmaRule
        enabled_rules = SigmaRule.query.filter_by(is_enabled=True).all()
        
        if not enabled_rules:
            logger.warning("No enabled SIGMA rules found, skipping hunt")
            return []
        
        # Create temporary directory with symlinks to enabled rules
        import tempfile
        import shutil
        temp_rules_dir = tempfile.mkdtemp(prefix='sigma_enabled_')
        
        try:
            # Create symlinks for enabled rules
            for rule in enabled_rules:
                rule_full_path = os.path.join('/opt/casescope/rules/sigma', rule.source_folder, rule.rule_path)
                if os.path.exists(rule_full_path):
                    # Create subdirectories as needed
                    rule_subdir = os.path.dirname(rule.rule_path)
                    if rule_subdir:
                        os.makedirs(os.path.join(temp_rules_dir, rule_subdir), exist_ok=True)
                    
                    # Create symlink
                    link_path = os.path.join(temp_rules_dir, rule.rule_path)
                    try:
                        os.symlink(rule_full_path, link_path)
                    except FileExistsError:
                        pass  # Link already exists
            
            logger.info(f"Using {len(enabled_rules)} enabled SIGMA rules for hunting")
            
            # STEP 1: Run Chainsaw on raw EVTX with enabled rules only
            output_json = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
            output_path = output_json.name
            output_json.close()
            
            cmd = [
                CHAINSAW_BIN,
                'hunt', evtx_path,
                '-s', temp_rules_dir,  # Use temp directory with only enabled rules
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
            
            # Cleanup output file
            if os.path.exists(output_path):
                os.unlink(output_path)
            
            logger.info(f"Matched {len(detections)} detections to OpenSearch documents")
            return detections
        
        finally:
            # Cleanup temporary rules directory
            if os.path.exists(temp_rules_dir):
                shutil.rmtree(temp_rules_dir)
        
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
