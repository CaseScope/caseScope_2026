"""
Global IOC Hunt Celery Task
Hunts IOCs across ALL case events (not per-file like normal processing)
"""

from celery import current_task
from celery_app import celery_app
from datetime import datetime
import logging
import json

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name='task_ioc_hunt.hunt_all_iocs')
def hunt_all_iocs_task(self, job_id, case_id):
    """
    Global IOC hunt - searches ALL case events for active IOCs.
    
    Uses same query patterns as file_processing.hunt_iocs() but without file_id filter.
    Processes IOCs in batches for progress tracking and memory efficiency.
    
    Args:
        job_id: IOCHuntJob ID
        case_id: Case ID to hunt
    """
    
    # Import here to avoid circular import (main imports celery_app which imports this)
    from main import db, opensearch_client, app
    from models import IOC, Case
    from model_ioc_hunt import IOCHuntJob, IOCHuntMatch
    
    # CRITICAL: Must run within Flask app context for database access
    with app.app_context():
        job = IOCHuntJob.query.get(job_id)
        if not job:
            return {"error": "Job not found"}
        
        try:
            # Get active IOCs for this case
            iocs = IOC.query.filter_by(case_id=case_id, is_active=True).all()
            
            if not iocs:
                job.status = "completed"
                job.message = "No active IOCs to hunt"
                job.completed_at = datetime.utcnow()
                db.session.commit()
                return
            
            # Get case index pattern (consolidated case index, e.g., "case_9")
            case = Case.query.get(case_id)
            if not case:
                job.status = "failed"
                job.message = "Case not found"
                job.completed_at = datetime.utcnow()
                db.session.commit()
                return
            
            index_name = f"case_{case_id}"
            
            # Verify index exists
            try:
                if not opensearch_client.indices.exists(index=index_name):
                    job.status = "completed"
                    job.message = "No indexed files for this case"
                    job.completed_at = datetime.utcnow()
                    db.session.commit()
                    return
            except Exception as e:
                logger.warning(f"[IOC_HUNT] Error checking index: {e}")
                # Continue anyway - might be transient error
            
            # Get total event count in case
            try:
                total_events_in_case = opensearch_client.count(index=index_name).get('count', 0)
            except:
                total_events_in_case = 0
            
            job.total_iocs = len(iocs)
            job.status = "running"
            db.session.commit()
            
            logger.info(f"[IOC_HUNT] Starting global hunt: {len(iocs)} IOCs across {total_events_in_case:,} events, case {case_id}")
            
            processed = 0
            total_matches = 0
            unique_events_with_iocs = set()  # Track unique event IDs with at least 1 IOC
            event_ioc_map = {}  # Map event_id -> list of (ioc_type, ioc_value) for tagging
            batch_size = 10  # Process 10 IOCs at a time
            
            # Process IOCs in batches
            for batch_idx in range(0, len(iocs), batch_size):
                # Check for cancellation
                db.session.expire(job)  # Refresh from database
                job = IOCHuntJob.query.get(job_id)
                if job.status == "cancelled":
                    logger.info(f"[IOC_HUNT] Job {job_id} cancelled by user")
                    return
                
                batch = iocs[batch_idx:batch_idx + batch_size]
                
                # Build batch query (OR logic)
                should_clauses = []
                for ioc in batch:
                    # Determine search value (same logic as file_processing.hunt_iocs)
                    search_value = ioc.ioc_value
                    
                    # Handle command IOCs specially (append .exe)
                    if ioc.ioc_type == 'command':
                        if not search_value.lower().endswith('.exe'):
                            search_value = f"{search_value}.exe"
                    
                    # Build query clause based on IOC type
                    if ioc.ioc_type == 'command_complex':
                        # Complex command - extract distinctive terms
                        import re
                        words = re.findall(r'\b\w{5,}\b', ioc.ioc_value)
                        distinctive_words = [w for w in words if not w.islower() and not w.isupper()]
                        if not distinctive_words:
                            distinctive_words = words[:5]
                        
                        search_terms = ' AND '.join(distinctive_words[:5])
                        should_clauses.append({
                            "query_string": {
                                "query": search_terms,
                                "fields": ["search_blob"],
                                "default_operator": "AND",
                                "lenient": True
                            }
                        })
                    else:
                        # Standard IOC - simple_query_string with phrase matching
                        should_clauses.append({
                            "simple_query_string": {
                                "query": f'"{search_value}"',
                                "fields": ["search_blob"],
                                "default_operator": "and"
                            }
                        })
                
                # Query OpenSearch for this batch
                query = {
                    "query": {
                        "bool": {
                            "should": should_clauses,
                            "minimum_should_match": 1
                        }
                    },
                    "size": 5000,
                    "_source": ["search_blob"]  # Only fetch what we need
                }
                
                # Use scroll API to get ALL results (handles >10K matches)
                try:
                    response = opensearch_client.search(
                        index=index_name,
                        body=query,
                        scroll='5m',
                        request_timeout=60
                    )
                    
                    scroll_id = response.get('_scroll_id')
                    all_hits = response['hits']['hits']
                    total_hits = response['hits']['total']['value']
                    
                    logger.info(f"[IOC_HUNT] Batch {batch_idx//batch_size + 1}: {total_hits} potential matches")
                    
                    # Continue scrolling if needed
                    while len(all_hits) < total_hits and scroll_id:
                        response = opensearch_client.scroll(
                            scroll_id=scroll_id,
                            scroll='5m'
                        )
                        scroll_id = response.get('_scroll_id')
                        batch_hits = response['hits']['hits']
                        if not batch_hits:
                            break
                        all_hits.extend(batch_hits)
                    
                    # Clear scroll context
                    if scroll_id:
                        try:
                            opensearch_client.clear_scroll(scroll_id=scroll_id)
                        except:
                            pass
                    
                except Exception as e:
                    logger.error(f"[IOC_HUNT] Query error for batch: {e}")
                    continue
                
                # Process matches - identify which IOC(s) matched each event
                # REQUIRED: Python check to determine which specific IOC(s) matched
                matches = []
                for hit in all_hits:
                    event_id = hit["_id"]
                    blob = hit["_source"].get("search_blob", "").lower()
                    
                    # Check each IOC in batch against this event
                    for ioc in batch:
                        # Get search value (with .exe for commands)
                        search_value = ioc.ioc_value
                        if ioc.ioc_type == 'command' and not search_value.lower().endswith('.exe'):
                            search_value = f"{search_value}.exe"
                        
                        # Check if IOC value appears in event
                        if search_value.lower() in blob:
                            # Track this event has at least one IOC
                            unique_events_with_iocs.add(event_id)
                            
                            # Track IOC details for this event (for tagging)
                            if event_id not in event_ioc_map:
                                event_ioc_map[event_id] = []
                            event_ioc_map[event_id].append((ioc.ioc_type, ioc.ioc_value))
                            
                            # Create match record
                            matches.append(IOCHuntMatch(
                                job_id=job_id,
                                case_id=case_id,
                                ioc_id=ioc.id,
                                event_id=event_id,
                                event_index=hit["_index"],
                                matched_value=ioc.ioc_value,
                                event_data=None  # Optional: could store JSON snapshot
                            ))
                
                # Bulk insert matches (efficient)
                if matches:
                    db.session.bulk_save_objects(matches)
                    db.session.commit()
                    total_matches += len(matches)
                    logger.info(f"[IOC_HUNT] Batch {batch_idx//batch_size + 1}: {len(matches)} confirmed matches")
                
                processed += len(batch)
                
                # Update progress
                job.processed_iocs = processed
                job.match_count = total_matches
                job.total_events_searched = total_events_in_case  # Total events in case
                job.progress = min(99, int((processed / len(iocs)) * 100))
                db.session.commit()
                
                # Update Celery task state for real-time UI updates
                self.update_state(
                    state="PROGRESS",
                    meta={
                        "processed_iocs": processed,
                        "total_iocs": len(iocs),
                        "matches": total_matches,
                        "progress": job.progress,
                        "current_batch": f"IOCs {batch_idx+1}-{min(batch_idx+batch_size, len(iocs))}"
                    }
                )
            
            # Update OpenSearch events with has_ioc flag and IOC details
            logger.info(f"[IOC_HUNT] Tagging {len(unique_events_with_iocs)} events with IOC details...")
            try:
                from opensearchpy.helpers import bulk as opensearch_bulk
                
                if event_ioc_map:
                    # Build bulk update operations
                    bulk_updates = []
                    for event_id, ioc_list in event_ioc_map.items():
                        # Get unique IOC types for this event
                        ioc_types = list(set([ioc_type for ioc_type, _ in ioc_list]))
                        
                        # Build matched_iocs array: ["ip:77.83.205.215", "username:tabadmin"]
                        matched_iocs = [f"{ioc_type}:{ioc_value[:50]}" for ioc_type, ioc_value in ioc_list]
                        
                        bulk_updates.append({
                            '_op_type': 'update',
                            '_index': index_name,
                            '_id': event_id,
                            'script': {
                                'source': '''
                                    ctx._source.has_ioc = true;
                                    ctx._source.ioc_count = params.ioc_count;
                                    ctx._source.ioc_details = params.ioc_types;
                                    ctx._source.matched_iocs = params.matched_iocs;
                                ''',
                                'lang': 'painless',
                                'params': {
                                    'ioc_count': len(ioc_list),
                                    'ioc_types': ioc_types,
                                    'matched_iocs': matched_iocs
                                }
                            }
                        })
                    
                    # Execute bulk update in batches
                    update_batch_size = 500
                    for i in range(0, len(bulk_updates), update_batch_size):
                        batch = bulk_updates[i:i+update_batch_size]
                        try:
                            success_count, errors = opensearch_bulk(
                                opensearch_client, 
                                batch, 
                                raise_on_error=False, 
                                raise_on_exception=False
                            )
                            if errors:
                                logger.warning(f"[IOC_HUNT] Bulk update had {len(errors)} errors")
                            else:
                                logger.info(f"[IOC_HUNT] Tagged batch {i//update_batch_size + 1} ({success_count} events)")
                        except Exception as e:
                            logger.error(f"[IOC_HUNT] Bulk update error: {e}")
                    
                    logger.info(f"[IOC_HUNT] Successfully tagged {len(event_ioc_map)} events with IOC details")
            except Exception as e:
                logger.warning(f"[IOC_HUNT] Failed to tag events: {e}")
            
            # Update CaseFile IOC counts by querying OpenSearch for file_id
            logger.info(f"[IOC_HUNT] Updating file IOC counts...")
            try:
                # Get unique event IDs with matches
                from sqlalchemy import func
                matched_event_ids = [m[0] for m in db.session.query(IOCHuntMatch.event_id).filter_by(
                    job_id=job_id
                ).distinct().all()]
                
                if matched_event_ids:
                    # Query OpenSearch to get file_id for each matched event
                    file_id_counts = {}
                    
                    # Fetch events in batches to get file_id
                    batch_size = 100
                    for i in range(0, len(matched_event_ids), batch_size):
                        batch = matched_event_ids[i:i+batch_size]
                        
                        try:
                            # Use mget to fetch multiple documents efficiently
                            mget_response = opensearch_client.mget(
                                index=index_name,
                                body={"ids": batch},
                                _source=["file_id"]
                            )
                            
                            for doc in mget_response.get('docs', []):
                                if doc.get('found'):
                                    file_id = doc['_source'].get('file_id')
                                    if file_id:
                                        file_id_counts[file_id] = file_id_counts.get(file_id, 0) + 1
                        except Exception as e:
                            logger.warning(f"[IOC_HUNT] Error fetching event batch: {e}")
                            continue
                    
                    # Update CaseFile records with counts
                    from models import CaseFile
                    for file_id, count in file_id_counts.items():
                        case_file = CaseFile.query.get(file_id)
                        if case_file and case_file.case_id == case_id:
                            case_file.ioc_event_count = count
                    
                    db.session.commit()
                    logger.info(f"[IOC_HUNT] Updated IOC counts for {len(file_id_counts)} files")
            except Exception as e:
                logger.warning(f"[IOC_HUNT] Failed to update file counts: {e}")
            
            # Mark complete
            job.status = "completed"
            job.progress = 100
            job.completed_at = datetime.utcnow()
            
            # Build completion message
            events_with_iocs_count = len(unique_events_with_iocs)
            job.message = f"Searched {total_events_in_case:,} events • Found IOCs in {events_with_iocs_count} events • {total_matches} total matches"
            
            db.session.commit()
            
            logger.info(f"[IOC_HUNT] Job {job_id} completed: {total_events_in_case:,} events searched, {events_with_iocs_count} events with IOCs, {total_matches} matches, events tagged")
            
        except Exception as e:
            logger.exception(f"[IOC_HUNT] Job {job_id} failed: {e}")
            job.status = "failed"
            job.message = f"Error: {str(e)}"
            job.completed_at = datetime.utcnow()
            db.session.commit()
            raise
