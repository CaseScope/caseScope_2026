#!/usr/bin/env python3
"""
Upload Integration Module (v9.6.0)

Flask route handlers for the new unified upload pipeline
Integrates upload_pipeline.py with main.py routes
"""

import os
import json
import redis
import threading
from flask import jsonify, request, current_app
from datetime import datetime


def handle_http_upload_v96(app, db, Case, CaseFile, SkippedFile, celery_app, current_user, uploaded_files, case_id):
    """
    Handle HTTP file uploads using v9.6.0 unified pipeline
    
    Args:
        app: Flask app instance
        db: Database session
        Case: Case model
        CaseFile: CaseFile model  
        SkippedFile: SkippedFile model
        celery_app: Celery app for task queuing
        current_user: Current logged-in user
        uploaded_files: List of Flask file objects
        case_id: Case ID (passed from route)
    
    Returns:
        Flask JSON response
    """
    try:
        # Import pipeline
        from upload_pipeline import (
            init_logger, ensure_staging_exists, stage_http_upload,
            extract_zips_in_staging, build_file_queue, filter_zero_event_files
        )
        
        # Initialize logger
        init_logger(app.logger)
        
        case_id = int(case_id)
        
        # Verify case exists
        case = db.session.get(Case, case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Ensure staging exists
        ensure_staging_exists(case_id)
        
        # STEP 1: Stage all uploaded files
        staged_files = []
        for file in uploaded_files:
            if file.filename:
                result = stage_http_upload(case_id, file, file.filename)
                if result['success']:
                    staged_files.append(result)
        
        if not staged_files:
            return jsonify({'success': False, 'error': 'No files uploaded'}), 400
        
        # STEP 2: Extract ZIPs
        extract_stats = extract_zips_in_staging(case_id)
        
        # STEP 3: Build queue (deduplicate)
        queue_stats = build_file_queue(db, CaseFile, SkippedFile, case_id)
        
        # STEP 4: Filter zero-event files
        filter_stats = filter_zero_event_files(db, CaseFile, SkippedFile, queue_stats['queue'], case_id)
        
        # STEP 5: Queue valid files for processing
        for file_id, filename, file_path, event_count in filter_stats['filtered_queue']:
            # Update uploader
            case_file = db.session.get(CaseFile, file_id)
            if case_file:
                case_file.uploaded_by = current_user.id
            
            # Queue for processing
            celery_app.send_task('tasks.process_file', args=[file_id, 'full'])
        
        db.session.commit()
        
        # Audit log file upload
        from audit_logger import log_action
        log_action('upload_files', resource_type='file', resource_id=None,
                  resource_name=f'{len(filter_stats["filtered_queue"])} files',
                  details={
                      'case_id': case_id,
                      'case_name': case.name,
                      'files_uploaded': len(filter_stats['filtered_queue']),
                      'files_staged': len(staged_files),
                      'files_extracted': extract_stats.get('files_extracted', 0),
                      'files_queued': len(filter_stats['filtered_queue']),
                      'files_skipped': queue_stats.get('duplicates_skipped', 0) + filter_stats.get('zero_event_files_skipped', 0)
                  })
        
        return jsonify({
            'success': True,
            'message': f'Upload complete: {filter_stats["valid_files"]} files queued',
            'stats': {
                'files_uploaded': len(staged_files),
                'zips_extracted': extract_stats['files_extracted'],
                'files_queued': filter_stats['valid_files'],
                'duplicates_skipped': queue_stats['duplicates_skipped'],
                'zero_events_skipped': filter_stats['zero_events']
            }
        })
        
    except Exception as e:
        app.logger.error(f"[Upload v9.6] Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


def handle_bulk_upload_v96(app, db, Case, CaseFile, SkippedFile, celery_app, case_id, local_folder):
    """
    Handle bulk folder uploads using v9.6.0 unified pipeline
    
    Args:
        app: Flask app instance
        db: Database session
        Case: Case model
        CaseFile: CaseFile model
        SkippedFile: SkippedFile model
        celery_app: Celery app for task queuing
        case_id: Case ID
        local_folder: Path to local upload folder
    
    Returns:
        dict: Pipeline statistics
    """
    try:
        # Import pipeline
        from upload_pipeline import (
            init_logger, ensure_staging_exists, stage_bulk_upload,
            extract_zips_in_staging, build_file_queue, filter_zero_event_files
        )
        
        # Initialize logger
        init_logger(app.logger)
        
        # Verify case exists
        case = db.session.get(Case, case_id)
        if not case:
            return {'success': False, 'error': 'Case not found'}
        
        # Ensure staging exists
        ensure_staging_exists(case_id)
        
        # STEP 1: Stage files from bulk folder
        stage_stats = stage_bulk_upload(case_id, local_folder)
        if not stage_stats['success']:
            return stage_stats
        
        # STEP 2: Extract ZIPs
        extract_stats = extract_zips_in_staging(case_id)
        
        # STEP 3: Build queue (deduplicate)
        queue_stats = build_file_queue(db, CaseFile, SkippedFile, case_id)
        
        # STEP 4: Filter zero-event files
        filter_stats = filter_zero_event_files(db, CaseFile, SkippedFile, queue_stats['queue'], case_id)
        
        # STEP 5: Queue valid files for processing
        for file_id, filename, file_path, event_count in filter_stats['filtered_queue']:
            celery_app.send_task('tasks.process_file_v9', args=[file_id, 'full'])
        
        db.session.commit()
        
        return {
            'success': True,
            'message': f'Bulk upload complete: {filter_stats["valid_files"]} files queued',
            'files_staged': stage_stats['files_staged'],
            'zips_extracted': extract_stats['files_extracted'],
            'files_queued': filter_stats['valid_files'],
            'duplicates_skipped': queue_stats['duplicates_skipped'],
            'zero_events_skipped': filter_stats['zero_events']
        }
        
    except Exception as e:
        app.logger.error(f"[Bulk Upload v9.6] Error: {e}")
        import traceback
        traceback.print_exc()
        return {'success': False, 'error': str(e)}


def handle_chunked_upload_finalize_v96(app, db, Case, CaseFile, SkippedFile, celery_app, 
                                       current_user, upload_id, filename, case_id, chunks_folder):
    """
    Handle chunked upload finalization using v9.6.0 unified pipeline
    
    Assembles chunks, stages file, runs through pipeline
    
    Args:
        app: Flask app instance
        db: Database session
        Case: Case model
        CaseFile: CaseFile model
        SkippedFile: SkippedFile model
        celery_app: Celery app for task queuing
        current_user: Current logged-in user
        upload_id: Upload ID
        filename: Original filename
        case_id: Case ID
        chunks_folder: Path to chunks folder
    
    Returns:
        Flask JSON response
    """
    try:
        import tempfile
        from upload_pipeline import (
            init_logger, ensure_staging_exists, get_staging_path,
            extract_zips_in_staging, build_file_queue, filter_zero_event_files
        )
        
        # Initialize logger
        init_logger(app.logger)
        
        # Verify case exists
        case = db.session.get(Case, case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Assemble chunks
        staging_dir = ensure_staging_exists(case_id)
        staging_path = os.path.join(staging_dir, filename)
        
        # Get all chunk files, sorted numerically
        chunk_files = sorted(
            [f for f in os.listdir(chunks_folder) if f.startswith(f"{upload_id}_")],
            key=lambda x: int(x.split('_')[-1])
        )
        
        # Assemble
        with open(staging_path, 'wb') as outfile:
            for chunk_file in chunk_files:
                chunk_path = os.path.join(chunks_folder, chunk_file)
                with open(chunk_path, 'rb') as infile:
                    outfile.write(infile.read())
                os.remove(chunk_path)  # Delete chunk after assembly
        
        # Clean up chunks folder
        try:
            os.rmdir(chunks_folder)
        except:
            pass
        
        app.logger.info(f"[Chunked Upload] Assembled: {filename} ({os.path.getsize(staging_path):,} bytes)")
        
        # STEP 2: Extract ZIPs (if applicable)
        extract_stats = extract_zips_in_staging(case_id)
        
        # STEP 3: Build queue (deduplicate)
        queue_stats = build_file_queue(db, CaseFile, SkippedFile, case_id)
        
        # STEP 4: Filter zero-event files
        filter_stats = filter_zero_event_files(db, CaseFile, SkippedFile, queue_stats['queue'], case_id)
        
        # STEP 5: Queue valid files for processing and trigger coordinator
        valid_file_ids = []
        for file_id, fname, file_path, event_count in filter_stats['filtered_queue']:
            # Update uploader
            case_file = db.session.get(CaseFile, file_id)
            if case_file:
                case_file.uploaded_by = current_user.id
                case_file.is_indexed = False
                # State will be set by processing modules
                valid_file_ids.append(file_id)
        
        db.session.commit()
        
        # Trigger the NEW coordinator to process all uploaded files
        if valid_file_ids:
            from coordinator_index import index_new_files_task
            task = index_new_files_task.delay(case_id)
            app.logger.info(f"[Upload] Triggered coordinator for case {case_id} (task_id: {task.id})")
        
        # Audit log
        try:
            from audit_logger import log_action
            case = db.session.get(Case, case_id)
            log_action('upload_file', resource_type='file', resource_id=None,
                      resource_name=filename,
                      details={
                          'case_id': case_id,
                          'case_name': case.name if case else None,
                          'files_queued': filter_stats['valid_files'],
                          'duplicates_skipped': queue_stats['duplicates_skipped'],
                          'coordinator_task_id': task.id if valid_file_ids else None
                      })
        except Exception as e:
            app.logger.warning(f"[AUDIT] Failed to log upload: {e}")
        
        return jsonify({
            'success': True,
            'message': f'Upload complete: {filter_stats["valid_files"]} files queued',
            'stats': {
                'zips_extracted': extract_stats['files_extracted'],
                'files_queued': filter_stats['valid_files'],
                'duplicates_skipped': queue_stats['duplicates_skipped'],
                'zero_events_skipped': filter_stats['zero_events']
            }
        })
        
    except Exception as e:
        app.logger.error(f"[Chunked Upload v9.6] Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

