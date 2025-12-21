#!/usr/bin/env python3
"""
Test Script for Modular Processing System v2.0
================================================

This script helps test the new phased processing system.

Usage:
    # Test individual phases
    python3 test_modular_processing.py --phase index --case-id 25
    python3 test_modular_processing.py --phase sigma --case-id 25
    python3 test_modular_processing.py --phase ioc --case-id 25
    
    # Test full processing flow
    python3 test_modular_processing.py --full --case-id 25
    
    # Check processing status
    python3 test_modular_processing.py --status --case-id 25

Author: CaseScope
Version: 2.0.0
"""

import sys
import argparse
import logging
from datetime import datetime

# Setup path
sys.path.insert(0, '/opt/casescope/app')

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def test_index_phase(case_id):
    """Test Phase 1: File Indexing"""
    from processing_index import index_all_files_in_queue, is_indexing_complete
    from main import app
    
    print("\n" + "="*80)
    print("TESTING PHASE 1: FILE INDEXING")
    print("="*80)
    
    with app.app_context():
        print(f"\nCase ID: {case_id}")
        
        # Check current status
        is_complete = is_indexing_complete(case_id)
        print(f"Indexing already complete: {is_complete}")
        
        if not is_complete:
            print("\nStarting indexing phase...")
            start_time = datetime.now()
            
            result = index_all_files_in_queue(case_id)
            
            duration = (datetime.now() - start_time).total_seconds()
            
            print(f"\n✓ Indexing complete in {duration:.1f}s")
            print(f"  - Status: {result['status']}")
            print(f"  - Total files: {result['total_files']}")
            print(f"  - Indexed: {result['indexed']}")
            print(f"  - Skipped: {result['skipped']}")
            print(f"  - Failed: {result['failed']}")
            
            if result['errors']:
                print(f"  - Errors: {result['errors'][:5]}")
        else:
            print("All files already indexed!")


def test_sigma_phase(case_id):
    """Test Phase 2: SIGMA Detection"""
    from processing_sigma import sigma_detect_all_files, is_sigma_complete
    from main import app
    
    print("\n" + "="*80)
    print("TESTING PHASE 2: SIGMA DETECTION")
    print("="*80)
    
    with app.app_context():
        print(f"\nCase ID: {case_id}")
        
        # Check current status
        is_complete = is_sigma_complete(case_id)
        print(f"SIGMA already complete: {is_complete}")
        
        print("\nStarting SIGMA detection phase...")
        start_time = datetime.now()
        
        result = sigma_detect_all_files(case_id)
        
        duration = (datetime.now() - start_time).total_seconds()
        
        print(f"\n✓ SIGMA detection complete in {duration:.1f}s")
        print(f"  - Status: {result['status']}")
        print(f"  - Total files: {result['total_files']}")
        print(f"  - Processed: {result['processed']}")
        print(f"  - Violations: {result['total_violations']}")
        print(f"  - Skipped: {result['skipped']}")
        print(f"  - Failed: {result['failed']}")
        
        if result['errors']:
            print(f"  - Errors: {result['errors'][:5]}")


def test_ioc_phase(case_id):
    """Test Phase 5: IOC Matching"""
    from processing_ioc import match_all_iocs
    from main import app
    
    print("\n" + "="*80)
    print("TESTING PHASE 5: IOC MATCHING")
    print("="*80)
    
    with app.app_context():
        print(f"\nCase ID: {case_id}")
        
        print("\nStarting IOC matching phase...")
        start_time = datetime.now()
        
        result = match_all_iocs(case_id)
        
        duration = (datetime.now() - start_time).total_seconds()
        
        print(f"\n✓ IOC matching complete in {duration:.1f}s")
        print(f"  - Status: {result['status']}")
        print(f"  - Total IOCs: {result['total_iocs']}")
        print(f"  - Matched: {result['matched']}")
        print(f"  - Total matches: {result['total_matches']}")
        print(f"  - Skipped: {result['skipped']}")
        print(f"  - Failed: {result['failed']}")
        
        if result['errors']:
            print(f"  - Errors: {result['errors'][:5]}")


def test_full_processing(case_id):
    """Test Full Phased Processing"""
    from phase_coordinator import run_phased_processing
    from main import app
    
    print("\n" + "="*80)
    print("TESTING FULL PHASED PROCESSING")
    print("="*80)
    
    def progress_callback(phase, status, message):
        print(f"  Phase {phase}: {status} - {message}")
    
    with app.app_context():
        print(f"\nCase ID: {case_id}")
        print("\nStarting full phased processing...")
        start_time = datetime.now()
        
        result = run_phased_processing(case_id, progress_callback=progress_callback)
        
        duration = (datetime.now() - start_time).total_seconds()
        
        print(f"\n✓ Phased processing complete in {duration:.1f}s")
        print(f"  - Status: {result['status']}")
        print(f"  - Phases completed: {result['phases_completed']}")
        print(f"  - Phases failed: {result['phases_failed']}")
        
        print("\nPhase Statistics:")
        for phase_name, stats in result['stats'].items():
            print(f"  {phase_name}:")
            for key, value in stats.items():
                print(f"    - {key}: {value}")
        
        if result['errors']:
            print(f"\nErrors: {result['errors'][:10]}")


def check_status(case_id):
    """Check Processing Status"""
    from phase_coordinator import get_processing_status
    from main import app, db
    from models import Case
    
    print("\n" + "="*80)
    print("PROCESSING STATUS")
    print("="*80)
    
    with app.app_context():
        case = db.session.get(Case, case_id)
        if not case:
            print(f"\n✗ Case {case_id} not found")
            return
        
        print(f"\nCase ID: {case_id}")
        print(f"Case Name: {case.name}")
        print(f"Company: {case.company}")
        
        status = get_processing_status(case_id)
        
        print(f"\nFile Counts:")
        print(f"  - Total files: {status['total_files']}")
        print(f"  - Indexed files: {status['indexed_files']}")
        print(f"  - Pending files: {status['pending_files']}")
        print(f"  - Failed files: {status['failed_files']}")
        
        print(f"\nPhase Completion:")
        print(f"  - Indexing complete: {'✓' if status['indexing_complete'] else '✗'}")
        print(f"  - SIGMA complete: {'✓' if status['sigma_complete'] else '✗'}")
        print(f"  - IOC matching complete: {'✓' if status['ioc_complete'] else '✗'}")
        
        print(f"\nCase Totals:")
        print(f"  - Total events: {case.total_events:,}")
        print(f"  - SIGMA violations: {case.total_events_with_SIGMA_violations:,}")
        print(f"  - IOC matches: {case.total_events_with_IOCs:,}")


def main():
    parser = argparse.ArgumentParser(description='Test Modular Processing System v2.0')
    parser.add_argument('--case-id', type=int, required=True, help='Case ID to test')
    parser.add_argument('--phase', choices=['index', 'sigma', 'ioc'], help='Test specific phase')
    parser.add_argument('--full', action='store_true', help='Test full processing flow')
    parser.add_argument('--status', action='store_true', help='Check processing status')
    
    args = parser.parse_args()
    
    if not any([args.phase, args.full, args.status]):
        print("Error: Must specify --phase, --full, or --status")
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.status:
            check_status(args.case_id)
        elif args.phase:
            if args.phase == 'index':
                test_index_phase(args.case_id)
            elif args.phase == 'sigma':
                test_sigma_phase(args.case_id)
            elif args.phase == 'ioc':
                test_ioc_phase(args.case_id)
        elif args.full:
            test_full_processing(args.case_id)
        
        print("\n" + "="*80)
        print("TEST COMPLETE")
        print("="*80 + "\n")
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

