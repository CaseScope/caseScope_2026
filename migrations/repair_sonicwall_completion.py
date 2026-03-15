#!/usr/bin/env python3
"""Repair missing ingest summaries and failed SonicWall IPv6 ingests.

Usage:
    python repair_sonicwall_completion.py [--case-uuid CASE_UUID] [--dry-run]
    python repair_sonicwall_completion.py --repair-completion-only
    python repair_sonicwall_completion.py --repair-sonicwall-only
"""
import argparse
import logging
import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('SECRET_KEY', 'repair-sonicwall-completion')

from app import create_app
from models.case import Case
from models.case_file import CaseFile
from models.audit_log import AuditAction, AuditEntityType, AuditLog
from tasks.celery_tasks import case_indexing_complete_task, parse_file_task
from utils.clickhouse import count_file_events


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)


def _iter_cases(case_uuid: str = None):
    """Yield cases, optionally scoped to a single case UUID."""
    if case_uuid:
        case = Case.get_by_uuid(case_uuid)
        return [case] if case else []
    return Case.query.order_by(Case.created_at.desc()).all()


def _find_cases_missing_ingest_summary(case_uuid: str = None):
    """Return finished cases that still lack the durable INGESTED summary."""
    results = []
    for case in _iter_cases(case_uuid):
        if not case:
            continue

        current_case_uuid = str(case.uuid)
        pending_count = CaseFile.query.filter(
            CaseFile.case_uuid == current_case_uuid,
            CaseFile.is_archive == False,
            CaseFile.status.in_(['new', 'queued', 'ingesting']),
        ).count()
        if pending_count > 0:
            continue

        latest_ingest = AuditLog.query.filter_by(
            case_uuid=current_case_uuid,
            entity_type=AuditEntityType.CASE_FILE,
            action=AuditAction.INGESTED,
        ).order_by(AuditLog.timestamp.desc()).first()
        if latest_ingest is None:
            results.append(case)

    return results


def _find_failed_sonicwall_files(case_uuid: str = None):
    """Return failed SonicWall file records that should be reparsed."""
    query = CaseFile.query.filter(
        CaseFile.is_archive == False,
        CaseFile.file_path.isnot(None),
        CaseFile.file_path.ilike('%.csv'),
        CaseFile.status.in_(['error', 'done']),
        CaseFile.ingestion_status.in_(['parse_error', 'error']),
    ).filter(
        (CaseFile.parser_type == 'sonicwall') |
        (CaseFile.file_type.ilike('%sonicwall%'))
    )

    if case_uuid:
        query = query.filter(CaseFile.case_uuid == case_uuid)

    return query.order_by(CaseFile.uploaded_at.asc()).all()


def _repair_failed_sonicwall_files(case_uuid: str = None, dry_run: bool = False):
    """Synchronously reparse failed SonicWall files using the fixed parser."""
    files = _find_failed_sonicwall_files(case_uuid)
    stats = {
        'files_considered': len(files),
        'files_reparsed': 0,
        'files_succeeded': 0,
        'files_failed': 0,
        'touched_cases': set(),
    }

    for cf in files:
        case = Case.get_by_uuid(cf.case_uuid)
        if not case or not cf.file_path or not os.path.exists(cf.file_path):
            logger.warning("Skipping SonicWall file %s because the case or file path is unavailable", cf.id)
            continue

        existing_events = count_file_events(cf.id)
        logger.info(
            "SonicWall repair candidate case=%s file_id=%s file=%s status=%s ingestion=%s events=%s",
            cf.case_uuid,
            cf.id,
            cf.filename,
            cf.status,
            cf.ingestion_status,
            existing_events,
        )
        stats['touched_cases'].add(cf.case_uuid)

        if dry_run:
            continue

        stats['files_reparsed'] += 1
        result = parse_file_task.apply(kwargs={
            'file_path': cf.file_path,
            'case_id': case.id,
            'source_host': cf.hostname or '',
            'case_file_id': cf.id,
        }).get()
        if result.get('success'):
            stats['files_succeeded'] += 1
        else:
            stats['files_failed'] += 1
            logger.warning(
                "SonicWall repair failed for case=%s file_id=%s: %s",
                cf.case_uuid,
                cf.id,
                result.get('errors') or result,
            )

    return stats


def _repair_missing_completion_summaries(case_uuid: str = None, dry_run: bool = False):
    """Synchronously rerun the case completion task for missing summaries."""
    cases = _find_cases_missing_ingest_summary(case_uuid)
    stats = {
        'cases_considered': len(cases),
        'cases_repaired': 0,
        'cases_failed': 0,
    }

    for case in cases:
        current_case_uuid = str(case.uuid)
        logger.info(
            "Completion repair candidate case=%s id=%s name=%s",
            current_case_uuid,
            case.id,
            case.name,
        )
        if dry_run:
            continue

        result = case_indexing_complete_task.apply(kwargs={
            'case_id': case.id,
            'case_uuid': current_case_uuid,
        }).get()
        if result.get('success'):
            stats['cases_repaired'] += 1
        else:
            stats['cases_failed'] += 1
            logger.warning(
                "Completion repair reported errors for case=%s: %s",
                current_case_uuid,
                result.get('errors') or result,
            )

    return stats


def main():
    parser = argparse.ArgumentParser(
        description='Repair failed SonicWall IPv6 ingests and missing case completion summaries'
    )
    parser.add_argument('--case-uuid', help='Restrict remediation to a specific case UUID')
    parser.add_argument('--dry-run', action='store_true', help='Report the planned repairs without changing data')
    parser.add_argument(
        '--repair-completion-only',
        action='store_true',
        help='Only rerun missing ingest summary completion tasks',
    )
    parser.add_argument(
        '--repair-sonicwall-only',
        action='store_true',
        help='Only reparse failed SonicWall files',
    )
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        if args.repair_completion_only and args.repair_sonicwall_only:
            parser.error('Choose only one of --repair-completion-only or --repair-sonicwall-only')

        if not args.repair_completion_only:
            sonicwall_stats = _repair_failed_sonicwall_files(args.case_uuid, dry_run=args.dry_run)
            logger.info("SonicWall repair summary: %s", sonicwall_stats)
        else:
            sonicwall_stats = None

        if not args.repair_sonicwall_only:
            completion_stats = _repair_missing_completion_summaries(args.case_uuid, dry_run=args.dry_run)
            logger.info("Completion repair summary: %s", completion_stats)
        else:
            completion_stats = None

        return {
            'sonicwall': sonicwall_stats,
            'completion': completion_stats,
        }


if __name__ == '__main__':
    main()
