#!/usr/bin/env python3
"""Case-scoped historical Investigation Graph backfill."""
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Iterable, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.audit_log import AuditEntityType, AuditLog
from models.case import Case
from models.database import db
from utils.clickhouse import get_fresh_client
from utils.graph_materializer import DEFAULT_GRAPH_WINDOW_SECONDS, materialize_events_for_case
from utils.graph_projection import (
    classify_case_for_graph_backfill,
    ensure_projection_state,
    graph_counts,
    graph_stream_explain_sql,
    has_active_ingest,
    mark_projection_state,
)


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Backfill missing Investigation Graph projections case-by-case")
    parser.add_argument("--dry-run", action="store_true", help="classify cases without materializing graph data")
    parser.add_argument("--case-uuid", help="process exactly one case UUID")
    parser.add_argument("--case-id", type=int, help="process exactly one case id")
    parser.add_argument("--all-missing", action="store_true", help="process only missing graph projections")
    parser.add_argument("--resume", action="store_true", help="resume pending/failed historical graph projections")
    parser.add_argument("--max-cases", type=int, default=None, help="maximum cases to process")
    parser.add_argument("--batch-size", type=int, default=5000, help="ClickHouse stream block size")
    parser.add_argument("--bulk-events", type=int, default=10000, help="eligible events per PostgreSQL bulk materialization batch")
    parser.add_argument("--progress-interval", type=int, default=50000, help="log progress every N eligible events")
    parser.add_argument("--window-seconds", type=int, default=DEFAULT_GRAPH_WINDOW_SECONDS, help="bounded ClickHouse timestamp window size")
    parser.add_argument("--explain-case-id", type=int, help="print ClickHouse EXPLAIN for one case-scoped stream query")
    return parser.parse_args(argv)


def _candidate_cases(args: argparse.Namespace) -> List[Case]:
    if args.case_uuid and args.case_id:
        raise RuntimeError("Use --case-uuid or --case-id, not both")
    if args.case_uuid:
        case = Case.get_by_uuid_unchecked(args.case_uuid)
        return [case] if case else []
    if args.case_id:
        case = Case.get_by_id_unchecked(args.case_id)
        return [case] if case else []
    return Case.query.order_by(Case.id.asc()).all()


def _print_row(row) -> None:
    qualifying = row['qualifying_evidence']
    if qualifying is None:
        qualifying_text = 'not_probed'
    else:
        qualifying_text = 'yes' if qualifying else 'no'
    print(
        f"case_id={row['case_id']} case_uuid={row['case_uuid']} "
        f"name={row['case_name']!r} graph_entities={row['graph_entities']} "
        f"graph_relationships={row['graph_relationships']} "
        f"projection_state={row['projection_state']} "
        f"active_ingest={'yes' if row['active_ingest'] else 'no'} "
        f"qualifying_evidence={qualifying_text} planned_action={row['planned_action']}"
    )


def _classify_cases(cases: Iterable[Case], *, client, probe: bool = True, mutate: bool = True) -> List[dict]:
    rows = []
    for case in cases:
        rows.append(classify_case_for_graph_backfill(case, client=client, probe=probe, mutate=mutate))
    return rows


def _print_summary(rows: List[dict]) -> None:
    summary = {
        'total cases': len(rows),
        'existing graph': sum(1 for row in rows if row['classification'] == 'existing_graph'),
        'missing + eligible': sum(1 for row in rows if row['classification'] == 'missing_eligible'),
        'missing + no eligible evidence': sum(1 for row in rows if row['classification'] == 'missing_no_eligible'),
        'active ingest deferred': sum(1 for row in rows if row['classification'] == 'active_ingest'),
        'previously failed/resumable': sum(1 for row in rows if row['classification'] == 'resumable'),
    }
    print("- Summary:")
    for label, value in summary.items():
        print(f"  {label}: {value}")


def _should_process(row: dict, args: argparse.Namespace) -> bool:
    if row['active_ingest']:
        return False
    if row['projection_state'] == 'running':
        return False
    if args.resume and row['projection_state'] in {'pending', 'failed'}:
        return True
    if args.all_missing and row['classification'] in {'missing_eligible', 'pending', 'resumable'}:
        return True
    if args.case_uuid or args.case_id:
        return row['classification'] in {'missing_eligible', 'pending', 'resumable'}
    return False


def _audit(case: Case, action: str, details: dict) -> None:
    AuditLog.log(
        AuditEntityType.CASE,
        case.uuid,
        action,
        username='migration/system',
        case_uuid=case.uuid,
        details=details,
    )


def _process_case(case: Case, row: dict, *, client, args: argparse.Namespace) -> dict:
    if has_active_ingest(case.uuid):
        return {'success': False, 'deferred': True, 'error': 'active ingest'}
    counts_before = graph_counts(case.id)
    state = row.get('state')
    if counts_before['graph_entities'] > 0 or counts_before['graph_relationships'] > 0:
        if state is None:
            return {'success': True, 'skipped': True, 'reason': 'existing graph'}
        if state.status == 'running':
            return {'success': False, 'deferred': True, 'error': 'projection already running'}
        if state.status not in {'pending', 'failed'}:
            return {'success': True, 'skipped': True, 'reason': 'existing graph'}
    if not row.get('state') and not row.get('qualifying_evidence'):
        row = classify_case_for_graph_backfill(case, client=client, probe=True)
    if row.get('qualifying_evidence') is False:
        return {'success': True, 'skipped': True, 'reason': 'no eligible evidence'}

    state = row.get('state') or ensure_projection_state(case, mode='historical_backfill', status='pending')
    mark_projection_state(state, status='running', mode='historical_backfill')
    _audit(
        case,
        'graph_projection_started',
        {
            'mode': 'historical_backfill',
            'graph_entities_before': counts_before['graph_entities'],
            'graph_entity_observations_before': counts_before['graph_entity_observations'],
            'graph_relationships_before': counts_before['graph_relationships'],
            'graph_relationship_evidence_before': counts_before['graph_relationship_evidence'],
        },
    )
    started = time.monotonic()
    result = materialize_events_for_case(
        case.id,
        client=client,
        batch_size=args.batch_size,
        bulk_events=args.bulk_events,
        projection_state=state,
        resume=bool(args.resume or state.last_timestamp_utc),
        mode='historical_backfill',
        progress_interval=args.progress_interval,
        window_seconds=args.window_seconds,
    )
    counts_after = graph_counts(case.id)
    action = 'graph_projection_failed' if result.get('errors') else 'graph_projection_completed'
    _audit(
        case,
        action,
        {
            'mode': 'historical_backfill',
            'duration_seconds': round(time.monotonic() - started, 3),
            'graph_entities_before': counts_before['graph_entities'],
            'graph_entity_observations_before': counts_before['graph_entity_observations'],
            'graph_relationships_before': counts_before['graph_relationships'],
            'graph_relationship_evidence_before': counts_before['graph_relationship_evidence'],
            'graph_entities_after': counts_after['graph_entities'],
            'graph_entity_observations_after': counts_after['graph_entity_observations'],
            'graph_relationships_after': counts_after['graph_relationships'],
            'graph_relationship_evidence_after': counts_after['graph_relationship_evidence'],
            'events_seen': result.get('events_seen', 0),
            'bulk_events': result.get('bulk_events', 0),
            'bulk_batches': result.get('bulk_batches', 0),
            'relationships_materialized': result.get('relationships_materialized', 0),
            'errors': result.get('errors', 0),
        },
    )
    return {'success': not bool(result.get('errors')), **result, **counts_after}


def migrate(argv: Optional[List[str]] = None) -> None:
    args = _parse_args(argv)
    app = create_app()
    with app.app_context():
        client = get_fresh_client()
        if args.explain_case_id:
            explain_sql = graph_stream_explain_sql(args.explain_case_id)
            print(explain_sql)
            result = client.query(explain_sql)
            for row in result.result_rows:
                print(" ".join(str(value) for value in row))
            return
        cases = _candidate_cases(args)
        if not cases:
            raise RuntimeError("No matching cases found")

        rows = _classify_cases(cases, client=client, probe=True, mutate=not args.dry_run)
        for row in rows:
            _print_row(row)
        _print_summary(rows)
        if args.dry_run:
            print("Dry run complete; no graph rows were materialized.")
            return

        selected = [row for row in rows if _should_process(row, args)]
        if args.max_cases is not None:
            selected = selected[: max(int(args.max_cases), 0)]
        if not selected:
            print("No cases selected for graph backfill.")
            return

        completed = failed = deferred = 0
        by_id = {case.id: case for case in cases}
        for row in selected:
            case = by_id[row['case_id']]
            print(f"- Backfilling case_id={case.id} case_uuid={case.uuid} name={case.name!r}")
            try:
                result = _process_case(case, row, client=client, args=args)
                if result.get('deferred'):
                    deferred += 1
                elif result.get('success'):
                    completed += 1
                else:
                    failed += 1
                print(f"  result={result}")
            except Exception as exc:
                failed += 1
                db.session.rollback()
                state = row.get('state')
                if state is not None:
                    mark_projection_state(state, status='failed', last_error=str(exc))
                print(f"  failed={exc}")
        print(f"- Backfill run complete: completed={completed} failed={failed} deferred={deferred}")


if __name__ == "__main__":
    migrate()
