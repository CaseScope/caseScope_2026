#!/usr/bin/env python3
"""Populate the privacy alias vault for cases ingested before fail-closed egress.

Cloud AI egress now blocks when a sanitized payload still carries a protected
value. Aliases are created lazily from each outgoing payload, so a populated
vault is not strictly required, but a case whose vault was never built pays
that cost on the first AI call and depends entirely on the payload text
containing every identifier in a recognisable form.

This scans the original ClickHouse events for every case and vaults what it
finds, so the control starts from full knowledge of the case rather than from
whatever happened to appear in the first prompt.

Idempotent: upserts by (case_id, entity_type, normalized_value), so a case that
was already populated gains only entities added by newer extractors.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app


def case_ids_needing_backfill():
    """Return case ids in ingest order, newest first."""
    from models.case import Case

    return [
        case_id
        for (case_id,) in Case.query.with_entities(Case.id)
        .order_by(Case.id.desc())
        .all()
    ]


def backfill():
    from models.database import db
    from utils.privacy_aliases import populate_case_privacy_aliases

    case_ids = case_ids_needing_backfill()
    if not case_ids:
        print('No cases found; nothing to backfill.')
        return 0

    print(f'Backfilling privacy alias vault for {len(case_ids)} case(s).')
    total_created = 0
    total_updated = 0
    failed = []

    for case_id in case_ids:
        try:
            summary = populate_case_privacy_aliases(case_id)
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            failed.append((case_id, str(exc)))
            print(f'  case {case_id}: FAILED ({exc})')
            continue

        created = int(summary.get('created') or 0)
        updated = int(summary.get('updated') or 0)
        total_created += created
        total_updated += updated
        print(f'  case {case_id}: {created} created, {updated} updated')

    print(f'Done. {total_created} aliases created, {total_updated} updated.')
    if failed:
        print(f'{len(failed)} case(s) failed; rerun the migration to retry them.')
        return 1
    return 0


def main():
    app = create_app()
    with app.app_context():
        return backfill()


if __name__ == '__main__':
    raise SystemExit(main())
