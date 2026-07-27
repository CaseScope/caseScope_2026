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

Only the entity types the configured privacy level substitutes are vaulted, so
raising the level later requires a rescan. Pass --reset to discard previously
backfilled aliases and rebuild them, which is what a level change needs.

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


def backfill(reset_generated=False):
    from models.database import db
    from utils.privacy_aliases import (
        get_configured_privacy_level,
        populate_case_privacy_aliases,
    )

    case_ids = case_ids_needing_backfill()
    if not case_ids:
        print('No cases found; nothing to backfill.')
        return 0

    level = get_configured_privacy_level()
    print(f'Backfilling privacy alias vault for {len(case_ids)} case(s) at privacy level {level}.')
    if reset_generated:
        print('Existing backfilled aliases will be discarded and rebuilt.')
    total_created = 0
    total_updated = 0
    failed = []

    for case_id in case_ids:
        try:
            summary = populate_case_privacy_aliases(case_id, reset_generated=reset_generated)
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            failed.append((case_id, str(exc)))
            print(f'  case {case_id}: FAILED ({exc})')
            continue

        upsert = summary.get('upsert') or {}
        created = int(upsert.get('created') or 0)
        updated = int(upsert.get('updated') or 0)
        truncated = int((summary.get('extracted') or {}).get('candidates_truncated') or 0)
        total_created += created
        total_updated += updated
        note = f', {truncated} candidates dropped over cap' if truncated else ''
        print(f'  case {case_id}: {created} created, {updated} updated{note}')

    print(f'Done. {total_created} aliases created, {total_updated} updated.')
    if failed:
        print(f'{len(failed)} case(s) failed; rerun the migration to retry them.')
        return 1
    return 0


def main():
    reset_generated = '--reset' in sys.argv[1:]
    app = create_app()
    with app.app_context():
        return backfill(reset_generated=reset_generated)


if __name__ == '__main__':
    raise SystemExit(main())
