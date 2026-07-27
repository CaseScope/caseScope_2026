#!/usr/bin/env python3
"""Record a one-time reconciliation marker for pre-instrumentation evidence state.

Evidence in existing cases already carries IOC tags, analyst tags, noise flags
and MITRE mappings that were applied before those mutations were audited.
Nothing in the audit log accounts for them, and they cannot be attributed
after the fact: the mutations ran as ClickHouse user 'default' with no user
context recorded anywhere.

Rather than leave that as an unexplained gap, this writes one audit entry per
case stating what state was observed at the cutover and that it predates
instrumentation. That is a defensible position to testify to -- the trail says
plainly where it begins and what it inherited -- whereas silence invites the
inference that entries were removed.

Idempotent: a case that already has a reconciliation marker is skipped.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app

EXPLANATION = (
    "Evidence state observed at the point audit instrumentation was introduced. "
    "IOC tags, analyst tags, noise flags and MITRE mappings counted here were "
    "applied before evidence mutations were recorded, and no actor attribution "
    "exists for them. Changes from this point forward are individually audited."
)


def collect_case_state():
    """Return per-case counts of audit-relevant evidence state from ClickHouse.

    One grouped pass rather than a query per case: ClickHouse is columnar, so
    this reads only the five columns involved.
    """
    from utils.clickhouse import get_client

    client = get_client()
    result = client.query(
        """
        SELECT
            case_id,
            count() AS total_events,
            countIf(length(ioc_types) > 0) AS ioc_tagged,
            countIf(analyst_tagged) AS analyst_tagged,
            countIf(noise_matched) AS noise_matched,
            countIf(length(mitre_attack_ids) > 0) AS mitre_mapped
        FROM events
        GROUP BY case_id
        """
    )
    return {
        int(row[0]): {
            "total_events": int(row[1]),
            "ioc_tagged_events": int(row[2]),
            "analyst_tagged_events": int(row[3]),
            "noise_matched_events": int(row[4]),
            "mitre_mapped_events": int(row[5]),
        }
        for row in result.result_rows
    }


def run_migration():
    """Write a reconciliation marker for every case that lacks one."""
    app = create_app()

    with app.app_context():
        from models.audit_log import AuditAction, AuditEntityType, AuditLog
        from models.case import Case
        from models.client import Client

        print("Reading current evidence state from ClickHouse...")
        state_by_case = collect_case_state()
        print(f"Found event state for {len(state_by_case)} case(s)")

        cases = Case.query.order_by(Case.id).all()
        already_marked = {
            row.entity_id
            for row in AuditLog.query.filter_by(
                entity_type=AuditEntityType.CASE,
                action=AuditAction.RECONCILED,
            ).all()
        }

        records = []
        skipped = 0

        for case in cases:
            if case.uuid in already_marked:
                skipped += 1
                continue

            state = state_by_case.get(
                case.id,
                {
                    "total_events": 0,
                    "ioc_tagged_events": 0,
                    "analyst_tagged_events": 0,
                    "noise_matched_events": 0,
                    "mitre_mapped_events": 0,
                },
            )

            client_name = None
            if case.client_id:
                client = Client.query.filter_by(id=case.client_id).first()
                client_name = client.name if client else None

            details = dict(state)
            details["explanation"] = EXPLANATION
            details["attribution"] = "unattributed (predates evidence audit instrumentation)"

            records.append(
                {
                    "entity_type": AuditEntityType.CASE,
                    "entity_id": case.uuid,
                    "entity_name": case.name,
                    "action": AuditAction.RECONCILED,
                    "field_name": "evidence_state",
                    "old_value": None,
                    "new_value": state,
                    "case_uuid": case.uuid,
                    "client_id": case.client_id,
                    "client_name": client_name,
                    "affected_count": state["total_events"],
                    "username": "system",
                    "details": details,
                }
            )
            print(
                f"  {case.name}: {state['total_events']} events, "
                f"{state['ioc_tagged_events']} IOC-tagged, "
                f"{state['analyst_tagged_events']} analyst-tagged, "
                f"{state['noise_matched_events']} noise, "
                f"{state['mitre_mapped_events']} MITRE-mapped"
            )

        # One chain extension for the whole backfill rather than one per case.
        AuditLog.log_many(records)
        print(f"\nMarkers written: {len(records)}, already present: {skipped}")

        from utils.audit_chain import verify_chain

        result = verify_chain()
        if not result["valid"]:
            raise RuntimeError(
                f"Chain verification failed at record {result['first_inconsistent_record_id']}"
            )
        print(f"Chain verified across {result['record_count_checked']} record(s)")
        return True


if __name__ == "__main__":
    print("=" * 60)
    print("Audit Reconciliation Markers")
    print("=" * 60)
    print()

    try:
        run_migration()
        sys.exit(0)
    except Exception as exc:
        print(f"Migration failed: {exc}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
