#!/opt/casescope/venv/bin/python3
"""Repair per-case ClickHouse event overlay state."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from flask import Flask

from config import Config
from models.case import Case
from models.database import db
from tasks.noise_tagger import tag_noise_events
from utils.event_overlay_repair import (
    get_case_event_overlay_row_counts,
    get_case_legacy_overlay_selector_counts,
    purge_case_event_overlay_state,
)
from utils.ioc_artifact_tagger import tag_all_iocs_globally


def build_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    return app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Repair stale event overlay state for a case.")
    parser.add_argument("--case-id", type=int, help="Numeric PostgreSQL case.id")
    parser.add_argument("--case-uuid", help="Case UUID")
    parser.add_argument("--username", default="system", help="Username recorded for rebuild operations")
    parser.add_argument("--skip-analyst", action="store_true", help="Do not clear analyst overlay rows")
    parser.add_argument("--skip-ioc", action="store_true", help="Do not clear IOC overlay rows")
    parser.add_argument("--skip-noise", action="store_true", help="Do not clear noise overlay rows")
    parser.add_argument("--retag-iocs", action="store_true", help="Rebuild IOC overlay rows after cleanup")
    parser.add_argument("--rescan-noise", action="store_true", help="Rebuild noise overlay rows after cleanup")
    return parser.parse_args()


def resolve_case(args: argparse.Namespace) -> Case:
    if not args.case_id and not args.case_uuid:
        raise ValueError("Either --case-id or --case-uuid is required")
    if args.case_id:
        case = Case.get_by_id(args.case_id)
    else:
        case = Case.get_by_uuid(args.case_uuid)
    if not case:
        raise ValueError("Case not found")
    return case


def main() -> int:
    args = parse_args()
    app = build_app()

    with app.app_context():
        case = resolve_case(args)
        include_analyst = not args.skip_analyst
        include_ioc = not args.skip_ioc
        include_noise = not args.skip_noise

        before_counts = get_case_event_overlay_row_counts(
            case.id,
            include_analyst=include_analyst,
            include_ioc=include_ioc,
            include_noise=include_noise,
        )
        legacy_counts = get_case_legacy_overlay_selector_counts(case.id)
        purge_summary = purge_case_event_overlay_state(
            case.id,
            wait=True,
            include_analyst=include_analyst,
            include_ioc=include_ioc,
            include_noise=include_noise,
        )

        rebuild_summary = {}
        if args.retag_iocs and include_ioc:
            rebuild_summary["ioc"] = tag_all_iocs_globally(case.id)
        if args.rescan_noise and include_noise:
            rebuild_summary["noise"] = tag_noise_events.run(case.id, args.username)

        after_counts = get_case_event_overlay_row_counts(
            case.id,
            include_analyst=include_analyst,
            include_ioc=include_ioc,
            include_noise=include_noise,
        )

        print(
            json.dumps(
                {
                    "case_id": case.id,
                    "case_uuid": case.uuid,
                    "before_counts": before_counts,
                    "legacy_selector_counts": legacy_counts,
                    "purge_summary": purge_summary,
                    "rebuild_summary": rebuild_summary,
                    "after_counts": after_counts,
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
