#!/usr/bin/env python3
"""Populate Cloud AI privacy aliases from original ClickHouse events."""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db


def main() -> int:
    parser = argparse.ArgumentParser(description='Populate privacy aliases for a case.')
    parser.add_argument('--case-id', type=int, required=True)
    parser.add_argument('--batch-size', type=int, default=5000)
    parser.add_argument(
        '--reset-generated',
        action='store_true',
        help='Delete generated ai_privacy_event_backfill aliases for the case before scanning.',
    )
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        from utils.privacy_aliases import populate_case_privacy_aliases, summary_as_json

        summary = populate_case_privacy_aliases(
            args.case_id,
            batch_size=args.batch_size,
            reset_generated=args.reset_generated,
        )
        db.session.commit()
        print(summary_as_json(summary))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
