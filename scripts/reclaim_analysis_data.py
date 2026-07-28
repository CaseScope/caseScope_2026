#!/usr/bin/env python3
"""Reclaim analysis data that no run stands behind.

Reports by default and deletes nothing until --apply is passed, because the
categories are inferred from run state and a run that is merely slow to finalize
must not have its working data pulled out from under it.

    scripts/reclaim_analysis_data.py                      # report only
    scripts/reclaim_analysis_data.py --apply
    scripts/reclaim_analysis_data.py --apply --category staged_candidate_events
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app


def main() -> int:
    from utils.analysis_reclaim import CATEGORIES, DEFAULT_BATCH_SIZE, reclaim

    parser = argparse.ArgumentParser(
        description='Report or reclaim analysis data no run stands behind.',
    )
    parser.add_argument(
        '--apply',
        action='store_true',
        help='Delete the rows. Without it, nothing is written.',
    )
    parser.add_argument(
        '--category',
        action='append',
        dest='categories',
        choices=sorted(CATEGORIES),
        help='Restrict to one category. Repeatable. Defaults to all of them.',
    )
    parser.add_argument('--batch-size', type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument('--json', action='store_true', help='Emit JSON only.')
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        result = reclaim(
            categories=args.categories,
            apply=args.apply,
            batch_size=args.batch_size,
        )

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return 0

    verb = 'Deleted' if result['applied'] else 'Would delete'
    print(f"{verb} {result['total_rows']:,} rows\n")
    for name, entry in result['categories'].items():
        if entry.get('error'):
            print(f"  {name}: failed - {entry['error']}")
            continue
        detail = ', '.join(
            f'{key}={value}' for key, value in entry.items() if key != 'rows'
        )
        print(f"  {name}: {entry['rows']:,} rows" + (f'  ({detail})' if detail else ''))

    wanting = result['reanalysis_recommended']
    if wanting:
        print(
            '\nCases whose behavioural baselines come from a run that did not finish.'
            '\nThe profiles are kept - they are the only baselines these cases have -'
            '\nbut the peer groups and anomaly scores built on them are only as good'
            '\nas the run that stopped, so a re-analysis is worth running:'
        )
        for case in wanting:
            print(
                f"  case {case['case_id']}: latest run {case['latest_status']}"
                f" ({case['user_profiles']} user, {case['system_profiles']} system"
                f" profiles, {case['peer_groups']} peer groups)"
            )

    if not result['applied'] and result['total_rows']:
        print('\nNothing was written. Re-run with --apply to delete.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
