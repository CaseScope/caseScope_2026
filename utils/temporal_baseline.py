"""Comparison of an entity's recent behaviour against its own earlier baseline.

The anomaly detector declared weights for two signals it never computed:
`new_targets` at 20 percent of the composite score and `auth_method_change` at
10 percent. Neither name ever appeared in the stored deviation scores, which
only ever hold `daily_logons`, `failure_rate`, `unique_hosts` and `off_hours`
for accounts and `auth_volume` and `unique_users` for hosts. Thirty percent of
the declared weight was therefore inert.

Both are temporal questions rather than peer questions - has this account
started reaching hosts it never reached before, and has it started
authenticating by a different mechanism - so neither can be answered by
comparing it to its peers. They are answered here by splitting the entity's own
observed activity into an earlier baseline and a recent window.

Two properties of real case data shape the split.

The window is anchored at the most recent activity, never at the earliest. The
earliest timestamp is unreliable: filesystem and browser artifacts put dates
decades in the past, and several unrelated cases in the corpus begin on exactly
1990-12-03. The latest timestamp is the collection date and is trustworthy.

The split is measured in days that actually saw authentication, not calendar
days. Authentication records cover a far shorter period than the artifacts
around them - on one case 186,422 of 186,607 authentication events fall inside
the final seven days - so a split by calendar span would put almost everything
on one side. Cases whose authentication history is too short to divide are
skipped rather than scored against a baseline of nothing.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from utils.event_time_window import event_time_bounds_sql

logger = logging.getLogger(__name__)

# Authentication events that name the host being reached and the mechanism used.
TEMPORAL_EVENT_IDS = ('4624', '4625', '4768', '4771', '4776', '18456')

# The most recent slice of an entity's authentication history forms the recent
# window and everything earlier forms the baseline.
DEFAULT_RECENT_FRACTION = 0.25

# An entity needs this many authenticating days in the baseline before a
# comparison means anything. Below it the entity is skipped: a single earlier day
# would make every host look newly reached.
DEFAULT_MIN_BASELINE_DAYS = 3

# A recent window with fewer authenticating days than this is not compared
# either, because one quiet day of unusual activity is what the peer comparison
# is for.
DEFAULT_MIN_RECENT_DAYS = 1

# Reaching this many hosts absent from the baseline is treated as sitting
# exactly on the anomaly threshold, so fewer scores below it and more above.
NEW_TARGET_SIGNIFICANT_COUNT = 3.0

# At least this share of the hosts reached recently must be ones the baseline
# never saw. A service account that legitimately reaches dozens of hosts will
# always pick up a few it had not reached before; what distinguishes lateral
# movement is that most of where it went is new.
MIN_NEW_TARGET_SHARE = 0.5

# No single signal may exceed this multiple of the threshold. An account that
# reached nineteen unfamiliar hosts is not six times more anomalous than one
# that reached three, and left uncapped it would swamp every other metric in the
# composite score.
MAX_SIGNAL_MULTIPLE = 3.0

# A shift of this many percentage points toward a weaker authentication package
# sits exactly on the anomaly threshold.
AUTH_SHIFT_SIGNIFICANT_POINTS = 25.0

# Packages ordered weakest first. A move toward the front is what matters: NTLM
# in place of Kerberos is a downgrade worth reporting, the reverse is not.
WEAK_AUTH_PACKAGES = ('NTLM', 'NTLMV1', 'NTLMV2', 'WDIGEST', 'MSV1_0')

# Built-in local identities that authenticate constantly as a side effect of the
# operating system running. They are excluded from temporal comparison only -
# the peer comparison still covers them - because "reached a host it had not
# reached before" carries no meaning for the local SYSTEM account, which by
# volume is the single noisiest name in the corpus at 164,070 logons.
BUILTIN_ACCOUNT_NAMES = frozenset({
    'system', 'local service', 'network service', 'anonymous logon',
    'iusr', 'defaultapppool', 'local system',
})

# Per-session accounts the desktop stack creates, named with a session number.
BUILTIN_ACCOUNT_PREFIXES = ('dwm-', 'umfd-')


@dataclass
class TemporalSignals:
    """Temporal deviation scores and evidence for one entity."""

    key: str
    baseline_days: int
    recent_days: int
    new_targets: List[str] = field(default_factory=list)
    baseline_target_count: int = 0
    recent_target_count: int = 0
    weak_auth_shift_points: float = 0.0
    baseline_auth_mix: Dict[str, float] = field(default_factory=dict)
    recent_auth_mix: Dict[str, float] = field(default_factory=dict)

    @property
    def new_target_share(self) -> float:
        """Fraction of recently reached hosts that the baseline never saw."""
        if not self.recent_target_count:
            return 0.0
        return len(self.new_targets) / self.recent_target_count

    def deviation_scores(self, threshold: float) -> Dict[str, float]:
        """Express the signals on the same scale as the peer deviation scores.

        A signal at its significance amount is reported as exactly `threshold`,
        so it lands on the anomaly boundary and contributes the same weight to
        the composite score as a peer deviation sitting on that boundary. This
        is what lets one scale carry both kinds of evidence.
        """
        scores = {}
        ceiling = threshold * MAX_SIGNAL_MULTIPLE

        if self.new_targets and self.new_target_share >= MIN_NEW_TARGET_SHARE:
            scores['new_targets'] = min(
                ceiling,
                threshold * (len(self.new_targets) / NEW_TARGET_SIGNIFICANT_COUNT),
            )

        if self.weak_auth_shift_points > 0:
            scores['auth_method_change'] = min(
                ceiling,
                threshold * (self.weak_auth_shift_points / AUTH_SHIFT_SIGNIFICANT_POINTS),
            )

        return scores

    def evidence(self) -> Dict[str, Any]:
        """Human-readable support for whatever the scores claim."""
        detail: Dict[str, Any] = {
            'baseline_days': self.baseline_days,
            'recent_days': self.recent_days,
        }
        if self.new_targets:
            detail['new_targets'] = sorted(self.new_targets)[:20]
            detail['new_target_count'] = len(self.new_targets)
            detail['baseline_target_count'] = self.baseline_target_count
            detail['recent_target_count'] = self.recent_target_count
            detail['new_target_share'] = round(self.new_target_share * 100, 1)
        if self.weak_auth_shift_points > 0:
            detail['weak_auth_shift_points'] = round(self.weak_auth_shift_points, 1)
            detail['baseline_auth_mix'] = self.baseline_auth_mix
            detail['recent_auth_mix'] = self.recent_auth_mix
        return detail


def build_activity_day_query() -> str:
    """Days on which each account authenticated, with the hosts and packages.

    One row per account per day keeps the result proportional to the number of
    authenticating days rather than to the number of events, which is what makes
    it affordable to split the history per account in Python.

    The host reached is taken only from the interactive and network logon events,
    where the machine that wrote the record is the machine being logged into. The
    Kerberos events are deliberately excluded from that part: a ticket request is
    recorded by the domain controller, so treating its `source_host` as the
    destination would name the DC as a target for every account in the domain and
    make ordinary accounts appear to be reaching new hosts constantly. Those
    events still contribute their authentication package.
    """
    builtin_names = ', '.join(f"'{name}'" for name in sorted(BUILTIN_ACCOUNT_NAMES))
    builtin_prefixes = ' OR '.join(
        f"lower(username) LIKE '{prefix}%'" for prefix in BUILTIN_ACCOUNT_PREFIXES
    )

    return """
        SELECT
            lower(username) AS entity,
            toDate(timestamp_utc) AS activity_day,
            groupUniqArray(50)(target) AS targets,
            groupUniqArray(10)(package) AS packages,
            count() AS attempts
        FROM (
            SELECT
                username,
                timestamp_utc,
                if(
                    event_id IN ('4624', '4625'),
                    nullIf(trim(upper(source_host)), ''),
                    NULL
                ) AS target,
                nullIf(trim(upper(auth_package)), '') AS package
            FROM events
            WHERE case_id = {case_id:UInt32}
              AND event_id IN (""" + ', '.join(f"'{eid}'" for eid in TEMPORAL_EVENT_IDS) + """)
              AND """ + event_time_bounds_sql() + """
              AND username != ''
              AND username NOT LIKE '%$'
              AND username NOT LIKE '##%'
              AND match(username, '[A-Za-z0-9]')
              AND lower(username) NOT IN (""" + builtin_names + """)
              AND NOT (""" + builtin_prefixes + """)
        )
        GROUP BY entity, activity_day
        ORDER BY entity, activity_day
    """


@dataclass
class _DayActivity:
    targets: Set[str]
    packages: Dict[str, int]
    attempts: int


def _weak_share(packages: Dict[str, int]) -> float:
    """Percentage of attempts using a weaker authentication package."""
    total = sum(packages.values())
    if not total:
        return 0.0
    weak = sum(
        count for package, count in packages.items()
        if package.upper() in WEAK_AUTH_PACKAGES
    )
    return (weak / total) * 100.0


def _auth_mix(packages: Dict[str, int]) -> Dict[str, float]:
    total = sum(packages.values())
    if not total:
        return {}
    return {
        package: round((count / total) * 100.0, 1)
        for package, count in sorted(packages.items(), key=lambda item: -item[1])
    }


def split_entity_history(
    days: Sequence,
    *,
    recent_fraction: float = DEFAULT_RECENT_FRACTION,
    min_baseline_days: int = DEFAULT_MIN_BASELINE_DAYS,
    min_recent_days: int = DEFAULT_MIN_RECENT_DAYS,
) -> Optional[tuple]:
    """Split ordered activity days into (baseline, recent), anchored at the end.

    Returns None when the history cannot support a comparison.
    """
    ordered = sorted(days, key=lambda entry: entry[0])
    if len(ordered) < min_baseline_days + min_recent_days:
        return None

    recent_count = max(min_recent_days, round(len(ordered) * recent_fraction))
    # Never let the recent window eat into the minimum baseline.
    recent_count = min(recent_count, len(ordered) - min_baseline_days)
    if recent_count < min_recent_days:
        return None

    split_at = len(ordered) - recent_count
    return ordered[:split_at], ordered[split_at:]


def compute_temporal_signals(
    rows: Iterable[Sequence],
    *,
    recent_fraction: float = DEFAULT_RECENT_FRACTION,
    min_baseline_days: int = DEFAULT_MIN_BASELINE_DAYS,
    min_recent_days: int = DEFAULT_MIN_RECENT_DAYS,
) -> Dict[str, TemporalSignals]:
    """Temporal signals per entity, from the activity-day query rows.

    Rows arrive as (entity, activity_day, targets, packages, attempts).
    """
    per_entity: Dict[str, List] = {}

    for row in rows:
        entity = str(row[0] or '').strip().lower()
        if not entity:
            continue
        targets = {str(value).strip() for value in (row[2] or ()) if value}
        packages = {str(value).strip(): 1 for value in (row[3] or ()) if value}
        per_entity.setdefault(entity, []).append(
            (row[1], _DayActivity(targets=targets, packages=packages, attempts=int(row[4] or 0)))
        )

    signals: Dict[str, TemporalSignals] = {}

    for entity, days in per_entity.items():
        split = split_entity_history(
            days,
            recent_fraction=recent_fraction,
            min_baseline_days=min_baseline_days,
            min_recent_days=min_recent_days,
        )
        if not split:
            continue

        baseline_days, recent_days = split

        baseline_targets: Set[str] = set()
        baseline_packages: Dict[str, int] = {}
        for _day, activity in baseline_days:
            baseline_targets |= activity.targets
            for package in activity.packages:
                baseline_packages[package] = baseline_packages.get(package, 0) + 1

        recent_targets: Set[str] = set()
        recent_packages: Dict[str, int] = {}
        for _day, activity in recent_days:
            recent_targets |= activity.targets
            for package in activity.packages:
                recent_packages[package] = recent_packages.get(package, 0) + 1

        # A baseline that recorded no targets at all cannot establish that any
        # host is newly reached.
        new_targets = sorted(recent_targets - baseline_targets) if baseline_targets else []

        weak_shift = _weak_share(recent_packages) - _weak_share(baseline_packages)

        signals[entity] = TemporalSignals(
            key=entity,
            baseline_days=len(baseline_days),
            recent_days=len(recent_days),
            new_targets=new_targets,
            baseline_target_count=len(baseline_targets),
            recent_target_count=len(recent_targets),
            weak_auth_shift_points=max(0.0, weak_shift),
            baseline_auth_mix=_auth_mix(baseline_packages),
            recent_auth_mix=_auth_mix(recent_packages),
        )

    return signals


def load_temporal_signals(client, case_id: int, **options) -> Dict[str, TemporalSignals]:
    """Run the activity-day query for a case and reduce it to per-entity signals."""
    from utils.event_time_window import event_time_parameters

    result = client.query(
        build_activity_day_query(),
        parameters={'case_id': case_id, **event_time_parameters()},
    )
    return compute_temporal_signals(result.result_rows, **options)
