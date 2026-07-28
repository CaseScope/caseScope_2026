"""Authentication event semantics shared by the stateful detectors.

Both the spray and brute-force detectors need to answer three questions about
an authentication event, and both were answering them wrongly.

Which events are authentication attempts. Only 4624, 4625 and 18456 were
counted as failures, so Kerberos was invisible. Across the indexed corpus that
missed 3,549 pre-authentication failures (4771), 3,359 failed ticket requests
(4768) and 9,605 failed NTLM validations (4776) - roughly four times as many
failures as were being counted.

Whether the event succeeded. 4771, 4768 and 4776 all report both outcomes and
carry the result in a status field, not in the event ID. Counting every 4768 as
a failure inverted the truth for the 11,116 that succeeded, and 4776 was
ignored entirely even though it splits 87,661 successes from 9,605 failures.

Where the attempt came from. Detection keyed on `src_ip`, which is a nullable
IPv4 column that almost no failure event populates: 0 of 3,549 on 4771, 0 of
97,266 on 4776, and 221 of 4,140 on 4625. The source is recoverable from other
fields, but each event family stores it differently, and one candidate field is
a trap - `source_host` is the machine that *logged* the event, so on a domain
controller it names the DC rather than the attacker.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from utils.event_time_window import (
    MIN_VALID_EVENT_TIME as EVENT_TIME_FLOOR,
    event_time_bounds_sql,
)

# Events that represent an authentication attempt of some kind.
AUTH_EVENT_IDS = ('4624', '4625', '4768', '4771', '4776', '18456')

# Events whose outcome is fixed by the event ID alone.
ALWAYS_FAILURE_EVENT_IDS = ('4625', '18456')
ALWAYS_SUCCESS_EVENT_IDS = ('4624',)

# Events that report both outcomes and carry the result in a status field.
STATUS_BEARING_EVENT_IDS = ('4768', '4771', '4776')

# Status text meaning the attempt succeeded. Kerberos reports KDC_ERR_NONE;
# NTLM credential validation reports "Status OK".
SUCCESS_STATUS_TOKENS = ('KDC_ERR_NONE', 'Status OK')

# Corrupt timestamps are excluded at both ends: events with no recoverable time
# land on the epoch and would be grouped into a single window in 1970, and
# artifact timestamps dated decades ahead would each form a window of their own.
MIN_VALID_EVENT_TIME = EVENT_TIME_FLOOR

# Source values that identify no remote party: placeholders the Windows logs
# use for "unknown", and loopback, which names the logging host itself.
UNRESOLVED_SOURCE_VALUES = ('-', '::', '0.0.0.0', 'localhost', '')
UNRESOLVED_SOURCE_PREFIXES = ('::1', '127.')


def _quoted_list(values) -> str:
    return ', '.join(f"'{value}'" for value in values)


# The status text is searched across every payload column rather than at one
# fixed index, because the column a parser writes the status into differs by
# event family: 4771 and 4776 use the third, 4768 uses the fifth.
_PAYLOAD_BLOB_EXPR = (
    "concatWithSeparator(' | ', payload_data1, payload_data2, payload_data3, "
    "payload_data4, payload_data5, payload_data6)"
)

_STATUS_OK_EXPR = ' OR '.join(
    f"positionCaseInsensitive(payload_blob, '{token}') > 0"
    for token in SUCCESS_STATUS_TOKENS
)

# Recovering the source in order of trustworthiness:
#   src_ip            - authoritative when the parser could fill it
#   workstation_name  - the clean NetBIOS name, populated on many 4625
#   payload workstation - 4776 records "Workstation: NAME" in a payload column
#   remote_host       - free text, either "NAME (IP)" or an IPv6-mapped address
#                       with an ephemeral port such as ::ffff:10.0.0.5:57392,
#                       which must have the port stripped or every connection
#                       from one host counts as a separate source
# `source_host` is deliberately absent: it is the host that wrote the event.
_SOURCE_IDENTITY_CTE = f"""
    {_PAYLOAD_BLOB_EXPR} AS payload_blob,
    ({_STATUS_OK_EXPR}) AS status_ok,
    nullIf(extract(remote_host, '([0-9]{{1,3}}\\\\.[0-9]{{1,3}}\\\\.[0-9]{{1,3}}\\\\.[0-9]{{1,3}})'), '') AS remote_ip,
    nullIf(trim(extract(remote_host, '^([^ (]+)')), '') AS remote_name,
    nullIf(trim(extract(payload_data2, '^Workstation:\\\\s*(.+)$')), '') AS payload_workstation,
    coalesce(
        nullIf(nullIf(toString(src_ip), '0.0.0.0'), ''),
        nullIf(workstation_name, ''),
        payload_workstation,
        remote_ip,
        remote_name
    ) AS raw_source_identity,
    if(
        raw_source_identity IN ({_quoted_list(UNRESOLVED_SOURCE_VALUES)})
        OR {' OR '.join(f"raw_source_identity LIKE '{prefix}%'" for prefix in UNRESOLVED_SOURCE_PREFIXES)},
        NULL,
        raw_source_identity
    ) AS source_identity,
    (
        event_id IN ({_quoted_list(ALWAYS_FAILURE_EVENT_IDS)})
        OR (event_id IN ({_quoted_list(STATUS_BEARING_EVENT_IDS)}) AND NOT status_ok)
    ) AS is_failure,
    (
        event_id IN ({_quoted_list(ALWAYS_SUCCESS_EVENT_IDS)})
        OR (event_id IN ({_quoted_list(STATUS_BEARING_EVENT_IDS)}) AND status_ok)
    ) AS is_success
"""

# Machine accounts authenticate constantly and are not what either detector is
# looking for, so they are excluded from both the targets and the totals. The
# alphanumeric requirement drops placeholder names the Windows logs write when
# no account was resolved, such as "-\-", which would otherwise be reported as
# an account under attack.
_REAL_ACCOUNT_FILTER = (
    "username != '' AND username NOT LIKE '%$' AND username NOT LIKE '##%' "
    "AND match(username, '[A-Za-z0-9]')"
)

# Interpolated into the query bodies below. The value carries a ClickHouse
# parameter placeholder of its own, which survives f-string interpolation
# because the substituted text is not scanned again.
event_bounds = event_time_bounds_sql()


def build_source_slot_query(slot_minutes: int, sample_size: int = 50) -> str:
    """Per-source authentication activity, aggregated into fixed time slots.

    The slots are deliberately much shorter than any detection window. Grouping
    straight into detection-sized buckets meant an attack straddling a boundary
    was split into two halves, each of which could fall under the thresholds;
    the caller slides a window across these slots instead.
    """
    return f"""
        WITH {_SOURCE_IDENTITY_CTE}
        SELECT
            source_identity,
            toStartOfInterval(timestamp_utc, INTERVAL {int(slot_minutes)} MINUTE) AS slot_start,
            countIf(is_failure) AS failures,
            countIf(is_success) AS successes,
            count() AS attempts,
            groupUniqArray({int(sample_size)})(username) AS usernames,
            min(timestamp_utc) AS first_event,
            max(timestamp_utc) AS last_event,
            groupArray({int(sample_size)})(tuple(timestamp_utc, username)) AS attempt_sample
        FROM events
        WHERE case_id = {{case_id:UInt32}}
          AND event_id IN ({_quoted_list(AUTH_EVENT_IDS)})
          AND {event_bounds}
          AND source_identity IS NOT NULL
          AND {_REAL_ACCOUNT_FILTER}
        GROUP BY source_identity, slot_start
        ORDER BY source_identity, slot_start
    """


def build_target_slot_query(slot_minutes: int, sample_size: int = 50) -> str:
    """Per-account authentication activity, aggregated into fixed time slots."""
    return f"""
        WITH {_SOURCE_IDENTITY_CTE}
        SELECT
            username,
            toStartOfInterval(timestamp_utc, INTERVAL {int(slot_minutes)} MINUTE) AS slot_start,
            countIf(is_failure) AS failures,
            countIf(is_success) AS successes,
            count() AS attempts,
            groupUniqArray({int(sample_size)})(coalesce(source_identity, 'unknown')) AS sources,
            min(timestamp_utc) AS first_event,
            max(timestamp_utc) AS last_event,
            groupArray({int(sample_size)})(tuple(timestamp_utc, coalesce(source_identity, 'unknown'))) AS attempt_sample
        FROM events
        WHERE case_id = {{case_id:UInt32}}
          AND event_id IN ({_quoted_list(AUTH_EVENT_IDS)})
          AND {event_bounds}
          AND {_REAL_ACCOUNT_FILTER}
        GROUP BY username, slot_start
        ORDER BY username, slot_start
    """


def build_successful_accounts_query() -> str:
    """Accounts that successfully authenticated from one source in a window."""
    return f"""
        WITH {_SOURCE_IDENTITY_CTE}
        SELECT DISTINCT username
        FROM events
        WHERE case_id = {{case_id:UInt32}}
          AND event_id IN ({_quoted_list(AUTH_EVENT_IDS)})
          AND is_success
          AND source_identity = {{source_identity:String}}
          AND timestamp_utc BETWEEN toDateTime64({{window_start:String}}, 3)
                               AND toDateTime64({{window_end:String}}, 3)
          AND {_REAL_ACCOUNT_FILTER}
        LIMIT 10
    """


def slot_query_parameters(case_id: int, **extra: Any) -> Dict[str, Any]:
    """Bound parameters shared by the slot queries."""
    parameters: Dict[str, Any] = {
        'case_id': case_id,
        'min_time': MIN_VALID_EVENT_TIME,
    }
    parameters.update(extra)
    return parameters


def resolve_thresholds(
    config: Any, spec: Dict[str, Tuple[str, Any]], overrides: Optional[Dict] = None
) -> Dict[str, Any]:
    """Resolve detector thresholds from configuration.

    `spec` maps each threshold to the configuration attribute that carries it
    and the documented default. The detectors previously kept their own default
    dictionary as well, which the configuration silently overrode: the code
    documented a brute-force minimum of 8 attempts at a 90 percent failure
    rate, while configuration supplied 20 at 95 percent, and configuration
    always won because its attribute was always present. The two are now kept
    equal, and a contract test fails if they diverge again.
    """
    resolved = {
        name: getattr(config, attribute, default)
        for name, (attribute, default) in spec.items()
    }
    if overrides:
        resolved.update(overrides)
    return resolved
