"""Phase 1.6 behavioral profiler set-based queries and canonical comparators.

Production ``profile_users`` / ``profile_systems`` still use the per-principal
path until the parity gate is green. This module can capture both modes
without writing PostgreSQL profile rows.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from utils.event_time_window import event_time_bounds_sql
from utils.phase1_step3_ioc_recall import CountingClient


USER_METRIC_KEYS = (
    "total_events",
    "profile_period_start",
    "profile_period_end",
    "activity_hours",
    "activity_days",
    "peak_hours",
    "off_hours_percentage",
    "total_logons",
    "logon_success_rate",
    "auth_types",
    "typical_source_hosts",
    "typical_target_hosts",
    "unique_hosts_accessed",
    "avg_daily_logons",
    "std_daily_logons",
    "max_daily_logons",
    "failure_rate",
    "avg_daily_failures",
    "anomaly_thresholds",
)

SYSTEM_METRIC_KEYS = (
    "total_events",
    "profile_period_start",
    "profile_period_end",
    "system_role",
    "activity_hours",
    "typical_users",
    "unique_users",
    "typical_source_ips",
    "typical_processes",
    "auth_destination_volume",
    "anomaly_thresholds",
)

ROLE_FIELDS = ("source_host", "workstation_name", "remote_host")
PRINCIPAL_CHUNK = 250


def _ch_quote(value: Any) -> str:
    return "'" + str(value or "").replace("\\", "\\\\").replace("'", "\\'") + "'"


def _json_ready(value: Any) -> Any:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _json_ready(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, list):
        return [_json_ready(v) for v in value]
    if isinstance(value, float):
        return round(value, 6)
    return value


def stable_peak_hours(activity_hours: Dict[str, Any], n: int = 3) -> List[int]:
    items = []
    for hour, count in (activity_hours or {}).items():
        try:
            items.append((int(hour), int(count or 0)))
        except (TypeError, ValueError):
            continue
    items.sort(key=lambda kv: (-kv[1], kv[0]))
    return [hour for hour, _count in items[:n]]


def top_n_stable_core(items: Optional[List[Dict[str, Any]]]) -> Dict[str, int]:
    """Drop the unstable cutoff tail (many values sharing the 10th-place count)."""
    rows = list(items or [])
    if not rows:
        return {}
    counts = [int(row.get("count") or 0) for row in rows]
    cutoff = min(counts)
    return {
        str(row.get("value") or ""): int(row.get("count") or 0)
        for row in rows
        if int(row.get("count") or 0) > cutoff
    }


def canonicalize_top_n(items: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    rows = list(items or [])
    rows.sort(key=lambda row: (-int(row.get("count") or 0), str(row.get("value") or "")))
    return rows


def canonicalize_user_profile(payload: Dict[str, Any]) -> Dict[str, Any]:
    out = {key: _json_ready(payload.get(key)) for key in (
        "identity", "username", "sid", *USER_METRIC_KEYS
    )}
    hours = payload.get("activity_hours") or {}
    out["peak_hours"] = stable_peak_hours(hours)
    out["typical_source_hosts"] = canonicalize_top_n(payload.get("typical_source_hosts"))
    out["typical_target_hosts"] = canonicalize_top_n(payload.get("typical_target_hosts"))
    out["typical_source_hosts_core"] = top_n_stable_core(payload.get("typical_source_hosts"))
    out["typical_target_hosts_core"] = top_n_stable_core(payload.get("typical_target_hosts"))
    return out


def canonicalize_system_profile(payload: Dict[str, Any]) -> Dict[str, Any]:
    out = {key: _json_ready(payload.get(key)) for key in (
        "identity", "hostname", *SYSTEM_METRIC_KEYS, "roles"
    )}
    out["typical_users"] = canonicalize_top_n(payload.get("typical_users"))
    out["typical_source_ips"] = canonicalize_top_n(payload.get("typical_source_ips"))
    out["typical_processes"] = canonicalize_top_n(payload.get("typical_processes"))
    out["typical_users_core"] = top_n_stable_core(payload.get("typical_users"))
    out["typical_source_ips_core"] = top_n_stable_core(payload.get("typical_source_ips"))
    out["typical_processes_core"] = top_n_stable_core(payload.get("typical_processes"))
    roles = payload.get("roles") or {}
    out["roles"] = {
        role: _json_ready(roles.get(role) or {"event_count": 0, "first_seen": None, "last_seen": None})
        for role in ROLE_FIELDS
    }
    return out


def profile_digest(payloads: Sequence[Dict[str, Any]]) -> str:
    blob = json.dumps(list(payloads), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _user_values_sql(users: Sequence[Any]) -> str:
    parts = []
    for user in users:
        parts.append(
            f"({int(user.id)}, {_ch_quote(user.username)}, {_ch_quote(user.sid)})"
        )
    return ", ".join(parts) if parts else "(toUInt32(0), '', '')"


def _system_values_sql(systems: Sequence[Any]) -> str:
    parts = []
    for system in systems:
        parts.append(
            f"({int(system.id)}, {_ch_quote((system.hostname or '').upper())})"
        )
    return ", ".join(parts) if parts else "(toUInt32(0), '')"


def fetch_user_rows_legacy(profiler, username: str, sid: str):
    from utils.behavioral_profiler import MIN_VALID_EVENT_TIME

    client = profiler._get_clickhouse_client()
    parameters: Dict[str, Any] = {
        "case_id": profiler.case_id,
        "tz": profiler.case_tz,
        "min_time": MIN_VALID_EVENT_TIME,
    }
    user_filters = []
    if username:
        user_filters.append("lower(username) = lower({username:String})")
        parameters["username"] = username
    if sid:
        user_filters.append("sid = {sid:String}")
        parameters["sid"] = sid
    if not user_filters:
        return []
    user_filter = f"({' OR '.join(user_filters)})"
    query = """
        SELECT
            toHour(toTimeZone(timestamp_utc, {tz:String})) as hour,
            toDayOfWeek(toTimeZone(timestamp_utc, {tz:String})) as day_of_week,
            toDate(toTimeZone(timestamp_utc, {tz:String})) as date,
            event_id,
            source_host,
            remote_host,
            auth_package,
            logon_type,
            count() as event_count
        FROM events
        WHERE case_id = {case_id:UInt32}
          AND """ + event_time_bounds_sql() + """
          AND """ + user_filter + """
        GROUP BY hour, day_of_week, date, event_id, source_host, remote_host, auth_package, logon_type
    """
    result = client.query(query, parameters=parameters)
    return result.result_rows or []


def fetch_system_rows_legacy(profiler, hostname: str):
    from utils.behavioral_profiler import MIN_VALID_EVENT_TIME

    client = profiler._get_clickhouse_client()
    parameters = {
        "case_id": profiler.case_id,
        "tz": profiler.case_tz,
        "min_time": MIN_VALID_EVENT_TIME,
        "hostname": (hostname or "").upper(),
    }
    query = """
        SELECT
            toHour(toTimeZone(timestamp_utc, {tz:String})) as hour,
            toDate(toTimeZone(timestamp_utc, {tz:String})) as date,
            username,
            src_ip,
            event_id,
            process_name,
            count() as event_count
        FROM events
        WHERE case_id = {case_id:UInt32}
          AND """ + event_time_bounds_sql() + """
          AND (upper(source_host) = {hostname:String}
               OR upper(workstation_name) = {hostname:String}
               OR upper(remote_host) = {hostname:String})
        GROUP BY hour, date, username, src_ip, event_id, process_name
    """
    result = client.query(query, parameters=parameters)
    return result.result_rows or []


def fetch_user_rows_set_based(profiler, users: Sequence[Any]) -> Dict[int, List[Tuple]]:
    """One case-wide grouped query, then map username OR SID onto KnownUsers."""
    from utils.behavioral_profiler import MIN_VALID_EVENT_TIME

    client = profiler._get_clickhouse_client()
    grouped: Dict[int, List[Tuple]] = defaultdict(list)
    eligible = [user for user in users if user.username or user.sid]
    if not eligible:
        return {}

    by_username: Dict[str, List[int]] = defaultdict(list)
    by_sid: Dict[str, List[int]] = defaultdict(list)
    for user in eligible:
        if user.username:
            by_username[str(user.username).lower()].append(int(user.id))
        if user.sid:
            by_sid[str(user.sid)].append(int(user.id))

    usernames = [str(user.username).lower() for user in eligible if user.username]
    sids = [str(user.sid) for user in eligible if user.sid]
    user_pred = []
    parameters = {
        "case_id": profiler.case_id,
        "tz": profiler.case_tz,
        "min_time": MIN_VALID_EVENT_TIME,
    }
    if usernames:
        parameters["usernames"] = usernames
        user_pred.append("lower(username) IN {usernames:Array(String)}")
    if sids:
        parameters["sids"] = sids
        user_pred.append("sid IN {sids:Array(String)}")
    identity_filter = " OR ".join(user_pred)

    query = """
        SELECT
            username,
            sid,
            toHour(toTimeZone(timestamp_utc, {tz:String})) as hour,
            toDayOfWeek(toTimeZone(timestamp_utc, {tz:String})) as day_of_week,
            toDate(toTimeZone(timestamp_utc, {tz:String})) as date,
            event_id,
            source_host,
            remote_host,
            auth_package,
            logon_type,
            count() as event_count
        FROM events
        WHERE case_id = {case_id:UInt32}
          AND """ + event_time_bounds_sql() + """
          AND (""" + identity_filter + """)
        GROUP BY username, sid, hour, day_of_week, date, event_id, source_host, remote_host, auth_package, logon_type
    """
    result = client.query(query, parameters=parameters)
    for row in result.result_rows or []:
        username, sid = row[0], row[1]
        rest = tuple(row[2:])
        matched = set()
        if username:
            matched.update(by_username.get(str(username).lower(), ()))
        if sid:
            matched.update(by_sid.get(str(sid), ()))
        for user_id in matched:
            grouped[user_id].append(rest)
    return grouped


def fetch_system_rows_set_based(profiler, systems: Sequence[Any]) -> Tuple[Dict[int, List[Tuple]], Dict[int, Dict[str, Dict[str, Any]]]]:
    """One case-wide grouped query. OR-match hostnames; count each grouped row once per system."""
    from utils.behavioral_profiler import MIN_VALID_EVENT_TIME

    client = profiler._get_clickhouse_client()
    grouped: Dict[int, List[Tuple]] = defaultdict(list)
    role_stats: Dict[int, Dict[str, Dict[str, Any]]] = defaultdict(
        lambda: {role: {"event_count": 0, "first_seen": None, "last_seen": None} for role in ROLE_FIELDS}
    )
    eligible = [system for system in systems if system.hostname]
    if not eligible:
        return {}, {}

    by_host: Dict[str, List[int]] = defaultdict(list)
    for system in eligible:
        by_host[str(system.hostname).upper()].append(int(system.id))

    hosts = [str(system.hostname).upper() for system in eligible]
    query = """
        SELECT
            upper(source_host) AS source_host,
            upper(workstation_name) AS workstation_name,
            upper(remote_host) AS remote_host,
            toHour(toTimeZone(timestamp_utc, {tz:String})) as hour,
            toDate(toTimeZone(timestamp_utc, {tz:String})) as date,
            username,
            src_ip,
            event_id,
            process_name,
            count() as event_count
        FROM events
        WHERE case_id = {case_id:UInt32}
          AND """ + event_time_bounds_sql() + """
          AND (
                upper(source_host) IN {hosts:Array(String)}
                OR upper(workstation_name) IN {hosts:Array(String)}
                OR upper(remote_host) IN {hosts:Array(String)}
          )
        GROUP BY source_host, workstation_name, remote_host, hour, date, username, src_ip, event_id, process_name
    """
    result = client.query(
        query,
        parameters={
            "case_id": profiler.case_id,
            "tz": profiler.case_tz,
            "min_time": MIN_VALID_EVENT_TIME,
            "hosts": hosts,
        },
    )
    for row in result.result_rows or []:
        source_host, workstation_name, remote_host = row[0], row[1], row[2]
        rest = tuple(row[3:])
        count = int(row[-1] or 0)
        date_value = row[4]
        matched = set()
        role_hits = {
            "source_host": source_host,
            "workstation_name": workstation_name,
            "remote_host": remote_host,
        }
        for role, host in role_hits.items():
            if not host:
                continue
            for system_id in by_host.get(str(host), ()):
                matched.add(system_id)
                stats = role_stats[system_id][role]
                stats["event_count"] += count
                if stats["first_seen"] is None or (date_value is not None and date_value < stats["first_seen"]):
                    stats["first_seen"] = date_value
                if stats["last_seen"] is None or (date_value is not None and date_value > stats["last_seen"]):
                    stats["last_seen"] = date_value
        for system_id in matched:
            grouped[system_id].append(rest)
    return grouped, role_stats


def fetch_system_role_stats(profiler, systems: Sequence[Any]) -> Dict[int, Dict[str, Dict[str, Any]]]:
    """Legacy-mode role diagnostic. Set-based mode computes this during the main fetch."""
    from utils.behavioral_profiler import MIN_VALID_EVENT_TIME

    client = profiler._get_clickhouse_client()
    stats: Dict[int, Dict[str, Dict[str, Any]]] = defaultdict(
        lambda: {role: {"event_count": 0, "first_seen": None, "last_seen": None} for role in ROLE_FIELDS}
    )
    eligible = [system for system in systems if system.hostname]
    if not eligible:
        return {}
    unions = []
    for role in ROLE_FIELDS:
        unions.append(f"""
            SELECT
                s.1 AS system_id,
                '{role}' AS role,
                count() AS event_count,
                min(toDate(toTimeZone(timestamp_utc, {{tz:String}}))) AS first_seen,
                max(toDate(toTimeZone(timestamp_utc, {{tz:String}}))) AS last_seen
            FROM events
            ARRAY JOIN [{_system_values_sql(eligible)}] AS s
            WHERE case_id = {{case_id:UInt32}}
              AND """ + event_time_bounds_sql() + f"""
              AND upper({role}) = s.2
            GROUP BY system_id, role
        """)
    query = " UNION ALL ".join(unions)
    result = client.query(
        query,
        parameters={
            "case_id": profiler.case_id,
            "tz": profiler.case_tz,
            "min_time": MIN_VALID_EVENT_TIME,
        },
    )
    for row in result.result_rows or []:
        system_id, role, count, first_seen, last_seen = row
        stats[int(system_id)][str(role)] = {
            "event_count": int(count or 0),
            "first_seen": first_seen,
            "last_seen": last_seen,
        }
    return stats


def user_payload_from_rows(profiler, user, rows) -> Optional[Dict[str, Any]]:
    metrics = profiler._user_metrics_from_rows(rows)
    if not metrics:
        return None
    return canonicalize_user_profile({
        "identity": f"user:{user.id}",
        "username": user.username,
        "sid": user.sid,
        **metrics,
    })


def system_payload_from_rows(profiler, system, rows, roles=None) -> Optional[Dict[str, Any]]:
    metrics = profiler._system_metrics_from_rows(rows, system.hostname)
    if not metrics:
        return None
    return canonicalize_system_profile({
        "identity": f"system:{system.id}",
        "hostname": system.hostname,
        "roles": roles or {},
        **metrics,
    })


def capture_profiles(profiler, users, systems, *, mode: str = "legacy") -> Dict[str, Any]:
    """Capture canonical profiler output without writing PostgreSQL profiles."""
    started = time.perf_counter()
    client = profiler._get_clickhouse_client()
    counting = CountingClient(client)
    profiler.ch_client = counting

    user_payloads = []
    system_payloads = []
    skipped_users = 0
    skipped_systems = 0

    if mode == "legacy":
        for user in users:
            rows = fetch_user_rows_legacy(profiler, user.username, user.sid)
            payload = user_payload_from_rows(profiler, user, rows)
            if payload:
                user_payloads.append(payload)
            else:
                skipped_users += 1
        role_stats = fetch_system_role_stats(profiler, systems)
        for system in systems:
            rows = fetch_system_rows_legacy(profiler, system.hostname)
            payload = system_payload_from_rows(
                profiler, system, rows, roles=role_stats.get(system.id)
            )
            if payload:
                system_payloads.append(payload)
            else:
                skipped_systems += 1
        expected_queries = len(users) + len(systems) + (1 if systems else 0)
    elif mode == "set_based":
        user_rows = fetch_user_rows_set_based(profiler, users)
        for user in users:
            payload = user_payload_from_rows(profiler, user, user_rows.get(user.id, []))
            if payload:
                user_payloads.append(payload)
            else:
                skipped_users += 1
        system_rows, role_stats = fetch_system_rows_set_based(profiler, systems)
        for system in systems:
            payload = system_payload_from_rows(
                profiler, system, system_rows.get(system.id, []), roles=role_stats.get(system.id)
            )
            if payload:
                system_payloads.append(payload)
            else:
                skipped_systems += 1
        expected_queries = (1 if users else 0) + (1 if systems else 0)
    else:
        raise ValueError(f"Unknown profiler mode {mode}")

    user_payloads.sort(key=lambda row: row["identity"])
    system_payloads.sort(key=lambda row: row["identity"])
    return {
        "mode": mode,
        "case_id": profiler.case_id,
        "users": user_payloads,
        "systems": system_payloads,
        "users_profiled": len(user_payloads),
        "systems_profiled": len(system_payloads),
        "users_skipped_below_min": skipped_users,
        "systems_skipped_below_min": skipped_systems,
        "clickhouse_statements": counting.statements,
        "clickhouse_query_wall_ms": round(counting.query_wall_ms, 3),
        "rows_returned": counting.rows_returned,
        "expected_bounded_statements": expected_queries,
        "wall_ms": round((time.perf_counter() - started) * 1000.0, 3),
        "user_digest": profile_digest(user_payloads),
        "system_digest": profile_digest(system_payloads),
    }


def _payload_for_diff(row: Dict[str, Any], kind: str) -> Dict[str, Any]:
    skip = {
        "typical_source_hosts",
        "typical_target_hosts",
        "typical_users",
        "typical_source_ips",
        "typical_processes",
    }
    return {key: value for key, value in row.items() if key not in skip}


def diff_canonical(legacy: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    user_mismatch = []
    legacy_users = {row["identity"]: row for row in legacy.get("users") or []}
    new_users = {row["identity"]: row for row in new.get("users") or []}
    for identity in sorted(set(legacy_users) | set(new_users)):
        left = _payload_for_diff(legacy_users.get(identity) or {}, "user")
        right = _payload_for_diff(new_users.get(identity) or {}, "user")
        if left != right:
            user_mismatch.append(identity)
    system_mismatch = []
    legacy_systems = {row["identity"]: row for row in legacy.get("systems") or []}
    new_systems = {row["identity"]: row for row in new.get("systems") or []}
    for identity in sorted(set(legacy_systems) | set(new_systems)):
        left = _payload_for_diff(legacy_systems.get(identity) or {}, "system")
        right = _payload_for_diff(new_systems.get(identity) or {}, "system")
        if left != right:
            system_mismatch.append(identity)
    return {
        "user_set_a_minus_b": sorted(set(legacy_users) - set(new_users)),
        "user_set_b_minus_a": sorted(set(new_users) - set(legacy_users)),
        "system_set_a_minus_b": sorted(set(legacy_systems) - set(new_systems)),
        "system_set_b_minus_a": sorted(set(new_systems) - set(legacy_systems)),
        "user_payload_mismatches": user_mismatch,
        "system_payload_mismatches": system_mismatch,
        "user_digest_equal": legacy.get("user_digest") == new.get("user_digest"),
        "system_digest_equal": legacy.get("system_digest") == new.get("system_digest"),
        "semantic_parity": not user_mismatch and not system_mismatch,
        "existing_nondeterministic_top_n": True,
        "top_n_compared_as_stable_core": True,
    }
