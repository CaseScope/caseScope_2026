"""Bounded deterministic evidence context for Investigation Graph anchors."""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from utils.graph_query import EVIDENCE_EVENT_COLUMNS, EVIDENCE_RECORD_KEY_RE, GraphNotFoundError, GraphQueryError


DEFAULT_CONTEXT_LIMIT = 100
MAX_CONTEXT_LIMIT = 500
WINDOWS = {
    "1s": timedelta(seconds=1),
    "30s": timedelta(seconds=30),
    "5m": timedelta(minutes=5),
    "1h": timedelta(hours=1),
}
MODES = {"relative", "same_host", "same_user", "process_lifetime", "logon_session"}
PROCESS_CREATION_EVENTS = {
    ("4688", "security"),
    ("1", "sysmon"),
    ("processrollup2", "crowdstrike"),
}
PROCESS_TERMINATION_EVENTS = {
    ("4689", "security"),
    ("5", "sysmon"),
}


class InvestigationContextError(GraphQueryError):
    """Raised for client-correctable context request errors."""


class InvestigationContextService:
    """Answer bounded evidence-context questions without graph mutation or AI."""

    def __init__(self, client=None):
        self.client = client

    def context(
        self,
        case_id: int,
        *,
        anchor_erk: str | None = None,
        anchor_timestamp: str | datetime | None = None,
        window: str = "30s",
        mode: str = "relative",
        source_types: Any = None,
        all_hosts: Any = False,
        limit: Any = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        case_id = int(case_id)
        mode = self._mode(mode)
        duration = self._window(window)
        effective_limit = self._limit(limit)
        source_type_values = self._source_types(source_types)
        all_hosts = self._bool(all_hosts)
        client = self._client()

        anchor = self._resolve_anchor(case_id, anchor_erk=anchor_erk, anchor_timestamp=anchor_timestamp, client=client)
        filters, identity_resolution = self._mode_filters(mode, anchor, all_hosts=all_hosts, client=client, case_id=case_id)

        start = anchor["timestamp_dt"] - duration
        end = anchor["timestamp_dt"] + duration
        if mode == "process_lifetime":
            start = filters.pop("time_start", start)
            end = filters.pop("time_end", end)
        cursor_values = self._decode_cursor(cursor)
        if filters.pop("unresolved", False):
            return self._response(
                anchor=anchor,
                mode=mode,
                window=window,
                identity_resolution=identity_resolution,
                records=[],
                truncated=False,
                next_cursor=None,
                effective_limit=effective_limit,
            )

        sql_filters = [
            "case_id = {case_id:UInt32}",
            "COALESCE(timestamp_utc, timestamp) >= {time_start:DateTime64(3)}",
            "COALESCE(timestamp_utc, timestamp) <= {time_end:DateTime64(3)}",
        ]
        params = {
            "case_id": case_id,
            "time_start": self._ch_dt(start),
            "time_end": self._ch_dt(end),
        }
        if source_type_values:
            sql_filters.append("artifact_type IN {source_types:Array(String)}")
            params["source_types"] = source_type_values
        for index, item in enumerate(filters.get("equals", [])):
            field = item["field"]
            name = f"filter_{index}"
            param_type = item.get("type") or "String"
            sql_filters.append(f"{field} = {{{name}:{param_type}}}")
            params[name] = item["value"]
        for item in filters.get("not_empty", []):
            sql_filters.append(f"{item} != ''")
        logical = self._fetch_logical_records(
            client,
            sql_filters,
            params,
            cursor_values=cursor_values,
            logical_target=effective_limit + 1,
        )
        page_records = logical[:effective_limit]
        truncated = len(logical) > effective_limit

        return self._response(
            anchor=anchor,
            mode=mode,
            window=window,
            identity_resolution=identity_resolution,
            records=page_records,
            truncated=truncated,
            next_cursor=self._encode_cursor(page_records[-1]) if truncated and page_records else None,
            effective_limit=effective_limit,
        )

    def _response(
        self,
        *,
        anchor: dict[str, Any],
        mode: str,
        window: str,
        identity_resolution: dict[str, Any],
        records: list[dict[str, Any]],
        truncated: bool,
        next_cursor: str | None,
        effective_limit: int,
    ) -> dict[str, Any]:
        return {
            "anchor": {
                "kind": anchor["kind"],
                "evidence_record_key": anchor.get("evidence_record_key"),
                "timestamp": anchor["timestamp_dt"].isoformat().replace("+00:00", "Z"),
                "stable_reference": None,
                "duplicates_detected": anchor.get("duplicates_detected", False),
                "duplicate_rows_returned": anchor.get("duplicate_rows_returned", 1),
            },
            "mode": mode,
            "window": window,
            "time_boundary": "inclusive: anchor_time - window <= timestamp <= anchor_time + window",
            "identity_resolution": identity_resolution,
            "records": records,
            "truncated": truncated,
            "next_cursor": next_cursor,
            "limit": effective_limit,
        }

    def _resolve_anchor(self, case_id: int, *, anchor_erk, anchor_timestamp, client) -> dict[str, Any]:
        if anchor_erk:
            anchor_erk = str(anchor_erk).strip()
            if not EVIDENCE_RECORD_KEY_RE.fullmatch(anchor_erk):
                raise InvestigationContextError("Invalid evidence record key; expected ^erk:v2:[0-9a-f]{64}$")
            sql = f"""
                SELECT {', '.join(EVIDENCE_EVENT_COLUMNS)}
                FROM events
                WHERE case_id = {{case_id:UInt32}}
                  AND evidence_record_key = {{evidence_record_key:String}}
                ORDER BY COALESCE(timestamp_utc, timestamp) ASC, selector_key ASC
                LIMIT {{limit:UInt32}}
            """
            result = client.query(
                sql,
                parameters={"case_id": case_id, "evidence_record_key": anchor_erk, "limit": MAX_CONTEXT_LIMIT + 1},
            )
            rows = list(result.result_rows or [])
            if not rows:
                raise GraphNotFoundError("Evidence not found")
            records = [self._event_dict(row, list(result.column_names)) for row in rows]
            first = records[0]
            ts = self._parse_timestamp(first.get("timestamp_utc") or first.get("timestamp"))
            if ts is None:
                raise InvestigationContextError("Anchor evidence has no timestamp")
            return {
                "kind": "evidence",
                "event": first,
                "evidence_record_key": anchor_erk,
                "timestamp_dt": ts,
                "duplicates_detected": len(rows) > 1,
                "duplicate_rows_returned": len(rows),
            }
        if anchor_timestamp:
            ts = self._parse_timestamp(anchor_timestamp)
            if ts is None:
                raise InvestigationContextError("Invalid anchor_timestamp")
            return {"kind": "timestamp", "event": {}, "evidence_record_key": None, "timestamp_dt": ts}
        raise InvestigationContextError("anchor_erk or anchor_timestamp is required")

    def _mode_filters(self, mode: str, anchor: dict[str, Any], *, all_hosts: bool, client, case_id: int):
        event = anchor.get("event") or {}
        filters = {"equals": [], "not_empty": []}
        resolution = {"status": "resolved", "basis": "exact ERK" if anchor.get("evidence_record_key") else "timestamp", "warning": None}

        host = str(event.get("source_host") or "").strip()
        if mode == "relative":
            if host and not all_hosts:
                filters["equals"].append({"field": "source_host", "value": host})
                resolution["basis"] = "exact ERK + anchor source_host"
            elif not all_hosts:
                filters["unresolved"] = True
                resolution = {
                    "status": "unresolved",
                    "basis": "source_host",
                    "warning": "Anchor has no source_host; relative context is not host scoped.",
                }
            else:
                resolution["basis"] = "explicit all-host relative context"
            return filters, resolution
        if mode == "same_host":
            if not host:
                filters["unresolved"] = True
                return filters, {"status": "unresolved", "basis": "source_host", "warning": "Anchor has no source_host"}
            filters["equals"].append({"field": "source_host", "value": host})
            return filters, {"status": "resolved", "basis": "exact source_host", "warning": None}
        if mode == "same_user":
            sid = str(event.get("sid") or "").strip()
            domain = str(event.get("domain") or "").strip()
            username = str(event.get("username") or "").strip()
            if sid:
                filters["equals"].append({"field": "sid", "value": sid})
                return filters, {"status": "resolved", "basis": "SID", "warning": None}
            if domain and username:
                filters["equals"].extend([{"field": "domain", "value": domain}, {"field": "username", "value": username}])
                return filters, {"status": "resolved", "basis": "authority/domain + username", "warning": None}
            if username and host:
                filters["equals"].extend([{"field": "source_host", "value": host}, {"field": "username", "value": username}])
                return filters, {"status": "ambiguous", "basis": "host-local username", "warning": "Bare username is host-scoped, not globally authoritative."}
            filters["unresolved"] = True
            return filters, {"status": "unresolved", "basis": "user identity", "warning": "Anchor has no defensible user identity"}
        if mode == "logon_session":
            logon_id = str(event.get("logon_id") or "").strip()
            if not host or not logon_id:
                filters["unresolved"] = True
                return filters, {"status": "unresolved", "basis": "host + logon_id", "warning": "Anchor has no host-scoped logon session"}
            filters["equals"].extend([{"field": "source_host", "value": host}, {"field": "logon_id", "value": logon_id}])
            filters["not_empty"].append("logon_id")
            return filters, {"status": "resolved", "basis": "host-scoped logon_id", "warning": None}
        if mode == "process_lifetime":
            return self._process_lifetime_filters(anchor, client=client, case_id=case_id)
        raise InvestigationContextError("Invalid context mode")

    def _process_lifetime_filters(self, anchor, *, client, case_id: int):
        event = anchor.get("event") or {}
        host = str(event.get("source_host") or "").strip()
        pid = event.get("process_id")
        start = anchor["timestamp_dt"]
        if not host or pid in (None, "") or not self._is_process_creation(event):
            return {"equals": [], "not_empty": [], "unresolved": True}, {
                "status": "unresolved",
                "basis": "process creation evidence",
                "warning": "Process lifetime requires an exact process creation anchor, not PID alone.",
            }
        next_start = self._next_process_creation(case_id, host, pid, start, client)
        termination = self._process_termination(case_id, host, pid, start, next_start, client)
        end = termination or next_start or start
        status = "resolved" if termination else "partial"
        warning = None if termination else "No exact termination evidence was found; PID reuse is bounded by the next creation when present."
        return {
            "equals": [{"field": "source_host", "value": host}, {"field": "process_id", "value": int(pid), "type": "UInt64"}],
            "not_empty": [],
            "time_start": start,
            "time_end": end,
        }, {
            "status": status,
            "basis": "host + PID + exact process creation timestamp",
            "warning": warning,
            "process_id": pid,
            "source_host": host,
            "started_at": start.isoformat().replace("+00:00", "Z"),
            "ended_at": end.isoformat().replace("+00:00", "Z") if termination else None,
        }

    def _next_process_creation(self, case_id, host, pid, start, client):
        sql = """
            SELECT COALESCE(timestamp_utc, timestamp) AS ts
            FROM events
            WHERE case_id = {case_id:UInt32}
              AND source_host = {source_host:String}
              AND process_id = {process_id:UInt64}
              AND COALESCE(timestamp_utc, timestamp) > {started_at:DateTime64(3)}
              AND (event_id = '4688' OR (event_id = '1' AND positionCaseInsensitive(channel, 'Sysmon') > 0)
                   OR (artifact_type = 'crowdstrike' AND event_id = 'ProcessRollup2'))
            ORDER BY ts ASC
            LIMIT 1
        """
        result = client.query(sql, parameters={"case_id": int(case_id), "source_host": host, "process_id": int(pid), "started_at": self._ch_dt(start)})
        rows = list(result.result_rows or [])
        return self._parse_timestamp(rows[0][0]) if rows else None

    def _process_termination(self, case_id, host, pid, start, next_start, client):
        filters = [
            "case_id = {case_id:UInt32}",
            "source_host = {source_host:String}",
            "process_id = {process_id:UInt64}",
            "COALESCE(timestamp_utc, timestamp) >= {started_at:DateTime64(3)}",
            "((event_id = '4689' AND lower(channel) = 'security') OR (event_id = '5' AND positionCaseInsensitive(channel, 'Sysmon') > 0))",
        ]
        params = {"case_id": int(case_id), "source_host": host, "process_id": int(pid), "started_at": self._ch_dt(start)}
        if next_start:
            filters.append("COALESCE(timestamp_utc, timestamp) < {next_start:DateTime64(3)}")
            params["next_start"] = self._ch_dt(next_start)
        sql = f"SELECT COALESCE(timestamp_utc, timestamp) AS ts FROM events WHERE {' AND '.join(filters)} ORDER BY ts ASC LIMIT 1"
        result = client.query(sql, parameters=params)
        rows = list(result.result_rows or [])
        return self._parse_timestamp(rows[0][0]) if rows else None

    def _fetch_logical_records(self, client, sql_filters, params, *, cursor_values, logical_target):
        logical = []
        seen = set()
        loop_cursor = cursor_values
        batch_limit = min(MAX_CONTEXT_LIMIT, max(int(logical_target), 128))
        max_batches = 8
        for _ in range(max_batches):
            batch_filters = list(sql_filters)
            batch_params = dict(params)
            batch_params["limit"] = batch_limit
            if loop_cursor:
                batch_filters.append(
                    "(COALESCE(timestamp_utc, timestamp) > {cursor_ts:DateTime64(3)} "
                    "OR (COALESCE(timestamp_utc, timestamp) = {cursor_ts:DateTime64(3)} "
                    "AND evidence_record_key > {cursor_erk:String}))"
                )
                batch_params["cursor_ts"] = self._ch_dt(loop_cursor["timestamp"])
                batch_params["cursor_erk"] = loop_cursor["evidence_record_key"]
            sql = f"""
                SELECT {', '.join(EVIDENCE_EVENT_COLUMNS)}
                FROM events
                WHERE {' AND '.join(batch_filters)}
                ORDER BY COALESCE(timestamp_utc, timestamp) ASC, evidence_record_key ASC
                LIMIT {{limit:UInt32}}
            """
            result = client.query(sql, parameters=batch_params)
            records = [self._summarize_event(row, list(result.column_names)) for row in list(result.result_rows or [])]
            if not records:
                break
            for record in records:
                key = record.get("evidence_record_key") or record.get("selector_key")
                if key in seen:
                    continue
                seen.add(key)
                logical.append(record)
                if len(logical) >= logical_target:
                    return logical
            if len(records) < batch_limit:
                break
            last = records[-1]
            loop_cursor = {
                "timestamp": self._parse_timestamp(last.get("timestamp")),
                "evidence_record_key": last.get("evidence_record_key") or "",
            }
            if loop_cursor["timestamp"] is None or not loop_cursor["evidence_record_key"]:
                break
        return logical

    def _client(self):
        if self.client is not None:
            return self.client
        from utils.clickhouse import get_client
        return get_client()

    @staticmethod
    def _window(value: str) -> timedelta:
        if value not in WINDOWS:
            raise InvestigationContextError("Invalid window; expected one of 1s, 30s, 5m, 1h")
        return WINDOWS[value]

    @staticmethod
    def _mode(value: str) -> str:
        normalized = str(value or "relative").strip()
        aliases = {"host": "same_host", "user": "same_user"}
        normalized = aliases.get(normalized, normalized)
        if normalized not in MODES:
            raise InvestigationContextError("Invalid context mode")
        return normalized

    @staticmethod
    def _limit(value) -> int:
        if value in (None, ""):
            return DEFAULT_CONTEXT_LIMIT
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise InvestigationContextError("Invalid limit") from exc
        if parsed < 1:
            raise InvestigationContextError("Limit must be positive")
        return min(parsed, MAX_CONTEXT_LIMIT)

    @staticmethod
    def _source_types(value) -> list[str]:
        if value in (None, ""):
            return []
        if isinstance(value, str):
            raw = value.split(",")
        else:
            raw = []
            for item in value:
                raw.extend(str(item or "").split(","))
        return sorted({item.strip() for item in raw if item and item.strip()})

    @staticmethod
    def _bool(value) -> bool:
        if isinstance(value, bool):
            return value
        return str(value or "").strip().lower() in {"1", "true", "yes", "on"}

    def _event_dict(self, row, columns):
        return {columns[index]: self._json_safe(value) for index, value in enumerate(row)}

    def _summarize_event(self, row, columns):
        event = self._event_dict(row, columns)
        summary_parts = [
            event.get("event_id"),
            event.get("process_name") or event.get("process_path"),
            event.get("username"),
            event.get("source_host"),
        ]
        return {
            "evidence_record_key": event.get("evidence_record_key") or "",
            "selector_key": event.get("selector_key") or "",
            "timestamp": self._format_ts(event.get("timestamp_utc") or event.get("timestamp")),
            "artifact_type": event.get("artifact_type") or "",
            "event_id": str(event.get("event_id") or ""),
            "source_host": event.get("source_host") or "",
            "user": self._format_user(event),
            "process_name": event.get("process_name") or "",
            "source_file": event.get("source_file") or "",
            "summary": " | ".join(str(part) for part in summary_parts if part not in (None, "")),
        }

    @staticmethod
    def _dedupe_logical_records(records):
        seen = set()
        logical = []
        for record in records:
            key = record.get("evidence_record_key") or record.get("selector_key")
            if key in seen:
                continue
            seen.add(key)
            logical.append(record)
        return logical

    @staticmethod
    def _parse_timestamp(value) -> datetime | None:
        if value in (None, ""):
            return None
        if isinstance(value, datetime):
            dt = value
        else:
            text = str(value).strip().replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(text)
            except ValueError:
                try:
                    dt = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def _format_ts(self, value):
        parsed = self._parse_timestamp(value)
        return parsed.isoformat().replace("+00:00", "Z") if parsed else ""

    @staticmethod
    def _ch_dt(value: datetime) -> str:
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    @staticmethod
    def _format_user(event):
        username = str(event.get("username") or "").strip()
        domain = str(event.get("domain") or "").strip()
        sid = str(event.get("sid") or "").strip()
        if domain and username:
            return f"{domain}\\{username}"
        return username or sid

    @staticmethod
    def _is_process_creation(event):
        event_id = str(event.get("event_id") or "").strip().lower()
        channel = str(event.get("channel") or "").strip().lower()
        artifact_type = str(event.get("artifact_type") or "").strip().lower()
        return (
            (event_id, channel) == ("4688", "security")
            or (event_id == "1" and "sysmon" in channel)
            or (artifact_type == "crowdstrike" and event_id == "processrollup2")
        )

    @staticmethod
    def _json_safe(value):
        if isinstance(value, datetime):
            return value.isoformat()
        return value

    def _encode_cursor(self, record):
        payload = {"timestamp": record.get("timestamp"), "evidence_record_key": record.get("evidence_record_key")}
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii")

    def _decode_cursor(self, cursor):
        if not cursor:
            return None
        try:
            payload = json.loads(base64.urlsafe_b64decode(str(cursor).encode("ascii")).decode("utf-8"))
            timestamp = self._parse_timestamp(payload.get("timestamp"))
            erk = str(payload.get("evidence_record_key") or "")
        except Exception as exc:
            raise InvestigationContextError("Invalid cursor") from exc
        if timestamp is None or not EVIDENCE_RECORD_KEY_RE.fullmatch(erk):
            raise InvestigationContextError("Invalid cursor")
        return {"timestamp": timestamp, "evidence_record_key": erk}
