#!/opt/casescope/venv/bin/python
"""ClickHouse executable-pool UDF for Evidence Identity v2 fallback rows."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from typing import Any, Dict


REPO_ROOT = os.environ.get("CASESCOPE_REPO_ROOT", "/opt/casescope")
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from utils.evidence_identity import build_identity_from_clickhouse_row  # noqa: E402


NUMERIC_FIELDS = {
    "case_id",
    "case_file_id",
    "record_id",
    "logon_type",
    "process_id",
    "parent_pid",
    "thread_id",
    "file_size",
    "src_port",
    "dst_port",
}

TIMESTAMP_FIELDS = {"timestamp", "timestamp_utc"}


def _clean_input_value(field_name: str, value: Any) -> Any:
    if value in (None, ""):
        return None if field_name in NUMERIC_FIELDS else ""
    if field_name in NUMERIC_FIELDS:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    if field_name in TIMESTAMP_FIELDS and isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    return value


def _identity_input(row: Dict[str, Any]) -> Dict[str, Any]:
    return {field_name: _clean_input_value(field_name, value) for field_name, value in row.items()}


def main() -> int:
    for raw_line in sys.stdin.buffer:
        if not raw_line.strip():
            continue
        row = json.loads(raw_line)
        identity = build_identity_from_clickhouse_row(_identity_input(row))
        payload = {
            "identity": [
                identity.evidence_record_key,
                identity.evidence_identity_version,
                identity.evidence_identity_quality,
            ]
        }
        sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
