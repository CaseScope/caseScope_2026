#!/usr/bin/env python3
"""Generate the pattern-check inventory CSV from live source files.

This script is the authoritative inventory source for the Phase 4a
pattern-check reframing. The CSV is derived from live code and should
not be hand-edited.
"""

from __future__ import annotations

import csv
import importlib.util
from pathlib import Path
from types import ModuleType


REPO_ROOT = Path(__file__).resolve().parents[2]
PATTERN_CHECKS_PATH = REPO_ROOT / "utils" / "pattern_check_definitions.py"
PATTERN_MAPPINGS_PATH = REPO_ROOT / "utils" / "pattern_event_mappings.py"
OUTPUT_PATH = REPO_ROOT / "docs" / "refactor" / "pattern_check_inventory.csv"


def load_module(module_name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    pattern_checks = load_module("pattern_check_definitions_refactor", PATTERN_CHECKS_PATH)
    pattern_mappings = load_module("pattern_event_mappings_refactor", PATTERN_MAPPINGS_PATH)

    rows: list[dict[str, str | int | bool | float]] = []

    for pattern_id, checks in pattern_checks.PATTERN_CHECKS.items():
        meta = pattern_mappings.PATTERN_EVENT_MAPPINGS.get(pattern_id, {})
        for check in checks:
            rows.append(
                {
                    "pattern_id": pattern_id,
                    "check_id": getattr(check, "id", ""),
                    "name": getattr(check, "name", ""),
                    "check_type": getattr(check, "check_type", ""),
                    "weight": getattr(check, "weight", ""),
                    "has_query": bool(getattr(check, "query_template", None)),
                    "has_tiers": bool(getattr(check, "tiers", None)),
                    "mitre": ",".join(meta.get("mitre_techniques", [])),
                    "anchor_events": ",".join(meta.get("anchor_events", [])),
                    "sigma_convertible": getattr(check, "check_type", "")
                    in ("anchor_match", "field_match"),
                }
            )

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "pattern_id",
                "check_id",
                "name",
                "check_type",
                "weight",
                "has_query",
                "has_tiers",
                "mitre",
                "anchor_events",
                "sigma_convertible",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
