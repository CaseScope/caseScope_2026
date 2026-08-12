"""Deterministic report adapter for immutable Investigation Thread snapshots."""
from __future__ import annotations

from datetime import datetime
from typing import Any


class InvestigationThreadReportAdapter:
    """Convert immutable Thread snapshots into non-AI report context."""

    def build_context(self, snapshots: list[dict[str, Any]]) -> dict[str, Any]:
        sections = [self._section(snapshot) for snapshot in snapshots]
        text = "\n\n".join(section["text"] for section in sections if section["text"])
        return {
            "investigation_threads_included": bool(sections),
            "investigation_thread_sections": sections,
            "investigation_thread_report_section_title": "Investigation Threads",
            "investigation_thread_report_section": text,
            "investigation_thread_snapshot_hashes": [section["snapshot_sha256"] for section in sections],
            "investigation_thread_graph_images": [
                {
                    "path": section["graph_render_path"],
                    "sha256": section["graph_render_sha256"],
                    "title": section["graph_render_title"],
                }
                for section in sections
                if section.get("graph_render_path")
            ],
        }

    def _section(self, row: dict[str, Any]) -> dict[str, Any]:
        snapshot = row.get("snapshot_json") or {}
        thread = snapshot.get("thread") or {}
        saved_view = snapshot.get("saved_view")
        evidence = sorted(
            snapshot.get("evidence") or [],
            key=lambda item: (
                ((item.get("frozen_snapshot") or item.get("snapshot_json") or {}).get("timestamp_utc") or ""),
                item.get("evidence_record_key") or "",
            ),
        )
        lines = [
            f"Investigation Thread: {thread.get('title') or 'Untitled'}",
            f"Status: {thread.get('status') or '-'}",
            f"Owner: {thread.get('owner') or '-'}",
            f"Thread version: {thread.get('version')}",
            f"Saved View version: {saved_view.get('version') if saved_view else 'No Saved Graph View captured'}",
            f"Evidence-set fingerprint: {snapshot.get('evidence_set_fingerprint') or '-'}",
            f"Report snapshot hash: {row.get('snapshot_sha256') or '-'}",
        ]
        if thread.get("time_start") or thread.get("time_end"):
            lines.append(f"Relevant time period: {thread.get('time_start') or '-'} to {thread.get('time_end') or '-'}")
        if thread.get("description"):
            lines.extend(["", "Description:", str(thread.get("description"))])
        if thread.get("conclusion"):
            lines.extend(["", "Analyst conclusion:", str(thread.get("conclusion"))])
        lines.extend(["", "Affected entities:"])
        lines.extend(self._entity_lines(snapshot.get("entities") or []))
        lines.extend(["", "Selected canonical relationships:"])
        lines.extend(self._relationship_lines(snapshot.get("relationships") or []))
        lines.extend(["", "Chronological evidence:"])
        lines.extend(self._evidence_lines(evidence))
        lines.extend(["", "Findings:"])
        lines.extend(self._snapshot_item_lines(snapshot.get("findings") or []))
        lines.extend(["", "IOCs:"])
        lines.extend(self._snapshot_item_lines(snapshot.get("iocs") or []))
        lines.extend(["", "Source availability:"])
        lines.extend(self._availability_lines(snapshot.get("source_availability") or []))
        if row.get("graph_render_path"):
            lines.extend(["", "Saved graph view: Embedded frozen graph image."])
            lines.append(f"Saved graph render hash: {row.get('graph_render_sha256') or '-'}")
        elif not saved_view:
            lines.extend(["", "Graph: No Saved Graph View was captured for this Investigation Thread."])
        return {
            "thread_uuid": thread.get("uuid"),
            "thread_version": thread.get("version"),
            "saved_view_uuid": saved_view.get("uuid") if saved_view else None,
            "saved_view_version": saved_view.get("version") if saved_view else None,
            "evidence_set_fingerprint": snapshot.get("evidence_set_fingerprint"),
            "snapshot_uuid": row.get("uuid"),
            "snapshot_sha256": row.get("snapshot_sha256"),
            "graph_render_path": row.get("graph_render_path"),
            "graph_render_sha256": row.get("graph_render_sha256"),
            "graph_render_title": saved_view.get("title") if saved_view else None,
            "text": "\n".join(lines),
        }

    @staticmethod
    def _entity_lines(items):
        if not items:
            return ["- None selected."]
        lines = []
        for item in items:
            snap = item.get("snapshot_json") or item.get("snapshot") or {}
            label = item.get("frozen_display_value") or snap.get("display_value") or item.get("stable_reference_key")
            lines.append(f"- {label} ({item.get('entity_type') or snap.get('entity_type') or 'entity'})")
        return lines

    @staticmethod
    def _relationship_lines(items):
        if not items:
            return ["- None selected."]
        lines = []
        for item in items:
            rel_type = item.get("relationship_type") or (item.get("snapshot_json") or {}).get("relationship_type")
            source = item.get("frozen_source_display_value") or (item.get("snapshot_json") or {}).get("source_display_value") or "source"
            target = item.get("frozen_target_display_value") or (item.get("snapshot_json") or {}).get("target_display_value") or "target"
            lines.append(f"- {source} --{rel_type or 'RELATIONSHIP'}--> {target} [{item.get('stable_reference_key')}]")
        return lines

    @staticmethod
    def _evidence_lines(items):
        if not items:
            return ["- None selected."]
        lines = []
        for item in items:
            snap = item.get("frozen_snapshot_json") or item.get("snapshot_json") or {}
            event = snap.get("event") or snap
            ts = event.get("timestamp_utc") or event.get("timestamp") or ""
            summary = item.get("analyst_visible_summary") or snap.get("analyst_visible_summary") or event.get("summary") or event.get("event_id") or "evidence"
            lines.append(f"- {ts}: {summary} [{item.get('evidence_record_key')}]")
        return lines

    @staticmethod
    def _snapshot_item_lines(items):
        if not items:
            return ["- None selected."]
        lines = []
        for item in items:
            snap = item.get("snapshot_json") or {}
            title = snap.get("title") or snap.get("value") or snap.get("ioc_value") or item.get("stable_reference_key")
            lines.append(f"- {title} [{item.get('stable_reference_key')}]")
        return lines

    @staticmethod
    def _availability_lines(items):
        if not items:
            return ["- No evidence-source availability entries."]
        lines = []
        for item in items:
            availability_status = item.get("original_source_status")
            if availability_status == "indeterminate":
                status_text = "Original-source availability could not be determined when this report snapshot was generated."
            elif availability_status == "available" or item.get("original_source_retrievable") is True:
                status_text = "Original supporting source currently retrievable: Yes"
            else:
                status_text = "Original supporting source currently retrievable: No"
            retained = "Yes" if item.get("snapshot_retained") else "No"
            line = f"- {item.get('evidence_record_key')}: Snapshot retained: {retained}; {status_text}"
            if item.get("warning"):
                line += f". {item['warning']}"
            lines.append(line)
        return lines
