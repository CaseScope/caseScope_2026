"""Immutable Investigation Thread report snapshot capture and rendering."""
from __future__ import annotations

import os
import struct
import uuid
import zlib
from datetime import datetime
from html import escape
from typing import Any

from config import Config
from models.audit_log import AuditAction, AuditEntityType, AuditLog
from models.case import Case
from models.database import db
from models.graph import GraphEntity, GraphRelationship
from models.graph_saved_view import GraphSavedView
from models.investigation_thread import InvestigationThread, InvestigationThreadReportSnapshot
from utils.graph_query import GraphNotFoundError, GraphQueryService
from utils.graph_saved_views import GraphSavedViewConflictError, GraphSavedViewNotFoundError, GraphSavedViewService
from utils.investigation_references import (
    build_entity_reference,
    canonical_json,
    resolve_entity_reference,
    resolve_relationship_reference,
    snapshot_sha256,
)
from utils.investigation_threads import InvestigationThreadConflictError, InvestigationThreadNotFoundError, InvestigationThreadService


SNAPSHOT_SCHEMA_VERSION = 1
SNAPSHOT_HASH_PREFIX = "report-snapshot:v1:"
GRAPH_HASH_PREFIX = "graph-render:v1:"


class InvestigationThreadReportSnapshotError(ValueError):
    """Client-correctable immutable report snapshot error."""


class InvestigationThreadReportSnapshotService:
    """Capture immutable Thread report state before rendering or async work."""

    def create_snapshot(
        self,
        case_id: int,
        *,
        thread_uuid: str,
        expected_thread_version: int,
        expected_saved_view_version: int | None = None,
        case_report_id: int | None = None,
        report_generation_uuid: str | None = None,
        actor: dict[str, Any],
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        case = Case.query.get(int(case_id))
        if case is None:
            raise InvestigationThreadReportSnapshotError("Case not found")
        report_generation_uuid = report_generation_uuid or str(uuid.uuid4())
        operation_id = operation_id or str(uuid.uuid4())
        actor_info = self._actor_info(actor)

        thread = (
            InvestigationThread.query.filter_by(case_id=case.id, uuid=str(thread_uuid))
            .with_for_update()
            .first()
        )
        if thread is None:
            raise InvestigationThreadNotFoundError("Investigation Thread not found")
        if expected_thread_version in (None, ""):
            raise InvestigationThreadReportSnapshotError("expected_thread_version is required")
        if int(thread.version) != int(expected_thread_version):
            raise InvestigationThreadConflictError("Investigation Thread was modified by another user", current_version=thread.version)

        saved_view = None
        if thread.current_saved_view_id is not None:
            saved_view = (
                GraphSavedView.query.filter_by(case_id=case.id, id=thread.current_saved_view_id)
                .with_for_update()
                .first()
            )
            if saved_view is None:
                raise GraphSavedViewNotFoundError("Saved graph view not found")
            if expected_saved_view_version is not None and int(saved_view.version) != int(expected_saved_view_version):
                raise GraphSavedViewConflictError(
                    "Saved graph view was modified by another user",
                    current_version=saved_view.version,
                )
        elif expected_saved_view_version not in (None, ""):
            raise InvestigationThreadReportSnapshotError("Thread has no Saved Graph View")

        payload = InvestigationThreadService().get_thread(case.id, thread.uuid, include_memberships=True)
        view_payload = self._saved_view_snapshot(case.id, saved_view)
        source_availability = self._source_availability(case.id, payload.get("evidence") or [])
        snapshot_json = {
            "snapshot_schema_version": SNAPSHOT_SCHEMA_VERSION,
            "thread": {
                "uuid": thread.uuid,
                "version": thread.version,
                "title": thread.title,
                "description": thread.description,
                "conclusion": thread.analyst_conclusion,
                "status": thread.status,
                "owner": thread.owner_username,
                "owner_user_id": thread.owner_user_id,
                "time_start": thread.time_start.isoformat() if thread.time_start else None,
                "time_end": thread.time_end.isoformat() if thread.time_end else None,
            },
            "saved_view": view_payload,
            "evidence_set_fingerprint": thread.evidence_set_fingerprint,
            "entities": payload.get("entities") or [],
            "relationships": payload.get("relationships") or [],
            "evidence": payload.get("evidence") or [],
            "iocs": payload.get("iocs") or [],
            "findings": payload.get("findings") or [],
            "notes": payload.get("notes") or [],
            "source_availability": source_availability,
            "captured_at": datetime.utcnow().isoformat(),
            "captured_by": actor_info["username"],
        }
        hash_value = f"{SNAPSHOT_HASH_PREFIX}{snapshot_sha256(snapshot_json)}"
        render = self._render_graph(case.uuid, report_generation_uuid, snapshot_json)

        row = InvestigationThreadReportSnapshot(
            case_id=case.id,
            case_report_id=case_report_id,
            report_generation_uuid=report_generation_uuid,
            thread_uuid=thread.uuid,
            thread_version=thread.version,
            saved_view_uuid=saved_view.uuid if saved_view else None,
            saved_view_version=saved_view.version if saved_view else None,
            evidence_set_fingerprint=thread.evidence_set_fingerprint,
            snapshot_schema_version=SNAPSHOT_SCHEMA_VERSION,
            snapshot_json=snapshot_json,
            snapshot_sha256=hash_value,
            graph_render_format=render["format"],
            graph_render_path=render["path"],
            graph_render_sha256=render["sha256"],
            created_by_user_id=actor_info["user_id"],
            created_by_username=actor_info["username"],
        )
        db.session.add(row)
        db.session.flush()
        AuditLog.log(
            entity_type=AuditEntityType.INVESTIGATION_THREAD_REPORT_SNAPSHOT,
            entity_id=row.uuid,
            entity_name=thread.title,
            action=AuditAction.CREATED,
            case_uuid=case.uuid,
            username=actor_info["username"],
            user_id=actor_info["user_id"],
            operation_id=operation_id,
            details={
                "case_id": case.id,
                "case_report_id": case_report_id,
                "report_generation_uuid": report_generation_uuid,
                "snapshot_uuid": row.uuid,
                "snapshot_hash": row.snapshot_sha256,
                "thread_uuid": row.thread_uuid,
                "thread_version": row.thread_version,
                "saved_view_uuid": row.saved_view_uuid,
                "saved_view_version": row.saved_view_version,
                "evidence_set_fingerprint": row.evidence_set_fingerprint,
            },
        )
        return self.serialize(row)

    def link_generation_to_report(self, case_id: int, report_generation_uuid: str, case_report_id: int) -> None:
        rows = InvestigationThreadReportSnapshot.query.filter_by(
            case_id=int(case_id),
            report_generation_uuid=str(report_generation_uuid),
        ).all()
        for row in rows:
            row.case_report_id = int(case_report_id)

    def cleanup_generation(self, case_id: int, report_generation_uuid: str) -> None:
        rows = InvestigationThreadReportSnapshot.query.filter_by(
            case_id=int(case_id),
            report_generation_uuid=str(report_generation_uuid),
        ).all()
        for row in rows:
            for path in self._render_paths(row.graph_render_path):
                try:
                    if path and os.path.exists(path):
                        os.remove(path)
                except OSError:
                    pass
            db.session.delete(row)

    @staticmethod
    def _render_paths(render_path: str | None) -> list[str]:
        if not render_path:
            return []
        root, ext = os.path.splitext(render_path)
        paths = [render_path]
        if ext.lower() == ".png":
            paths.append(f"{root}.svg")
        elif ext.lower() == ".svg":
            paths.append(f"{root}.png")
        return paths

    def get_snapshot(self, case_id: int, snapshot_uuid: str) -> dict[str, Any]:
        row = InvestigationThreadReportSnapshot.query.filter_by(case_id=int(case_id), uuid=str(snapshot_uuid)).first()
        if row is None:
            raise InvestigationThreadReportSnapshotError("Report snapshot not found")
        return self.serialize(row)

    def serialize(self, row: InvestigationThreadReportSnapshot) -> dict[str, Any]:
        return {
            "id": row.id,
            "uuid": row.uuid,
            "case_id": row.case_id,
            "case_report_id": row.case_report_id,
            "report_generation_uuid": row.report_generation_uuid,
            "thread_uuid": row.thread_uuid,
            "thread_version": row.thread_version,
            "saved_view_uuid": row.saved_view_uuid,
            "saved_view_version": row.saved_view_version,
            "evidence_set_fingerprint": row.evidence_set_fingerprint,
            "snapshot_schema_version": row.snapshot_schema_version,
            "snapshot_json": row.snapshot_json,
            "snapshot_sha256": row.snapshot_sha256,
            "graph_render_format": row.graph_render_format,
            "graph_render_path": row.graph_render_path,
            "graph_render_sha256": row.graph_render_sha256,
            "ai_used": row.ai_used,
            "ai_provider": row.ai_provider,
            "ai_model": row.ai_model,
            "ai_generated_at": row.ai_generated_at.isoformat() if row.ai_generated_at else None,
            "ai_provenance": row.ai_provenance_json or {},
            "created_by": row.created_by_username,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }

    def _saved_view_snapshot(self, case_id: int, saved_view: GraphSavedView | None) -> dict[str, Any] | None:
        if saved_view is None:
            return None
        view = GraphSavedViewService().get_view(case_id, saved_view.uuid, resolve_live=False)["view"]
        state = view.get("view_state_json") or {}
        frozen_entities = self._freeze_view_entities(case_id, state)
        frozen_relationships = self._freeze_view_relationships(case_id, state)
        return {
            "uuid": saved_view.uuid,
            "version": saved_view.version,
            "title": saved_view.title,
            "description": saved_view.description,
            "projection_version": saved_view.projection_contract_version,
            "evidence_set_fingerprint": saved_view.evidence_set_fingerprint,
            "state": state,
            "frozen_entities": frozen_entities,
            "frozen_relationships": frozen_relationships,
        }

    def _freeze_view_entities(self, case_id: int, state: dict[str, Any]) -> list[dict[str, Any]]:
        refs = []
        for key in ("root_entity_references", "expanded_entity_references", "pinned_node_references", "hidden_node_references"):
            refs.extend([ref for ref in state.get(key) or [] if isinstance(ref, dict)])
        selected = state.get("selected_entity_reference")
        if isinstance(selected, dict):
            refs.append(selected)
        by_key = {}
        for ref in refs:
            stable_key = ref.get("stable_reference_key")
            if stable_key in by_key:
                continue
            entity, live_available = resolve_entity_reference(case_id, ref)
            by_key[stable_key] = {
                "stable_reference_key": stable_key,
                "reference": ref,
                "live_available": live_available,
                "entity_type": entity.entity_type if entity else ref.get("entity_type"),
                "entity_key": entity.entity_key if entity else ref.get("entity_key"),
                "label": entity.display_value if entity else ref.get("entity_key"),
                "coordinates": (state.get("node_coordinates") or {}).get(stable_key),
                "pinned": stable_key in {item.get("stable_reference_key") for item in state.get("pinned_node_references") or [] if isinstance(item, dict)},
                "hidden": stable_key in {item.get("stable_reference_key") for item in state.get("hidden_node_references") or [] if isinstance(item, dict)},
            }
        return sorted(by_key.values(), key=lambda item: item.get("stable_reference_key") or "")

    def _freeze_view_relationships(self, case_id: int, state: dict[str, Any]) -> list[dict[str, Any]]:
        refs = [ref for ref in state.get("visible_relationship_references") or [] if isinstance(ref, dict)]
        selected = state.get("selected_relationship_reference")
        if isinstance(selected, dict):
            refs.append(selected)
        by_key = {}
        for ref in refs:
            stable_key = ref.get("stable_reference_key")
            if stable_key in by_key:
                continue
            relationship, live_available, source, target = resolve_relationship_reference(case_id, ref)
            by_key[stable_key] = {
                "stable_reference_key": stable_key,
                "reference": ref,
                "live_available": live_available,
                "relationship_type": relationship.relationship_type if relationship else ref.get("relationship_type"),
                "derivation_type": relationship.derivation_type if relationship else ref.get("derivation_type"),
                "source_reference_key": self._entity_ref_key(source) or self._entity_ref_key_from_relationship_ref(case_id, ref, "source"),
                "target_reference_key": self._entity_ref_key(target) or self._entity_ref_key_from_relationship_ref(case_id, ref, "target"),
                "source_label": source.display_value if source else ref.get("source_display_value") or ref.get("source_entity_key"),
                "target_label": target.display_value if target else ref.get("target_display_value") or ref.get("target_entity_key"),
            }
        return sorted(by_key.values(), key=lambda item: item.get("stable_reference_key") or "")

    @staticmethod
    def _entity_ref_key(entity: GraphEntity | None) -> str | None:
        if entity is None:
            return None
        from utils.investigation_references import entity_reference_from_graph_entity
        return entity_reference_from_graph_entity(entity)["stable_reference_key"]

    @staticmethod
    def _entity_ref_key_from_relationship_ref(case_id: int, ref: dict[str, Any], endpoint: str) -> str | None:
        entity_type = ref.get(f"{endpoint}_entity_type")
        entity_key = ref.get(f"{endpoint}_entity_key")
        if not entity_type or not entity_key:
            return None
        return build_entity_reference(case_id=case_id, entity_type=entity_type, entity_key=entity_key)["stable_reference_key"]

    def _source_availability(self, case_id: int, evidence_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        service = GraphQueryService()
        availability = []
        for row in evidence_rows:
            erk = row.get("evidence_record_key")
            status = "unavailable"
            if erk:
                try:
                    service.exact_evidence(case_id, erk)
                    status = "available"
                except GraphNotFoundError:
                    status = "unavailable"
                except Exception:
                    status = "indeterminate"
            available = status == "available"
            availability.append(
                {
                    "evidence_record_key": erk,
                    "snapshot_retained": bool(row.get("snapshot_available")),
                    "original_source_status": status,
                    "original_source_retrievable": available,
                    "warning": self._source_availability_warning(status),
                }
            )
        return availability

    @staticmethod
    def _source_availability_warning(status: str) -> str | None:
        if status == "available":
            return None
        if status == "indeterminate":
            return (
                "The original-source availability check could not be completed due to an infrastructure "
                "or query failure. The Investigation Thread's retained evidence snapshot is shown."
            )
        return (
            "The original supporting source was unavailable when this report snapshot was generated. "
            "The Investigation Thread's retained evidence snapshot is shown."
        )

    def _render_graph(self, case_uuid: str, generation_uuid: str, snapshot_json: dict[str, Any]) -> dict[str, Any]:
        saved_view = snapshot_json.get("saved_view")
        if not saved_view:
            return {"format": None, "path": None, "sha256": None}
        svg = self._build_svg(saved_view)
        render_hash = f"{GRAPH_HASH_PREFIX}{snapshot_sha256({'svg': svg})}"
        folder = os.path.join(Config.STORAGE_FOLDER, case_uuid, "reports", "snapshots")
        os.makedirs(folder, exist_ok=True)
        base = os.path.join(folder, f"{generation_uuid}_{snapshot_json['thread']['uuid']}")
        svg_path = f"{base}.svg"
        png_path = f"{base}.png"
        with open(svg_path, "w", encoding="utf-8") as handle:
            handle.write(svg)
        with open(png_path, "wb") as handle:
            handle.write(self._build_png(saved_view))
        try:
            import shutil
            shutil.chown(svg_path, user="casescope", group="casescope")
            shutil.chown(png_path, user="casescope", group="casescope")
        except (PermissionError, LookupError):
            pass
        return {"format": "png", "path": png_path, "sha256": render_hash}

    def _build_svg(self, saved_view: dict[str, Any]) -> str:
        entities = [item for item in saved_view.get("frozen_entities") or [] if not item.get("hidden")]
        relationships = saved_view.get("frozen_relationships") or []
        coords = {}
        for index, entity in enumerate(entities):
            coord = entity.get("coordinates") or {}
            coords[entity["stable_reference_key"]] = {
                "x": float(coord.get("x", 120 + (index % 5) * 180)),
                "y": float(coord.get("y", 120 + (index // 5) * 120)),
            }
        nodes_svg = []
        for entity in entities:
            coord = coords[entity["stable_reference_key"]]
            label = escape(str(entity.get("label") or entity.get("entity_key") or "entity"))
            nodes_svg.append(
                f'<g><circle cx="{coord["x"]:.2f}" cy="{coord["y"]:.2f}" r="28" fill="#eef4ff" stroke="#315b9d" stroke-width="2"/>'
                f'<text x="{coord["x"]:.2f}" y="{coord["y"] + 44:.2f}" text-anchor="middle" font-size="12">{label}</text></g>'
            )
        edges_svg = []
        visible = {entity["stable_reference_key"] for entity in entities}
        for relationship in relationships:
            source_key = relationship.get("source_reference_key")
            target_key = relationship.get("target_reference_key")
            if source_key not in visible or target_key not in visible:
                continue
            source = coords[source_key]
            target = coords[target_key]
            label = escape(str(relationship.get("relationship_type") or "RELATIONSHIP"))
            mid_x = (source["x"] + target["x"]) / 2
            mid_y = (source["y"] + target["y"]) / 2
            edges_svg.append(
                f'<line x1="{source["x"]:.2f}" y1="{source["y"]:.2f}" x2="{target["x"]:.2f}" y2="{target["y"]:.2f}" '
                'stroke="#607080" stroke-width="1.5" marker-end="url(#arrow)"/>'
                f'<text x="{mid_x:.2f}" y="{mid_y - 6:.2f}" text-anchor="middle" font-size="10">{label}</text>'
            )
        body = "".join(edges_svg + nodes_svg)
        return (
            '<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="800" viewBox="0 0 1200 800">'
            '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">'
            '<path d="M 0 0 L 10 5 L 0 10 z" fill="#607080"/></marker></defs>'
            f"{body}</svg>"
        )

    def _build_png(self, saved_view: dict[str, Any]) -> bytes:
        width, height = 1200, 800
        pixels = bytearray([255, 255, 255] * width * height)
        entities = [item for item in saved_view.get("frozen_entities") or [] if not item.get("hidden")]
        coords = {}
        for index, entity in enumerate(entities):
            coord = entity.get("coordinates") or {}
            coords[entity["stable_reference_key"]] = (
                int(float(coord.get("x", 120 + (index % 5) * 180))),
                int(float(coord.get("y", 120 + (index // 5) * 120))),
            )
        visible = set(coords)
        for relationship in saved_view.get("frozen_relationships") or []:
            source_key = relationship.get("source_reference_key")
            target_key = relationship.get("target_reference_key")
            if source_key in visible and target_key in visible:
                self._draw_line(pixels, width, height, coords[source_key], coords[target_key], (96, 112, 128))
        for key in sorted(visible):
            x, y = coords[key]
            self._draw_circle(pixels, width, height, x, y, 28, (238, 244, 255), fill=True)
            self._draw_circle(pixels, width, height, x, y, 28, (49, 91, 157), fill=False)
        return self._png_bytes(width, height, pixels)

    @staticmethod
    def _set_pixel(pixels: bytearray, width: int, height: int, x: int, y: int, color: tuple[int, int, int]) -> None:
        if x < 0 or y < 0 or x >= width or y >= height:
            return
        offset = (y * width + x) * 3
        pixels[offset:offset + 3] = bytes(color)

    def _draw_line(self, pixels, width, height, start, end, color):
        x1, y1 = start
        x2, y2 = end
        dx = abs(x2 - x1)
        dy = -abs(y2 - y1)
        sx = 1 if x1 < x2 else -1
        sy = 1 if y1 < y2 else -1
        err = dx + dy
        while True:
            self._set_pixel(pixels, width, height, x1, y1, color)
            if x1 == x2 and y1 == y2:
                break
            doubled = 2 * err
            if doubled >= dy:
                err += dy
                x1 += sx
            if doubled <= dx:
                err += dx
                y1 += sy

    def _draw_circle(self, pixels, width, height, cx, cy, radius, color, *, fill):
        r2 = radius * radius
        inner = (radius - 2) * (radius - 2)
        for y in range(cy - radius, cy + radius + 1):
            for x in range(cx - radius, cx + radius + 1):
                d2 = (x - cx) * (x - cx) + (y - cy) * (y - cy)
                if (fill and d2 <= r2) or (not fill and inner <= d2 <= r2):
                    self._set_pixel(pixels, width, height, x, y, color)

    @staticmethod
    def _png_bytes(width: int, height: int, pixels: bytearray) -> bytes:
        def chunk(kind: bytes, data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

        rows = bytearray()
        row_width = width * 3
        for y in range(height):
            rows.append(0)
            start = y * row_width
            rows.extend(pixels[start:start + row_width])
        return (
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(rows), level=9))
            + chunk(b"IEND", b"")
        )

    @staticmethod
    def _actor_info(actor: dict[str, Any]) -> dict[str, Any]:
        return {
            "user_id": actor.get("user_id"),
            "username": actor.get("username") or "system",
        }
