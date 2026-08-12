"""Saved Graph View models — durable analyst workspace arrangements.

Saved views persist stable entity/relationship references so layouts survive
graph rebuild/reprojection. Transient graph row IDs are never the durable
identity. Phase 0D does not generate immutable report snapshots (Phase 0F).
"""
from __future__ import annotations

import uuid
from datetime import datetime

from models.database import db


class GraphSavedView(db.Model):
    """Case-scoped saved investigation graph workspace state."""

    __tablename__ = "graph_saved_views"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)

    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)

    root_entity_references = db.Column(db.JSON, nullable=False, default=list)
    expanded_entity_references = db.Column(db.JSON, nullable=False, default=list)
    visible_relationship_references = db.Column(db.JSON, nullable=False, default=list)

    filters_json = db.Column(db.JSON, nullable=False, default=dict)

    time_start = db.Column(db.DateTime, nullable=True)
    time_end = db.Column(db.DateTime, nullable=True)

    pinned_node_references = db.Column(db.JSON, nullable=False, default=list)
    hidden_node_references = db.Column(db.JSON, nullable=False, default=list)
    hidden_group_state = db.Column(db.JSON, nullable=False, default=dict)

    node_coordinates_json = db.Column(db.JSON, nullable=False, default=dict)

    selected_entity_reference = db.Column(db.JSON, nullable=True)
    selected_relationship_reference = db.Column(db.JSON, nullable=True)

    projection_contract_version = db.Column(db.String(40), nullable=False, default="graph-view:v1")

    evidence_set_fingerprint = db.Column(db.String(96), nullable=False, default="")
    view_state_json = db.Column(db.JSON, nullable=False, default=dict)
    view_state_sha256 = db.Column(db.String(64), nullable=False, default="")

    version = db.Column(db.Integer, nullable=False, default=1)

    created_by_user_id = db.Column(db.Integer, nullable=True)
    created_by_username = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    updated_by_user_id = db.Column(db.Integer, nullable=True)
    updated_by_username = db.Column(db.String(80), nullable=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    case = db.relationship("Case", backref=db.backref("graph_saved_views", lazy="dynamic"))

    __table_args__ = (
        db.Index("idx_graph_saved_view_case_updated", "case_id", "updated_at"),
        db.Index("idx_graph_saved_view_case_title", "case_id", "title"),
    )

    def __repr__(self):
        return f"<GraphSavedView {self.uuid} case={self.case_id}>"
