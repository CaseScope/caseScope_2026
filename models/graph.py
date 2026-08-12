"""Evidence-backed investigative graph models."""
from datetime import datetime

from models.database import db


class GraphEntity(db.Model):
    """Case-scoped canonical investigative entity."""

    __tablename__ = 'graph_entities'

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, index=True)
    entity_type = db.Column(db.String(50), nullable=False, index=True)
    entity_key = db.Column(db.String(512), nullable=False)
    display_value = db.Column(db.String(1024), nullable=False)
    canonical_value = db.Column(db.String(1024), nullable=True)
    first_seen_at = db.Column(db.DateTime, nullable=True)
    last_seen_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    metadata_json = db.Column(db.JSON, nullable=False, default=dict)

    case = db.relationship('Case', backref=db.backref('graph_entities', lazy='dynamic', cascade='all, delete-orphan'))

    __table_args__ = (
        db.UniqueConstraint('case_id', 'entity_type', 'entity_key', name='uq_graph_entity_case_type_key'),
        db.Index('idx_graph_entity_case_type', 'case_id', 'entity_type'),
        db.Index('idx_graph_entity_case_key', 'case_id', 'entity_key'),
    )

    def __repr__(self):
        return f'<GraphEntity {self.case_id}:{self.entity_type}:{self.entity_key}>'


class GraphEntityObservation(db.Model):
    """Evidence observation explaining why an entity exists."""

    __tablename__ = 'graph_entity_observations'

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, index=True)
    entity_id = db.Column(
        db.Integer,
        db.ForeignKey('graph_entities.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
    )
    evidence_record_key = db.Column(db.String(96), nullable=False, index=True)
    observation_role = db.Column(db.String(80), nullable=False)
    observed_value = db.Column(db.String(2048), nullable=True)
    observed_at = db.Column(db.DateTime, nullable=True)
    source_table = db.Column(db.String(80), nullable=False, default='events')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    metadata_json = db.Column(db.JSON, nullable=False, default=dict)

    entity = db.relationship('GraphEntity', backref=db.backref('observations', lazy='dynamic', cascade='all, delete-orphan'))

    __table_args__ = (
        db.UniqueConstraint(
            'entity_id',
            'evidence_record_key',
            'observation_role',
            'source_table',
            name='uq_graph_entity_observation_evidence_role',
        ),
        db.Index('idx_graph_entity_observation_case_key', 'case_id', 'evidence_record_key'),
    )

    def __repr__(self):
        return f'<GraphEntityObservation {self.entity_id}:{self.evidence_record_key}>'


class GraphRelationship(db.Model):
    """Canonical case-scoped relationship between two graph entities."""

    __tablename__ = 'graph_relationships'

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, index=True)
    source_entity_id = db.Column(
        db.Integer,
        db.ForeignKey('graph_entities.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
    )
    relationship_type = db.Column(db.String(80), nullable=False, index=True)
    target_entity_id = db.Column(
        db.Integer,
        db.ForeignKey('graph_entities.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
    )
    first_seen_at = db.Column(db.DateTime, nullable=True)
    last_seen_at = db.Column(db.DateTime, nullable=True)
    confidence = db.Column(db.Float, nullable=False, default=1.0)
    derivation_type = db.Column(db.String(40), nullable=False, index=True)
    extractor_name = db.Column(db.String(120), nullable=False)
    extractor_version = db.Column(db.String(40), nullable=False)
    validation_state = db.Column(db.String(40), nullable=False, default='ACTIVE', index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    metadata_json = db.Column(db.JSON, nullable=False, default=dict)

    case = db.relationship('Case', backref=db.backref('graph_relationships', lazy='dynamic', cascade='all, delete-orphan'))
    source_entity = db.relationship(
        'GraphEntity',
        foreign_keys=[source_entity_id],
        backref=db.backref('outgoing_relationships', lazy='dynamic', cascade='all, delete-orphan'),
    )
    target_entity = db.relationship(
        'GraphEntity',
        foreign_keys=[target_entity_id],
        backref=db.backref('incoming_relationships', lazy='dynamic', cascade='all, delete-orphan'),
    )

    __table_args__ = (
        db.UniqueConstraint(
            'case_id',
            'source_entity_id',
            'relationship_type',
            'target_entity_id',
            'derivation_type',
            name='uq_graph_relationship_canonical_edge',
        ),
        db.Index('idx_graph_relationship_case_type', 'case_id', 'relationship_type'),
        db.Index('idx_graph_relationship_source', 'source_entity_id'),
        db.Index('idx_graph_relationship_target', 'target_entity_id'),
    )

    def __repr__(self):
        return f'<GraphRelationship {self.source_entity_id}:{self.relationship_type}:{self.target_entity_id}>'


class GraphRelationshipEvidence(db.Model):
    """Evidence provenance for a canonical graph relationship."""

    __tablename__ = 'graph_relationship_evidence'

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, index=True)
    relationship_id = db.Column(
        db.Integer,
        db.ForeignKey('graph_relationships.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
    )
    evidence_record_key = db.Column(db.String(96), nullable=False, index=True)
    source_table = db.Column(db.String(80), nullable=False, default='events')
    evidence_role = db.Column(db.String(80), nullable=False, default='supporting_record')
    extractor_name = db.Column(db.String(120), nullable=False)
    extractor_version = db.Column(db.String(40), nullable=False)
    observed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    metadata_json = db.Column(db.JSON, nullable=False, default=dict)
    # Phase 0E support lifecycle fields
    support_state = db.Column(db.String(40), nullable=False, default='ACTIVE', index=True)
    source_ref_type = db.Column(db.String(40), nullable=True, index=True)
    source_ref_id = db.Column(db.Integer, nullable=True, index=True)
    support_locator_json = db.Column(db.JSON, nullable=True)
    support_state_reason = db.Column(db.String(255), nullable=True)
    support_state_changed_at = db.Column(db.DateTime, nullable=True)

    relationship = db.relationship(
        'GraphRelationship',
        backref=db.backref('evidence_rows', lazy='dynamic', cascade='all, delete-orphan'),
    )

    __table_args__ = (
        db.UniqueConstraint(
            'relationship_id',
            'evidence_record_key',
            'evidence_role',
            'extractor_name',
            'extractor_version',
            name='uq_graph_relationship_evidence_once',
        ),
        db.Index('idx_graph_relationship_evidence_case_key', 'case_id', 'evidence_record_key'),
        db.Index('idx_graph_rel_evidence_case_support_state', 'case_id', 'support_state'),
        db.Index(
            'idx_graph_rel_evidence_case_source_ref',
            'case_id',
            'source_ref_type',
            'source_ref_id',
        ),
    )

    def __repr__(self):
        return f'<GraphRelationshipEvidence {self.relationship_id}:{self.evidence_record_key}>'
