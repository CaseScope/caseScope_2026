"""Privacy alias vault models for Cloud AI Privacy Mode."""
from datetime import datetime

from models.database import db


class PrivacyAlias(db.Model):
    """Case-scoped mapping from original protected values to typed aliases."""

    __tablename__ = 'privacy_aliases'

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    tenant_id = db.Column(db.String(255), nullable=True, index=True)

    entity_type = db.Column(db.String(64), nullable=False, index=True)
    original_value = db.Column(db.Text, nullable=False)
    normalized_value = db.Column(db.Text, nullable=False)
    alias_value = db.Column(db.String(128), nullable=False)

    sensitivity_classification = db.Column(db.String(64), nullable=False, default='protected')
    source = db.Column(db.String(64), nullable=False, default='ai_privacy_scan')
    manual_override = db.Column(db.Boolean, nullable=False, default=False)

    seen_count = db.Column(db.Integer, nullable=False, default=1)
    first_seen_at = db.Column(db.DateTime, nullable=True)
    last_seen_at = db.Column(db.DateTime, nullable=True)
    sample_fields = db.Column(db.JSON, nullable=False, default=list)
    relationships = db.Column(db.JSON, nullable=False, default=dict)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    case = db.relationship('Case', backref=db.backref('privacy_aliases', lazy='dynamic'))

    __table_args__ = (
        db.UniqueConstraint(
            'case_id',
            'entity_type',
            'normalized_value',
            name='uq_privacy_alias_case_type_normalized',
        ),
        db.UniqueConstraint(
            'case_id',
            'alias_value',
            name='uq_privacy_alias_case_alias',
        ),
    )

    def to_dict(self):
        """Convert alias metadata to a dictionary without hiding original values."""
        return {
            'id': self.id,
            'case_id': self.case_id,
            'tenant_id': self.tenant_id,
            'entity_type': self.entity_type,
            'original_value': self.original_value,
            'normalized_value': self.normalized_value,
            'alias_value': self.alias_value,
            'sensitivity_classification': self.sensitivity_classification,
            'source': self.source,
            'manual_override': self.manual_override,
            'seen_count': self.seen_count,
            'first_seen_at': self.first_seen_at.isoformat() if self.first_seen_at else None,
            'last_seen_at': self.last_seen_at.isoformat() if self.last_seen_at else None,
            'sample_fields': self.sample_fields or [],
            'relationships': self.relationships or {},
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class PrivacyAliasCounter(db.Model):
    """Per-case, per-entity alias sequence state."""

    __tablename__ = 'privacy_alias_counters'

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    entity_type = db.Column(db.String(64), nullable=False)
    next_number = db.Column(db.Integer, nullable=False, default=1)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint(
            'case_id',
            'entity_type',
            name='uq_privacy_alias_counter_case_type',
        ),
    )
