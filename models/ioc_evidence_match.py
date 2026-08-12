"""Exact IOC UUID -> evidence ERK match provenance (Phase 0E).

events.ioc_types remains a display label only and never proves which IOC matched.
"""
from datetime import datetime

from models.database import db


class IOCEvidenceMatch(db.Model):
    """Durable case-scoped exact IOC match against a normalized event ERK."""

    __tablename__ = 'ioc_evidence_matches'

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, index=True)
    ioc_id = db.Column(db.Integer, db.ForeignKey('iocs.id', ondelete='CASCADE'), nullable=False, index=True)
    ioc_uuid = db.Column(db.String(36), nullable=False, index=True)
    ioc_type = db.Column(db.String(100), nullable=False)
    matched_value = db.Column(db.String(4096), nullable=False)
    matched_field = db.Column(db.String(80), nullable=False, default='search_blob')
    evidence_record_key = db.Column(db.String(96), nullable=False, index=True)
    source_table = db.Column(db.String(80), nullable=False, default='events')
    source_ref_type = db.Column(db.String(40), nullable=True)
    source_ref_id = db.Column(db.Integer, nullable=True)
    support_state = db.Column(db.String(40), nullable=False, default='ACTIVE', index=True)
    observed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    metadata_json = db.Column(db.JSON, nullable=False, default=dict)

    __table_args__ = (
        db.UniqueConstraint(
            'case_id',
            'ioc_uuid',
            'evidence_record_key',
            'matched_field',
            name='uq_ioc_evidence_match_exact',
        ),
        db.Index('idx_ioc_evidence_match_case_ioc', 'case_id', 'ioc_uuid'),
        db.Index('idx_ioc_evidence_match_case_erk', 'case_id', 'evidence_record_key'),
        db.Index('idx_ioc_evidence_match_case_source', 'case_id', 'source_ref_type', 'source_ref_id'),
        db.Index('idx_ioc_evidence_match_case_state', 'case_id', 'support_state'),
    )

    def __repr__(self):
        return f'<IOCEvidenceMatch case={self.case_id} ioc={self.ioc_uuid} erk={self.evidence_record_key}>'
