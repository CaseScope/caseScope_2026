"""MITRE ATT&CK Enterprise reference models."""
from datetime import datetime

from models.database import db


class MitreAttackMetadata(db.Model):
    """Tracks the installed MITRE ATT&CK Enterprise snapshot."""

    __tablename__ = 'mitre_attack_metadata'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(50), nullable=False, unique=True, default='enterprise')
    attack_version = db.Column(db.String(50), nullable=True, index=True)
    attack_spec_version = db.Column(db.String(50), nullable=True)
    source_url = db.Column(db.String(500), nullable=False)
    source_modified = db.Column(db.String(50), nullable=True)
    raw_object_count = db.Column(db.Integer, nullable=False, default=0)
    last_updated_at = db.Column(db.DateTime, nullable=True)
    last_checked_at = db.Column(db.DateTime, nullable=True)
    latest_available_version = db.Column(db.String(50), nullable=True)
    update_available = db.Column(db.Boolean, nullable=False, default=False)
    updated_by = db.Column(db.String(100), nullable=True)

    @classmethod
    def get_enterprise(cls):
        return cls.query.filter_by(domain='enterprise').first()

    @classmethod
    def ensure_enterprise(cls):
        row = cls.get_enterprise()
        if row:
            return row
        row = cls(domain='enterprise', source_url='')
        db.session.add(row)
        return row


class MitreAttackObject(db.Model):
    """Stores tactics, techniques, sub-techniques, and procedure examples."""

    __tablename__ = 'mitre_attack_object'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(50), nullable=False, default='enterprise', index=True)
    object_type = db.Column(db.String(30), nullable=False, index=True)
    stix_id = db.Column(db.String(120), nullable=False, unique=True, index=True)
    external_id = db.Column(db.String(30), nullable=True, index=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    tactic_shortname = db.Column(db.String(100), nullable=True, index=True)
    tactic_name = db.Column(db.String(150), nullable=True)
    technique_stix_id = db.Column(db.String(120), nullable=True, index=True)
    technique_external_id = db.Column(db.String(30), nullable=True, index=True)
    parent_stix_id = db.Column(db.String(120), nullable=True, index=True)
    platforms = db.Column(db.JSON, nullable=False, default=list)
    data_sources = db.Column(db.JSON, nullable=False, default=list)
    permissions_required = db.Column(db.JSON, nullable=False, default=list)
    detection = db.Column(db.Text, nullable=True)
    url = db.Column(db.String(500), nullable=True)
    version = db.Column(db.String(50), nullable=True)
    stix_created = db.Column(db.String(50), nullable=True)
    stix_modified = db.Column(db.String(50), nullable=True)
    source_name = db.Column(db.String(255), nullable=True)
    source_type = db.Column(db.String(80), nullable=True)
    metadata_json = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        db.Index('ix_mitre_attack_object_domain_type', 'domain', 'object_type'),
        db.Index('ix_mitre_attack_object_external_type', 'external_id', 'object_type'),
    )

    @classmethod
    def get_stats(cls):
        """Return object counts grouped for the settings UI."""
        from sqlalchemy import func

        rows = db.session.query(cls.object_type, func.count(cls.id)).group_by(cls.object_type).all()
        counts = {object_type: count for object_type, count in rows}
        metadata = MitreAttackMetadata.get_enterprise()
        return {
            'tactics': counts.get('tactic', 0),
            'techniques': counts.get('technique', 0),
            'sub_techniques': counts.get('sub_technique', 0),
            'procedures': counts.get('procedure', 0),
            'total': sum(counts.values()),
            'attack_version': metadata.attack_version if metadata else None,
            'attack_spec_version': metadata.attack_spec_version if metadata else None,
            'source_url': metadata.source_url if metadata else None,
            'source_modified': metadata.source_modified if metadata else None,
            'raw_object_count': metadata.raw_object_count if metadata else 0,
            'last_updated_at': metadata.last_updated_at.isoformat() if metadata and metadata.last_updated_at else None,
            'last_checked_at': metadata.last_checked_at.isoformat() if metadata and metadata.last_checked_at else None,
            'latest_available_version': metadata.latest_available_version if metadata else None,
            'update_available': bool(metadata.update_available) if metadata else False,
        }
