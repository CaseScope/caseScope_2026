#!/usr/bin/env python3
"""Migration: Phase 0E graph support lifecycle + exact IOC evidence matches."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.ioc_evidence_match import IOCEvidenceMatch
from sqlalchemy import inspect, text


EVIDENCE_COLUMNS = {
    'support_state': "ALTER TABLE graph_relationship_evidence ADD COLUMN IF NOT EXISTS support_state VARCHAR(40) NOT NULL DEFAULT 'ACTIVE'",
    'source_ref_type': "ALTER TABLE graph_relationship_evidence ADD COLUMN IF NOT EXISTS source_ref_type VARCHAR(40)",
    'source_ref_id': "ALTER TABLE graph_relationship_evidence ADD COLUMN IF NOT EXISTS source_ref_id INTEGER",
    'support_locator_json': "ALTER TABLE graph_relationship_evidence ADD COLUMN IF NOT EXISTS support_locator_json JSONB",
    'support_state_reason': "ALTER TABLE graph_relationship_evidence ADD COLUMN IF NOT EXISTS support_state_reason VARCHAR(255)",
    'support_state_changed_at': "ALTER TABLE graph_relationship_evidence ADD COLUMN IF NOT EXISTS support_state_changed_at TIMESTAMP",
}

EVIDENCE_INDEXES = {
    'idx_graph_rel_evidence_case_support_state': (
        'CREATE INDEX IF NOT EXISTS idx_graph_rel_evidence_case_support_state '
        'ON graph_relationship_evidence (case_id, support_state)'
    ),
    'idx_graph_rel_evidence_case_source_ref': (
        'CREATE INDEX IF NOT EXISTS idx_graph_rel_evidence_case_source_ref '
        'ON graph_relationship_evidence (case_id, source_ref_type, source_ref_id)'
    ),
}


def _column_names(inspector, table_name):
    if table_name not in inspector.get_table_names():
        return set()
    return {col['name'] for col in inspector.get_columns(table_name)}


def _index_names(inspector, table_name):
    if table_name not in inspector.get_table_names():
        return set()
    return {idx['name'] for idx in inspector.get_indexes(table_name)}


def migrate():
    app = create_app()
    with app.app_context():
        inspector = inspect(db.engine)
        changed = []

        if 'graph_relationship_evidence' in inspector.get_table_names():
            existing_cols = _column_names(inspector, 'graph_relationship_evidence')
            for name, ddl in EVIDENCE_COLUMNS.items():
                if name not in existing_cols:
                    db.session.execute(text(ddl))
                    changed.append(f'added graph_relationship_evidence.{name}')
            db.session.commit()

            # Initialize existing support rows as ACTIVE (idempotent).
            db.session.execute(text(
                "UPDATE graph_relationship_evidence "
                "SET support_state = 'ACTIVE' "
                "WHERE support_state IS NULL OR support_state = ''"
            ))
            db.session.commit()

            inspector = inspect(db.engine)
            existing_indexes = _index_names(inspector, 'graph_relationship_evidence')
            for name, ddl in EVIDENCE_INDEXES.items():
                if name not in existing_indexes:
                    db.session.execute(text(ddl))
                    changed.append(f'added index {name}')
            db.session.commit()

        if not db.engine.dialect.has_table(db.engine.connect(), IOCEvidenceMatch.__tablename__):
            IOCEvidenceMatch.__table__.create(db.engine)
            changed.append(f'created {IOCEvidenceMatch.__tablename__}')

        if changed:
            print('Phase 0E migration applied:')
            for item in changed:
                print(f'  - {item}')
        else:
            print('Phase 0E migration already applied')


if __name__ == '__main__':
    migrate()
