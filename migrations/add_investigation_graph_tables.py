#!/usr/bin/env python3
"""Migration: add Phase 0B investigative graph tables."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.graph import (
    GraphEntity,
    GraphEntityObservation,
    GraphRelationship,
    GraphRelationshipEvidence,
)
from sqlalchemy import inspect, text


RELATIONSHIP_EDGE_CONSTRAINT = 'uq_graph_relationship_canonical_edge'
RELATIONSHIP_EDGE_COLUMNS = [
    'case_id',
    'source_entity_id',
    'relationship_type',
    'target_entity_id',
    'derivation_type',
]


def _unique_constraint_columns(inspector, table_name, constraint_name):
    for constraint in inspector.get_unique_constraints(table_name):
        if constraint.get('name') == constraint_name:
            return list(constraint.get('column_names') or [])
    return []


def _ensure_relationship_edge_constraint():
    """Converge graph_relationships from the 4.13.0 uniqueness contract."""
    inspector = inspect(db.engine)
    if 'graph_relationships' not in inspector.get_table_names():
        return False

    current_columns = _unique_constraint_columns(
        inspector,
        'graph_relationships',
        RELATIONSHIP_EDGE_CONSTRAINT,
    )
    if current_columns == RELATIONSHIP_EDGE_COLUMNS:
        print(f"Constraint already current: {RELATIONSHIP_EDGE_CONSTRAINT}")
        return False

    db.session.execute(text(
        f"ALTER TABLE graph_relationships DROP CONSTRAINT IF EXISTS {RELATIONSHIP_EDGE_CONSTRAINT}"
    ))
    db.session.execute(text(f"""
        ALTER TABLE graph_relationships
        ADD CONSTRAINT {RELATIONSHIP_EDGE_CONSTRAINT}
        UNIQUE ({', '.join(RELATIONSHIP_EDGE_COLUMNS)})
    """))
    db.session.commit()
    print(f"Updated constraint: {RELATIONSHIP_EDGE_CONSTRAINT}")
    return True


def migrate():
    """Create PostgreSQL tables for the evidence-backed investigative graph."""
    app = create_app()
    with app.app_context():
        tables = [
            GraphEntity.__table__,
            GraphEntityObservation.__table__,
            GraphRelationship.__table__,
            GraphRelationshipEvidence.__table__,
        ]
        created = []
        skipped = []
        with db.engine.connect() as connection:
            for table in tables:
                if not db.engine.dialect.has_table(connection, table.name):
                    table.create(db.engine)
                    created.append(table.name)
                    print(f"Created table: {table.name}")
                else:
                    skipped.append(table.name)
                    print(f"Table already exists: {table.name}")
        constraint_updated = _ensure_relationship_edge_constraint()
        print(f"Migration complete: {len(created)} created, {len(skipped)} skipped")
        return True if created or constraint_updated else True


if __name__ == '__main__':
    migrate()
