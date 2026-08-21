#!/usr/bin/env python3
"""Migration: add Phase 1B Tranche F1 completion-reconciliation audit."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.database_flow import CaseCompletionReconciliationAudit


def migrate_postgres():
    app = create_app()
    with app.app_context():
        CaseCompletionReconciliationAudit.__table__.create(db.engine, checkfirst=True)
        print("- Added or verified case_completion_reconciliation_audit")
    return True


def migrate():
    print("=" * 50)
    print("Phase 1B Tranche F1 Completion Reconciliation Migration")
    print("=" * 50)
    migrate_postgres()
    print("\n" + "=" * 50)
    print("Migration complete!")
    print("=" * 50)
    return True


if __name__ == "__main__":
    migrate()
