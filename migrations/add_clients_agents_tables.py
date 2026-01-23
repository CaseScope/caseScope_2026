#!/usr/bin/env python3
"""
Migration: Add Clients and Agents Tables

Creates tables for client/agent management:
- clients: Organizations that cases belong to
- agents: Deployed collection agents per client
- Adds client_id FK to cases table
- Auto-migrates existing case.company values to clients

Run with: python migrations/add_clients_agents_tables.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.client import Client
from models.agent import Agent
from models.case import Case
from sqlalchemy import text, inspect


def table_exists(engine, table_name):
    """Check if a table exists in the database"""
    inspector = inspect(engine)
    return table_name in inspector.get_table_names()


def column_exists(engine, table_name, column_name):
    """Check if a column exists in a table"""
    inspector = inspect(engine)
    if table_name not in inspector.get_table_names():
        return False
    columns = [col['name'] for col in inspector.get_columns(table_name)]
    return column_name in columns


def migrate():
    """Create clients and agents tables, migrate existing data"""
    app = create_app()
    
    with app.app_context():
        print("=" * 60)
        print("Migration: Add Clients and Agents Tables")
        print("=" * 60)
        
        created_tables = []
        skipped_tables = []
        
        # Step 1: Create clients table
        print("\n[Step 1/5] Creating clients table...")
        if not table_exists(db.engine, 'clients'):
            Client.__table__.create(db.engine)
            created_tables.append('clients')
            print("  ✓ Created table: clients")
        else:
            skipped_tables.append('clients')
            print("  ○ Table already exists: clients")
        
        # Step 2: Create agents table
        print("\n[Step 2/5] Creating agents table...")
        if not table_exists(db.engine, 'agents'):
            Agent.__table__.create(db.engine)
            created_tables.append('agents')
            print("  ✓ Created table: agents")
        else:
            skipped_tables.append('agents')
            print("  ○ Table already exists: agents")
        
        # Step 3: Add client_id column to cases table
        print("\n[Step 3/5] Adding client_id column to cases table...")
        if not column_exists(db.engine, 'cases', 'client_id'):
            with db.engine.connect() as conn:
                conn.execute(text("""
                    ALTER TABLE cases 
                    ADD COLUMN client_id INTEGER REFERENCES clients(id)
                """))
                conn.commit()
            print("  ✓ Added column: cases.client_id")
            
            # Create index on client_id
            with db.engine.connect() as conn:
                conn.execute(text("""
                    CREATE INDEX IF NOT EXISTS ix_cases_client_id ON cases(client_id)
                """))
                conn.commit()
            print("  ✓ Created index: ix_cases_client_id")
        else:
            print("  ○ Column already exists: cases.client_id")
        
        # Step 4: Migrate existing companies to clients
        print("\n[Step 4/5] Migrating existing companies to clients...")
        
        # Get distinct company names from cases that don't have a client_id yet
        cases_without_client = Case.query.filter(Case.client_id.is_(None)).all()
        
        if not cases_without_client:
            print("  ○ No cases without client_id found")
        else:
            # Get unique company names
            unique_companies = set()
            for case in cases_without_client:
                if case.company:
                    unique_companies.add(case.company.strip())
            
            print(f"  Found {len(unique_companies)} unique company name(s) to migrate")
            
            clients_created = 0
            for company_name in sorted(unique_companies):
                # Check if client already exists with this name
                existing_client = Client.query.filter(
                    db.func.lower(Client.name) == company_name.lower()
                ).first()
                
                if existing_client:
                    print(f"  ○ Client already exists: {company_name}")
                    client = existing_client
                else:
                    # Generate a unique code
                    code = Client.generate_code_from_name(company_name)
                    
                    # Create new client
                    client = Client(
                        name=company_name,
                        code=code,
                        created_by='migration'
                    )
                    db.session.add(client)
                    db.session.flush()  # Get the ID
                    clients_created += 1
                    print(f"  ✓ Created client: {company_name} (code: {code})")
                
                # Update all cases with this company to use the new client_id
                cases_updated = Case.query.filter(
                    Case.company == company_name,
                    Case.client_id.is_(None)
                ).update({Case.client_id: client.id})
                
                if cases_updated > 0:
                    print(f"    → Linked {cases_updated} case(s)")
            
            db.session.commit()
            print(f"\n  Summary: {clients_created} client(s) created")
        
        # Step 5: Verify migration
        print("\n[Step 5/5] Verifying migration...")
        
        total_clients = Client.query.count()
        total_agents = Agent.query.count()
        total_cases = Case.query.count()
        cases_with_client = Case.query.filter(Case.client_id.isnot(None)).count()
        cases_without_client = Case.query.filter(Case.client_id.is_(None)).count()
        
        print(f"  Total clients: {total_clients}")
        print(f"  Total agents: {total_agents}")
        print(f"  Total cases: {total_cases}")
        print(f"  Cases with client_id: {cases_with_client}")
        print(f"  Cases without client_id: {cases_without_client}")
        
        if cases_without_client > 0:
            print(f"\n  ⚠ Warning: {cases_without_client} case(s) still without client_id")
            print("    These may have empty company names")
        
        # Print summary
        print("\n" + "=" * 60)
        print("Migration Complete")
        print("=" * 60)
        print(f"Tables created: {len(created_tables)} ({', '.join(created_tables) if created_tables else 'none'})")
        print(f"Tables skipped: {len(skipped_tables)} ({', '.join(skipped_tables) if skipped_tables else 'none'})")
        
        return True


def rollback():
    """Rollback the migration (use with caution)"""
    app = create_app()
    
    with app.app_context():
        print("=" * 60)
        print("Rollback: Remove Clients and Agents Tables")
        print("=" * 60)
        print("\n⚠ WARNING: This will delete all client and agent data!")
        
        confirm = input("Type 'CONFIRM' to proceed: ")
        if confirm != 'CONFIRM':
            print("Rollback cancelled.")
            return False
        
        # Remove client_id column from cases
        print("\n[Step 1/3] Removing client_id column from cases...")
        if column_exists(db.engine, 'cases', 'client_id'):
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE cases DROP COLUMN client_id"))
                conn.commit()
            print("  ✓ Removed column: cases.client_id")
        else:
            print("  ○ Column does not exist: cases.client_id")
        
        # Drop agents table
        print("\n[Step 2/3] Dropping agents table...")
        if table_exists(db.engine, 'agents'):
            with db.engine.connect() as conn:
                conn.execute(text("DROP TABLE agents"))
                conn.commit()
            print("  ✓ Dropped table: agents")
        else:
            print("  ○ Table does not exist: agents")
        
        # Drop clients table
        print("\n[Step 3/3] Dropping clients table...")
        if table_exists(db.engine, 'clients'):
            with db.engine.connect() as conn:
                conn.execute(text("DROP TABLE clients"))
                conn.commit()
            print("  ✓ Dropped table: clients")
        else:
            print("  ○ Table does not exist: clients")
        
        print("\nRollback complete.")
        return True


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--rollback':
        rollback()
    else:
        migrate()
