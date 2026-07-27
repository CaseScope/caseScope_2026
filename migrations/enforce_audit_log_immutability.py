#!/usr/bin/env python3
"""Enforce append-only audit tables at the PostgreSQL level.

Until now `audit_log` and `ai_audit_log` were immutable only inside
SQLAlchemy, via before_update/before_delete listeners. Any statement issued
outside the ORM -- psql, a bulk UPDATE, a compromised application role --
could rewrite or erase history with nothing left to show for it.

This migration closes that path three ways:

1. A BEFORE UPDATE OR DELETE row trigger and a BEFORE TRUNCATE statement
   trigger raise an exception on any attempt to alter existing rows.
2. Table ownership moves to `postgres`, so the application role cannot drop
   the triggers, alter the table, or grant itself back the privileges it
   lost. The application keeps only SELECT and INSERT.
3. The hash chain added in add_audit_log_forensic_columns.py makes any
   change a superuser does force through detectable after the fact.

Run as the postgres OS user so peer authentication applies:

    sudo -u postgres /opt/casescope/venv/bin/python \\
        migrations/enforce_audit_log_immutability.py

Because ownership moves away from the application role, later schema changes
to these tables must also be applied as postgres. Run
add_audit_log_forensic_columns.py first; it needs UPDATE to seed the chain.
"""

import os
import sys

import psycopg2

APP_ROLE = os.environ.get("CASESCOPE_DB_ROLE", "casescope")
DB_NAME = os.environ.get("CASESCOPE_DB_NAME", "casescope")
DB_SOCKET = os.environ.get("CASESCOPE_DB_SOCKET", "/var/run/postgresql")

PROTECTED_TABLES = ("audit_log", "ai_audit_log")

TRIGGER_FUNCTION = """
CREATE OR REPLACE FUNCTION audit_log_prevent_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'Table % is append-only: % is not permitted', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege',
              HINT = 'Audit history is retained for chain of custody. '
                     'Append a correcting entry instead of altering history.';
END;
$$ LANGUAGE plpgsql;
"""


def apply_table(cursor, table: str) -> None:
    """Install triggers and lock down privileges for one audit table."""
    cursor.execute(
        f"DROP TRIGGER IF EXISTS {table}_no_modify ON {table}"
    )
    cursor.execute(
        f"""
        CREATE TRIGGER {table}_no_modify
        BEFORE UPDATE OR DELETE ON {table}
        FOR EACH ROW EXECUTE FUNCTION audit_log_prevent_modification()
        """
    )

    cursor.execute(
        f"DROP TRIGGER IF EXISTS {table}_no_truncate ON {table}"
    )
    cursor.execute(
        f"""
        CREATE TRIGGER {table}_no_truncate
        BEFORE TRUNCATE ON {table}
        FOR EACH STATEMENT EXECUTE FUNCTION audit_log_prevent_modification()
        """
    )

    # Ownership must leave the application role, otherwise it could simply
    # drop the triggers it is being constrained by.
    cursor.execute(f"ALTER TABLE {table} OWNER TO postgres")
    cursor.execute(f"ALTER SEQUENCE IF EXISTS {table}_id_seq OWNER TO postgres")

    cursor.execute(f"REVOKE ALL ON {table} FROM PUBLIC")
    cursor.execute(f"REVOKE ALL ON {table} FROM {APP_ROLE}")
    cursor.execute(f"GRANT SELECT, INSERT ON {table} TO {APP_ROLE}")
    cursor.execute(f"GRANT USAGE, SELECT ON SEQUENCE {table}_id_seq TO {APP_ROLE}")


def report(cursor, table: str) -> None:
    """Print the resulting ownership, grants and triggers for one table."""
    cursor.execute(
        "SELECT tableowner FROM pg_tables WHERE tablename = %s",
        (table,),
    )
    owner_row = cursor.fetchone()
    owner = owner_row[0] if owner_row else "unknown"

    cursor.execute(
        """
        SELECT privilege_type FROM information_schema.table_privileges
         WHERE table_name = %s AND grantee = %s
         ORDER BY privilege_type
        """,
        (table, APP_ROLE),
    )
    grants = [row[0] for row in cursor.fetchall()]

    cursor.execute(
        """
        SELECT tgname FROM pg_trigger
         WHERE tgrelid = %s::regclass AND NOT tgisinternal
         ORDER BY tgname
        """,
        (table,),
    )
    triggers = [row[0] for row in cursor.fetchall()]

    print(f"  {table}: owner={owner} {APP_ROLE}_grants={grants or 'none'}")
    print(f"    triggers: {', '.join(triggers) if triggers else 'none'}")


def run_migration() -> bool:
    """Apply append-only enforcement to every protected audit table."""
    connection = psycopg2.connect(host=DB_SOCKET, user="postgres", dbname=DB_NAME)
    connection.autocommit = False
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_user")
            if cursor.fetchone()[0] != "postgres":
                raise RuntimeError("This migration must run as the postgres superuser")

            cursor.execute(TRIGGER_FUNCTION)
            print("Trigger function installed")

            for table in PROTECTED_TABLES:
                cursor.execute("SELECT to_regclass(%s)", (table,))
                if cursor.fetchone()[0] is None:
                    print(f"  {table}: not present, skipped")
                    continue
                apply_table(cursor, table)

        connection.commit()

        print("\nResulting state:")
        with connection.cursor() as cursor:
            for table in PROTECTED_TABLES:
                cursor.execute("SELECT to_regclass(%s)", (table,))
                if cursor.fetchone()[0] is not None:
                    report(cursor, table)
        return True
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


if __name__ == "__main__":
    print("=" * 60)
    print("Audit Log Immutability Enforcement")
    print("=" * 60)
    print()

    try:
        run_migration()
        sys.exit(0)
    except Exception as exc:
        print(f"Migration failed: {exc}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
