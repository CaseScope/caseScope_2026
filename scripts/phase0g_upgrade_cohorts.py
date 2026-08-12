#!/usr/bin/env python3
"""Historical upgrade-cohort validation for Improvement #1 Phase 0G.

Each cohort:
1. checks out a representative historical SHA in a disposable git worktree
2. bootstraps that version's schema on a disposable PostgreSQL/ClickHouse database
3. inserts representative rows
4. upgrades by running the current documented Version 4 migrations plus
   Improvement #1 migrations from this candidate tree
5. reruns Improvement #1 migrations to prove convergence
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
WORKTREE_ROOT = Path(os.environ.get("PHASE0G_UPGRADE_WORKTREE_ROOT", "/tmp/casescope-phase0g-upgrade-worktrees"))
CURRENT_PYTHON = str(ROOT / "venv" / "bin" / "python")

IMPROVEMENT1_MIGRATIONS = [
    "migrations/add_evidence_record_identity.py",
    "migrations/evidence_identity_udf.py",
    "migrations/add_investigation_graph_tables.py",
    "migrations/add_investigation_threads_tables.py",
    "migrations/add_graph_phase0e_support_lifecycle.py",
    "migrations/invalidate_phase0e_4160_dns_relationships.py",
    "migrations/add_investigation_thread_report_snapshots.py",
]

# Documented Version 4 migration cohorts from wiki/update-software.md.
COHORTS = [
    {
        "id": "pre-4.0.0",
        "sha": "a3ac4e3f3203ada50f4dfc42764533e0392bdd56",
        "version": "3.411.0",
        "database": "phase0g_upgrade_pre400",
        "documented_migrations": [
            "migrations/add_audit_log_forensic_columns.py",
            "migrations/add_audit_reconciliation_markers.py",
            "migrations/backfill_privacy_alias_vault.py",
        ],
        "postgres_migrations": ["migrations/enforce_audit_log_immutability.py"],
        "alias_vault_reset": False,
    },
    {
        "id": "exactly-4.0.0",
        "sha": "91eae6f68551703d2b320f3bb67682f3c043f2f1",
        "version": "4.0.0",
        "database": "phase0g_upgrade_400",
        "documented_migrations": [],
        "postgres_migrations": [],
        "alias_vault_reset": True,
    },
    {
        "id": "4.0.1-through-4.2.x",
        "sha": "4902188b",
        "version": "4.2.0",
        "database": "phase0g_upgrade_401",
        "documented_migrations": [],
        "postgres_migrations": [],
        "alias_vault_reset": False,
    },
    {
        "id": "4.17.2-pre-improvement1",
        "sha": "4298bd24cac5bcb87d3128941aa227df33dfac84",
        "version": "4.17.2",
        "database": "phase0g_upgrade_4172",
        "documented_migrations": [],
        "postgres_migrations": [],
        "alias_vault_reset": False,
    },
]


def _run(command, *, env=None, cwd=ROOT, timeout=300):
    completed = subprocess.run(command, cwd=str(cwd), env=env, text=True, capture_output=True, timeout=timeout)
    return {
        "command": command,
        "exit_code": completed.returncode,
        "stdout": (completed.stdout or "")[-8000:],
        "stderr": (completed.stderr or "")[-8000:],
    }


def _casescope_run(command, *, env, cwd=ROOT, timeout=300):
    """PostgreSQL peer auth requires the casescope OS user."""
    keep = [
        "DATABASE_URL", "CLICKHOUSE_HOST", "CLICKHOUSE_PORT", "CLICKHOUSE_DATABASE",
        "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD", "SECRET_KEY", "DEFAULT_ADMIN_PASSWORD",
        "PYTHONPATH", "HOME", "PATH", "LANG", "LC_ALL",
    ]
    env_args = [f"{key}={env[key]}" for key in keep if env.get(key)]
    wrapped = ["sudo", "-n", "-u", "casescope", "env", f"HOME={env.get('HOME', '/opt/casescope')}", *env_args, *command]
    return _run(wrapped, cwd=cwd, timeout=timeout)


def _db_name(url: str) -> str:
    return urlparse(url).path.rsplit("/", 1)[-1]


def _assert_disposable(dbname: str) -> None:
    if not dbname.startswith("phase0g_"):
        raise SystemExit(f"Refusing non-disposable upgrade database {dbname}")


def _worktree_path(cohort_id: str) -> Path:
    return WORKTREE_ROOT / cohort_id


def _ensure_worktree(cohort: dict) -> dict:
    dest = _worktree_path(cohort["id"])
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        head = _run(["git", "rev-parse", "HEAD"], cwd=dest, timeout=30)
        current = (head["stdout"] or "").strip()
        if current.startswith(cohort["sha"]) or cohort["sha"].startswith(current[:8]):
            version = _run(["git", "show", f"{cohort['sha']}:version.json"], timeout=30)
            return {
                "worktree": str(dest),
                "add": {"command": ["reuse"], "exit_code": 0, "stdout": "reused", "stderr": ""},
                "head": current,
                "version_json": (version["stdout"] or "").strip()[:500],
            }
        _run(["git", "worktree", "remove", "--force", str(dest)], timeout=60)
        shutil.rmtree(dest, ignore_errors=True)
    added = _run(["git", "worktree", "add", "--detach", str(dest), cohort["sha"]], timeout=120)
    head = _run(["git", "rev-parse", "HEAD"], cwd=dest, timeout=30)
    version = _run(["git", "show", f"{cohort['sha']}:version.json"], timeout=30)
    return {
        "worktree": str(dest),
        "add": added,
        "head": (head["stdout"] or "").strip(),
        "version_json": (version["stdout"] or "").strip()[:500],
    }


def _historical_bootstrap(worktree: Path, env: dict) -> dict:
    # Historical create_app signatures differ. Try the current optional kwargs
    # first, then the older no-arg form. Always run from the historical tree.
    script = (
        "import traceback\n"
        "from app import create_app\n"
        "app = None\n"
        "try:\n"
        "    app = create_app(run_startup_bootstrap=True, register_blueprints=False)\n"
        "    print('bootstrap-ok-kwargs')\n"
        "except TypeError:\n"
        "    app = create_app()\n"
        "    print('bootstrap-ok-legacy')\n"
        "except Exception:\n"
        "    traceback.print_exc()\n"
        "    raise\n"
        "from models.database import db\n"
        "from models.case import Case\n"
        "from models.client import Client\n"
        "with app.app_context():\n"
        "    db.create_all()\n"
        "    client = Client.query.filter_by(code='PHASE0G').first()\n"
        "    if client is None:\n"
        "        kwargs = {'name': 'PHASE0G Client', 'code': 'PHASE0G'}\n"
        "        if hasattr(Client, 'timezone'):\n"
        "            kwargs['timezone'] = 'UTC'\n"
        "        client = Client(**kwargs)\n"
        "        db.session.add(client)\n"
        "        db.session.flush()\n"
        "    case = Case.query.filter_by(name='phase0g_upgrade_case').first()\n"
        "    if case is None:\n"
        "        kwargs = {\n"
        "            'name': 'phase0g_upgrade_case',\n"
        "            'company': 'PHASE0G',\n"
        "            'description': 'Disposable upgrade cohort case',\n"
        "            'created_by': 'phase0g',\n"
        "        }\n"
        "        if hasattr(Case, 'timezone'):\n"
        "            kwargs['timezone'] = 'UTC'\n"
        "        if hasattr(Case, 'client_id'):\n"
        "            kwargs['client_id'] = client.id\n"
        "        case = Case(**kwargs)\n"
        "        db.session.add(case)\n"
        "    db.session.commit()\n"
        "    print('case-id', getattr(case, 'id', None), 'case-uuid', getattr(case, 'uuid', None))\n"
    )
    hist_env = env.copy()
    hist_env["PYTHONPATH"] = str(worktree)
    hist_env["SECRET_KEY"] = hist_env.get("SECRET_KEY", "phase0g-disposable-secret")
    hist_env["DEFAULT_ADMIN_PASSWORD"] = hist_env.get("DEFAULT_ADMIN_PASSWORD", "Phase0gAdmin1")
    return _casescope_run([CURRENT_PYTHON, "-c", script], env=hist_env, cwd=worktree, timeout=180)


def _run_migration(path: str, env: dict, *, as_postgres: bool = False, extra_args=None, timeout=180) -> dict:
    extra_args = extra_args or []
    command = [CURRENT_PYTHON, str(ROOT / path), *extra_args]
    if as_postgres:
        result = _run(["sudo", "-n", "-u", "postgres", "env", *[f"{k}={v}" for k, v in env.items() if k in (
            "DATABASE_URL", "CLICKHOUSE_HOST", "CLICKHOUSE_PORT", "CLICKHOUSE_DATABASE",
            "SECRET_KEY", "DEFAULT_ADMIN_PASSWORD", "PYTHONPATH",
        )], CURRENT_PYTHON, str(ROOT / path), *extra_args], cwd=ROOT, timeout=timeout)
    else:
        result = _casescope_run(command, env=env, cwd=ROOT, timeout=timeout)
    return {"migration": path, "as_postgres": as_postgres, "extra_args": extra_args, **result}


def _schema_probe(env: dict) -> dict:
    script = (
        "from sqlalchemy import inspect, text\n"
        "from app import create_app\n"
        "from models.database import db\n"
        "app = create_app(run_startup_bootstrap=False, register_blueprints=False)\n"
        "with app.app_context():\n"
        "    insp = inspect(db.engine)\n"
        "    tables = set(insp.get_table_names())\n"
        "    wanted = [\n"
        "        'graph_entities', 'graph_relationships', 'graph_relationship_evidence',\n"
        "        'investigation_threads', 'graph_saved_views',\n"
        "        'investigation_thread_report_snapshots',\n"
        "    ]\n"
        "    print('tables', {name: name in tables for name in wanted})\n"
        "    if 'graph_relationship_evidence' in tables:\n"
        "        cols = {c['name'] for c in insp.get_columns('graph_relationship_evidence')}\n"
        "        print('support_cols', sorted(x for x in ('support_state','source_ref_type','source_ref_id') if x in cols))\n"
    )
    return _casescope_run([CURRENT_PYTHON, "-c", script], env=env, timeout=120)


def main() -> int:
    results = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tested_sha": _run(["git", "rev-parse", "HEAD"])["stdout"].strip(),
        "cohorts": [],
        "migrations": [],
    }
    pg_user = os.environ.get("PHASE0G_PG_USER", "casescope")
    for cohort in COHORTS:
        dbname = cohort["database"]
        _assert_disposable(dbname)
        env = os.environ.copy()
        env["DATABASE_URL"] = f"postgresql://{pg_user}@/{dbname}?host=/var/run/postgresql"
        env["CLICKHOUSE_DATABASE"] = dbname
        env["CLICKHOUSE_HOST"] = env.get("CLICKHOUSE_HOST", "localhost")
        env["CLICKHOUSE_PORT"] = env.get("CLICKHOUSE_PORT", "8123")
        env["SECRET_KEY"] = env.get("SECRET_KEY", "phase0g-disposable-secret")
        env["DEFAULT_ADMIN_PASSWORD"] = env.get("DEFAULT_ADMIN_PASSWORD", "Phase0gAdmin1")
        env["PYTHONPATH"] = str(ROOT)
        print(json.dumps({
            "event": "phase0g_upgrade_targets",
            "cohort": cohort["id"],
            "sha": cohort["sha"],
            "postgres_host": "unix-socket",
            "postgres_database": dbname,
            "clickhouse_host": env["CLICKHOUSE_HOST"],
            "clickhouse_database": dbname,
            "git_sha": results["tested_sha"],
        }))
        worktree = _ensure_worktree(cohort)
        bootstrap = _historical_bootstrap(Path(worktree["worktree"]), env)
        events_table = _run_migration("migrations/add_events_table.py", env)
        documented = []
        for migration in cohort["documented_migrations"]:
            documented.append(_run_migration(migration, env))
        if cohort.get("alias_vault_reset"):
            documented.append(_run_migration("migrations/backfill_privacy_alias_vault.py", env, extra_args=["--reset"]))
        postgres_runs = []
        for migration in cohort["postgres_migrations"]:
            postgres_runs.append(_run_migration(migration, env, as_postgres=True))
        first = [_run_migration(migration, env) for migration in IMPROVEMENT1_MIGRATIONS]
        second = [_run_migration(migration, env) for migration in IMPROVEMENT1_MIGRATIONS]
        probe = _schema_probe(env)
        first_ok = all(item["exit_code"] == 0 for item in first)
        second_ok = all(item["exit_code"] == 0 for item in second)
        documented_ok = all(item["exit_code"] == 0 for item in documented) if documented else True
        postgres_ok = all(item["exit_code"] == 0 for item in postgres_runs) if postgres_runs else True
        cohort_result = {
            **cohort,
            "worktree": worktree,
            "bootstrap": bootstrap,
            "documented_first": documented,
            "postgres_migrations_result": postgres_runs,
            "events_table": {"exit_code": events_table["exit_code"], "stdout": events_table["stdout"][-1500:], "stderr": events_table["stderr"][-1500:]},
            "first_run": [{"migration": item["migration"], "exit_code": item["exit_code"], "stdout": item["stdout"][-1500:], "stderr": item["stderr"][-1500:]} for item in first],
            "second_run": [{"migration": item["migration"], "exit_code": item["exit_code"], "stdout": item["stdout"][-1500:], "stderr": item["stderr"][-1500:]} for item in second],
            "schema_probe": probe,
            "first_run_ok": first_ok,
            "second_run_ok": second_ok,
            "documented_ok": documented_ok,
            "postgres_ok": postgres_ok,
            "converged": first_ok and second_ok,
            "bootstrap_ok": bootstrap["exit_code"] == 0,
        }
        results["cohorts"].append(cohort_result)
        results["migrations"].extend(
            [{"cohort": cohort["id"], "pass": 1, "migration": item["migration"], "exit_code": item["exit_code"]} for item in first]
            + [{"cohort": cohort["id"], "pass": 2, "migration": item["migration"], "exit_code": item["exit_code"]} for item in second]
        )
        print(json.dumps({
            "event": "phase0g_upgrade_cohort_done",
            "cohort": cohort["id"],
            "bootstrap_ok": cohort_result["bootstrap_ok"],
            "first_run_ok": first_ok,
            "second_run_ok": second_ok,
            "converged": cohort_result["converged"],
        }))
    results["status"] = "PASS" if all(item["converged"] and item["bootstrap_ok"] for item in results["cohorts"]) else "FAIL"
    output = Path(os.environ.get("PHASE0G_UPGRADE_OUTPUT", "/tmp/casescope-phase0g-results/phase0g_upgrade.json"))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"event": "phase0g_upgrade_result", "output": str(output), "status": results["status"]}))
    return 0 if results["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
