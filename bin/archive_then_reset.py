#!/opt/casescope/venv/bin/python3
"""Archive all case/client data, then reset the app to a fresh client/case state."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence
from unittest.mock import patch
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from flask import Flask
from sqlalchemy import inspect, text

from config import Config
from models.case import Case
from models.client import Client
from models.database import db
from models.system_settings import SettingKeys, SystemSettings
from models.network_log import (
    wait_for_mutation_completion,
)
from utils.artifact_paths import get_case_artifact_paths
from utils.case_deletion import delete_client_permanently
from utils.clickhouse import (
    destructive_event_rewrite_guard,
    get_client as get_clickhouse_client,
)
from utils.event_overlay_repair import purge_case_event_overlay_state


SERVICE_NAMES = ("casescope-workers", "casescope-web")
CLICKHOUSE_BACKUP_TABLES = (
    "events",
    "network_logs",
    "case_unified_findings",
    "detection_summary",
    "event_analyst_state",
    "event_ioc_case_state",
    "event_ioc_state",
    "event_noise_case_state",
    "event_noise_state",
    "event_noise_manual_state",
    "timeline_hourly",
)
CASE_ANALYTICS_TABLES = CLICKHOUSE_BACKUP_TABLES + (
    "events_buffer",
    "network_logs_buffer",
)
DEFAULT_ARCHIVE_LAYOUT_PREFIX = "system_reset"
CLICKHOUSE_NATIVE_PORT = int(os.environ.get("CLICKHOUSE_NATIVE_PORT", 9000))


@dataclass
class SnapshotLayout:
    root: Path
    postgres_dir: Path
    clickhouse_dir: Path
    cases_dir: Path
    manifests_dir: Path
    inventory_path: Path
    postgresql_dump_path: Path
    postgresql_schema_path: Path
    root_manifest_path: Path


def build_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    return app


def utc_now_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_stats(root: Path) -> Dict[str, int]:
    if not root.exists():
        return {"file_count": 0, "size_bytes": 0}
    file_count = 0
    size_bytes = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        file_count += 1
        size_bytes += path.stat().st_size
    return {"file_count": file_count, "size_bytes": size_bytes}


def ensure_casescope_permissions(path: Path) -> None:
    try:
        shutil.chown(path, user="casescope", group="casescope")
    except (LookupError, PermissionError, OSError):
        pass


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    ensure_casescope_permissions(path)
    try:
        path.chmod(0o2775)
    except OSError:
        pass
    return path


def write_json(path: Path, payload: Any) -> None:
    ensure_directory(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    ensure_casescope_permissions(path)
    try:
        path.chmod(0o664)
    except OSError:
        pass


def run_command(args: Sequence[str], *, stdout_path: Path | None = None, input_path: Path | None = None) -> None:
    stdout_handle = None
    stdin_handle = None
    try:
        if stdout_path is not None:
            ensure_directory(stdout_path.parent)
            stdout_handle = stdout_path.open("wb")
        if input_path is not None:
            stdin_handle = input_path.open("rb")
        subprocess.run(
            list(args),
            check=True,
            stdout=stdout_handle or subprocess.PIPE,
            stdin=stdin_handle,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
        raise RuntimeError(f"Command failed: {' '.join(args)}\n{stderr}") from exc
    finally:
        if stdout_handle is not None:
            stdout_handle.close()
            ensure_casescope_permissions(stdout_path)
            try:
                stdout_path.chmod(0o664)
            except OSError:
                pass
        if stdin_handle is not None:
            stdin_handle.close()


def get_archive_root(app: Flask) -> Path:
    with app.app_context():
        configured = SystemSettings.get(SettingKeys.ARCHIVE_PATH, "/archive")
    return Path(configured)


def build_layout(app: Flask, *, timestamp_slug: str) -> SnapshotLayout:
    archive_root = get_archive_root(app)
    snapshot_root = archive_root / f"{DEFAULT_ARCHIVE_LAYOUT_PREFIX}_{timestamp_slug}"
    return SnapshotLayout(
        root=snapshot_root,
        postgres_dir=snapshot_root / "postgres",
        clickhouse_dir=snapshot_root / "clickhouse",
        cases_dir=snapshot_root / "cases",
        manifests_dir=snapshot_root / "manifests",
        inventory_path=snapshot_root / "manifests" / "inventory.json",
        postgresql_dump_path=snapshot_root / "postgres" / "casescope_full.dump",
        postgresql_schema_path=snapshot_root / "postgres" / "casescope_schema.sql",
        root_manifest_path=snapshot_root / "manifest.json",
    )


def collect_inventory(app: Flask) -> Dict[str, Any]:
    with app.app_context():
        inspector = inspect(db.engine)
        clients = Client.query.order_by(Client.id).all()
        cases = Case.query.order_by(Case.id).all()
        archive_path = SystemSettings.get(SettingKeys.ARCHIVE_PATH, "/archive")
        originals_path = SystemSettings.get(SettingKeys.ORIGINALS_PATH, "/originals")

        clients_payload: List[Dict[str, Any]] = []
        for client in clients:
            client_cases = [case for case in cases if case.client_id == client.id]
            clients_payload.append(
                {
                    "id": client.id,
                    "uuid": client.uuid,
                    "name": client.name,
                    "code": client.code,
                    "case_count": len(client_cases),
                    "cases": [
                        {
                            "id": case.id,
                            "uuid": case.uuid,
                            "name": case.name,
                            "status": case.status,
                            "timezone": case.timezone,
                        }
                        for case in client_cases
                    ],
                }
            )

        pg_tables = inspector.get_table_names()
        pg_case_tables = []
        for table in pg_tables:
            columns = {column["name"] for column in inspector.get_columns(table)}
            if {"case_id", "case_uuid", "client_id"} & columns:
                count = db.session.execute(text(f'SELECT count(*) FROM "{table}"')).scalar_one()
                pg_case_tables.append(
                    {
                        "table": table,
                        "columns": sorted(columns),
                        "row_count": int(count),
                    }
                )

    clickhouse_client = get_clickhouse_client()
    clickhouse_counts = {}
    for table in CASE_ANALYTICS_TABLES:
        clickhouse_counts[table] = int(clickhouse_client.query(f"SELECT count() FROM {table}").result_rows[0][0])

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "archive_path": archive_path,
            "originals_path": originals_path,
            "storage_folder": Config.STORAGE_FOLDER,
            "upload_folder_web": Config.UPLOAD_FOLDER_WEB,
            "upload_folder_sftp": Config.UPLOAD_FOLDER_SFTP,
            "staging_folder": Config.STAGING_FOLDER,
            "evidence_folder": Config.EVIDENCE_FOLDER,
            "pcap_upload_folder": Config.PCAP_UPLOAD_FOLDER,
        },
        "counts": {
            "clients": len(clients_payload),
            "cases": sum(item["case_count"] for item in clients_payload),
        },
        "clients": clients_payload,
        "postgres_case_scoped_tables": pg_case_tables,
        "clickhouse_case_scoped_tables": clickhouse_counts,
    }


def archive_case_files(case: Case, layout: SnapshotLayout) -> Dict[str, Any]:
    case_root = ensure_directory(layout.cases_dir / case.uuid)
    artifact_paths = get_case_artifact_paths(case.uuid)
    archived_sets: Dict[str, Any] = {
        "case_id": case.id,
        "case_uuid": case.uuid,
        "case_name": case.name,
        "status": case.status,
        "archives": {},
    }

    archive_sources = {
        "storage": Path(artifact_paths["storage"]),
        "evidence": Path(artifact_paths["evidence"]),
        "originals_root": Path(artifact_paths["originals_root"]),
        "web_upload": Path(artifact_paths["web_upload"]),
        "sftp_upload": Path(artifact_paths["sftp_upload"]),
        "pcap_upload": Path(artifact_paths["pcap_upload"]),
        "evidence_bulk": Path(artifact_paths["evidence_bulk"]),
    }

    for label, source_path in archive_sources.items():
        dest_path = case_root / label
        if not source_path.exists():
            archived_sets["archives"][label] = {
                "source": str(source_path),
                "archive_path": str(dest_path),
                "exists": False,
                "file_count": 0,
                "size_bytes": 0,
            }
            continue

        if dest_path.exists():
            shutil.rmtree(dest_path)
        shutil.copytree(source_path, dest_path, copy_function=shutil.copy2)
        ensure_casescope_permissions(dest_path)

        source_stats = tree_stats(source_path)
        copied_stats = tree_stats(dest_path)
        if source_stats != copied_stats:
            raise RuntimeError(
                f"Archive copy verification failed for {case.uuid} {label}: "
                f"source={source_stats} copied={copied_stats}"
            )

        archived_sets["archives"][label] = {
            "source": str(source_path),
            "archive_path": str(dest_path),
            "exists": True,
            "file_count": copied_stats["file_count"],
            "size_bytes": copied_stats["size_bytes"],
        }

    manifest_path = case_root / "manifest.json"
    write_json(manifest_path, archived_sets)
    return archived_sets


def backup_postgres(layout: SnapshotLayout) -> Dict[str, Any]:
    database_uri = Config.SQLALCHEMY_DATABASE_URI
    parsed = urlparse(database_uri)
    run_command(["pg_dump", database_uri, "-Fc", "-f", str(layout.postgresql_dump_path)])
    run_command(["pg_dump", database_uri, "--schema-only", "-f", str(layout.postgresql_schema_path)])
    run_command(["pg_restore", "-l", str(layout.postgresql_dump_path)])

    return {
        "database": parsed.path.lstrip("/"),
        "uri_host": parsed.hostname,
        "dump_path": str(layout.postgresql_dump_path),
        "dump_sha256": sha256_file(layout.postgresql_dump_path),
        "schema_path": str(layout.postgresql_schema_path),
        "schema_sha256": sha256_file(layout.postgresql_schema_path),
    }


def export_clickhouse_table(table: str, output_path: Path) -> Dict[str, Any]:
    args = [
        "clickhouse-client",
        "--host",
        Config.CLICKHOUSE_HOST,
        "--port",
        str(CLICKHOUSE_NATIVE_PORT),
        "--user",
        Config.CLICKHOUSE_USER,
        "--database",
        Config.CLICKHOUSE_DATABASE,
        "--query",
        f"SELECT * FROM {table} FORMAT Native",
    ]
    if Config.CLICKHOUSE_PASSWORD:
        args.extend(["--password", Config.CLICKHOUSE_PASSWORD])
    run_command(args, stdout_path=output_path)
    row_count = int(
        get_clickhouse_client().query(f"SELECT count() FROM {table}").result_rows[0][0]
    )
    return {
        "table": table,
        "path": str(output_path),
        "row_count": row_count,
        "size_bytes": output_path.stat().st_size,
    }


def backup_clickhouse(layout: SnapshotLayout) -> Dict[str, Any]:
    exports = []
    for table in CLICKHOUSE_BACKUP_TABLES:
        exports.append(export_clickhouse_table(table, layout.clickhouse_dir / f"{table}.native"))
    return {"tables": exports}


def get_service_active(service_name: str) -> bool:
    result = subprocess.run(
        ["systemctl", "is-active", service_name],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "active"


@contextmanager
def quiesced_services():
    previous_state = {service: get_service_active(service) for service in SERVICE_NAMES}
    try:
        for service in SERVICE_NAMES:
            if previous_state[service]:
                subprocess.run(["systemctl", "stop", service], check=True)
        yield previous_state
    finally:
        for service in reversed(SERVICE_NAMES):
            if previous_state.get(service):
                subprocess.run(["systemctl", "start", service], check=True)


def delete_clickhouse_case_auxiliary(case_id: int) -> Dict[str, Any]:
    client = get_clickhouse_client()
    deleted = {}

    def _delete_where_case_id(table: str) -> None:
        fragment = f"DELETE WHERE case_id = {int(case_id)}"
        client.command(f"ALTER TABLE {table} {fragment}")
        wait_for_mutation_completion(table, fragment, client=client)
        deleted[table] = True

    with destructive_event_rewrite_guard("system_reset_auxiliary_case_delete", case_id=case_id):
        for table in ("case_unified_findings", "detection_summary", "timeline_hourly"):
            _delete_where_case_id(table)
    overlay_result = purge_case_event_overlay_state(case_id, client=client, wait=True)
    for table_name, deleted_rows in overlay_result["tables"].items():
        if deleted_rows > 0:
            deleted[table_name] = True

    return deleted


def validate_post_reset(app: Flask) -> Dict[str, Any]:
    with app.app_context():
        clients_count = Client.query.count()
        cases_count = Case.query.count()

        inspector = inspect(db.engine)
        lingering_pg = []
        for table in inspector.get_table_names():
            columns = {column["name"] for column in inspector.get_columns(table)}
            if {"case_id", "case_uuid", "client_id"} & columns:
                count = db.session.execute(text(f'SELECT count(*) FROM "{table}"')).scalar_one()
                if count:
                    lingering_pg.append({"table": table, "row_count": int(count)})

    clickhouse_client = get_clickhouse_client()
    lingering_clickhouse = {}
    for table in CASE_ANALYTICS_TABLES:
        count = int(clickhouse_client.query(f"SELECT count() FROM {table}").result_rows[0][0])
        lingering_clickhouse[table] = count

    return {
        "clients": clients_count,
        "cases": cases_count,
        "postgres_lingering": lingering_pg,
        "clickhouse_counts": lingering_clickhouse,
    }


def perform_reset(app: Flask, inventory: Dict[str, Any]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {"clients": []}
    with app.app_context():
        clients = Client.query.order_by(Client.id).all()
        for client in clients:
            case_ids = [case["id"] for case in next(item for item in inventory["clients"] if item["id"] == client.id)["cases"]]
            for case_id in case_ids:
                delete_clickhouse_case_auxiliary(case_id)

            with patch("utils.case_deletion._collect_archive_paths", return_value=[]):
                client_summary = delete_client_permanently(client)
            client_summary["client_id"] = client.id
            client_summary["client_uuid"] = client.uuid
            client_summary["client_name"] = client.name
            summary["clients"].append(client_summary)
    return summary


def create_root_manifest(
    layout: SnapshotLayout,
    *,
    inventory: Dict[str, Any],
    postgres_backup: Dict[str, Any],
    clickhouse_backup: Dict[str, Any],
    case_archives: List[Dict[str, Any]],
    reset_summary: Dict[str, Any] | None,
    validation: Dict[str, Any] | None,
    executed: bool,
) -> None:
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "executed": executed,
        "inventory_path": str(layout.inventory_path),
        "postgres_backup": postgres_backup,
        "clickhouse_backup": clickhouse_backup,
        "case_archives": case_archives,
        "inventory_counts": inventory["counts"],
        "reset_summary": reset_summary,
        "post_reset_validation": validation,
    }
    write_json(layout.root_manifest_path, manifest)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Archive all client/case data to /archive, then reset Postgres and ClickHouse case state.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Perform the destructive reset after creating backups.",
    )
    parser.add_argument(
        "--yes-reset-all-case-data",
        action="store_true",
        help="Required with --execute to confirm the destructive reset.",
    )
    parser.add_argument(
        "--timestamp",
        default=utc_now_slug(),
        help="Override the UTC timestamp slug used in the archive folder name.",
    )
    parser.add_argument(
        "--reuse-snapshot-root",
        help="Reuse an existing dry-run snapshot root for --execute instead of creating a new backup set.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.execute and not args.yes_reset_all_case_data:
        print("--execute requires --yes-reset-all-case-data", file=sys.stderr)
        return 2
    if args.reuse_snapshot_root and not args.execute:
        print("--reuse-snapshot-root is only supported together with --execute", file=sys.stderr)
        return 2

    app = build_app()
    if args.reuse_snapshot_root:
        layout_root = Path(args.reuse_snapshot_root).resolve()
        layout = SnapshotLayout(
            root=layout_root,
            postgres_dir=layout_root / "postgres",
            clickhouse_dir=layout_root / "clickhouse",
            cases_dir=layout_root / "cases",
            manifests_dir=layout_root / "manifests",
            inventory_path=layout_root / "manifests" / "inventory.json",
            postgresql_dump_path=layout_root / "postgres" / "casescope_full.dump",
            postgresql_schema_path=layout_root / "postgres" / "casescope_schema.sql",
            root_manifest_path=layout_root / "manifest.json",
        )
        if not layout.inventory_path.exists():
            raise RuntimeError(f"Existing snapshot is missing inventory: {layout.inventory_path}")
        if not layout.root_manifest_path.exists():
            raise RuntimeError(f"Existing snapshot is missing manifest: {layout.root_manifest_path}")
        with layout.inventory_path.open("r", encoding="utf-8") as handle:
            inventory = json.load(handle)
        with layout.root_manifest_path.open("r", encoding="utf-8") as handle:
            existing_manifest = json.load(handle)
        postgres_backup = existing_manifest.get("postgres_backup", {})
        clickhouse_backup = existing_manifest.get("clickhouse_backup", {})
        case_archives = existing_manifest.get("case_archives", [])
    else:
        layout = build_layout(app, timestamp_slug=args.timestamp)
        for path in (layout.root, layout.postgres_dir, layout.clickhouse_dir, layout.cases_dir, layout.manifests_dir):
            ensure_directory(path)

        inventory = collect_inventory(app)
        write_json(layout.inventory_path, inventory)
        postgres_backup = {}
        clickhouse_backup = {}
        case_archives: List[Dict[str, Any]] = []

    if inventory["counts"]["cases"] == 0 and inventory["counts"]["clients"] == 0:
        create_root_manifest(
            layout,
            inventory=inventory,
            postgres_backup={},
            clickhouse_backup={},
            case_archives=[],
            reset_summary=None,
            validation=None,
            executed=False,
        )
        print(json.dumps({"status": "no-op", "snapshot_root": str(layout.root), "inventory": inventory["counts"]}, indent=2))
        return 0

    with quiesced_services():
        if not args.reuse_snapshot_root:
            postgres_backup = backup_postgres(layout)
            clickhouse_backup = backup_clickhouse(layout)

            with app.app_context():
                for case in Case.query.order_by(Case.id).all():
                    case_archives.append(archive_case_files(case, layout))

        if not args.execute:
            create_root_manifest(
                layout,
                inventory=inventory,
                postgres_backup=postgres_backup,
                clickhouse_backup=clickhouse_backup,
                case_archives=case_archives,
                reset_summary=None,
                validation=None,
                executed=False,
            )
            print(
                json.dumps(
                    {
                        "status": "dry-run-ready",
                        "snapshot_root": str(layout.root),
                        "inventory": inventory["counts"],
                        "postgres_dump": str(layout.postgresql_dump_path),
                        "clickhouse_exports": len(clickhouse_backup["tables"]),
                        "case_archives": len(case_archives),
                    },
                    indent=2,
                )
            )
            return 0

        reset_summary = perform_reset(app, inventory)
        validation = validate_post_reset(app)
        create_root_manifest(
            layout,
            inventory=inventory,
            postgres_backup=postgres_backup,
            clickhouse_backup=clickhouse_backup,
            case_archives=case_archives,
            reset_summary=reset_summary,
            validation=validation,
            executed=True,
        )

    if validation["clients"] != 0 or validation["cases"] != 0:
        raise RuntimeError(f"Reset incomplete: {validation}")
    if validation["postgres_lingering"]:
        raise RuntimeError(f"PostgreSQL case-scoped rows remain: {validation['postgres_lingering']}")
    nonzero_clickhouse = {k: v for k, v in validation["clickhouse_counts"].items() if v != 0}
    if nonzero_clickhouse:
        raise RuntimeError(f"ClickHouse case-scoped rows remain: {nonzero_clickhouse}")

    print(
        json.dumps(
            {
                "status": "completed",
                "snapshot_root": str(layout.root),
                "inventory": inventory["counts"],
                "validation": validation,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
