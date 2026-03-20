"""Shared helpers for case-scoped artifact paths and retention moves."""
import os
import shutil
from typing import Dict, Iterable, Optional

from config import Config


DEFAULT_DIR_MODE = 0o2775
DEFAULT_ORIGINALS_ROOT = '/originals'
SQLITE_COMPANION_SUFFIXES = ('-wal', '-shm', '-journal')


def ensure_directory(path: str) -> str:
    """Create a directory and apply the standard CaseScope ownership/mode."""
    os.makedirs(path, exist_ok=True)
    try:
        shutil.chown(path, user='casescope', group='casescope')
        os.chmod(path, DEFAULT_DIR_MODE)
    except (PermissionError, LookupError, OSError):
        pass
    return path


def get_originals_base_path() -> str:
    """Return the configured root path for retained original uploads."""
    try:
        from models.system_settings import SettingKeys, SystemSettings
        configured = SystemSettings.get(SettingKeys.ORIGINALS_PATH, DEFAULT_ORIGINALS_ROOT)
        if configured:
            return configured
    except Exception:
        pass
    return DEFAULT_ORIGINALS_ROOT


def ensure_originals_base_path() -> str:
    """Ensure the configured originals root exists."""
    return ensure_directory(get_originals_base_path())


def get_case_originals_root(case_uuid: str) -> str:
    """Return the case-scoped root for retained originals."""
    return os.path.join(get_originals_base_path(), case_uuid)


def get_case_originals_path(case_uuid: str) -> str:
    """Return the main originals directory for a case."""
    return os.path.join(get_case_originals_root(case_uuid), 'originals')


def ensure_case_originals_path(case_uuid: str) -> str:
    """Ensure the main originals directory exists for a case."""
    return ensure_directory(get_case_originals_path(case_uuid))


def ensure_case_originals_subdir(case_uuid: str, *parts: str) -> str:
    """Ensure a subdirectory under case originals exists."""
    path = os.path.join(get_case_originals_path(case_uuid), *parts)
    return ensure_directory(path)


def get_case_artifact_paths(case_uuid: str) -> Dict[str, str]:
    """Return all standard case-scoped artifact directories."""
    base_storage = os.path.join(Config.STORAGE_FOLDER, case_uuid)
    staging_base = os.path.join(Config.STAGING_FOLDER, case_uuid)
    originals_root = get_case_originals_root(case_uuid)
    originals_base = get_case_originals_path(case_uuid)
    return {
        'web_upload': os.path.join(Config.UPLOAD_FOLDER_WEB, case_uuid),
        'sftp_upload': os.path.join(Config.UPLOAD_FOLDER_SFTP, case_uuid),
        'rebuild_upload': os.path.join(Config.UPLOAD_FOLDER_WEB, case_uuid, '_rebuild'),
        'staging': staging_base,
        'pcap_staging': os.path.join(staging_base, 'pcap'),
        'memory_staging': os.path.join(staging_base, 'memory'),
        'storage': base_storage,
        'originals_root': originals_root,
        'originals': originals_base,
        'evidence': os.path.join(Config.EVIDENCE_FOLDER, case_uuid),
        'evidence_bulk': os.path.join(Config.EVIDENCE_BULK_FOLDER, case_uuid),
        'pcap_upload': os.path.join(Config.PCAP_UPLOAD_FOLDER, case_uuid),
        'pcap_rebuild_upload': os.path.join(Config.PCAP_UPLOAD_FOLDER, case_uuid, '_rebuild'),
        'pcap_storage': os.path.join(base_storage, 'pcap'),
        'pcap_originals': os.path.join(originals_base, 'pcap'),
        'memory_upload': os.path.join(Config.UPLOAD_FOLDER_SFTP, case_uuid, 'memory'),
        'memory_web_upload': os.path.join(Config.UPLOAD_FOLDER_WEB, case_uuid, 'memory'),
        'memory_upload_meta': os.path.join(Config.UPLOAD_FOLDER_SFTP, case_uuid, 'memory', '.upload_meta'),
        'memory_rebuild_upload': os.path.join(Config.UPLOAD_FOLDER_SFTP, case_uuid, 'memory', '_rebuild'),
        'memory_originals': os.path.join(originals_base, 'memory'),
        'duplicates': os.path.join(base_storage, 'duplicates'),
        'archives': os.path.join(base_storage, 'archives'),
        'failed': os.path.join(base_storage, 'failed'),
        'quarantine': os.path.join(base_storage, 'quarantine'),
    }


def ensure_case_artifact_paths(case_uuid: str) -> Dict[str, str]:
    """Ensure the standard case-scoped directories exist."""
    paths = get_case_artifact_paths(case_uuid)
    lazy_originals_keys = {
        'originals_root',
        'originals',
        'pcap_originals',
        'memory_originals',
    }
    for key, path in paths.items():
        if key in lazy_originals_keys:
            continue
        ensure_directory(path)
    return paths


def ensure_case_subdir(case_uuid: str, *parts: str) -> str:
    """Ensure a subdirectory under case storage exists."""
    path = os.path.join(Config.STORAGE_FOLDER, case_uuid, *parts)
    return ensure_directory(path)


def unique_destination_path(dest_dir: str, filename: str) -> str:
    """Return a collision-safe destination path in a directory."""
    ensure_directory(dest_dir)
    candidate = os.path.join(dest_dir, filename)
    if not os.path.exists(candidate):
        return candidate

    base, ext = os.path.splitext(filename)
    counter = 1
    while True:
        candidate = os.path.join(dest_dir, f'{base}_{counter}{ext}')
        if not os.path.exists(candidate):
            return candidate
        counter += 1


def move_to_directory(source_path: str, dest_dir: str, filename: Optional[str] = None) -> Optional[str]:
    """Move a file into a directory, preserving it under retention."""
    if not source_path or not os.path.exists(source_path):
        return None

    final_name = filename or os.path.basename(source_path)
    dest_path = unique_destination_path(dest_dir, final_name)
    shutil.move(source_path, dest_path)
    try:
        shutil.chown(dest_path, user='casescope', group='casescope')
    except (PermissionError, LookupError, OSError):
        pass
    return dest_path


def copy_to_directory(source_path: str, dest_dir: str, filename: Optional[str] = None) -> Optional[str]:
    """Copy a file into a directory, preserving metadata when possible."""
    if not source_path or not os.path.exists(source_path):
        return None

    final_name = filename or os.path.basename(source_path)
    dest_path = unique_destination_path(dest_dir, final_name)
    shutil.copy2(source_path, dest_path)
    try:
        shutil.chown(dest_path, user='casescope', group='casescope')
    except (PermissionError, LookupError, OSError):
        pass
    return dest_path


def move_from_prefix(source_path: str, source_prefix: str, dest_prefix: str) -> Optional[str]:
    """Move a file between rooted trees while preserving its relative path."""
    if not source_path or not os.path.exists(source_path):
        return None

    real_source = os.path.realpath(source_path)
    real_prefix = os.path.realpath(source_prefix)
    if real_source != real_prefix and not real_source.startswith(real_prefix + os.sep):
        return None

    relative_path = os.path.relpath(real_source, real_prefix)
    dest_path = os.path.join(dest_prefix, relative_path)
    ensure_directory(os.path.dirname(dest_path))
    shutil.move(real_source, dest_path)
    try:
        shutil.chown(dest_path, user='casescope', group='casescope')
    except (PermissionError, LookupError, OSError):
        pass
    return dest_path


def move_from_prefix_with_companions(
    source_path: str,
    source_prefix: str,
    dest_prefix: str,
    companion_suffixes: Iterable[str] = SQLITE_COMPANION_SUFFIXES,
) -> Dict[str, str]:
    """Move a file and any SQLite companion sidecars between rooted trees."""
    moved_paths: Dict[str, str] = {}
    primary_dest = move_from_prefix(source_path, source_prefix, dest_prefix)
    if not primary_dest:
        return moved_paths

    moved_paths[source_path] = primary_dest
    for suffix in companion_suffixes:
        companion_source = f'{source_path}{suffix}'
        if not os.path.exists(companion_source):
            continue
        companion_dest = move_from_prefix(companion_source, source_prefix, dest_prefix)
        if companion_dest:
            moved_paths[companion_source] = companion_dest

    return moved_paths


def is_within_root(path: str, root: str) -> bool:
    """Return True when a path resolves under a given root."""
    if not path or not root:
        return False
    real_path = os.path.realpath(path)
    real_root = os.path.realpath(root)
    return real_path == real_root or real_path.startswith(real_root + os.sep)


def is_within_any_root(path: str, roots: Iterable[str]) -> bool:
    """Return True when a path resolves under one of the provided roots."""
    return any(is_within_root(path, root) for root in roots if root)
