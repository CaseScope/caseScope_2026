"""Shared helpers for originals-based rebuild workflows."""
import os
import shutil
import uuid
import zipfile
from typing import Dict, Iterable, List, Optional

from utils.artifact_paths import (
    copy_to_directory,
    ensure_case_artifact_paths,
    ensure_directory,
    is_within_root,
)


STANDARD_REBUILD_MODE_PARENT_ARCHIVE = 'parent_archive'
STANDARD_REBUILD_MODE_SINGLE_MEMBER = 'single_member'
STANDARD_REBUILD_MODE_STANDALONE = 'standalone'
STANDARD_REBUILD_MODE_CASE = 'case'


def create_rebuild_run_id(prefix: str = 'rebuild') -> str:
    """Return a short identifier for a rebuild run."""
    return f'{prefix}_{uuid.uuid4().hex[:12]}'


def ensure_case_rebuild_workspace(case_uuid: str, artifact_type: str, run_id: Optional[str] = None) -> str:
    """Create an isolated rebuild workspace for the given artifact type."""
    case_paths = ensure_case_artifact_paths(case_uuid)
    workspace_roots = {
        'standard': case_paths['rebuild_upload'],
        'pcap': case_paths['pcap_rebuild_upload'],
        'memory': case_paths['memory_rebuild_upload'],
    }
    root = workspace_roots[artifact_type]
    ensure_directory(root)
    workspace = os.path.join(root, run_id or create_rebuild_run_id(artifact_type))
    return ensure_directory(workspace)


def remove_path_if_exists(path: Optional[str]) -> bool:
    """Best-effort removal for rebuild workspaces and stale derived data."""
    if not path or not os.path.exists(path):
        return False
    try:
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        else:
            os.remove(path)
        return True
    except OSError:
        return False


def copy_file_to_workspace(source_path: str, workspace_root: str, relative_path: Optional[str] = None) -> Optional[str]:
    """Copy a retained original into a rebuild workspace, preserving relative layout."""
    if not source_path or not os.path.exists(source_path):
        return None

    relative_name = relative_path or os.path.basename(source_path)
    dest_path = os.path.join(workspace_root, relative_name)
    ensure_directory(os.path.dirname(dest_path))
    shutil.copy2(source_path, dest_path)
    try:
        shutil.chown(dest_path, user='casescope', group='casescope')
    except (PermissionError, LookupError, OSError):
        pass
    return dest_path


def copy_tree_to_workspace(
    source_root: str,
    workspace_root: str,
    skip_top_level: Optional[Iterable[str]] = None,
) -> List[Dict[str, str]]:
    """Copy a rooted set of retained originals into a rebuild workspace."""
    copied: List[Dict[str, str]] = []
    if not source_root or not os.path.isdir(source_root):
        return copied

    skipped = {part.lower() for part in (skip_top_level or [])}
    for root, dirs, files in os.walk(source_root):
        rel_root = os.path.relpath(root, source_root)
        if rel_root == '.':
            dirs[:] = [d for d in dirs if d.lower() not in skipped]
        for filename in files:
            source_path = os.path.join(root, filename)
            rel_path = os.path.relpath(source_path, source_root)
            dest_path = copy_file_to_workspace(source_path, workspace_root, rel_path)
            if dest_path:
                copied.append({
                    'source_path': source_path,
                    'workspace_path': dest_path,
                    'relative_path': rel_path,
                    'name': os.path.basename(rel_path),
                })
    return copied


def get_standard_original_entries(case_uuid: str) -> List[Dict[str, str]]:
    """Return standard retained-original files, excluding PCAP and memory trees."""
    case_paths = ensure_case_artifact_paths(case_uuid)
    return copy_tree_to_workspace(
        case_paths['originals'],
        ensure_case_rebuild_workspace(case_uuid, 'standard'),
        skip_top_level=('pcap', 'memory'),
    )


def resolve_standard_rebuild_target(case_file, case_uuid: str, rebuild_mode: str) -> Dict[str, object]:
    """Resolve the retained-original source and delete scope for a standard file rebuild."""
    case_paths = ensure_case_artifact_paths(case_uuid)
    retained_path = case_file.source_path if is_within_root(case_file.source_path, case_paths['originals']) else None
    if not retained_path and is_within_root(case_file.file_path, case_paths['originals']):
        retained_path = case_file.file_path

    if not case_file.is_extracted:
        return {
            'mode': STANDARD_REBUILD_MODE_STANDALONE,
            'source_path': retained_path,
            'selected_member': None,
            'delete_parent_family': False,
            'parent_record': None,
        }

    parent_record = case_file.parent
    if not parent_record:
        return {
            'mode': STANDARD_REBUILD_MODE_STANDALONE,
            'source_path': retained_path,
            'selected_member': None,
            'delete_parent_family': False,
            'parent_record': None,
        }

    parent_source = parent_record.source_path if is_within_root(parent_record.source_path, case_paths['originals']) else None
    if not parent_source and is_within_root(parent_record.file_path, case_paths['originals']):
        parent_source = parent_record.file_path

    relative_member = case_file.filename or case_file.original_filename
    parent_prefix = f'{parent_record.original_filename}/'
    if relative_member and relative_member.startswith(parent_prefix):
        relative_member = relative_member[len(parent_prefix):]

    if rebuild_mode == STANDARD_REBUILD_MODE_SINGLE_MEMBER:
        return {
            'mode': STANDARD_REBUILD_MODE_SINGLE_MEMBER,
            'source_path': parent_source,
            'selected_member': relative_member,
            'delete_parent_family': False,
            'parent_record': parent_record,
        }

    return {
        'mode': STANDARD_REBUILD_MODE_PARENT_ARCHIVE,
        'source_path': parent_source,
        'selected_member': None,
        'delete_parent_family': True,
        'parent_record': parent_record,
    }


def extract_archive_member_to_workspace(
    archive_path: str,
    member_name: str,
    workspace_root: str,
    output_name: Optional[str] = None,
) -> Optional[str]:
    """Extract a single archive member into a rebuild workspace."""
    if not archive_path or not os.path.exists(archive_path) or not member_name:
        return None

    safe_name = output_name or os.path.basename(member_name)
    dest_path = os.path.join(workspace_root, safe_name)
    ensure_directory(os.path.dirname(dest_path))

    with zipfile.ZipFile(archive_path, 'r') as archive:
        normalized_target = member_name.replace('\\', '/')
        for member in archive.infolist():
            if member.filename.replace('\\', '/') != normalized_target:
                continue
            with archive.open(member, 'r') as src, open(dest_path, 'wb') as dst:
                shutil.copyfileobj(src, dst)
            try:
                shutil.chown(dest_path, user='casescope', group='casescope')
            except (PermissionError, LookupError, OSError):
                pass
            return dest_path
    return None


def build_rebuild_audit_details(run_id: str, scope: str, mode: Optional[str], source_paths: Iterable[str]) -> Dict[str, object]:
    """Build normalized audit details for rebuild actions."""
    normalized_sources = [path for path in source_paths if path]
    return {
        'run_id': run_id,
        'scope': scope,
        'mode': mode,
        'source_count': len(normalized_sources),
        'source_samples': normalized_sources[:10],
    }
