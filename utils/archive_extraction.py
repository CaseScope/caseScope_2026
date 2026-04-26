"""Archive extraction helpers shared by upload/rebuild tasks."""
import os
import shutil
import subprocess
import zipfile
from typing import Any, Dict


PYTHON_ZIP_COMPRESSION_METHODS = {
    zipfile.ZIP_STORED,
    zipfile.ZIP_DEFLATED,
    zipfile.ZIP_BZIP2,
    zipfile.ZIP_LZMA,
}
EXTERNAL_ZIP_EXTRACTOR = '/usr/bin/7z'


def safe_archive_member_target(extract_root: str, member_name: str) -> str:
    """Return the extraction target or raise if the archive member escapes root."""
    normalized_name = (member_name or '').replace('\\', '/')
    if os.path.isabs(normalized_name):
        raise ValueError(f'blocked absolute archive member {member_name}')
    target_path = os.path.realpath(os.path.join(extract_root, normalized_name))
    root_real = os.path.realpath(extract_root)
    if target_path != root_real and not target_path.startswith(root_real + os.sep):
        raise ValueError(f'blocked path traversal member {member_name}')
    return target_path


def inspect_zip_archive(workspace_path: str, extract_root: str) -> Dict[str, Any]:
    """Inspect a ZIP before extraction and decide whether Python can read it."""
    methods = set()
    member_count = 0
    total_uncompressed = 0
    unsafe_members = []
    with zipfile.ZipFile(workspace_path, 'r') as archive:
        for member in archive.infolist():
            member_count += 1
            total_uncompressed += member.file_size
            methods.add(member.compress_type)
            try:
                safe_archive_member_target(extract_root, member.filename)
            except ValueError as exc:
                unsafe_members.append(str(exc))

    unsupported_methods = sorted(method for method in methods if method not in PYTHON_ZIP_COMPRESSION_METHODS)
    return {
        'member_count': member_count,
        'total_uncompressed': total_uncompressed,
        'methods': sorted(methods),
        'unsupported_methods': unsupported_methods,
        'requires_external_extractor': bool(unsupported_methods),
        'unsafe_members': unsafe_members,
    }


def validate_extracted_tree(extract_root: str):
    """Defensive post-extraction check for external archive extractors."""
    root_real = os.path.realpath(extract_root)
    for root, dirnames, filenames in os.walk(extract_root):
        for name in [*dirnames, *filenames]:
            path_real = os.path.realpath(os.path.join(root, name))
            if path_real != root_real and not path_real.startswith(root_real + os.sep):
                raise ValueError(f'extracted path escaped archive root: {path_real}')


def extract_zip_archive(
    workspace_path: str,
    extract_root: str,
    *,
    max_members: int = None,
    max_uncompressed_bytes: int = None,
) -> Dict[str, Any]:
    """Extract ZIP archives, using 7z for methods Python zipfile cannot read."""
    inspection = inspect_zip_archive(workspace_path, extract_root)
    if inspection['unsafe_members']:
        raise ValueError('; '.join(inspection['unsafe_members'][:5]))
    if max_members is not None and inspection['member_count'] > max_members:
        raise ValueError('Archive contains too many members')
    if max_uncompressed_bytes is not None and inspection['total_uncompressed'] > max_uncompressed_bytes:
        raise ValueError('Archive exceeds uncompressed size limit')

    if inspection['requires_external_extractor']:
        extractor = EXTERNAL_ZIP_EXTRACTOR if os.path.exists(EXTERNAL_ZIP_EXTRACTOR) else shutil.which('7z')
        if not extractor:
            methods = ', '.join(str(method) for method in inspection['unsupported_methods'])
            raise RuntimeError(f'ZIP uses unsupported compression method(s) {methods}; install 7zip')
        result = subprocess.run(
            [extractor, 'x', '-y', f'-o{extract_root}', workspace_path],
            capture_output=True,
            text=True,
            timeout=7200,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or 'unknown 7z extraction error').strip()
            raise RuntimeError(f'7z extraction failed: {detail[:1000]}')
        extraction_method = '7z'
    else:
        with zipfile.ZipFile(workspace_path, 'r') as archive:
            for member in archive.infolist():
                if member.filename.endswith('/'):
                    continue
                safe_archive_member_target(extract_root, member.filename)
                archive.extract(member, extract_root)
        extraction_method = 'python_zipfile'

    validate_extracted_tree(extract_root)
    return {
        **inspection,
        'extraction_method': extraction_method,
    }
