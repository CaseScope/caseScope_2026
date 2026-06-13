"""Archive extraction helpers shared by upload/rebuild tasks."""
import os
import shutil
import subprocess
import tarfile
import zipfile
from typing import Any, Dict


PYTHON_ZIP_COMPRESSION_METHODS = {
    zipfile.ZIP_STORED,
    zipfile.ZIP_DEFLATED,
    zipfile.ZIP_BZIP2,
    zipfile.ZIP_LZMA,
}
EXTERNAL_ZIP_EXTRACTOR = '/usr/bin/7z'
EXTERNAL_ZIP_EXTRACTOR_COMMANDS = ('7z', '7zz', '7za')


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


def inspect_tar_archive(workspace_path: str, extract_root: str) -> Dict[str, Any]:
    """Inspect a tar/tar.gz archive before extraction."""
    member_count = 0
    total_uncompressed = 0
    unsafe_members = []
    with tarfile.open(workspace_path, 'r:*') as archive:
        for member in archive.getmembers():
            member_count += 1
            total_uncompressed += max(member.size, 0)
            try:
                safe_archive_member_target(extract_root, member.name)
            except ValueError as exc:
                unsafe_members.append(str(exc))
            if member.issym() or member.islnk():
                unsafe_members.append(f'blocked archive link member {member.name}')
            if not (member.isfile() or member.isdir()):
                unsafe_members.append(f'blocked non-file archive member {member.name}')
    return {
        'member_count': member_count,
        'total_uncompressed': total_uncompressed,
        'methods': ['tar'],
        'unsupported_methods': [],
        'requires_external_extractor': False,
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


def find_external_zip_extractor() -> str:
    """Find a 7z-compatible extractor for ZIP methods Python cannot read."""
    if os.path.exists(EXTERNAL_ZIP_EXTRACTOR):
        return EXTERNAL_ZIP_EXTRACTOR
    for command in EXTERNAL_ZIP_EXTRACTOR_COMMANDS:
        extractor = shutil.which(command)
        if extractor:
            return extractor
    return ''


def extract_zip_archive(
    workspace_path: str,
    extract_root: str,
    *,
    max_members: int = None,
    max_uncompressed_bytes: int = None,
) -> Dict[str, Any]:
    """Extract ZIP or tar archives, using 7z for ZIP methods Python cannot read."""
    if os.path.exists(workspace_path) and tarfile.is_tarfile(workspace_path):
        inspection = inspect_tar_archive(workspace_path, extract_root)
        if inspection['unsafe_members']:
            raise ValueError('; '.join(inspection['unsafe_members'][:5]))
        if max_members is not None and inspection['member_count'] > max_members:
            raise ValueError(
                f"Archive contains too many members ({inspection['member_count']} > {max_members})"
            )
        if max_uncompressed_bytes is not None and inspection['total_uncompressed'] > max_uncompressed_bytes:
            raise ValueError('Archive exceeds uncompressed size limit')
        with tarfile.open(workspace_path, 'r:*') as archive:
            for member in archive.getmembers():
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ValueError(f'blocked non-file archive member {member.name}')
                safe_archive_member_target(extract_root, member.name)
                try:
                    archive.extract(member, extract_root, filter='data')
                except TypeError:
                    archive.extract(member, extract_root)
        validate_extracted_tree(extract_root)
        return {
            **inspection,
            'extraction_method': 'python_tarfile',
        }

    inspection = inspect_zip_archive(workspace_path, extract_root)
    if inspection['unsafe_members']:
        raise ValueError('; '.join(inspection['unsafe_members'][:5]))
    if max_members is not None and inspection['member_count'] > max_members:
        raise ValueError(
            f"Archive contains too many members ({inspection['member_count']} > {max_members})"
        )
    if max_uncompressed_bytes is not None and inspection['total_uncompressed'] > max_uncompressed_bytes:
        raise ValueError('Archive exceeds uncompressed size limit')

    if inspection['requires_external_extractor']:
        extractor = find_external_zip_extractor()
        if not extractor:
            methods = ', '.join(str(method) for method in inspection['unsupported_methods'])
            raise RuntimeError(f'ZIP uses unsupported compression method(s) {methods}; install 7zip or p7zip-full')
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
