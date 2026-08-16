"""Deterministic EVTX external producer signatures for managed ingest."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


SIGNATURE_ALGORITHM = "evtx-producer-signature:v1"
EXCLUDED_DIR_NAMES = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}
EXCLUDED_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".tmp",
    ".temp",
    ".log",
    ".lock",
    ".swp",
}


def _sha256_file(path: str) -> Optional[str]:
    if not path or not os.path.isfile(path):
        return None
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _command_output(args: Iterable[str], *, cwd: Optional[str] = None, timeout: int = 30) -> Optional[str]:
    try:
        result = subprocess.run(
            list(args),
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except Exception:
        return None
    text = (result.stdout or result.stderr or "").strip()
    if not text:
        return None
    return text.splitlines()[0].strip()


def _iter_signature_files(root: str) -> Iterable[Path]:
    root_path = Path(root)
    if not root_path.is_dir():
        return []
    files = []
    for path in root_path.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root_path)
        if any(part in EXCLUDED_DIR_NAMES for part in relative.parts):
            continue
        if path.suffix.lower() in EXCLUDED_SUFFIXES:
            continue
        files.append(path)
    return sorted(files, key=lambda item: item.relative_to(root_path).as_posix())


def directory_content_digest(root: Optional[str]) -> Optional[str]:
    """Hash a directory by sorted relative path plus file content."""
    if not root or not os.path.isdir(root):
        return None
    root_path = Path(root)
    digest = hashlib.sha256()
    digest.update(SIGNATURE_ALGORITHM.encode("utf-8"))
    digest.update(b"\0dir\0")
    for path in _iter_signature_files(root):
        relative = path.relative_to(root_path).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        file_digest = _sha256_file(str(path)) or ""
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def evtx_producer_signature_payload(
    *,
    evtxecmd_bin: str,
    maps_dir: Optional[str],
    hayabusa_bin: str,
    rules_dir: Optional[str],
    rules_config_dir: Optional[str],
    hayabusa_profile: str,
    min_level: str,
    enrich_detections: bool,
    wrapper_version: str,
) -> Dict[str, Any]:
    """Return stable semantic inputs for EVTX managed producer identity."""
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "evtxecmd": {
            "version": _command_output([evtxecmd_bin, "--version"]),
            "binary_sha256": _sha256_file(evtxecmd_bin),
            "maps_digest": directory_content_digest(maps_dir),
        },
        "hayabusa": {
            "version": _command_output([hayabusa_bin, "help"]),
            "binary_sha256": _sha256_file(hayabusa_bin),
            "rules_digest": directory_content_digest(rules_dir),
            "config_digest": directory_content_digest(rules_config_dir),
            "profile": hayabusa_profile,
            "min_level": min_level,
            "enrich_detections": bool(enrich_detections),
        },
        "wrapper_version": wrapper_version,
    }


def compact_evtx_producer_signature(**kwargs: Any) -> str:
    """Return a generation-column-safe deterministic EVTX producer signature."""
    payload = evtx_producer_signature_payload(**kwargs)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"evtx:{SIGNATURE_ALGORITHM.split(':')[-1]}:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"
