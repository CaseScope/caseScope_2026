"""Phase 1.7 EVTX directory-mode identity, staging, and tool helpers.

Source-file identity is mandatory for multi-file Hayabusa correlation.
RecordID-only directory correlation is forbidden.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# Absolute safety caps. Never treat these as the preferred production group size.
EVTX_DIRECTORY_GROUP_MAX_FILES = 32
EVTX_DIRECTORY_GROUP_MAX_BYTES = 512 * 1024 * 1024
# Preferred grouping targets. Must remain <= the safety caps. Selected from
# Step 4 latency-closure measurements; not inferred from the 8-file corpus as
# a 32-file production optimum.
EVTX_DIRECTORY_GROUP_TARGET_FILES = 8
EVTX_DIRECTORY_GROUP_TARGET_BYTES = 128 * 1024 * 1024
# First currently-ready EVTX uses the per-file path; remaining queued files
# use bounded directory groups. The eager file is never reprocessed.
EVTX_DIRECTORY_EAGER_FIRST = True
# Queued files are grouped immediately. Do not wait for later uploads or the
# rest of the case. A debounce/fill window is not used.
EVTX_DIRECTORY_GROUP_FILL_WINDOW_SECONDS = 0
HAYABUSA_DIRECTORY_TIMEOUT_SECONDS = 3600
EVTXECMD_DIRECTORY_TIMEOUT_SECONDS = 3600


class DirectoryModeError(RuntimeError):
    """Bounded directory-mode failure.

    ``unsafe_retry`` marks parser-level failures where directory attribution is
    uncertain. Callers must still fail closed if any rows may already have been
    inserted; it never permits fallback without proven cleanup.
    """

    def __init__(self, reason: str, message: str, *, unsafe_retry: bool = False):
        super().__init__(message)
        self.reason = reason
        self.unsafe_retry = unsafe_retry


class AttributionError(DirectoryModeError):
    def __init__(self, message: str):
        super().__init__("attribution_ambiguity", message, unsafe_retry=True)


@dataclass(frozen=True)
class EvtxGroupMember:
    file_path: str
    case_file_id: Optional[int]
    source_host: str
    source_file: str = ""
    source_path: str = ""
    size_bytes: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "file_path", os.path.abspath(self.file_path))
        object.__setattr__(self, "source_path", self.source_path or self.file_path)
        object.__setattr__(self, "source_file", self.source_file or os.path.basename(self.file_path))
        if not self.size_bytes and os.path.isfile(self.file_path):
            object.__setattr__(self, "size_bytes", os.path.getsize(self.file_path))

    @property
    def canonical_token(self) -> str:
        return canonical_source_token(self.file_path)


@dataclass
class StagingManifest:
    staging_dir: str
    members_by_staged_token: Dict[str, EvtxGroupMember] = field(default_factory=dict)
    members_by_original_token: Dict[str, EvtxGroupMember] = field(default_factory=dict)

    def lookup_staged(self, path_or_token: str) -> EvtxGroupMember:
        raw = str(path_or_token or "")
        candidates = [raw]
        if raw and not os.path.isabs(raw):
            # Hayabusa/EvtxECmd may emit paths relative to cwd=work_dir.
            candidates.append(os.path.join(self.staging_dir, raw))
            parent = os.path.dirname(self.staging_dir)
            if parent:
                candidates.append(os.path.join(parent, raw))
        for candidate in candidates:
            if not candidate:
                continue
            token = canonical_source_token(candidate)
            member = self.members_by_staged_token.get(token)
            if member is None:
                member = self.members_by_staged_token.get(os.path.abspath(candidate))
            if member is not None:
                return member
        raise AttributionError(
            f"Tool output path does not map to a staged EVTX member: {path_or_token}"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "staging_dir": self.staging_dir,
            "members": [
                {
                    "staged_token": token,
                    "original_path": member.file_path,
                    "source_file": member.source_file,
                    "case_file_id": member.case_file_id,
                    "source_host": member.source_host,
                }
                for token, member in sorted(self.members_by_staged_token.items())
            ],
        }


def canonical_source_token(path: str) -> str:
    """Collision-safe source identity: realpath when the file exists, else abspath."""
    if not path:
        raise AttributionError("Empty source path")
    expanded = os.path.abspath(os.path.expanduser(str(path)))
    try:
        return os.path.realpath(expanded)
    except OSError:
        return expanded


def detection_correlation_key(source_token: str, record_id: Any) -> Tuple[str, str]:
    if not source_token:
        raise AttributionError("Detection correlation requires source-file identity")
    if record_id in (None, ""):
        raise AttributionError("Detection correlation requires RecordID")
    return (str(source_token), str(record_id))


# Must match parsers.evtx_parser.EvtxECmdParser.LEVEL_MAP.
HAYABUSA_LEVEL_MAP = {
    "informational": "info",
    "info": "info",
    "low": "low",
    "medium": "med",
    "med": "med",
    "high": "high",
    "critical": "crit",
    "crit": "crit",
}


def hayabusa_detection_entry(event: Mapping[str, Any]) -> Dict[str, Any]:
    """Preserve the current per-file attached detection schema."""
    mitre_tactics = event.get("MitreTactics") or []
    mitre_tags = event.get("MitreTags") or []
    if isinstance(mitre_tactics, str):
        mitre_tactics = [mitre_tactics] if mitre_tactics else []
    if isinstance(mitre_tags, str):
        mitre_tags = [mitre_tags] if mitre_tags else []
    return {
        "rule_title": event.get("RuleTitle"),
        "rule_level": HAYABUSA_LEVEL_MAP.get(
            str(event.get("Level", "")).lower(),
            event.get("Level"),
        ),
        "rule_file": event.get("RuleFile"),
        "mitre_tactics": mitre_tactics,
        "mitre_tags": mitre_tags,
    }


def index_hayabusa_detections(
    rows: Iterable[Mapping[str, Any]],
    *,
    manifest: Optional[StagingManifest] = None,
    single_source_token: Optional[str] = None,
) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    """Index Hayabusa JSONL rows by (canonical_source_file, RecordID).

    Directory mode requires EvtxFile and never falls back to RecordID-only keys.
    """
    detections: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for event in rows:
        if not isinstance(event, Mapping):
            continue
        record_id = event.get("RecordID")
        if record_id in (None, ""):
            continue
        evtx_file = event.get("EvtxFile")
        if manifest is not None:
            if not evtx_file:
                raise AttributionError("Hayabusa directory row missing EvtxFile")
            member = manifest.lookup_staged(str(evtx_file))
            source_token = member.canonical_token
        elif single_source_token:
            source_token = single_source_token
        else:
            if not evtx_file:
                raise AttributionError("Hayabusa row missing EvtxFile and no single-source token")
            source_token = canonical_source_token(str(evtx_file))
        key = detection_correlation_key(source_token, record_id)
        detections.setdefault(key, []).append(hayabusa_detection_entry(event))
    return detections


def lookup_hayabusa_detections(
    detections: Mapping[Any, List[Dict[str, Any]]],
    record_id: Any,
    source_token: Optional[str] = None,
    *,
    allow_record_id_only: bool = False,
) -> List[Dict[str, Any]]:
    """Look up detections. RecordID-only is allowed only for proven single-file runs."""
    if record_id in (None, ""):
        return []
    rid = str(record_id)
    if source_token:
        keyed = detections.get(detection_correlation_key(source_token, rid))
        if keyed:
            return keyed
        # Tuple-keyed maps must not silently fall back to RecordID-only.
        if any(isinstance(key, tuple) for key in detections):
            return []
    if allow_record_id_only:
        return list(detections.get(rid, []))
    return []


def remap_evtxecmd_sourcefile(
    event: Mapping[str, Any],
    manifest: StagingManifest,
) -> Tuple[Dict[str, Any], EvtxGroupMember]:
    """Map an EvtxECmd JSON row back to the original CaseFile and restore SourceFile."""
    source_file = event.get("SourceFile")
    if not source_file:
        raise AttributionError("EvtxECmd directory row missing SourceFile")
    member = manifest.lookup_staged(str(source_file))
    remapped = dict(event)
    remapped["SourceFile"] = member.file_path
    return remapped, member


def stage_evtx_group(members: Sequence[EvtxGroupMember], staging_dir: Optional[str] = None) -> StagingManifest:
    """Stage members with original basenames in unique per-member directories.

    Preserving the original basename avoids Hayabusa channel-filename filtering
    artifacts. Duplicate basenames are isolated by case_file_id (or ordinal)
    parent directories. Hayabusa and EvtxECmd both recurse.
    """
    if not members:
        raise DirectoryModeError("empty_group", "Directory group has no EVTX members")
    seen_tokens = set()
    for member in members:
        token = member.canonical_token
        if token in seen_tokens:
            raise DirectoryModeError(
                "duplicate_member",
                f"Duplicate EVTX realpath in group: {member.file_path}",
                unsafe_retry=True,
            )
        seen_tokens.add(token)
        if not os.path.isfile(member.file_path):
            raise DirectoryModeError("missing_file", f"EVTX file not found: {member.file_path}")

    if staging_dir is None:
        staging_dir = tempfile.mkdtemp(prefix="evtx_dir_group_")
    os.makedirs(staging_dir, exist_ok=True)
    manifest = StagingManifest(staging_dir=staging_dir)

    for ordinal, member in enumerate(members, start=1):
        ident = member.case_file_id if member.case_file_id is not None else ordinal
        member_dir = os.path.join(staging_dir, f"cf_{ident}")
        os.makedirs(member_dir, exist_ok=True)
        staged_path = os.path.join(member_dir, member.source_file)
        if os.path.exists(staged_path):
            raise DirectoryModeError(
                "staging_collision",
                f"Staged path collision for {member.source_file} (id={ident})",
                unsafe_retry=True,
            )
        _link_or_copy(member.file_path, staged_path)
        staged_token = canonical_source_token(staged_path)
        manifest.members_by_staged_token[staged_token] = member
        manifest.members_by_staged_token[os.path.abspath(staged_path)] = member
        manifest.members_by_original_token[member.canonical_token] = member
    return manifest


def _link_or_copy(src: str, dst: str) -> None:
    try:
        os.link(src, dst)
        return
    except OSError:
        pass
    try:
        os.symlink(src, dst)
        return
    except OSError:
        pass
    shutil.copy2(src, dst)


def chunk_evtx_members(
    members: Sequence[EvtxGroupMember],
    *,
    max_files: int = EVTX_DIRECTORY_GROUP_MAX_FILES,
    max_bytes: int = EVTX_DIRECTORY_GROUP_MAX_BYTES,
) -> List[List[EvtxGroupMember]]:
    """Split a queued EVTX set into bounded directory groups. Never unbounded."""
    groups: List[List[EvtxGroupMember]] = []
    current: List[EvtxGroupMember] = []
    current_bytes = 0
    for member in members:
        size = member.size_bytes or 0
        too_many = len(current) >= max_files
        too_big = current and (current_bytes + size) > max_bytes
        if current and (too_many or too_big):
            groups.append(current)
            current = []
            current_bytes = 0
        current.append(member)
        current_bytes += size
    if current:
        groups.append(current)
    return groups


@dataclass(frozen=True)
class EvtxParseUnit:
    """One dispatch unit: a single per-file parse or one directory group."""

    mode: str
    members: Tuple[EvtxGroupMember, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "members", tuple(self.members))
        if self.mode not in ("per_file", "directory"):
            raise ValueError(f"Unknown EVTX parse unit mode: {self.mode}")
        if self.mode == "per_file" and len(self.members) != 1:
            raise ValueError("per_file units must contain exactly one member")
        if self.mode == "directory" and len(self.members) < 2:
            raise ValueError("directory units require at least two members")

    @property
    def size_bytes(self) -> int:
        return sum(int(member.size_bytes or 0) for member in self.members)

    def member_ids(self) -> List[Optional[int]]:
        return [member.case_file_id for member in self.members]


def _ordered_evtx_members(members: Sequence[EvtxGroupMember], order: str) -> List[EvtxGroupMember]:
    ordered = list(members)
    if order == "queue":
        return ordered
    if order == "smallest":
        ordered.sort(
            key=lambda member: (
                int(member.size_bytes or 0),
                member.source_file or "",
                member.case_file_id if member.case_file_id is not None else 0,
                member.file_path,
            )
        )
        return ordered
    raise ValueError(f"Unknown EVTX plan order: {order}")


def plan_evtx_parse_units(
    members: Sequence[EvtxGroupMember],
    *,
    eager_first: bool = EVTX_DIRECTORY_EAGER_FIRST,
    target_files: int = EVTX_DIRECTORY_GROUP_TARGET_FILES,
    target_bytes: int = EVTX_DIRECTORY_GROUP_TARGET_BYTES,
    max_files: int = EVTX_DIRECTORY_GROUP_MAX_FILES,
    max_bytes: int = EVTX_DIRECTORY_GROUP_MAX_BYTES,
    order: str = "queue",
) -> List[EvtxParseUnit]:
    """Plan per-file vs directory units for one already-queued EVTX set.

    - Groups only files already in this invocation. No fill window.
    - Preferred target_files/target_bytes are capped by the safety maxima.
    - eager_first uses the current per-file path for the first ready file and
      never reprocesses that file in a later directory group.
    - order is queue (production) or smallest (measurement only).
    """
    if EVTX_DIRECTORY_GROUP_FILL_WINDOW_SECONDS:
        raise DirectoryModeError(
            "group_fill_window",
            "EVTX grouping must not wait for additional uploads",
        )
    ordered = _ordered_evtx_members(members, order)
    cap_files = max(1, min(int(target_files), int(max_files)))
    cap_bytes = max(1, min(int(target_bytes), int(max_bytes)))
    units: List[EvtxParseUnit] = []
    remaining = ordered
    if eager_first and len(remaining) >= 2:
        units.append(EvtxParseUnit(mode="per_file", members=(remaining[0],)))
        remaining = remaining[1:]
    if cap_files == 1:
        for member in remaining:
            units.append(EvtxParseUnit(mode="per_file", members=(member,)))
    else:
        for group in chunk_evtx_members(remaining, max_files=cap_files, max_bytes=cap_bytes):
            if len(group) <= 1:
                units.append(EvtxParseUnit(mode="per_file", members=tuple(group)))
            else:
                units.append(EvtxParseUnit(mode="directory", members=tuple(group)))
    seen = []
    for unit in units:
        for member in unit.members:
            token = member.canonical_token
            if token in seen:
                raise DirectoryModeError(
                    "duplicate_member",
                    f"Parse plan would process an EVTX member twice: {member.file_path}",
                    unsafe_retry=True,
                )
            seen.append(token)
    return units


def hayabusa_json_timeline_cmd(
    *,
    hayabusa_bin: str,
    output_path: str,
    file_path: Optional[str] = None,
    directory: Optional[str] = None,
    rules_dir: Optional[str] = None,
    rules_config_dir: Optional[str] = None,
    profile: str = "all-field-info-verbose",
    min_level: str = "informational",
) -> List[str]:
    if bool(file_path) == bool(directory):
        raise ValueError("Hayabusa command requires exactly one of file_path or directory")
    # Keep flag order identical to the current per-file parser after substituting input.
    if file_path:
        cmd = [
            hayabusa_bin, "json-timeline",
            "-f", file_path,
            "-o", output_path,
            "-L", "-w", "-q", "-C", "--no-color",
            "-p", profile, "--min-level", min_level, "-U",
        ]
    else:
        cmd = [
            hayabusa_bin, "json-timeline",
            "-d", directory,
            "-o", output_path,
            "-L", "-w", "-q", "-C", "--no-color",
            "-p", profile, "--min-level", min_level, "-U",
        ]
    if rules_dir and os.path.isdir(rules_dir):
        cmd.extend(["-r", rules_dir])
    # Directory runs isolate cwd so Hayabusa cannot see ./rules/config. Pass it explicitly.
    # Do not add this to the per-file path; per-file keeps process cwd.
    if rules_config_dir and os.path.isdir(rules_config_dir):
        cmd.extend(["-c", rules_config_dir])
    return cmd


def evtxecmd_json_cmd(
    *,
    evtxecmd_bin: str,
    json_dir: str,
    json_name: str,
    file_path: Optional[str] = None,
    directory: Optional[str] = None,
    maps_dir: Optional[str] = None,
) -> List[str]:
    if bool(file_path) == bool(directory):
        raise ValueError("EvtxECmd command requires exactly one of file_path or directory")
    cmd = [evtxecmd_bin]
    if file_path:
        cmd.extend(["-f", file_path])
    else:
        cmd.extend(["-d", directory])
    cmd.extend(["--json", json_dir, "--jsonf", json_name])
    if maps_dir:
        cmd.extend(["--maps", maps_dir])
    return cmd


def hayabusa_directory_had_errors(stdout: str, stderr: str) -> bool:
    text = f"{stdout or ''}\n{stderr or ''}"
    return "Errors were generated" in text


def is_evtx_path(file_path: str, filename: str = "") -> bool:
    name = (filename or file_path or "").lower()
    return name.endswith(".evtx")
