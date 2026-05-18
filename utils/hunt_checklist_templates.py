"""Versioned hunt checklist definitions for bounded negative findings."""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Optional

from models.database import db
from models.hunt import HuntChecklistDefinition

APPROVED_TRACED_TOOLS = {
    "query_events",
    "get_processes",
    "search_artifacts",
    "get_findings",
    "search_memory",
}

SUPPORTED_TEMPLATE_SCOPES = {
    "case",
    "host",
    "user",
    "process",
    "network",
}

COMMON_BLOCKED_LANGUAGE = [
    "nothing happened",
    "no compromise",
    "host is clean",
    "environment is clean",
    "network is clean",
    "no breach",
    "no data theft",
    "no exfiltration occurred",
    "no lateral movement occurred",
    "no ransomware occurred",
    "attacker did not",
    "could not have",
]


def _traced_check(
    key: str,
    name: str,
    tools: List[str],
    search_terms: Optional[List[str]] = None,
    look_for: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "key": key,
        "name": name,
        "type": "traced_tool",
        "required": True,
        "approved_tools": tools,
        "search_terms": search_terms or [],
        "look_for": look_for or [],
        "blocks_finding_if_missing": True,
    }


RANSOMWARE_PREPARATION_REVIEW_V1 = {
    "slug": "ransomware_preparation_review",
    "version": "1.0",
    "display_name": "Ransomware Preparation Review",
    "description": (
        "Review for evidence of ransomware preparation or destructive "
        "pre-encryption behavior in reviewed artifacts."
    ),
    "supported_scopes": ["case", "host", "user", "process"],
    "target_metadata_fields": ["target_host", "target_user", "target_process"],
    "required_sources": [
        "process_telemetry",
        "windows_event_logs",
        "filesystem_artifacts",
    ],
    "optional_sources": [
        "defender_operational_logs",
        "prefetch",
        "amcache",
        "sysmon",
        "memory_artifacts",
    ],
    "required_checks": [
        _traced_check(
            "shadow_copy_deletion_check",
            "Shadow copy deletion check",
            ["query_events", "get_processes", "search_artifacts"],
            [
                "vssadmin delete shadows",
                "wmic shadowcopy delete",
                "powershell Get-WmiObject Win32_ShadowCopy",
                "Delete-VolumeShadowCopy",
            ],
        ),
        _traced_check(
            "backup_deletion_check",
            "Backup deletion check",
            ["query_events", "get_processes"],
            [
                "wbadmin delete catalog",
                "wbadmin delete systemstatebackup",
                "wbadmin delete backup",
                "wevtutil cl",
            ],
        ),
        _traced_check(
            "recovery_disable_check",
            "Recovery disable check",
            ["query_events", "get_processes"],
            [
                "bcdedit /set recoveryenabled no",
                "bcdedit /set bootstatuspolicy ignoreallfailures",
                "reagentc /disable",
            ],
        ),
        _traced_check(
            "boot_config_or_safe_mode_check",
            "Boot configuration or safe mode check",
            ["query_events", "get_processes"],
            ["bcdedit", "safeboot", "bootstatuspolicy"],
        ),
        _traced_check(
            "ransom_note_search",
            "Ransom note search",
            ["search_artifacts"],
            ["README", "RECOVER", "DECRYPT", "ransom", "restore files", "how_to_decrypt"],
        ),
        _traced_check(
            "mass_rename_or_extension_change_search",
            "Mass rename or extension change search",
            ["search_artifacts", "get_findings"],
            look_for=[
                "high-volume file rename bursts",
                "suspicious new extensions",
                "rapid modified timestamps across user/data folders",
            ],
        ),
        _traced_check(
            "known_ransomware_tooling_search",
            "Known ransomware tooling search",
            ["query_events", "get_processes", "search_artifacts", "get_findings"],
            ["cipher /w", "sdelete", "7z", "rar", "winrar", "powershell encryption", "suspicious unsigned payloads"],
        ),
        _traced_check(
            "suspicious_payload_or_encryption_process_search",
            "Suspicious payload or encryption process search",
            ["get_processes", "search_artifacts", "search_memory", "get_findings"],
            look_for=[
                "suspicious unsigned binaries",
                "payloads launched from temp/user-writable paths",
                "process chains tied to encryption-like behavior",
            ],
        ),
    ],
    "tool_mappings": {},
    "coverage_rules": {
        "complete": {
            "required_sources_available": [
                "process_telemetry",
                "windows_event_logs",
                "filesystem_artifacts",
            ],
            "negative_finding_allowed": True,
        },
        "partial": {
            "minimum_sources_available": ["process_telemetry"],
            "minimum_corroborating_source_count": 1,
            "limitation_required": True,
            "negative_finding_allowed": True,
        },
        "insufficient": {"negative_finding_allowed": False},
        "not_available": {"negative_finding_allowed": False},
        "unknown": {"negative_finding_allowed": False},
    },
    "finding_eligibility_rules": [
        "coverage_status must be complete or partial",
        "all required checks must be completed or documented not_applicable",
        "completed traced checks must link to HuntStep records",
        "not_applicable checks must include reasons",
        "partial coverage requires mandatory limitation text",
        "proposed statement must match an approved language template",
    ],
    "finding_block_reasons": [
        "missing_process_telemetry",
        "missing_windows_event_logs",
        "missing_filesystem_artifacts",
        "required_check_not_completed",
        "check_not_linked_to_hunt_step",
        "coverage_insufficient",
        "coverage_unknown",
        "unapproved_absence_language",
    ],
    "allowed_language_by_coverage": {
        "complete": [
            {
                "key": "complete_standard",
                "statement": "No evidence of ransomware-preparation activity was identified in the reviewed artifacts.",
            }
        ],
        "partial": [
            {
                "key": "partial_source_limited",
                "statement": (
                    "No evidence of ransomware-preparation activity was identified in the reviewed "
                    "artifacts available for this case. This conclusion is limited by the unavailable "
                    "or incomplete sources listed in the review."
                ),
            }
        ],
    },
    "blocked_language": COMMON_BLOCKED_LANGUAGE + [
        "No ransomware occurred.",
        "No encryption happened.",
        "The host is clean.",
        "The attacker did not prepare ransomware.",
        "There was no destructive activity.",
        "There was no compromise.",
    ],
    "mandatory_limitations": ["unavailable or incomplete sources listed in the review"],
    "report_safe_examples": [
        (
            "No evidence of ransomware-preparation activity was identified in the reviewed artifacts "
            "for ATN62288. The review included process telemetry, Windows event logs, and filesystem "
            "artifact searches for shadow copy deletion, backup deletion, recovery-disabling commands, "
            "ransom note creation, mass file-renaming behavior, and suspicious encryption-related tooling."
        )
    ],
}


FILE_EXFILTRATION_REVIEW_V1 = {
    "slug": "file_exfiltration_review",
    "version": "1.0",
    "display_name": "File Exfiltration Review",
    "description": (
        "Review for evidence of file staging, archive preparation, upload tooling, "
        "cloud upload behavior, or remote-access file-transfer behavior."
    ),
    "supported_scopes": ["case", "host", "user", "process", "network"],
    "target_metadata_fields": [
        "target_host",
        "target_user",
        "target_process",
        "target_source_host",
        "target_destination_host",
        "target_protocol",
        "target_port",
    ],
    "required_sources": [
        "process_telemetry",
        "filesystem_artifacts",
        "network_or_remote_access_transfer_visibility",
    ],
    "optional_sources": [
        "browser_history",
        "webcache",
        "dns_logs",
        "powershell_logs",
        "bits_logs",
        "cloud_sync_logs",
        "prefetch",
        "amcache",
        "memory_artifacts",
    ],
    "required_checks": [
        _traced_check(
            "archive_staging_check",
            "Archive staging check",
            ["get_processes", "search_artifacts", "get_findings"],
            ["rar.exe", "winrar.exe", "7z.exe", "7za.exe", "tar.exe", "makecab.exe", "Compress-Archive", ".zip", ".rar", ".7z"],
        ),
        _traced_check(
            "bulk_file_collection_check",
            "Bulk file collection check",
            ["get_processes", "search_artifacts"],
            ["robocopy", "xcopy", "copy", "C:\\DATA", "staging", "backup", "temp archive directories"],
        ),
        _traced_check(
            "upload_tool_check",
            "Upload tool check",
            ["get_processes", "search_artifacts", "search_memory"],
            ["rclone", "winscp", "megacmd", "pscp", "ftp.exe", "curl.exe", "wget.exe", "azcopy", "aws.exe", "gdrive"],
        ),
        _traced_check(
            "command_line_upload_check",
            "Command-line upload check",
            ["query_events", "get_processes"],
            [
                "curl -T",
                "curl --upload-file",
                "curl -F",
                "Invoke-WebRequest -Method POST",
                "Invoke-RestMethod -Method POST",
                "-InFile",
                "bitsadmin /transfer",
            ],
        ),
        _traced_check(
            "remote_access_file_transfer_check",
            "Remote-access file-transfer check",
            ["query_events", "get_processes", "search_artifacts"],
            ["ScreenConnect.WindowsFileManager.exe", "file transfer", "remote file manager", "AnyDesk transfer", "Splashtop file transfer"],
        ),
        _traced_check(
            "cloud_storage_upload_check",
            "Cloud storage upload check",
            ["get_processes", "search_artifacts"],
            ["Dropbox", "OneDrive", "Google Drive", "mega.nz", "box.com", "SharePoint upload", "sync client", "cloud upload"],
        ),
        _traced_check(
            "bits_transfer_check",
            "BITS transfer check",
            ["query_events", "get_processes"],
            ["bitsadmin", "Start-BitsTransfer", "Microsoft-Windows-Bits-Client"],
        ),
        _traced_check(
            "browser_upload_or_web_upload_check",
            "Browser or web upload check",
            ["search_artifacts", "query_events"],
            ["upload", "web upload", "file picker", "browser cache upload artifacts"],
        ),
        {
            "key": "large_outbound_transfer_check",
            "name": "Large outbound transfer check",
            "type": "source_metadata",
            "required": True,
            "approved_tools": [],
            "source_metadata_required": True,
            "blocks_finding_if_missing": False,
            "forces_partial_limitation_if_unavailable": True,
            "guidance": [
                "If telemetry is available through an approved traced tool, link the check to that HuntStep.",
                "If telemetry exists outside approved traced tools, record source name, time window, availability, and limitations.",
                "If telemetry is unavailable, mark not_available or incomplete and require partial-coverage limitation language.",
            ],
        },
    ],
    "tool_mappings": {},
    "coverage_rules": {
        "complete": {
            "required_sources_available": [
                "process_telemetry",
                "filesystem_artifacts",
                "network_or_remote_access_transfer_visibility",
            ],
            "negative_finding_allowed": True,
        },
        "partial": {
            "minimum_sources_available": ["process_telemetry", "filesystem_artifacts"],
            "limitation_required": True,
            "negative_finding_allowed": True,
        },
        "insufficient": {"negative_finding_allowed": False},
        "not_available": {"negative_finding_allowed": False},
        "unknown": {"negative_finding_allowed": False},
    },
    "finding_eligibility_rules": [
        "coverage_status must be complete or partial",
        "archive, collection, upload, transfer, cloud, BITS, browser, and outbound-transfer checks must be completed or documented not_applicable",
        "completed traced checks must link to HuntStep records",
        "source-driven metadata checks must document reviewed source, time window, and limitations",
        "partial coverage requires mandatory limitation text",
        "proposed statement must match an approved language template",
    ],
    "finding_block_reasons": [
        "missing_process_telemetry",
        "missing_filesystem_artifacts",
        "missing_network_or_remote_transfer_visibility",
        "required_check_not_completed",
        "check_not_linked_to_hunt_step",
        "source_metadata_not_documented",
        "coverage_insufficient",
        "coverage_unknown",
        "unapproved_absence_language",
    ],
    "allowed_language_by_coverage": {
        "complete": [
            {
                "key": "complete_standard",
                "statement": "No evidence of file exfiltration was identified in the reviewed artifacts.",
            }
        ],
        "partial": [
            {
                "key": "partial_network_limited",
                "statement": (
                    "No evidence of file exfiltration was identified in the reviewed artifacts available "
                    "for this case. This conclusion is limited by unavailable or incomplete network, "
                    "proxy, firewall, or remote-access file-transfer logs."
                ),
            }
        ],
    },
    "blocked_language": COMMON_BLOCKED_LANGUAGE + [
        "No data was exfiltrated.",
        "No files left the network.",
        "The attacker did not steal data.",
        "There was no data breach.",
        "No exfiltration occurred.",
        "Nothing was taken.",
    ],
    "mandatory_limitations": [
        "unavailable or incomplete network, proxy, firewall, or remote-access file-transfer logs"
    ],
    "report_safe_examples": [
        (
            "No evidence of file exfiltration was identified in the reviewed artifacts for ATN62288. "
            "The review included process telemetry and filesystem artifact searches for archive staging, "
            "bulk file collection, upload utilities, command-line upload behavior, cloud storage tooling, "
            "BITS transfer behavior, browser/web upload artifacts, and remote-access file-transfer indicators. "
            "This conclusion is limited by the availability and completeness of network, proxy, firewall, "
            "and remote-access transfer telemetry."
        )
    ],
}


DIRECT_LATERAL_MOVEMENT_REVIEW_V1 = {
    "slug": "direct_lateral_movement_review",
    "version": "1.0",
    "display_name": "Direct Lateral Movement Review",
    "description": (
        "Review for evidence that the threat actor directly moved from the reviewed "
        "system, account, or scope to another internal system."
    ),
    "supported_scopes": ["case", "host", "user", "process", "network"],
    "target_metadata_fields": [
        "target_host",
        "target_user",
        "target_process",
        "target_source_host",
        "target_destination_host",
        "target_source_user",
        "target_destination_user",
        "target_protocol",
        "target_port",
    ],
    "required_sources": [
        "process_telemetry",
        "windows_security_logs",
        "authentication_or_network_visibility",
    ],
    "optional_sources": [
        "sysmon",
        "powershell_logs",
        "wmi_activity_logs",
        "terminal_services_logs",
        "edr_network_telemetry",
        "firewall_logs",
        "vpn_logs",
        "memory_artifacts",
    ],
    "required_checks": [
        _traced_check(
            "rdp_outbound_check",
            "RDP outbound check",
            ["query_events", "get_processes"],
            ["mstsc.exe", "Event ID 4624 LogonType 10", "TerminalServices", "outbound 3389"],
        ),
        _traced_check(
            "smb_admin_share_check",
            "SMB admin share check",
            ["query_events", "get_processes", "search_artifacts"],
            ["\\\\ADMIN$", "\\\\C$", "\\\\IPC$", "net use", "copy \\\\host\\C$", "outbound 445"],
        ),
        _traced_check(
            "remote_service_creation_check",
            "Remote service creation check",
            ["query_events", "get_processes"],
            ["Event ID 7045", "services.exe", "sc.exe \\\\host create", "remote service"],
        ),
        _traced_check(
            "wmi_remote_execution_check",
            "WMI remote execution check",
            ["query_events", "get_processes"],
            ["wmic /node", "WmiPrvSE.exe", "Event ID 5857", "Event ID 5858", "Event ID 5861"],
        ),
        _traced_check(
            "winrm_powershell_remoting_check",
            "WinRM PowerShell remoting check",
            ["query_events", "get_processes"],
            ["Enter-PSSession", "Invoke-Command", "winrs", "wsmprovhost.exe", "PowerShell remoting"],
        ),
        _traced_check(
            "psexec_or_remote_admin_tool_check",
            "PsExec or remote admin tooling check",
            ["get_processes", "query_events", "search_artifacts"],
            ["psexec", "paexec", "smbexec", "atexec", "impacket", "remcom"],
        ),
        _traced_check(
            "credentialed_network_logon_check",
            "Credentialed network logon check",
            ["query_events"],
            ["Event ID 4624", "LogonType 3", "LogonType 9", "LogonType 10", "Event ID 4648", "explicit credentials"],
        ),
        _traced_check(
            "internal_discovery_to_movement_sequence_check",
            "Internal discovery to movement sequence check",
            ["get_processes", "query_events", "get_findings"],
            ["net view", "net group", "nltest", "dsquery", "quser", "qwinsta", "arp -a", "ipconfig /all"],
            ["discovery followed by remote execution or authentication indicators"],
        ),
    ],
    "tool_mappings": {},
    "coverage_rules": {
        "complete": {
            "required_sources_available": [
                "process_telemetry",
                "windows_security_logs",
                "authentication_or_network_visibility",
            ],
            "negative_finding_allowed": True,
        },
        "partial": {
            "minimum_sources_available": ["process_telemetry", "windows_security_logs"],
            "limitation_required": True,
            "negative_finding_allowed": True,
        },
        "insufficient": {"negative_finding_allowed": False},
        "not_available": {"negative_finding_allowed": False},
        "unknown": {"negative_finding_allowed": False},
    },
    "finding_eligibility_rules": [
        "coverage_status must be complete or partial",
        "RDP, SMB/admin-share, remote-service, WMI, WinRM, PsExec-like tooling, credentialed logon, and discovery-to-movement checks must be completed or documented not_applicable",
        "completed traced checks must link to HuntStep records",
        "partial coverage requires mandatory limitation text",
        "proposed statement must match an approved language template",
    ],
    "finding_block_reasons": [
        "missing_process_telemetry",
        "missing_windows_security_logs",
        "missing_authentication_or_network_visibility",
        "required_check_not_completed",
        "check_not_linked_to_hunt_step",
        "coverage_insufficient",
        "coverage_unknown",
        "unapproved_absence_language",
    ],
    "allowed_language_by_coverage": {
        "complete": [
            {
                "key": "complete_standard",
                "statement": "No evidence of direct threat-actor lateral movement was identified in the reviewed artifacts.",
            }
        ],
        "partial": [
            {
                "key": "partial_auth_network_limited",
                "statement": (
                    "No evidence of direct threat-actor lateral movement was identified in the reviewed "
                    "artifacts available for this case. This conclusion is limited by unavailable or "
                    "incomplete authentication, endpoint, or network telemetry."
                ),
            }
        ],
    },
    "blocked_language": COMMON_BLOCKED_LANGUAGE + [
        "No lateral movement occurred.",
        "The attacker did not move laterally.",
        "No other systems were accessed.",
        "The environment was not compromised beyond this host.",
        "The network is clean.",
        "No internal access occurred.",
    ],
    "mandatory_limitations": ["unavailable or incomplete authentication, endpoint, or network telemetry"],
    "report_safe_examples": [
        (
            "No evidence of direct threat-actor lateral movement from ATN62288 was identified in the reviewed "
            "artifacts. The review included process telemetry, Windows logon events, remote-service indicators, "
            "WMI and WinRM checks, PsExec-style tooling searches, credentialed network-logon review, and internal "
            "discovery-to-movement sequence checks. This conclusion is limited to the reviewed artifacts and "
            "available telemetry for the incident window."
        )
    ],
}


def _populate_tool_mappings(definition: Dict[str, Any]) -> None:
    definition["tool_mappings"] = {
        check["key"]: {
            "type": check["type"],
            "approved_tools": check.get("approved_tools", []),
        }
        for check in definition["required_checks"]
    }


for _definition in (
    RANSOMWARE_PREPARATION_REVIEW_V1,
    FILE_EXFILTRATION_REVIEW_V1,
    DIRECT_LATERAL_MOVEMENT_REVIEW_V1,
):
    _populate_tool_mappings(_definition)


HUNT_CHECKLIST_DEFINITIONS = [
    RANSOMWARE_PREPARATION_REVIEW_V1,
    FILE_EXFILTRATION_REVIEW_V1,
    DIRECT_LATERAL_MOVEMENT_REVIEW_V1,
]


def checklist_definitions() -> List[Dict[str, Any]]:
    """Return defensive copies of all built-in checklist definitions."""
    return deepcopy(HUNT_CHECKLIST_DEFINITIONS)


def get_checklist_definition(slug: str, version: str = "1.0") -> Optional[Dict[str, Any]]:
    """Return one built-in checklist definition by slug and version."""
    for definition in HUNT_CHECKLIST_DEFINITIONS:
        if definition["slug"] == slug and definition["version"] == version:
            return deepcopy(definition)
    return None


def validate_checklist_definition(definition: Dict[str, Any]) -> None:
    """Validate the static Phase 3A definition contract."""
    required_keys = {
        "slug",
        "version",
        "display_name",
        "description",
        "supported_scopes",
        "target_metadata_fields",
        "required_sources",
        "optional_sources",
        "required_checks",
        "tool_mappings",
        "coverage_rules",
        "finding_eligibility_rules",
        "finding_block_reasons",
        "allowed_language_by_coverage",
        "blocked_language",
        "mandatory_limitations",
        "report_safe_examples",
    }
    missing = sorted(required_keys - set(definition))
    if missing:
        raise ValueError(f"{definition.get('slug', 'unknown')} missing keys: {', '.join(missing)}")

    unsupported_scopes = set(definition["supported_scopes"]) - SUPPORTED_TEMPLATE_SCOPES
    if unsupported_scopes:
        raise ValueError(f"{definition['slug']} has unsupported scopes: {sorted(unsupported_scopes)}")

    for check in definition["required_checks"]:
        unsupported_tools = set(check.get("approved_tools") or []) - APPROVED_TRACED_TOOLS
        if unsupported_tools:
            raise ValueError(f"{definition['slug']} check {check['key']} has unsupported tools: {sorted(unsupported_tools)}")
        if check.get("type") == "source_metadata" and check.get("approved_tools"):
            raise ValueError(f"{definition['slug']} source metadata check {check['key']} cannot define approved_tools")


def validate_all_checklist_definitions() -> None:
    """Validate all built-in definitions."""
    seen = set()
    for definition in HUNT_CHECKLIST_DEFINITIONS:
        validate_checklist_definition(definition)
        key = (definition["slug"], definition["version"])
        if key in seen:
            raise ValueError(f"Duplicate checklist definition: {key}")
        seen.add(key)


def seed_hunt_checklist_definitions() -> Dict[str, int]:
    """Create or refresh built-in checklist definitions when safe."""
    validate_all_checklist_definitions()
    created = 0
    updated = 0
    skipped = 0

    for definition in checklist_definitions():
        existing = HuntChecklistDefinition.query.filter_by(
            slug=definition["slug"],
            version=definition["version"],
        ).first()
        if existing is None:
            db.session.add(HuntChecklistDefinition(
                slug=definition["slug"],
                version=definition["version"],
                display_name=definition["display_name"],
                description=definition["description"],
                category="negative_finding",
                is_active=True,
                definition_json=definition,
            ))
            created += 1
            continue

        if existing.checklist_runs.count() > 0:
            skipped += 1
            continue

        existing.display_name = definition["display_name"]
        existing.description = definition["description"]
        existing.category = "negative_finding"
        existing.is_active = True
        existing.definition_json = definition
        updated += 1

    db.session.commit()
    return {"created": created, "updated": updated, "skipped": skipped}
