"""Parser catalog and hunt mapping for CaseScope.

Centralizes parser metadata that used to be duplicated across the registry,
the hunting UI, and roadmap notes. This keeps new parser families aligned with
their upload lane, storage destination, and default hunt surface.
"""
from dataclasses import dataclass, asdict, field
from typing import Dict, List


@dataclass(frozen=True)
class ParserCapability:
    """Describes how a parser family fits into CaseScope."""
    parser_key: str
    display_name: str
    upload_lane: str
    storage_model: str
    default_hunt_tab: str
    timezone_behavior: str
    artifact_types: List[str]
    category: str = 'other'
    user_selectable: bool = False
    upload_label: str = ''
    upload_hint_artifact_types: List[str] = field(default_factory=list)
    upload_aliases: List[str] = field(default_factory=list)


PARSER_CAPABILITIES: List[ParserCapability] = [
    ParserCapability('evtx', 'Windows Event Logs', 'standard', 'events', 'events', 'utc', ['evtx'], 'evtx'),
    ParserCapability('prefetch', 'Windows Prefetch', 'standard', 'events', 'filesystem', 'utc', ['prefetch']),
    ParserCapability('registry', 'Windows Registry', 'standard', 'events', 'registry', 'utc', ['registry']),
    ParserCapability('lnk', 'Windows LNK', 'standard', 'events', 'filesystem', 'utc', ['lnk']),
    ParserCapability('jumplist', 'Windows Jump Lists', 'standard', 'events', 'filesystem', 'utc', ['jumplist']),
    ParserCapability('mft', 'NTFS MFT', 'standard', 'events', 'filesystem', 'utc', ['mft']),
    ParserCapability('usn', 'NTFS USN Journal', 'standard', 'events', 'filesystem', 'utc', ['usn']),
    ParserCapability('srum', 'Windows SRUM', 'standard', 'events', 'activity', 'utc', ['srum']),
    ParserCapability(
        'iis', 'IIS Logs', 'standard', 'events', 'iis', 'case', ['iis'],
        user_selectable=True,
        upload_label='IIS Logs',
        upload_hint_artifact_types=['iis'],
        upload_aliases=['IIS Log'],
    ),
    ParserCapability(
        'generic_weblog', 'Apache/Nginx Access Logs', 'standard', 'events', 'iis', 'case', ['generic_weblog'],
        user_selectable=True,
        upload_label='Apache/Nginx Access Logs',
        upload_hint_artifact_types=['generic_weblog'],
        upload_aliases=['Apache Access Log', 'Nginx Access Log'],
    ),
    ParserCapability('firewall', 'Generic Firewall Logs', 'standard', 'events', 'events', 'case', ['firewall'], 'firewall'),
    ParserCapability(
        'sonicwall', 'SonicWall Firewall', 'standard', 'events', 'events', 'case', ['sonicwall'], 'firewall',
        user_selectable=True,
        upload_label='SonicWall CSV',
        upload_hint_artifact_types=['sonicwall', 'firewall', 'csv_log'],
        upload_aliases=['Sonicwall CSV'],
    ),
    ParserCapability(
        'sonicwall_syslog', 'SonicWall Syslog', 'standard', 'events', 'events', 'case', ['sonicwall_syslog'], 'firewall',
        user_selectable=True,
        upload_label='SonicWall Syslog',
        upload_hint_artifact_types=['sonicwall_syslog', 'firewall'],
    ),
    ParserCapability(
        'huntress', 'Huntress EDR', 'standard', 'events', 'events', 'utc', ['huntress'], 'edr',
        user_selectable=True,
        upload_label='Huntress EDR',
        upload_hint_artifact_types=['huntress', 'json_log'],
        upload_aliases=['Huntress NDJSON'],
    ),
    ParserCapability(
        'json_log', 'Generic JSON Logs', 'standard', 'events', 'events', 'utc', ['json_log'],
        user_selectable=True,
        upload_label='Generic JSON Logs',
        upload_hint_artifact_types=['json_log'],
    ),
    ParserCapability(
        'csv_log', 'Generic CSV Logs', 'standard', 'events', 'events', 'case', ['csv_log'],
        user_selectable=True,
        upload_label='Generic CSV Logs',
        upload_hint_artifact_types=['csv_log'],
    ),
    ParserCapability('powershell_history', 'PowerShell History', 'standard', 'events', 'events', 'case', ['powershell_history']),
    ParserCapability('hosts', 'Windows Hosts File', 'standard', 'events', 'activity', 'case', ['hosts']),
    ParserCapability('setupapi', 'SetupAPI Device Install Logs', 'standard', 'events', 'filesystem', 'case', ['setupapi']),
    ParserCapability('recycle_bin', 'Windows Recycle Bin', 'standard', 'events', 'filesystem', 'utc', ['recycle_bin']),
    ParserCapability('file_triage', 'Collected File Security Triage', 'standard', 'events', 'filesystem', 'utc', ['file_triage']),
    ParserCapability('office_autosave', 'Office Autosave Recovery Files', 'standard', 'events', 'filesystem', 'utc', ['office_autosave']),
    ParserCapability('windows_search_db', 'Windows Search Databases', 'standard', 'events', 'filesystem', 'utc', ['windows_search_db']),
    ParserCapability('ntfs_metadata', 'NTFS Metadata Files', 'standard', 'events', 'filesystem', 'utc', ['ntfs_metadata', 'ntfs_logfile', 'ntfs_log_tracker_export', 'ntfs_logfile_event']),
    ParserCapability('kape_log', 'KAPE Acquisition Logs', 'standard', 'events', 'acquisition', 'utc', ['kape_log']),
    ParserCapability('cylr_acquisition', 'CyLR Acquisition Summary', 'standard', 'events', 'acquisition', 'utc', ['cylr_acquisition']),
    ParserCapability('diagnostic_log', 'Windows Diagnostic Logs', 'standard', 'events', 'events', 'utc', ['diagnostic_log', 'windows_etl', 'windows_etl_event', 'etl_trace']),
    ParserCapability('windows_error_report', 'Windows Error Reporting Reports', 'standard', 'events', 'events', 'utc', ['windows_error_report']),
    ParserCapability('crash_dump_triage', 'Windows Crash Dump Triage', 'standard', 'events', 'filesystem', 'utc', ['crash_dump_triage']),
    ParserCapability('wbem_repository', 'WBEM/WMI Repository Metadata', 'standard', 'events', 'events', 'utc', ['wbem_repository']),
    ParserCapability('browser_state', 'Browser Profile State Files', 'standard', 'events', 'browsers', 'utc', ['browser_state']),
    ParserCapability('cloud_metadata', 'Cloud Sync Metadata', 'standard', 'events', 'events', 'utc', ['cloud_metadata']),
    ParserCapability('transaction_sidecar', 'Transaction Sidecar Metadata', 'standard', 'events', 'filesystem', 'utc', ['transaction_sidecar']),
    ParserCapability(
        'browser',
        'Browser SQLite Artifacts',
        'standard',
        'events',
        'browsers',
        'utc',
        [
            'browser',
            'browser_history',
            'browser_cookies',
            'browser_forms',
            'browser_logins',
            'browser_autofill',
            'browser_download',
            'sqlite_firefox_origin_storage',
            'sqlite_firefox_cache_storage',
            'sqlite_firefox_indexeddb',
        ],
    ),
    ParserCapability(
        'firefox_session',
        'Firefox Session Files',
        'standard',
        'events',
        'browsers',
        'utc',
        ['firefox_session'],
    ),
    ParserCapability(
        'firefox_json',
        'Firefox JSON Artifacts',
        'standard',
        'events',
        'browsers',
        'utc',
        ['firefox_json', 'firefox_addon', 'firefox_search_engine', 'firefox_handler'],
    ),
    ParserCapability('scheduled_task', 'Windows Scheduled Tasks', 'standard', 'events', 'tasks', 'case', ['scheduled_task']),
    ParserCapability(
        'activities_cache',
        'Windows Timeline',
        'standard',
        'events',
        'activity',
        'utc',
        ['activities_cache', 'activity_operation'],
    ),
    ParserCapability(
        'webcache',
        'WebCache ESE',
        'standard',
        'events',
        'browsers',
        'utc',
        [
            'webcache',
            'webcache_history',
            'webcache_cookies',
            'webcache_cache',
            'webcache_downloads',
            'webcache_dom_storage',
            'webcache_compatibility',
        ],
    ),
    ParserCapability(
        'defender_av', 'Windows Defender AV Exports', 'standard', 'events', 'events', 'utc', ['defender_av'], 'edr',
        user_selectable=True,
        upload_label='Windows Defender AV',
        upload_hint_artifact_types=['defender_av', 'json_log', 'csv_log'],
        upload_aliases=['Defender AV'],
    ),
    ParserCapability(
        'mde_xdr', 'Microsoft Defender XDR Exports', 'standard', 'events', 'events', 'utc', ['mde_xdr'], 'edr',
        user_selectable=True,
        upload_label='Microsoft Defender XDR',
        upload_hint_artifact_types=['mde_xdr', 'json_log', 'csv_log'],
        upload_aliases=['Defender XDR'],
    ),
    ParserCapability(
        'palo_alto', 'Palo Alto Firewall Exports', 'standard', 'events', 'events', 'case', ['palo_alto'], 'firewall',
        user_selectable=True,
        upload_label='Palo Alto Firewall',
        upload_hint_artifact_types=['palo_alto', 'firewall', 'csv_log'],
    ),
    ParserCapability(
        'fortigate', 'FortiGate Logs', 'standard', 'events', 'events', 'case', ['fortigate'], 'firewall',
        user_selectable=True,
        upload_label='FortiGate Logs',
        upload_hint_artifact_types=['fortigate', 'firewall'],
    ),
    ParserCapability(
        'pfsense', 'pfSense OPNsense Filter Logs', 'standard', 'events', 'events', 'case', ['pfsense'], 'firewall',
        user_selectable=True,
        upload_label='pfSense / OPNsense',
        upload_hint_artifact_types=['pfsense', 'firewall'],
    ),
    ParserCapability(
        'cisco_asa', 'Cisco ASA FTD Logs', 'standard', 'events', 'events', 'case', ['cisco_asa'], 'firewall',
        user_selectable=True,
        upload_label='Cisco ASA / FTD',
        upload_hint_artifact_types=['cisco_asa', 'firewall'],
    ),
    ParserCapability(
        'suricata', 'Suricata EVE Logs', 'standard', 'events', 'events', 'utc', ['suricata'], 'firewall',
        user_selectable=True,
        upload_label='Suricata EVE',
        upload_hint_artifact_types=['suricata', 'json_log'],
    ),
    ParserCapability(
        'velociraptor', 'Velociraptor Exports', 'standard', 'events', 'events', 'utc', ['velociraptor'],
        user_selectable=True,
        upload_label='Velociraptor Exports',
        upload_hint_artifact_types=['velociraptor', 'json_log', 'csv_log'],
    ),
    ParserCapability(
        'plaso', 'Plaso Timeline Exports', 'standard', 'events', 'events', 'utc', ['plaso'],
        user_selectable=True,
        upload_label='Plaso Timeline Exports',
        upload_hint_artifact_types=['plaso', 'json_log', 'csv_log'],
    ),
    ParserCapability(
        'crowdstrike', 'CrowdStrike Exports', 'standard', 'events', 'events', 'utc', ['crowdstrike'], 'edr',
        user_selectable=True,
        upload_label='CrowdStrike Exports',
        upload_hint_artifact_types=['crowdstrike', 'json_log', 'csv_log'],
    ),
    ParserCapability(
        'sentinelone', 'SentinelOne Exports', 'standard', 'events', 'events', 'utc', ['sentinelone'], 'edr',
        user_selectable=True,
        upload_label='SentinelOne Exports',
        upload_hint_artifact_types=['sentinelone', 'json_log', 'csv_log'],
    ),
    ParserCapability(
        'sophos', 'Sophos Exports', 'standard', 'events', 'events', 'utc', ['sophos'], 'edr',
        user_selectable=True,
        upload_label='Sophos Exports',
        upload_hint_artifact_types=['sophos', 'json_log', 'csv_log'],
    ),
]


PARSER_CAPABILITIES_BY_KEY: Dict[str, ParserCapability] = {
    capability.parser_key: capability for capability in PARSER_CAPABILITIES
}

AUTO_DETECT_UPLOAD_KEY = 'auto_detect'
CYLR_UPLOAD_KEY = 'cylr_archive'
KAPE_UPLOAD_KEY = 'kape_archive'
AUTO_DETECT_UPLOAD_LABEL = 'Auto-detect / Other'
CYLR_UPLOAD_LABEL = 'CyLR / Triage ZIP'
KAPE_UPLOAD_LABEL = 'KAPE Triage ZIP'


def get_upload_type_rows() -> List[Dict[str, object]]:
    """Return curated upload families for the upload queue dropdown."""
    rows: List[Dict[str, object]] = [
        {
            'key': AUTO_DETECT_UPLOAD_KEY,
            'label': AUTO_DETECT_UPLOAD_LABEL,
            'parser_hints': [],
            'is_archive': False,
            'aliases': ['Other', 'Auto-detect', 'Auto Detect'],
        },
        {
            'key': CYLR_UPLOAD_KEY,
            'label': CYLR_UPLOAD_LABEL,
            'parser_hints': [],
            'is_archive': True,
            'aliases': ['CyLR', 'Triage ZIP'],
        },
        {
            'key': KAPE_UPLOAD_KEY,
            'label': KAPE_UPLOAD_LABEL,
            'parser_hints': [],
            'is_archive': True,
            'aliases': ['KAPE', 'KAPE ZIP', 'KAPE Collection'],
        },
    ]

    for capability in PARSER_CAPABILITIES:
        if not capability.user_selectable:
            continue
        rows.append({
            'key': capability.parser_key,
            'label': capability.upload_label or capability.display_name,
            'parser_hints': list(capability.upload_hint_artifact_types or [capability.parser_key]),
            'is_archive': False,
            'aliases': list(capability.upload_aliases),
        })

    return rows


def resolve_upload_type_selection(selection: str) -> Dict[str, object]:
    """Normalize an upload selection into a canonical label and parser hints."""
    normalized = (selection or '').strip().lower()
    default_row = get_upload_type_rows()[0]
    if not normalized:
        return dict(default_row)

    for row in get_upload_type_rows():
        lookup_values = [row['key'], row['label'], *row.get('aliases', [])]
        if normalized in {value.strip().lower() for value in lookup_values if value}:
            return dict(row)

    return dict(default_row)



def get_parser_hints_for_upload_type(selection: str) -> List[str]:
    """Return preferred parser keys for an upload selection."""
    hints = resolve_upload_type_selection(selection).get('parser_hints', [])
    return [hint for hint in hints if isinstance(hint, str) and hint]


HUNTING_TABS = [
    {'id': 'events', 'label': 'Events', 'icon': '📋'},
    {'id': 'mitre', 'label': 'MITRE', 'icon': '🎯'},
    {'id': 'browsers', 'label': 'Browsers', 'icon': '🌐'},
    {'id': 'filesystem', 'label': 'File System', 'icon': '📁'},
    {'id': 'registry', 'label': 'Registry', 'icon': '🗂️'},
    {'id': 'iis', 'label': 'IIS', 'icon': '🖥️'},
    {'id': 'tasks', 'label': 'Tasks', 'icon': '⏰'},
    {'id': 'activity', 'label': 'Apps & Network', 'icon': '📊'},
    {'id': 'acquisition', 'label': 'Acquisition', 'icon': '📦'},
    {'id': 'other', 'label': 'Other', 'icon': '🔧'},
]


HUNTING_TAB_TYPES: Dict[str, List[str]] = {
    'events': [
        'evtx', 'firewall', 'sonicwall', 'sonicwall_syslog', 'huntress', 'json_log', 'csv_log',
        'defender_av', 'mde_xdr', 'palo_alto', 'fortigate', 'pfsense',
        'cisco_asa', 'suricata', 'velociraptor', 'plaso', 'crowdstrike',
        'sentinelone', 'sophos', 'powershell_history',
        'diagnostic_log', 'windows_etl', 'windows_etl_event', 'etl_trace', 'windows_error_report',
        'wbem_repository', 'cloud_metadata',
    ],
    'mitre': [],
    'browsers': [
        'browser', 'browser_history', 'browser_cookies', 'browser_forms',
        'browser_logins', 'browser_autofill', 'browser_download',
        'sqlite_firefox_origin_storage', 'sqlite_firefox_cache_storage',
        'sqlite_firefox_indexeddb',
        'firefox_session', 'firefox_addon', 'firefox_search_engine',
        'firefox_handler', 'firefox_json', 'webcache', 'webcache_history',
        'webcache_cookies', 'webcache_cache', 'webcache_downloads',
        'webcache_dom_storage', 'webcache_compatibility', 'browser_state',
    ],
    'filesystem': [
        'prefetch', 'lnk', 'jumplist', 'mft', 'usn', 'setupapi',
        'recycle_bin', 'file_triage', 'office_autosave',
        'windows_search_db', 'ntfs_metadata', 'ntfs_logfile', 'ntfs_log_tracker_export', 'ntfs_logfile_event',
        'crash_dump_triage', 'transaction_sidecar',
    ],
    'registry': ['registry'],
    'iis': ['iis', 'generic_weblog'],
    'tasks': ['scheduled_task'],
    'activity': ['srum', 'activities_cache', 'activity_operation', 'hosts'],
    'acquisition': ['kape_log', 'cylr_acquisition'],
    'other': [],
}


EVENT_FILTER_GROUPS: Dict[str, List[str]] = {
    'evtx': ['evtx'],
    'firewall': ['firewall', 'sonicwall', 'sonicwall_syslog', 'palo_alto', 'fortigate', 'pfsense', 'cisco_asa', 'suricata'],
    'edr': ['huntress', 'defender_av', 'mde_xdr', 'crowdstrike', 'sentinelone', 'sophos'],
}


def get_hunting_tabs() -> List[Dict[str, str]]:
    """Return hunt-tab definitions with their current artifact types."""
    tabs = []
    for tab in HUNTING_TABS:
        tab_data = dict(tab)
        tab_data['artifact_types'] = HUNTING_TAB_TYPES.get(tab['id'], [])
        tabs.append(tab_data)
    return tabs


def get_parser_capability_rows() -> List[Dict[str, object]]:
    """Return the parser catalog as serializable dictionaries."""
    rows = []
    for capability in PARSER_CAPABILITIES:
        row = asdict(capability)
        row['artifact_types_csv'] = ','.join(capability.artifact_types)
        rows.append(row)
    return rows
