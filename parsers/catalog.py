"""Parser catalog and hunt mapping for CaseScope.

Centralizes parser metadata that used to be duplicated across the registry,
the hunting UI, and roadmap notes. This keeps new parser families aligned with
their upload lane, storage destination, and default hunt surface.
"""
from dataclasses import dataclass, asdict
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


PARSER_CAPABILITIES: List[ParserCapability] = [
    ParserCapability('evtx', 'Windows Event Logs', 'standard', 'events', 'events', 'utc', ['evtx'], 'evtx'),
    ParserCapability('prefetch', 'Windows Prefetch', 'standard', 'events', 'filesystem', 'utc', ['prefetch']),
    ParserCapability('registry', 'Windows Registry', 'standard', 'events', 'registry', 'utc', ['registry']),
    ParserCapability('lnk', 'Windows LNK', 'standard', 'events', 'filesystem', 'utc', ['lnk']),
    ParserCapability('jumplist', 'Windows Jump Lists', 'standard', 'events', 'filesystem', 'utc', ['jumplist']),
    ParserCapability('mft', 'NTFS MFT', 'standard', 'events', 'filesystem', 'utc', ['mft']),
    ParserCapability('srum', 'Windows SRUM', 'standard', 'events', 'activity', 'utc', ['srum']),
    ParserCapability('iis', 'IIS Logs', 'standard', 'events', 'iis', 'case', ['iis']),
    ParserCapability('firewall', 'Generic Firewall Logs', 'standard', 'events', 'events', 'case', ['firewall'], 'firewall'),
    ParserCapability('sonicwall', 'SonicWall Firewall', 'standard', 'events', 'events', 'case', ['sonicwall'], 'firewall'),
    ParserCapability('sonicwall_syslog', 'SonicWall Syslog', 'standard', 'events', 'events', 'case', ['sonicwall_syslog'], 'firewall'),
    ParserCapability('huntress', 'Huntress EDR', 'standard', 'events', 'events', 'utc', ['huntress'], 'edr'),
    ParserCapability('json_log', 'Generic JSON Logs', 'standard', 'events', 'events', 'utc', ['json_log']),
    ParserCapability('csv_log', 'Generic CSV Logs', 'standard', 'events', 'events', 'case', ['csv_log']),
    ParserCapability('powershell_history', 'PowerShell History', 'standard', 'events', 'filesystem', 'case', ['powershell_history']),
    ParserCapability('hosts', 'Windows Hosts File', 'standard', 'events', 'filesystem', 'case', ['hosts']),
    ParserCapability('setupapi', 'SetupAPI Device Install Logs', 'standard', 'events', 'filesystem', 'case', ['setupapi']),
    ParserCapability(
        'browser',
        'Browser SQLite Artifacts',
        'standard',
        'events',
        'browsers',
        'utc',
        ['browser', 'browser_history', 'browser_cookies', 'browser_forms', 'browser_logins', 'browser_autofill', 'browser_download'],
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
        ['webcache', 'webcache_history', 'webcache_cookies', 'webcache_cache', 'webcache_downloads'],
    ),
    ParserCapability('defender_av', 'Windows Defender AV Exports', 'standard', 'events', 'events', 'utc', ['defender_av'], 'edr'),
    ParserCapability('mde_xdr', 'Microsoft Defender XDR Exports', 'standard', 'events', 'events', 'utc', ['mde_xdr'], 'edr'),
    ParserCapability('palo_alto', 'Palo Alto Firewall Exports', 'standard', 'events', 'events', 'case', ['palo_alto'], 'firewall'),
    ParserCapability('fortigate', 'FortiGate Logs', 'standard', 'events', 'events', 'case', ['fortigate'], 'firewall'),
    ParserCapability('pfsense', 'pfSense OPNsense Filter Logs', 'standard', 'events', 'events', 'case', ['pfsense'], 'firewall'),
    ParserCapability('cisco_asa', 'Cisco ASA FTD Logs', 'standard', 'events', 'events', 'case', ['cisco_asa'], 'firewall'),
    ParserCapability('suricata', 'Suricata EVE Logs', 'standard', 'events', 'events', 'utc', ['suricata'], 'firewall'),
    ParserCapability('velociraptor', 'Velociraptor Exports', 'standard', 'events', 'events', 'utc', ['velociraptor']),
    ParserCapability('plaso', 'Plaso Timeline Exports', 'standard', 'events', 'events', 'utc', ['plaso']),
    ParserCapability('crowdstrike', 'CrowdStrike Exports', 'standard', 'events', 'events', 'utc', ['crowdstrike'], 'edr'),
    ParserCapability('sentinelone', 'SentinelOne Exports', 'standard', 'events', 'events', 'utc', ['sentinelone'], 'edr'),
    ParserCapability('sophos', 'Sophos Exports', 'standard', 'events', 'events', 'utc', ['sophos'], 'edr'),
]


PARSER_CAPABILITIES_BY_KEY: Dict[str, ParserCapability] = {
    capability.parser_key: capability for capability in PARSER_CAPABILITIES
}


HUNTING_TABS = [
    {'id': 'events', 'label': 'Events', 'icon': '📋'},
    {'id': 'browsers', 'label': 'Browsers', 'icon': '🌐'},
    {'id': 'filesystem', 'label': 'File System', 'icon': '📁'},
    {'id': 'registry', 'label': 'Registry', 'icon': '🗂️'},
    {'id': 'iis', 'label': 'IIS', 'icon': '🖥️'},
    {'id': 'tasks', 'label': 'Tasks', 'icon': '⏰'},
    {'id': 'activity', 'label': 'Apps & Network', 'icon': '📊'},
    {'id': 'other', 'label': 'Other', 'icon': '🔧'},
]


HUNTING_TAB_TYPES: Dict[str, List[str]] = {
    'events': [
        'evtx', 'firewall', 'sonicwall', 'sonicwall_syslog', 'huntress', 'json_log', 'csv_log',
        'defender_av', 'mde_xdr', 'palo_alto', 'fortigate', 'pfsense',
        'cisco_asa', 'suricata', 'velociraptor', 'plaso', 'crowdstrike',
        'sentinelone', 'sophos',
    ],
    'browsers': [
        'browser', 'browser_history', 'browser_cookies', 'browser_forms',
        'browser_logins', 'browser_autofill', 'browser_download',
        'firefox_session', 'firefox_addon', 'firefox_search_engine',
        'firefox_handler', 'firefox_json', 'webcache', 'webcache_history',
        'webcache_cookies', 'webcache_cache', 'webcache_downloads',
    ],
    'filesystem': ['prefetch', 'lnk', 'jumplist', 'mft', 'powershell_history', 'hosts', 'setupapi'],
    'registry': ['registry'],
    'iis': ['iis'],
    'tasks': ['scheduled_task'],
    'activity': ['srum', 'activities_cache', 'activity_operation'],
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
