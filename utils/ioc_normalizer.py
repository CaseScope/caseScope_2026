"""Shared IOC normalization and AI-guardrail helpers."""

from __future__ import annotations

import importlib.util
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit


def _load_local_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name,
        os.path.join(os.path.dirname(__file__), filename),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_ioc_text = _load_local_module("ioc_normalizer_text_shared", "ioc_text.py")

INVALID_HASH_PLACEHOLDERS = (
    'file is no longer on disk',
    'not available',
    'not present',
    'unknown',
    'n/a',
    'none',
)

INVALID_AI_PLACEHOLDERS = {
    '',
    '...',
    '…',
    'unknown',
    'n/a',
    'none',
    'null',
    'nil',
    'tbd',
}

COMPROMISE_EVIDENCE_HINTS = (
    'credential theft',
    'credentials stolen',
    'compromised account',
    'compromised user',
    'password observed',
    'password reset',
    'password spray',
    'unauthorized login',
    'account takeover',
    'stolen credentials',
)

URL_PATTERN = re.compile(
    r'(?:hxxps?|https?)(?:\[?://\]?|://)[\w\-\.]+(?:\[\.\]|\.)[\w\-\.]+[^\s<>"{}|\\^`\[\]]*',
    re.I,
)


def _is_valid_ipv4(ip: str) -> bool:
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
        except ValueError:
            return False
        if num < 0 or num > 255:
            return False
    return True


def _defang_text(value: str) -> str:
    """Normalize common defanged IOC encodings."""
    return _ioc_text._defang_text(value)


def _normalize_extracted_file_path(value: Any) -> Tuple[Optional[str], str]:
    """Strip Huntress remediation/status annotations from a captured file path."""
    return _ioc_text._normalize_extracted_file_path(value)


def _is_placeholder_value(value: Any) -> bool:
    """Return True for schema placeholders and model filler values."""
    if value is None:
        return True
    cleaned = str(value).strip().strip('"').strip("'").lower()
    if not cleaned:
        return True
    if cleaned in INVALID_AI_PLACEHOLDERS:
        return True
    if set(cleaned) <= {'.'}:
        return True
    return False


def _is_huntress_portal_value(value: str) -> bool:
    """Return True when the value points at Huntress portal infrastructure."""
    return 'huntress.io' in _defang_text(value or '').lower()


def _normalize_ai_network_item(item: Any, item_type: str) -> Optional[Dict[str, Any]]:
    """Normalize AI-provided network IOC items into saveable values."""
    normalized = dict(item) if isinstance(item, dict) else {'value': item}
    value = str(normalized.get('value', '')).strip()
    if _is_placeholder_value(value):
        return None

    cleaned = _defang_text(value).strip()
    if item_type == 'domain':
        if '://' in cleaned:
            cleaned = cleaned.split('://', 1)[1]
        cleaned = cleaned.split('/', 1)[0].rstrip('.').lower()
        if not cleaned or _is_huntress_portal_value(cleaned):
            return None
    elif item_type == 'url':
        if _is_huntress_portal_value(cleaned):
            return None
    elif item_type == 'ipv4':
        if not _is_valid_ipv4(cleaned):
            return None
    elif item_type == 'ipv6':
        cleaned = cleaned.lower()

    normalized['value'] = cleaned
    return normalized


def _normalize_ai_hash_item(item: Any) -> Optional[Dict[str, Any]]:
    """Drop placeholder hashes and keep only valid hash values."""
    normalized = dict(item) if isinstance(item, dict) else {'value': item}
    declared_hash_type = str(normalized.get('type') or '').strip().lower()
    hash_type = declared_hash_type or 'sha256'
    value = str(normalized.get('value', '')).strip().lower()
    if _is_placeholder_value(value):
        return None
    if any(placeholder in value for placeholder in INVALID_HASH_PLACEHOLDERS):
        return None

    inferred_hash_type = None
    if re.fullmatch(r'[a-f0-9]{32}', value):
        inferred_hash_type = 'md5'
    elif re.fullmatch(r'[a-f0-9]{40}', value):
        inferred_hash_type = 'sha1'
    elif re.fullmatch(r'[a-f0-9]{64}', value):
        inferred_hash_type = 'sha256'

    if not inferred_hash_type:
        return None

    validation_warnings = list(normalized.get('validation_warnings') or [])
    if declared_hash_type and declared_hash_type != inferred_hash_type:
        validation_warnings.append(
            f'Hash type corrected from {declared_hash_type} to {inferred_hash_type} based on value length.'
        )
    elif not declared_hash_type:
        validation_warnings.append(
            f'Hash type filled as {inferred_hash_type} based on value length.'
        )

    hash_type = inferred_hash_type
    validators = {
        'md5': re.compile(r'^[a-f0-9]{32}$'),
        'sha1': re.compile(r'^[a-f0-9]{40}$'),
        'sha256': re.compile(r'^[a-f0-9]{64}$'),
    }
    validator = validators.get(hash_type)
    if validator and not validator.match(value):
        return None

    normalized['value'] = value
    normalized['type'] = hash_type
    if validation_warnings:
        normalized['validation_warnings'] = validation_warnings
    return normalized


def _normalize_ai_file_path_item(item: Any) -> Optional[Dict[str, Any]]:
    """Normalize AI-provided file path items."""
    normalized = dict(item) if isinstance(item, dict) else {'value': item}
    if _is_placeholder_value(normalized.get('value', '')):
        return None
    value, note = _normalize_extracted_file_path(normalized.get('value', ''))
    if not value:
        return None
    normalized['value'] = value
    if note:
        existing_context = str(normalized.get('context', '') or '').strip()
        if note.lower() not in existing_context.lower():
            normalized['context'] = f"{existing_context} | {note}" if existing_context else note
    return normalized


def _normalize_ai_file_name(value: Any) -> Optional[str]:
    """Collapse path-like file names to basenames."""
    if value is None:
        return None
    if _is_placeholder_value(value):
        return None
    cleaned, _ = _normalize_extracted_file_path(value)
    if not cleaned:
        return None
    if '\\' in cleaned or '/' in cleaned:
        cleaned = cleaned.replace('\\', '/').rsplit('/', 1)[-1]
    return cleaned or None


def _normalize_ai_user_item(item: Any, context: str = '') -> Optional[Dict[str, Any]]:
    """Map AI user objects into the importer's expected value shape."""
    if isinstance(item, dict):
        username = str(item.get('value') or item.get('username') or '').strip()
        if _is_placeholder_value(username):
            return None
        normalized = dict(item)
        normalized['value'] = username
        if context and not normalized.get('context'):
            normalized['context'] = context
        return normalized

    username = str(item).strip()
    if _is_placeholder_value(username):
        return None
    normalized = {'value': username}
    if context:
        normalized['context'] = context
    return normalized


def _extract_report_urls(report_text: str) -> List[str]:
    """Extract defanged non-Huntress URLs from the source report."""
    clean_text = _defang_text(report_text or '')
    urls = []
    seen = set()
    for match in URL_PATTERN.findall(clean_text):
        cleaned = str(match).strip().rstrip('),.;\'"')
        if not cleaned or _is_huntress_portal_value(cleaned):
            continue
        lowered = cleaned.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        urls.append(cleaned)
    return urls


def _reconcile_url_against_report(url_value: str, report_urls: List[str]) -> str:
    """Prefer the exact scheme and path observed in the report text."""
    candidate = (url_value or '').strip()
    if not candidate:
        return candidate

    try:
        candidate_parts = urlsplit(candidate)
    except Exception:
        return candidate

    for report_url in report_urls:
        try:
            report_parts = urlsplit(report_url)
        except Exception:
            continue
        if (
            report_parts.netloc.lower() == candidate_parts.netloc.lower()
            and report_parts.path == candidate_parts.path
            and report_parts.query == candidate_parts.query
        ):
            return report_url
        if candidate.startswith('http://'):
            https_candidate = 'https://' + candidate[len('http://'):]
            if report_url.lower() == https_candidate.lower():
                return report_url
    return candidate


def _report_supports_compromised_users(report_text: str) -> bool:
    """Require explicit compromise language before trusting compromised_users."""
    lowered = (report_text or '').lower()
    return any(hint in lowered for hint in COMPROMISE_EVIDENCE_HINTS)


def _dedupe_mixed_list(*sequences: List[Any]) -> List[Any]:
    """Deduplicate strings and dict-like values while preserving order."""
    seen = set()
    unique = []
    for sequence in sequences:
        for item in sequence or []:
            if isinstance(item, dict):
                key = json.dumps(item, sort_keys=True, default=str)
            else:
                key = str(item).strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            unique.append(item)
    return unique


def _apply_ai_guardrails(normalized: Dict[str, Any], report_text: str) -> Dict[str, Any]:
    """Apply model-family guardrails against the original report text."""
    iocs = normalized.setdefault('iocs', {})
    summary = normalized.setdefault('extraction_summary', {})
    report_urls = _extract_report_urls(report_text)

    affected_hosts = [
        host for host in summary.get('affected_hosts', [])
        if not _is_placeholder_value(host)
    ]
    summary['affected_hosts'] = affected_hosts
    iocs['hostnames'] = [
        host for host in iocs.get('hostnames', [])
        if not _is_placeholder_value(host)
    ]

    for user in summary.get('affected_users', []) or []:
        cleaned_user = _normalize_ai_user_item(user, context='Affected user in report')
        if cleaned_user:
            iocs.setdefault('users', []).append(cleaned_user)
        sid = str((user or {}).get('sid') or '').strip()
        if sid and not _is_placeholder_value(sid):
            iocs.setdefault('sids', []).append({'value': sid, 'context': 'Affected user SID in report'})

    normalized_urls = []
    for url_item in iocs.get('urls', []):
        if not isinstance(url_item, dict):
            continue
        corrected = dict(url_item)
        corrected_value = _reconcile_url_against_report(url_item.get('value', ''), report_urls)
        if _is_placeholder_value(corrected_value):
            continue
        corrected['value'] = corrected_value
        normalized_urls.append(corrected)
    iocs['urls'] = normalized_urls

    seen_domains = set()
    merged_domains = []
    for domain_item in iocs.get('domains', []):
        cleaned_domain = _normalize_ai_network_item(domain_item, 'domain')
        if not cleaned_domain:
            continue
        lowered = cleaned_domain['value'].lower()
        if lowered in seen_domains:
            continue
        seen_domains.add(lowered)
        merged_domains.append(cleaned_domain)
    for url_item in iocs.get('urls', []):
        try:
            hostname = urlsplit(url_item.get('value', '')).netloc.lower()
        except Exception:
            hostname = ''
        if not hostname or hostname in seen_domains or _is_huntress_portal_value(hostname):
            continue
        seen_domains.add(hostname)
        merged_domains.append({
            'value': hostname,
            'context': 'Derived from extracted URL',
        })
    iocs['domains'] = merged_domains

    seen_file_names = set()
    merged_file_names = []
    for file_name in iocs.get('file_names', []):
        cleaned_name = _normalize_ai_file_name(file_name)
        if not cleaned_name:
            continue
        lowered = cleaned_name.lower()
        if lowered in seen_file_names:
            continue
        seen_file_names.add(lowered)
        merged_file_names.append(cleaned_name)
    for file_path in iocs.get('file_paths', []):
        cleaned_name = _normalize_ai_file_name((file_path or {}).get('value', ''))
        if not cleaned_name:
            continue
        lowered = cleaned_name.lower()
        if lowered in seen_file_names:
            continue
        seen_file_names.add(lowered)
        merged_file_names.append(cleaned_name)
    for hash_item in iocs.get('hashes', []):
        cleaned_name = _normalize_ai_file_name((hash_item or {}).get('filename', ''))
        if not cleaned_name:
            continue
        lowered = cleaned_name.lower()
        if lowered in seen_file_names:
            continue
        seen_file_names.add(lowered)
        merged_file_names.append(cleaned_name)
    iocs['file_names'] = merged_file_names

    if not _report_supports_compromised_users(report_text):
        auth_context_users = []
        for user_item in iocs.get('users', []):
            context = str((user_item or {}).get('context') or '').lower()
            if 'compromised' in context:
                continue
            auth_context_users.append(user_item)
        iocs['users'] = auth_context_users

    iocs['domains'] = _dedupe_mixed_list(iocs.get('domains', []))
    iocs['urls'] = _dedupe_mixed_list(iocs.get('urls', []))
    iocs['file_paths'] = _dedupe_mixed_list(iocs.get('file_paths', []))
    iocs['file_names'] = _dedupe_mixed_list(iocs.get('file_names', []))
    iocs['users'] = _dedupe_mixed_list(iocs.get('users', []))
    iocs['sids'] = _dedupe_mixed_list(iocs.get('sids', []))

    return normalized


def _normalize_command_anchor_text(value: Any) -> str:
    """Normalize report and command text enough to catch formatting-only differences."""
    text = _defang_text(str(value or ''))
    text = text.replace('\\\\', '\\')
    text = text.replace('\\"', '"').replace("\\'", "'")
    text = text.replace('“', '"').replace('”', '"').replace('‘', "'").replace('’', "'")
    text = re.sub(r'\s+', ' ', text)
    return text.strip().strip('"').lower()


def _apply_ai_command_anchoring(normalized: Dict[str, Any], report_text: str) -> Dict[str, Any]:
    """Remove AI command lines that are inferred instead of anchored in source text."""
    iocs = normalized.setdefault('iocs', {})
    summary = normalized.setdefault('extraction_summary', {})
    report_anchor = _normalize_command_anchor_text(report_text)
    accepted_commands = []
    rejected_commands = []

    for command in iocs.get('commands', []) or []:
        command_value = command.get('value', '') if isinstance(command, dict) else str(command)
        normalized_command = _normalize_command_anchor_text(command_value)
        if normalized_command and normalized_command in report_anchor:
            accepted_commands.append(command)
            continue
        rejected_commands.append(
            {
                'type': 'command',
                'value': command_value,
                'reason': 'not_found_verbatim_in_normalized_source',
            }
        )

    if rejected_commands:
        iocs['commands'] = accepted_commands
        existing_rejections = summary.get('rejected_candidates') or []
        summary['rejected_candidates'] = [*existing_rejections, *rejected_commands]
        warnings = list(summary.get('validation_warnings') or [])
        warnings.extend(
            f"Command line not found verbatim in normalized source: {item['value']}"
            for item in rejected_commands
        )
        summary['validation_warnings'] = warnings
    return normalized


def _normalize_ai_extraction(extraction: Dict[str, Any], report_text: str = '') -> Dict[str, Any]:
    """Normalize AI extraction output to the legacy importer-compatible shape."""
    normalized = {
        'extraction_summary': extraction.get('extraction_summary', {}),
        'iocs': {
            'hashes': [],
            'ip_addresses': [],
            'domains': [],
            'urls': [],
            'file_paths': [],
            'file_names': [],
            'users': [],
            'sids': [],
            'registry_keys': [],
            'commands': [],
            'processes': [],
            'credentials': [],
            'hostnames': [],
            'timestamps': [],
            'network_shares': [],
            'email_addresses': [],
            'mitre_indicators': [],
            'services': [],
            'scheduled_tasks': [],
            'cves': [],
            'threat_names': [],
        },
        'raw_artifacts': extraction.get('raw_artifacts', {}),
    }

    network = extraction.get('network_iocs', {})
    for ip in network.get('ipv4', []):
        cleaned_ip = _normalize_ai_network_item(ip, 'ipv4')
        if cleaned_ip:
            cleaned_ip['type'] = 'ipv4'
            normalized['iocs']['ip_addresses'].append(cleaned_ip)

    for ip in network.get('ipv6', []):
        cleaned_ip = _normalize_ai_network_item(ip, 'ipv6')
        if cleaned_ip:
            cleaned_ip['type'] = 'ipv6'
            normalized['iocs']['ip_addresses'].append(cleaned_ip)

    for domain in network.get('domains', []):
        cleaned_domain = _normalize_ai_network_item(domain, 'domain')
        if cleaned_domain:
            normalized['iocs']['domains'].append(cleaned_domain)

    for tunnel in network.get('cloudflare_tunnels', []):
        normalized['iocs']['domains'].append({
            'value': tunnel,
            'context': 'Cloudflare Quick Tunnel (potential C2)',
        })

    for url in network.get('urls', []):
        cleaned_url = _normalize_ai_network_item(url, 'url')
        if cleaned_url:
            normalized['iocs']['urls'].append(cleaned_url)

    file_iocs = extraction.get('file_iocs', {})
    for hash_item in file_iocs.get('hashes', []):
        cleaned_hash = _normalize_ai_hash_item(hash_item)
        if cleaned_hash:
            normalized['iocs']['hashes'].append(cleaned_hash)

    for file_path in file_iocs.get('file_paths', []):
        cleaned_path = _normalize_ai_file_path_item(file_path)
        if cleaned_path:
            normalized['iocs']['file_paths'].append(cleaned_path)

    for file_name in file_iocs.get('file_names', []):
        cleaned_name = _normalize_ai_file_name(file_name)
        if cleaned_name:
            normalized['iocs']['file_names'].append(cleaned_name)

    process_iocs = extraction.get('process_iocs', {})
    for cmd in process_iocs.get('commands', []):
        if isinstance(cmd, dict):
            normalized['iocs']['commands'].append({
                'value': cmd.get('full_command', ''),
                'executable': cmd.get('executable', ''),
                'context': cmd.get('context', ''),
                'parent': cmd.get('parent_process', ''),
                'user': cmd.get('user', ''),
                'pid': cmd.get('pid', ''),
            })
        else:
            normalized['iocs']['commands'].append({'value': cmd})

    for service in process_iocs.get('services', []):
        if isinstance(service, dict):
            normalized['iocs']['services'].append(service)
        else:
            normalized['iocs']['services'].append({'name': service})

    for task in process_iocs.get('scheduled_tasks', []):
        if isinstance(task, dict):
            normalized['iocs']['scheduled_tasks'].append(task)
        else:
            normalized['iocs']['scheduled_tasks'].append({'name': task})

    persistence = extraction.get('persistence_iocs', {})
    for reg in persistence.get('registry', []):
        if isinstance(reg, dict):
            normalized['iocs']['registry_keys'].append({
                'value': reg.get('key', ''),
                'value_name': reg.get('value_name', ''),
                'value_data': reg.get('value_data', ''),
                'action': reg.get('action', 'unknown'),
                'context': reg.get('context', ''),
            })

    for cred_theft in persistence.get('credential_theft_indicators', []):
        if isinstance(cred_theft, dict):
            normalized['iocs']['registry_keys'].append({
                'value': cred_theft.get('registry_key', ''),
                'value_name': cred_theft.get('value', ''),
                'value_data': cred_theft.get('data', ''),
                'context': f"Credential theft: {cred_theft.get('context', '')}",
            })

    auth = extraction.get('authentication_iocs', {})
    if _report_supports_compromised_users(report_text):
        for user in auth.get('compromised_users', []):
            cleaned_user = _normalize_ai_user_item(user, context='Compromised user in report')
            if cleaned_user:
                normalized['iocs']['users'].append(cleaned_user)

    for user in auth.get('created_users', []):
        if isinstance(user, dict):
            cleaned_user = _normalize_ai_user_item(user, context='Attacker-created account')
            if cleaned_user:
                normalized['iocs']['users'].append(cleaned_user)
            if user.get('password'):
                normalized['iocs']['credentials'].append({
                    'type': 'password',
                    'username': user.get('username', ''),
                    'value': user.get('password', ''),
                    'context': 'Attacker-created account password',
                })

    for cred in auth.get('passwords_observed', []):
        if isinstance(cred, dict):
            normalized['iocs']['credentials'].append({
                'type': 'password',
                'username': cred.get('username', ''),
                'value': cred.get('password', ''),
                'context': cred.get('context', ''),
            })

    vuln = extraction.get('vulnerability_iocs', {})
    for cve in vuln.get('cves', []):
        normalized['iocs']['cves'].append(cve)

    for webshell in vuln.get('webshells', []):
        if isinstance(webshell, dict):
            normalized['iocs']['file_paths'].append({
                'value': webshell.get('path', ''),
                'context': f"Web shell: {webshell.get('context', '')}",
                'action': 'malicious',
            })

    legacy_iocs = extraction.get('iocs', {})
    if legacy_iocs:
        for key in normalized['iocs'].keys():
            if key in legacy_iocs and legacy_iocs[key]:
                normalized['iocs'][key].extend(legacy_iocs[key])

    threat = extraction.get('threat_intel', {})
    for name in threat.get('threat_names', []):
        normalized['iocs']['threat_names'].append(name)

    for host in extraction.get('affected_hosts', []):
        normalized['iocs']['hostnames'].append(host)
    summary = extraction.get('extraction_summary', {})
    for host in summary.get('affected_hosts', []):
        normalized['iocs']['hostnames'].append(host)

    normalized['extraction_summary'] = summary if summary else {}
    if extraction.get('affected_hosts'):
        normalized['extraction_summary']['affected_hosts'] = extraction['affected_hosts']
    if extraction.get('affected_users'):
        normalized['extraction_summary']['affected_users'] = extraction['affected_users']

    normalized = _apply_ai_command_anchoring(normalized, report_text)
    return _apply_ai_guardrails(normalized, report_text)
