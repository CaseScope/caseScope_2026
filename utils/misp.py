"""MISP client for settings validation and IOC enrichment."""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

from config import Config

logger = logging.getLogger(__name__)

MISP_ENRICHMENT_SCHEMA_VERSION = 1

ENRICHABLE_IOC_TYPES = {
    'IP Address (IPv4)',
    'IP Address (IPv6)',
    'Domain',
    'FQDN',
    'Hostname',
    'URL',
    'MD5 Hash',
    'SHA1 Hash',
    'SHA256 Hash',
    'Imphash',
    'Email Address',
    'X-Originating-IP',
    'Registry Key',
}


class MISPClient:
    """Helper for validating MISP connectivity and looking up IOC intelligence."""

    def __init__(self, url: str, api_key: str, ssl_verify: bool = False, timeout: int = 10):
        self.url = (url or '').strip().rstrip('/')
        self.api_key = (api_key or '').strip()
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.init_error: Optional[str] = None
        self.last_error: Optional[str] = None

        if not self.url:
            self.init_error = 'MISP URL is required'
        elif not self.api_key:
            self.init_error = 'MISP API key is required'

    def _headers(self) -> Dict[str, str]:
        return {
            'Authorization': self.api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': f'CaseScope/{getattr(Config, "VERSION", "unknown")} MISP Client',
        }

    def _request(self, method: str, path: str) -> requests.Response:
        if self.init_error:
            raise RuntimeError(self.init_error)

        response = requests.request(
            method=method,
            url=f'{self.url}{path}',
            headers=self._headers(),
            timeout=self.timeout,
            verify=self.ssl_verify,
        )
        return response

    def _request_json(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        response = self._request(method, path) if payload is None else requests.request(
            method=method,
            url=f'{self.url}{path}',
            headers=self._headers(),
            timeout=self.timeout,
            verify=self.ssl_verify,
            json=payload,
        )
        response.raise_for_status()
        return response.json() if response.content else {}

    def ping(self) -> bool:
        """Return True when the configured MISP instance is reachable and accepts the API key."""
        try:
            response = self._request('GET', '/users/view/me')
            if response.ok:
                self.last_error = None
                return True

            if response.status_code in (401, 403):
                self.last_error = 'MISP rejected the API key'
            else:
                self.last_error = f'MISP returned HTTP {response.status_code}'
            return False
        except requests.exceptions.SSLError as exc:
            self.last_error = f'SSL verification failed: {exc}'
            return False
        except requests.exceptions.RequestException as exc:
            self.last_error = str(exc)
            return False

    def get_error(self) -> str:
        return self.init_error or self.last_error or 'Unknown MISP connection error'

    def _normalize_lookup_value(self, value: str, ioc_type: str) -> str:
        normalized = (value or '').strip()
        lowercase_types = {
            'Domain', 'FQDN', 'Hostname', 'URL', 'Email Address',
            'MD5 Hash', 'SHA1 Hash', 'SHA256 Hash', 'Imphash',
            'Registry Key', 'X-Originating-IP',
        }
        if ioc_type in lowercase_types:
            normalized = normalized.lower()
        return normalized

    def _resolve_ioc_type(self, value: str, ioc_type: str) -> str:
        try:
            from models.ioc import detect_ioc_type_from_value
            detected = detect_ioc_type_from_value(value or '')
            if ioc_type in ('Unknown', 'Text', None, '') and detected:
                return detected
        except Exception:
            pass
        return ioc_type or 'Unknown'

    def _is_enrichable_type(self, ioc_type: str) -> bool:
        return ioc_type in ENRICHABLE_IOC_TYPES

    def _map_ioc_type_to_misp_types(self, ioc_type: str) -> List[str]:
        return {
            'IP Address (IPv4)': ['ip-src', 'ip-dst'],
            'IP Address (IPv6)': ['ip-src', 'ip-dst'],
            'X-Originating-IP': ['ip-src', 'ip-dst'],
            'Domain': ['domain'],
            'FQDN': ['domain', 'hostname'],
            'Hostname': ['hostname', 'domain'],
            'URL': ['url'],
            'MD5 Hash': ['md5'],
            'SHA1 Hash': ['sha1'],
            'SHA256 Hash': ['sha256'],
            'Imphash': ['imphash'],
            'Email Address': ['email-src', 'email-dst'],
            'Registry Key': ['regkey'],
        }.get(ioc_type, [])

    def _build_base_result(
        self,
        value: str,
        requested_type: str,
        resolved_type: str,
        status: str,
        message: str = '',
    ) -> Dict[str, Any]:
        return {
            'provider': 'misp',
            'provider_label': 'MISP',
            'found': False,
            'status': status,
            'message': message,
            'schema_version': MISP_ENRICHMENT_SCHEMA_VERSION,
            'lookup_value': value,
            'lookup_type': requested_type or resolved_type or 'Unknown',
            'resolved_ioc_type': resolved_type or requested_type or 'Unknown',
            'checked_at': datetime.utcnow().isoformat(),
            'available_connectors': [],
            'connector_count': 0,
            'match_source': 'misp_exact',
            'labels': [],
            'threat_actors': [],
            'campaigns': [],
            'malware_families': [],
            'external_references': [],
        }

    def _extract_attributes(self, payload: Any) -> List[Dict[str, Any]]:
        if isinstance(payload, list):
            results = []
            for item in payload:
                results.extend(self._extract_attributes(item))
            return results

        if not isinstance(payload, dict):
            return []

        if 'response' in payload:
            return self._extract_attributes(payload['response'])

        if 'Attribute' in payload:
            attrs = payload.get('Attribute') or []
            return attrs if isinstance(attrs, list) else [attrs]

        if payload.get('value') and payload.get('type'):
            return [payload]

        results = []
        for value in payload.values():
            results.extend(self._extract_attributes(value))
        return results

    def _attribute_matches_exact(self, attribute: Dict[str, Any], normalized_value: str, misp_types: List[str]) -> bool:
        attr_type = (attribute.get('type') or '').strip().lower()
        attr_value = self._normalize_lookup_value(attribute.get('value', ''), attribute.get('type', ''))
        if misp_types and attr_type not in misp_types:
            return False
        return attr_value == normalized_value

    def _extract_tag_names(self, attribute: Dict[str, Any]) -> List[str]:
        tag_names = []
        for source in (attribute.get('Tag') or [], ((attribute.get('Event') or {}).get('Tag') or [])):
            for tag in source:
                if isinstance(tag, dict):
                    name = tag.get('name')
                    if name:
                        tag_names.append(name)
        return tag_names

    def _extract_tlp(self, tags: List[str]) -> str:
        for tag in tags:
            lowered = tag.lower()
            if 'tlp:' in lowered:
                return tag.upper()
        return 'TLP:CLEAR'

    def _extract_event_name(self, attribute: Dict[str, Any]) -> str:
        event = attribute.get('Event') or {}
        return event.get('info') or ''

    def _extract_comment(self, attribute: Dict[str, Any]) -> str:
        return attribute.get('comment') or ((attribute.get('Event') or {}).get('info') or '')

    def _extract_external_references(self, attributes: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        refs = []
        seen = set()
        for attribute in attributes:
            event = attribute.get('Event') or {}
            event_id = event.get('id')
            if event_id and event_id not in seen:
                seen.add(event_id)
                refs.append({
                    'source_name': 'MISP Event',
                    'url': f'{self.url}/events/view/{event_id}',
                    'description': event.get('info', ''),
                })
        return refs[:5]

    def _calculate_score(self, attributes: List[Dict[str, Any]]) -> int:
        unique_events = {str((attribute.get('Event') or {}).get('id') or '') for attribute in attributes if (attribute.get('Event') or {}).get('id')}
        score = min(90, max(20, len(unique_events) * 20))
        if any(attribute.get('to_ids') for attribute in attributes):
            score = min(100, score + 10)
        return score

    def _search_exact_attributes(self, normalized_value: str, misp_types: List[str]) -> List[Dict[str, Any]]:
        payload = {
            'returnFormat': 'json',
            'value': normalized_value,
            'type': misp_types,
            'includeEventTags': True,
            'includeEventUuid': True,
            'includeContext': True,
            'limit': 50,
        }
        response = self._request_json('POST', '/attributes/restSearch', payload)
        attributes = self._extract_attributes(response)
        return [
            attribute for attribute in attributes
            if self._attribute_matches_exact(attribute, normalized_value, [t.lower() for t in misp_types])
        ]

    def check_indicator(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        """Check if an IOC has exact MISP attribute matches and return normalized enrichment data."""
        if self.init_error:
            result = self._build_base_result(ioc_value, ioc_type, ioc_type or 'Unknown', 'error', 'MISP client is not available')
            result['error'] = self.init_error
            return result

        try:
            resolved_type = self._resolve_ioc_type(ioc_value, ioc_type)
            normalized_value = self._normalize_lookup_value(ioc_value, resolved_type)
            if not self._is_enrichable_type(resolved_type):
                return self._build_base_result(
                    normalized_value,
                    ioc_type,
                    resolved_type,
                    'not_applicable',
                    f'{resolved_type} is not eligible for exact MISP enrichment',
                )

            misp_types = self._map_ioc_type_to_misp_types(resolved_type)
            if not misp_types:
                return self._build_base_result(
                    normalized_value,
                    ioc_type,
                    resolved_type,
                    'not_applicable',
                    f'{resolved_type} does not have a configured MISP attribute mapping',
                )

            attributes = self._search_exact_attributes(normalized_value, misp_types)
            if not attributes:
                return self._build_base_result(
                    normalized_value,
                    ioc_type,
                    resolved_type,
                    'not_found',
                    'No exact MISP match found',
                )

            labels = sorted({name for attribute in attributes for name in self._extract_tag_names(attribute)})
            campaigns = sorted({self._extract_event_name(attribute) for attribute in attributes if self._extract_event_name(attribute)})[:10]
            descriptions = [self._extract_comment(attribute) for attribute in attributes if self._extract_comment(attribute)]

            result = self._build_base_result(normalized_value, ioc_type, resolved_type, 'found')
            result.update({
                'found': True,
                'score': self._calculate_score(attributes),
                'tlp': self._extract_tlp(labels),
                'labels': labels[:20],
                'campaigns': campaigns,
                'description': descriptions[0] if descriptions else '',
                'external_references': self._extract_external_references(attributes),
                'event_count': len({str((attribute.get('Event') or {}).get('id') or '') for attribute in attributes if (attribute.get('Event') or {}).get('id')}),
                'attribute_count': len(attributes),
                'to_ids': any(attribute.get('to_ids') for attribute in attributes),
                'matching_attribute_types': sorted({(attribute.get('type') or '') for attribute in attributes if attribute.get('type')}),
            })
            return result
        except requests.exceptions.SSLError as exc:
            result = self._build_base_result(ioc_value, ioc_type, ioc_type or 'Unknown', 'error', 'MISP lookup failed')
            result['error'] = f'SSL verification failed: {exc}'
            return result
        except requests.exceptions.RequestException as exc:
            result = self._build_base_result(ioc_value, ioc_type, ioc_type or 'Unknown', 'error', 'MISP lookup failed')
            result['error'] = str(exc)
            return result
        except Exception as exc:
            logger.error(f'[MISP] Error checking indicator {ioc_value}: {exc}')
            result = self._build_base_result(ioc_value, ioc_type, ioc_type or 'Unknown', 'error', 'MISP lookup failed')
            result['error'] = str(exc)
            return result


def get_misp_client():
    """Return a configured MISP client when the environment and settings allow it."""
    if not getattr(Config, 'MISP_ENABLED', False):
        return None

    try:
        from models.system_settings import SystemSettings, SettingKeys, get_misp_api_key

        if not SystemSettings.get(SettingKeys.MISP_ENABLED, False):
            return None

        url = SystemSettings.get(SettingKeys.MISP_URL, '')
        api_key = get_misp_api_key(log_errors=False)
        ssl_verify = SystemSettings.get(SettingKeys.MISP_SSL_VERIFY, False)
        if not url or not api_key:
            return None

        return MISPClient(url, api_key, ssl_verify)
    except Exception as exc:
        logger.warning(f'[MISP] Failed to initialize client from settings: {exc}')
        return None


def is_misp_auto_enrich_enabled() -> bool:
    """Return True when IOC auto-enrichment should run for MISP."""
    if not getattr(Config, 'MISP_ENABLED', False):
        return False

    try:
        from models.system_settings import SystemSettings, SettingKeys
        from utils.licensing.license_manager import LicenseManager

        if not LicenseManager.is_feature_activated('opencti'):
            return False

        return (
            SystemSettings.get(SettingKeys.MISP_ENABLED, False)
            and SystemSettings.get(SettingKeys.MISP_AUTO_ENRICH, False)
        )
    except Exception:
        return False


def get_misp_status_summary() -> Dict[str, Any]:
    """Return a lightweight MISP status summary for the settings page."""
    from utils.feature_availability import FeatureAvailability

    license_active = FeatureAvailability.is_activated('opencti')

    try:
        from models.system_settings import SystemSettings, SettingKeys, get_misp_api_key

        setting_enabled = SystemSettings.get(SettingKeys.MISP_ENABLED, False)
        configured = bool(
            SystemSettings.get(SettingKeys.MISP_URL, '')
            and get_misp_api_key(log_errors=False)
        )
    except Exception:
        setting_enabled = False
        configured = False

    summary = {
        'enabled': False,
        'licensed': license_active,
        'config_enabled': getattr(Config, 'MISP_ENABLED', False),
        'setting_enabled': setting_enabled,
        'configured': configured,
        'reachable': False,
        'error': None,
    }

    if not (summary['licensed'] and summary['config_enabled'] and summary['setting_enabled'] and summary['configured']):
        return summary

    client = get_misp_client()
    if not client:
        summary['error'] = 'MISP client unavailable'
        return summary

    reachable = client.ping()
    summary['reachable'] = reachable
    summary['enabled'] = reachable
    if not reachable:
        summary['error'] = client.get_error()
    return summary
