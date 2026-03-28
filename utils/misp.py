"""Minimal MISP client for admin settings validation and status checks."""

import logging
from typing import Any, Dict, Optional

import requests

from config import Config

logger = logging.getLogger(__name__)


class MISPClient:
    """Small helper for validating MISP API connectivity."""

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
