import os
import sys
import types
import unittest
import importlib.util
from unittest.mock import patch

os.environ.setdefault('SECRET_KEY', 'test-secret')

REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


def _load_module(name: str, relative_path: str):
    module_path = os.path.join(REPO_ROOT, relative_path)
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


feature_availability_module = _load_module(
    'phase0_feature_availability',
    os.path.join('utils', 'feature_availability.py'),
)
misp_module = _load_module(
    'phase0_misp',
    os.path.join('utils', 'misp.py'),
)
FeatureAvailability = feature_availability_module.FeatureAvailability


class _PingClient:
    def ping(self):
        return True


class Phase0FeatureGatingTestCase(unittest.TestCase):
    def tearDown(self):
        FeatureAvailability.clear_cache()

    def test_opencti_enabled_checks_settings_and_connectivity(self):
        fake_settings_module = types.ModuleType('models.system_settings')

        class SettingKeys:
            OPENCTI_ENABLED = 'opencti_enabled'

        class SystemSettings:
            @staticmethod
            def get(key, default=None):
                if key == SettingKeys.OPENCTI_ENABLED:
                    return True
                return default

        fake_settings_module.SettingKeys = SettingKeys
        fake_settings_module.SystemSettings = SystemSettings

        fake_opencti_module = types.ModuleType('utils.opencti')
        fake_opencti_module.get_opencti_client = lambda: _PingClient()

        with patch.dict(
            sys.modules,
            {
                'models.system_settings': fake_settings_module,
                'utils.opencti': fake_opencti_module,
            },
        ):
            with patch.object(FeatureAvailability, 'is_activated', return_value=True):
                with patch.object(FeatureAvailability, '_opencti_check_time', None):
                    with patch.object(FeatureAvailability, '_opencti_available', None):
                        with patch.object(FeatureAvailability, '_misp_check_time', None):
                            with patch.object(FeatureAvailability, '_misp_available', None):
                                with patch.object(
                                    feature_availability_module.Config,
                                    'OPENCTI_ENABLED',
                                    True,
                                    create=True,
                                ):
                                    self.assertTrue(FeatureAvailability.is_opencti_enabled())
                                    self.assertTrue(FeatureAvailability.is_threat_intel_enabled())

    def test_get_misp_client_requires_threat_intel_license(self):
        fake_settings_module = types.ModuleType('models.system_settings')

        class SettingKeys:
            MISP_ENABLED = 'misp_enabled'
            MISP_URL = 'misp_url'
            MISP_SSL_VERIFY = 'misp_ssl_verify'

        class SystemSettings:
            @staticmethod
            def get(key, default=None):
                values = {
                    SettingKeys.MISP_ENABLED: True,
                    SettingKeys.MISP_URL: 'https://misp.test',
                    SettingKeys.MISP_SSL_VERIFY: False,
                }
                return values.get(key, default)

        fake_settings_module.SettingKeys = SettingKeys
        fake_settings_module.SystemSettings = SystemSettings
        fake_settings_module.get_misp_api_key = lambda log_errors=False: 'secret'

        fake_license_module = types.ModuleType('utils.licensing.license_manager')

        class LicenseManager:
            @staticmethod
            def is_feature_activated(feature):
                return False

        fake_license_module.LicenseManager = LicenseManager

        with patch.dict(
            sys.modules,
            {
                'models.system_settings': fake_settings_module,
                'utils.licensing.license_manager': fake_license_module,
            },
        ):
            with patch.object(misp_module.Config, 'MISP_ENABLED', True, create=True):
                self.assertIsNone(misp_module.get_misp_client())


if __name__ == '__main__':
    unittest.main()
