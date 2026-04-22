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
    def _load_opencti_context_module(self):
        fake_models = types.ModuleType('models')
        fake_models.__path__ = []
        fake_database = types.ModuleType('models.database')
        fake_database.db = types.SimpleNamespace(session=types.SimpleNamespace(commit=lambda: None))
        fake_behavioral_profiles = types.ModuleType('models.behavioral_profiles')
        fake_behavioral_profiles.OpenCTICache = type(
            'OpenCTICache',
            (),
            {
                'query': types.SimpleNamespace(
                    filter_by=lambda **_kwargs: types.SimpleNamespace(
                        filter=lambda *_args, **_kwargs: types.SimpleNamespace(first=lambda: None),
                        delete=lambda: None,
                    )
                )
            },
        )
        fake_config = types.ModuleType('config')
        fake_config.Config = type('Config', (), {'OPENCTI_CACHE_TTL_HOURS': 24})

        stubbed_modules = {
            'models': fake_models,
            'models.database': fake_database,
            'models.behavioral_profiles': fake_behavioral_profiles,
            'config': fake_config,
        }
        previous_modules = {name: sys.modules.get(name) for name in stubbed_modules}
        for name, module in stubbed_modules.items():
            sys.modules[name] = module

        try:
            module = _load_module(
                'phase0_opencti_context',
                os.path.join('utils', 'opencti_context.py'),
            )
        finally:
            for name, previous in previous_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

        return module

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

    def test_shared_premium_gate_helpers_route_to_central_checks(self):
        with patch.object(FeatureAvailability, 'is_threat_intel_enabled', return_value=True):
            self.assertTrue(FeatureAvailability.is_chat_tool_feature_enabled('lookup_threat_intel'))
            self.assertTrue(FeatureAvailability.is_ioc_threat_intel_enrichment_enabled())
            self.assertTrue(FeatureAvailability.is_chat_tool_feature_enabled('count_events'))

        with patch.object(FeatureAvailability, 'is_opencti_enabled', return_value=False):
            self.assertFalse(FeatureAvailability.is_opencti_context_enabled())

    def test_opencti_context_provider_uses_shared_opencti_context_gate(self):
        opencti_context = self._load_opencti_context_module()
        provider = opencti_context.OpenCTIContextProvider(case_id=9, analysis_id='analysis-9')
        provider._get_client = lambda: self.fail('shared availability gate should short-circuit first')

        fake_feature_availability = types.ModuleType('utils.feature_availability')
        fake_feature_availability.FeatureAvailability = types.SimpleNamespace(
            is_opencti_context_enabled=lambda: False
        )

        previous_feature_module = sys.modules.get('utils.feature_availability')
        sys.modules['utils.feature_availability'] = fake_feature_availability
        try:
            self.assertFalse(provider.is_available())
            self.assertFalse(provider._available)
        finally:
            if previous_feature_module is None:
                sys.modules.pop('utils.feature_availability', None)
            else:
                sys.modules['utils.feature_availability'] = previous_feature_module


if __name__ == '__main__':
    unittest.main()
