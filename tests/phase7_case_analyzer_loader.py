import importlib.util
import os
import sys
import types


BASE_DIR = os.path.dirname(os.path.dirname(__file__))


def _load_module(module_name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(
        module_name,
        os.path.join(BASE_DIR, relative_path),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def load_case_analyzer_with_stubs(module_name: str):
    fake_models = types.ModuleType("models")
    fake_models.__path__ = []

    fake_database = types.ModuleType("models.database")
    fake_database.db = types.SimpleNamespace(session=types.SimpleNamespace(commit=lambda: None))

    fake_behavioral_profiles = types.ModuleType("models.behavioral_profiles")
    fake_behavioral_profiles.CaseAnalysisRun = type("CaseAnalysisRun", (), {})
    fake_behavioral_profiles.AnalysisMode = types.SimpleNamespace()
    fake_behavioral_profiles.AnalysisStatus = types.SimpleNamespace(
        COMPLETE="complete",
        PARTIAL="partial",
        FAILED="failed",
    )
    fake_behavioral_profiles.UserBehaviorProfile = types.SimpleNamespace(query=None)
    fake_behavioral_profiles.SystemBehaviorProfile = types.SimpleNamespace(query=None)
    fake_behavioral_profiles.PeerGroup = types.SimpleNamespace(query=None)
    fake_behavioral_profiles.GapDetectionFinding = type("GapDetectionFinding", (), {})
    fake_behavioral_profiles.SuggestedAction = type("SuggestedAction", (), {})

    fake_case = types.ModuleType("models.case")
    fake_case.Case = type(
        "Case",
        (),
        {
            "query": types.SimpleNamespace(
                get=lambda _case_id: types.SimpleNamespace(timezone="UTC")
            )
        },
    )

    fake_config = types.ModuleType("config")
    fake_config.Config = type("Config", (), {})

    fake_case_finalize = types.ModuleType("pipeline.case_finalize")
    fake_case_finalize.finalize_case_analysis_run = lambda *args, **kwargs: True

    fake_celery = types.ModuleType("celery")
    fake_celery.__path__ = []
    # The dispatcher composes the analysis phases with a chord.
    fake_celery.chord = lambda *args, **kwargs: None
    fake_celery.group = lambda *args, **kwargs: None
    fake_celery.chain = lambda *args, **kwargs: None
    fake_celery_exceptions = types.ModuleType("celery.exceptions")
    fake_celery_exceptions.SoftTimeLimitExceeded = type(
        "SoftTimeLimitExceeded",
        (Exception,),
        {},
    )

    fake_async_cancellation = types.ModuleType("utils.async_cancellation")
    fake_async_cancellation.clear_cancellation = lambda *args, **kwargs: None
    fake_async_cancellation.is_cancellation_requested = lambda *args, **kwargs: False

    # Every utils submodule the analyzer imports has to be stubbed, because
    # utils/__init__.py imports the decorators, which need the real config.
    fake_analysis_phases = types.ModuleType("utils.analysis_phases")
    fake_analysis_phases.is_optional = lambda phase: phase in {
        "ai_triage", "ai_synthesis", "opencti_enrichment",
    }
    fake_analysis_phases.phase_progress = lambda _phase, fraction: int(fraction * 100)

    fake_analysis_progress = types.ModuleType("utils.analysis_progress")
    fake_analysis_progress.record_analysis_progress = lambda *args, **kwargs: True

    stubbed_modules = {
        "celery": fake_celery,
        "celery.exceptions": fake_celery_exceptions,
        "models": fake_models,
        "models.database": fake_database,
        "models.behavioral_profiles": fake_behavioral_profiles,
        "models.case": fake_case,
        "config": fake_config,
        "pipeline.case_finalize": fake_case_finalize,
        "utils.async_cancellation": fake_async_cancellation,
        "utils.analysis_phases": fake_analysis_phases,
        "utils.analysis_progress": fake_analysis_progress,
    }
    original_modules = {name: sys.modules.get(name) for name in stubbed_modules}

    for name, module in stubbed_modules.items():
        sys.modules[name] = module

    case_analyzer = _load_module(module_name, "utils/case_analyzer.py")

    def restore_modules():
        sys.modules.pop(module_name, None)
        for name, previous in original_modules.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous

    return case_analyzer, restore_modules
