import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret")

REPO_ROOT = Path(__file__).resolve().parents[1]
UTILS_DIR = REPO_ROOT / "utils"


def _load_module(name: str, relative_path: str):
    module_path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


utils_pkg = sys.modules.setdefault("utils", types.ModuleType("utils"))
utils_pkg.__path__ = [str(UTILS_DIR)]

event_noise_state_stub = types.ModuleType("utils.event_noise_state")
event_noise_state_stub.build_effective_not_noise_clause = lambda *a, **k: "NOT (noise_matched = true)"
event_noise_state_stub.ensure_event_noise_state_tables = lambda *a, **k: None
event_noise_state_stub.replace_legacy_noise_filter = lambda query, *a, **k: query
sys.modules["utils.event_noise_state"] = event_noise_state_stub

pattern_check_definitions = _load_module(
    "scoring22_pattern_check_definitions",
    Path("utils") / "pattern_check_definitions.py",
)
deterministic_evidence_engine = _load_module(
    "scoring22_deterministic_evidence_engine",
    Path("utils") / "deterministic_evidence_engine.py",
)
pattern_event_mappings = _load_module(
    "scoring22_pattern_event_mappings",
    Path("utils") / "pattern_event_mappings.py",
)

CheckDefinition = pattern_check_definitions.CheckDefinition
CheckResult = pattern_check_definitions.CheckResult
CoverageAssessment = pattern_check_definitions.CoverageAssessment
PATTERN_CHECKS = pattern_check_definitions.PATTERN_CHECKS
PATTERN_EVENT_MAPPINGS = pattern_event_mappings.PATTERN_EVENT_MAPPINGS


def _defs(*specs):
    return [
        CheckDefinition(
            id=cid,
            name=cid.replace("_", " ").title(),
            weight=weight,
            check_type="anchor_match" if role == "anchor" else "field_match",
            role=role,
            coverage_policy=policy,
        )
        for cid, weight, role, policy in specs
    ]


def _result(cid, status, weight):
    return CheckResult(
        check_id=cid,
        status=status,
        weight=weight,
        contribution=weight if status == "PASS" else 0,
        detail=f"{cid} {status}",
        source="anchor_match" if cid == "anchor" else "field_match",
    )


class Scoring22NormalizationTestCase(unittest.TestCase):
    def setUp(self):
        self.engine = object.__new__(deterministic_evidence_engine.DeterministicEvidenceEngine)
        self.engine.case_id = 42
        self.config = {
            "scoring_version": "2.2",
            "anchor_class": "definitive",
            "emit_score_threshold": 50,
        }

    def _score(self, check_defs, checks, *, config=None, anchor=None):
        return self.engine._compute_scoring(
            pattern_id="fixture",
            pattern_name="Fixture",
            pattern_config=config or self.config,
            scoring_version="2.2",
            check_defs=check_defs,
            checks=checks,
            bursts=[],
            sequences=[],
            coverage=CoverageAssessment(host="HOST-A", coverage_status="full"),
            anchor=anchor,
        )

    def test_score_is_percentage_of_evaluable_weight(self):
        """60 of 120 evaluable points scores 50, not 60."""
        check_defs = _defs(
            ("anchor", 40, "anchor", "include"),
            ("corrob_a", 20, "corroboration", "include"),
            ("corrob_b", 30, "corroboration", "include"),
            ("corrob_c", 30, "corroboration", "include"),
        )
        checks = [
            _result("anchor", "PASS", 40),
            _result("corrob_a", "PASS", 20),
            _result("corrob_b", "FAIL", 30),
            _result("corrob_c", "FAIL", 30),
        ]
        scoring = self._score(check_defs, checks)

        self.assertEqual(scoring["score_normalization"]["raw_score"], 60.0)
        self.assertEqual(scoring["score_normalization"]["raw_evaluable_weight"], 120.0)
        self.assertEqual(scoring["score"], 50.0)
        self.assertEqual(scoring["max_possible"], 100.0)

    def test_heavy_pattern_no_longer_scores_above_100(self):
        """A 145-point budget used to clamp; now it reports a real percentage."""
        check_defs = _defs(*[
            (f"c{i}", 29, "anchor" if i == 0 else "corroboration", "include")
            for i in range(5)
        ])
        checks = [_result(f"c{i}", "PASS", 29) for i in range(5)]
        scoring = self._score(check_defs, checks)

        self.assertEqual(scoring["score_normalization"]["raw_score"], 145.0)
        self.assertEqual(scoring["score"], 100.0)

    def test_equal_evidence_fraction_scores_equally_across_weight_budgets(self):
        """The calibration fix: same fraction passed means same score."""
        light = self._score(
            _defs(("anchor", 30, "anchor", "include"), ("corrob_a", 30, "corroboration", "include")),
            [_result("anchor", "PASS", 30), _result("corrob_a", "FAIL", 30)],
        )
        heavy = self._score(
            _defs(
                ("anchor", 70, "anchor", "include"),
                ("corrob_a", 40, "corroboration", "include"),
                ("corrob_b", 30, "corroboration", "include"),
            ),
            [
                _result("anchor", "PASS", 70),
                _result("corrob_a", "FAIL", 40),
                _result("corrob_b", "FAIL", 30),
            ],
        )
        self.assertEqual(light["score"], 50.0)
        self.assertEqual(heavy["score"], 50.0)

    def test_score_reasons_still_sum_to_the_score(self):
        check_defs = _defs(
            ("anchor", 40, "anchor", "include"),
            ("corrob_a", 20, "corroboration", "include"),
            ("corrob_b", 40, "corroboration", "include"),
        )
        checks = [
            _result("anchor", "PASS", 40),
            _result("corrob_a", "PASS", 20),
            _result("corrob_b", "FAIL", 40),
        ]
        scoring = self._score(check_defs, checks)

        summed = sum(float(r["delta"]) for r in scoring["score_reasons"])
        self.assertAlmostEqual(summed, scoring["score"], places=0)

    def test_thin_evidence_base_is_blocked_even_at_high_percentage(self):
        """One passing check out of a mostly-unevaluable pattern must not emit."""
        check_defs = _defs(
            ("anchor", 20, "anchor", "include"),
            ("corrob_a", 40, "corroboration", "exclude"),
            ("corrob_b", 40, "corroboration", "exclude"),
        )
        checks = [
            _result("anchor", "PASS", 20),
            _result("corrob_a", "INCONCLUSIVE", 40),
            _result("corrob_b", "INCONCLUSIVE", 40),
        ]
        scoring = self._score(check_defs, checks)

        self.assertEqual(scoring["score"], 100.0)
        self.assertEqual(scoring["score_normalization"]["evaluable_fraction"], 0.2)
        self.assertIn("insufficient_evaluable_weight", scoring["emit_block_reasons"])
        self.assertFalse(scoring["eligible_to_emit"])

    def test_adequate_coverage_clears_the_floor(self):
        check_defs = _defs(
            ("anchor", 40, "anchor", "include"),
            ("corrob_a", 30, "corroboration", "include"),
            ("corrob_b", 30, "corroboration", "exclude"),
        )
        checks = [
            _result("anchor", "PASS", 40),
            _result("corrob_a", "PASS", 30),
            _result("corrob_b", "INCONCLUSIVE", 30),
        ]
        scoring = self._score(check_defs, checks)

        self.assertEqual(scoring["score_normalization"]["evaluable_fraction"], 0.7)
        self.assertNotIn("insufficient_evaluable_weight", scoring["emit_block_reasons"])
        self.assertTrue(scoring["eligible_to_emit"])

    def test_threshold_is_read_as_a_percentage(self):
        check_defs = _defs(
            ("anchor", 40, "anchor", "include"),
            ("corrob_a", 60, "corroboration", "include"),
        )
        checks = [_result("anchor", "PASS", 40), _result("corrob_a", "FAIL", 60)]

        scoring = self._score(check_defs, checks)
        self.assertEqual(scoring["score"], 40.0)
        self.assertIn("score_below_emit_threshold", scoring["emit_block_reasons"])

        lenient = dict(self.config, emit_score_threshold=35)
        scoring = self._score(check_defs, checks, config=lenient)
        self.assertNotIn("score_below_emit_threshold", scoring["emit_block_reasons"])

    def test_noise_reduction_applies_after_normalization(self):
        check_defs = _defs(
            ("anchor", 50, "anchor", "include"),
            ("corrob_a", 50, "corroboration", "include"),
        )
        checks = [_result("anchor", "PASS", 50), _result("corrob_a", "PASS", 50)]

        clean = self._score(check_defs, checks)
        noisy = self._score(check_defs, checks, anchor={"noise_matched": True})

        self.assertEqual(clean["score"], 100.0)
        self.assertEqual(noisy["score"], 85.0)
        self.assertEqual(noisy["score_components"]["noise_reduction"], -15.0)

    def test_engine_level_noise_pass_does_not_double_apply(self):
        engine_module = deterministic_evidence_engine
        source = Path(engine_module.__file__).read_text()
        self.assertIn("effective_scoring_version not in ('2.1', '2.2')", source)

    def test_unclamped_helpers_do_not_leak_into_other_versions(self):
        for version in ("1.0", "2.0", "2.1"):
            with self.subTest(version=version):
                scoring = self.engine._compute_scoring(
                    pattern_id="fixture",
                    pattern_name="Fixture",
                    pattern_config={"scoring_version": version, "anchor_class": "definitive"},
                    scoring_version=version,
                    check_defs=_defs(("anchor", 40, "anchor", "include")),
                    checks=[_result("anchor", "PASS", 40)],
                    bursts=[],
                    sequences=[],
                    coverage=CoverageAssessment(host="HOST-A", coverage_status="full"),
                )
                self.assertNotIn("unclamped_score", scoring)
                self.assertNotIn("unclamped_evaluable_weight", scoring)
                self.assertNotIn("unclamped_raw_total_weight", scoring)


class Scoring22PatternMigrationTestCase(unittest.TestCase):
    def test_migrated_patterns_declare_2_2(self):
        migrated = {
            pid
            for pid, cfg in PATTERN_EVENT_MAPPINGS.items()
            if str(cfg.get("scoring_version") or "1.0") == "2.2"
        }
        self.assertEqual(len(migrated), 9)
        self.assertIn("pass_the_ticket", migrated)
        self.assertIn("lsass_memory_dump", migrated)

    def test_no_pattern_is_left_on_2_1(self):
        stale = [
            pid
            for pid, cfg in PATTERN_EVENT_MAPPINGS.items()
            if str(cfg.get("scoring_version") or "1.0") == "2.1"
        ]
        self.assertEqual(stale, [])

    def test_migrated_thresholds_are_valid_percentages(self):
        for pid, cfg in PATTERN_EVENT_MAPPINGS.items():
            if str(cfg.get("scoring_version") or "1.0") != "2.2":
                continue
            with self.subTest(pattern=pid):
                threshold = float(cfg.get("emit_score_threshold", 50) or 50)
                self.assertGreater(threshold, 0.0)
                self.assertLessEqual(threshold, 100.0)

    def test_emit_bar_is_now_uniform_in_meaning(self):
        """Before 2.2 the bar ranged from 34.5% to 83.3% of a pattern's own weight."""
        bars = []
        for pid, cfg in PATTERN_EVENT_MAPPINGS.items():
            if str(cfg.get("scoring_version") or "1.0") != "2.2":
                continue
            bars.append(float(cfg.get("emit_score_threshold", 50) or 50))
        self.assertTrue(bars)
        self.assertLessEqual(max(bars) - min(bars), 10.0)


if __name__ == "__main__":
    unittest.main()
