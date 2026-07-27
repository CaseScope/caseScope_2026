"""Phase 8: the configured evidence window must be able to mean something.

evaluate_pattern spanned every anchor in a correlation key plus half a window
at each end, so a key whose anchors are three days apart was evaluated over
three days no matter what time_window_minutes said. PATTERN_WINDOW_STRICT pins
the window to the representative anchor instead.
"""

import unittest
from datetime import datetime
from unittest import mock

from utils.deterministic_evidence_engine import DeterministicEvidenceEngine


def engine():
    return DeterministicEvidenceEngine.__new__(DeterministicEvidenceEngine)


def anchor(timestamp):
    return {'timestamp_utc': timestamp, 'username': 'jsmith', 'source_host': 'WKS01'}


THREE_DAY_SPREAD = [
    anchor('2026-04-20T00:00:00'),
    anchor('2026-04-21T12:00:00'),
    anchor('2026-04-23T00:00:00'),
]


class PermissiveWindowTests(unittest.TestCase):
    """Default behaviour is unchanged until the flag is turned on."""

    def test_window_spans_every_anchor_plus_half_a_window(self):
        with mock.patch.object(
            DeterministicEvidenceEngine, '_window_strict_enabled', staticmethod(lambda: False)
        ):
            start, end = engine()._resolve_key_window(
                THREE_DAY_SPREAD, THREE_DAY_SPREAD[0], 30
            )

        self.assertEqual(start, datetime(2026, 4, 19, 23, 45))
        self.assertEqual(end, datetime(2026, 4, 23, 0, 15))
        self.assertGreater((end - start).total_seconds() / 60, 30)

    def test_single_anchor_key_already_honours_the_window(self):
        single = [anchor('2026-04-20T12:00:00')]
        with mock.patch.object(
            DeterministicEvidenceEngine, '_window_strict_enabled', staticmethod(lambda: False)
        ):
            start, end = engine()._resolve_key_window(single, single[0], 30)

        self.assertEqual((end - start).total_seconds() / 60, 30)


class StrictWindowTests(unittest.TestCase):
    def test_window_is_pinned_to_the_configured_length(self):
        with mock.patch.object(
            DeterministicEvidenceEngine, '_window_strict_enabled', staticmethod(lambda: True)
        ):
            start, end = engine()._resolve_key_window(
                THREE_DAY_SPREAD, THREE_DAY_SPREAD[0], 30
            )

        self.assertEqual((end - start).total_seconds() / 60, 30)

    def test_window_is_centred_on_the_representative_anchor(self):
        with mock.patch.object(
            DeterministicEvidenceEngine, '_window_strict_enabled', staticmethod(lambda: True)
        ):
            start, end = engine()._resolve_key_window(
                THREE_DAY_SPREAD, THREE_DAY_SPREAD[1], 60
            )

        self.assertEqual(start, datetime(2026, 4, 21, 11, 30))
        self.assertEqual(end, datetime(2026, 4, 21, 12, 30))

    def test_every_configured_window_length_is_respected(self):
        for minutes in (15, 30, 60, 120):
            with self.subTest(minutes=minutes):
                with mock.patch.object(
                    DeterministicEvidenceEngine,
                    '_window_strict_enabled',
                    staticmethod(lambda: True),
                ):
                    start, end = engine()._resolve_key_window(
                        THREE_DAY_SPREAD, THREE_DAY_SPREAD[0], minutes
                    )
                self.assertEqual((end - start).total_seconds() / 60, minutes)


class UnparseableTimestampTests(unittest.TestCase):
    def test_falls_back_to_the_representative_anchor(self):
        bad = [{'timestamp_utc': 'not-a-time'}, {'timestamp_utc': ''}]
        for strict in (True, False):
            with self.subTest(strict=strict):
                with mock.patch.object(
                    DeterministicEvidenceEngine,
                    '_window_strict_enabled',
                    staticmethod(lambda: strict),
                ):
                    start, end = engine()._resolve_key_window(bad, anchor('2026-04-20T12:00:00'), 30)
                self.assertEqual((end - start).total_seconds() / 60, 30)


class FlagPlumbingTests(unittest.TestCase):
    def test_flag_defaults_to_off(self):
        from config import Config

        self.assertFalse(getattr(Config, 'PATTERN_WINDOW_STRICT'))

    def test_flag_reads_the_config_value(self):
        import config

        with mock.patch.object(config.Config, 'PATTERN_WINDOW_STRICT', True, create=True):
            self.assertTrue(DeterministicEvidenceEngine._window_strict_enabled())
        with mock.patch.object(config.Config, 'PATTERN_WINDOW_STRICT', False, create=True):
            self.assertFalse(DeterministicEvidenceEngine._window_strict_enabled())


if __name__ == '__main__':
    unittest.main()
