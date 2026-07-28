"""Equivalence and cost tests for the trie-compiled alias matcher.

The matcher is the CUI control's substitution engine, so replacing its flat
alternation with a prefix trie is only safe if the two produce identical
matches. These tests compile both forms over the same values and compare them
against generated text, including the adversarial cases: one alias that
prefixes another, values differing only in case, and values carrying regex
metacharacters.
"""

import importlib.util
import os
import random
import re
import sys
import time
import types
import unittest


os.environ.setdefault("SECRET_KEY", "test-secret")


def _load_privacy_aliases():
    fake_models = types.ModuleType("models")
    fake_models.__path__ = []
    fake_database = types.ModuleType("models.database")
    fake_database.db = types.SimpleNamespace()
    fake_privacy_alias = types.ModuleType("models.privacy_alias")
    fake_privacy_alias.PrivacyAlias = type("PrivacyAlias", (), {})
    fake_privacy_alias.PrivacyAliasCounter = type("PrivacyAliasCounter", (), {})

    previous = {
        name: sys.modules.get(name)
        for name in ("models", "models.database", "models.privacy_alias")
    }
    sys.modules["models"] = fake_models
    sys.modules["models.database"] = fake_database
    sys.modules["models.privacy_alias"] = fake_privacy_alias
    try:
        spec = importlib.util.spec_from_file_location(
            "privacy_aliases_matcher_test", "/opt/casescope/utils/privacy_aliases.py"
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules["privacy_aliases_matcher_test"] = module
        spec.loader.exec_module(module)
        return module
    finally:
        for name, prior in previous.items():
            if prior is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prior


PRIVACY = _load_privacy_aliases()


def _flat_pattern(originals):
    """The previous implementation: one length-sorted flat alternation."""
    ordered = sorted(originals, key=len, reverse=True)
    return re.compile(
        PRIVACY.ALIAS_LEADING_GUARD
        + "(?:"
        + "|".join(re.escape(original) for original in ordered)
        + ")"
        + PRIVACY.ALIAS_TRAILING_GUARD,
        re.IGNORECASE,
    )


def _trie_pattern(originals):
    return re.compile(
        PRIVACY.ALIAS_LEADING_GUARD
        + PRIVACY._alias_trie_pattern(originals)
        + PRIVACY.ALIAS_TRAILING_GUARD,
        re.IGNORECASE,
    )


class AliasMatcherEquivalenceTestCase(unittest.TestCase):
    def _assert_same_matches(self, originals, text):
        flat = [(m.start(), m.group(0)) for m in _flat_pattern(originals).finditer(text)]
        trie = [(m.start(), m.group(0)) for m in _trie_pattern(originals).finditer(text)]
        self.assertEqual(flat, trie, f"diverged on {text!r}")

    def test_longer_alias_still_wins_over_a_shorter_prefix(self):
        originals = ["corp", "corp.example", "corp.example.com", "corpsvc"]
        for text in (
            "logon to corp.example.com succeeded",
            "logon to corp.example succeeded",
            "domain corp only",
            "account corpsvc ran",
        ):
            with self.subTest(text=text):
                self._assert_same_matches(originals, text)

    def test_regex_metacharacters_in_values_are_literal(self):
        originals = [
            r"c:\users\a.smith\appdata",
            r"\\fileserv\share$",
            "host+one",
            "a(b)c",
            "dot.star*value",
            "brack[et]s",
        ]
        text = (
            r"opened c:\users\a.smith\appdata then \\fileserv\share$ "
            "from host+one about a(b)c and dot.star*value and brack[et]s"
        )
        self._assert_same_matches(originals, text)

    def test_case_insensitive_matching_is_unchanged(self):
        originals = ["acmecorp", "wkstn-07"]
        for text in (
            "ACMECORP and WKSTN-07",
            "AcmeCorp and wkstn-07",
            "acmecorp and Wkstn-07",
        ):
            with self.subTest(text=text):
                self._assert_same_matches(originals, text)

    def test_boundary_guards_behave_identically(self):
        originals = ["corp", "host01"]
        for text in (
            "corp",
            "corp.",
            "corp.example.com",
            "xcorp",
            "corpx",
            "corp-x",
            "corp_x",
            "(corp)",
            "host01$",
            "myhost01",
            "host01.corp",
        ):
            with self.subTest(text=text):
                self._assert_same_matches(originals, text)

    def test_randomized_corpus_agrees_with_the_flat_alternation(self):
        rng = random.Random(20260728)
        alphabet = "abcdeXY0123.-_$\\"
        originals = sorted({
            "".join(rng.choice(alphabet) for _ in range(rng.randint(3, 12)))
            for _ in range(400)
        })

        for _ in range(200):
            words = []
            for _ in range(rng.randint(1, 12)):
                if rng.random() < 0.5:
                    words.append(rng.choice(originals))
                else:
                    words.append(
                        "".join(rng.choice(alphabet + " ") for _ in range(rng.randint(1, 10)))
                    )
            text = " ".join(words)
            self._assert_same_matches(originals, text)

    def test_substitution_still_replaces_every_vault_value(self):
        rows = [
            types.SimpleNamespace(
                original_value="acmecorp",
                alias_value="DOMAIN_0007",
                entity_type="DOMAIN",
                sensitivity_classification=None,
            ),
            types.SimpleNamespace(
                original_value="wkstn-07.acmecorp.local",
                alias_value="FQDN_0011",
                entity_type="FQDN",
                sensitivity_classification=None,
            ),
        ]

        text = "wkstn-07.acmecorp.local joined acmecorp"
        replaced, count, categories = PRIVACY._replace_aliases_in_text(text, rows)

        self.assertEqual(replaced, "FQDN_0011 joined DOMAIN_0007")
        self.assertEqual(count, 2)
        self.assertEqual(categories, {"DOMAIN", "FQDN"})


class AliasMatcherCostTestCase(unittest.TestCase):
    def test_scanning_cost_does_not_scale_with_vault_size(self):
        """A larger vault must not make an unrelated scan proportionally slower.

        The flat alternation tried every value at every offset, so a chat turn
        against a large case spent seconds per provider call aliasing text.
        """
        rng = random.Random(7)

        def corpus(size):
            return sorted({
                "host-%d-%s" % (index, "".join(rng.choice("abcdef0123") for _ in range(6)))
                for index in range(size)
            })

        text = ("the analyst reviewed the timeline and found nothing of note. " * 40)

        small = _trie_pattern(corpus(500))
        large = _trie_pattern(corpus(40000))

        def scan_seconds(pattern):
            start = time.perf_counter()
            for _ in range(20):
                pattern.findall(text)
            return time.perf_counter() - start

        small_seconds = scan_seconds(small)
        large_seconds = scan_seconds(large)

        self.assertLess(
            large_seconds,
            max(small_seconds * 6, 0.75),
            "an 80x larger vault should not scale the scan cost with it",
        )


if __name__ == "__main__":
    unittest.main()
