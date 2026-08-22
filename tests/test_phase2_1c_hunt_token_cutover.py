"""Phase 2.1C Hunt token-search semantic cutover tests.

Grammar matrix for ``build_hunting_search_clause``. Live ClickHouse tokenizer
replica checks run when the server is reachable. Production ERK/EXPLAIN proofs
are recorded by the 2.1C operator script, not this module.
"""
from __future__ import annotations

import inspect
import os
import unittest

os.environ.setdefault("SECRET_KEY", "phase2-1c-test-secret")

from routes.hunting_query_helpers import (
    HASANY_TOKENS_CHUNK,
    HUNT_ATOM_EXCLUSION_PRESERVE,
    HUNT_ATOM_INVALID,
    HUNT_ATOM_STRUCTURED,
    HUNT_ATOM_SUBSTRING_REQUIRED,
    HUNT_ATOM_TOKEN_SAFE,
    build_hunting_publication_bridge,
    build_hunting_search_clause,
    classify_hunt_free_text_atom,
    split_search_blob_tokens,
)


SHA256 = "22ff8911577dff70b0938a267e23f504433e710686825a5724215480d5479e04"
GUID = "F4E57C4B-2036-45F0-A9AB-443BCFE33D9F"

TOKENIZER_FIXTURES = {
    "powershell": ["powershell"],
    "PowerShell": ["PowerShell"],
    "Administrator": ["Administrator"],
    "PCLAPPVM": ["PCLAPPVM"],
    "svchost": ["svchost"],
    "cmd.exe": ["cmd", "exe"],
    "10.0.0.1": ["10", "0", "0", "1"],
    "host01": ["host01"],
    "host01.domain.local": ["host01", "domain", "local"],
    r"DOMAIN\user": ["DOMAIN", "user"],
    "user@example.com": ["user", "example", "com"],
    r"C:\Windows\System32\cmd.exe": ["C", "Windows", "System32", "cmd", "exe"],
    r"HKLM\Software\Microsoft": ["HKLM", "Software", "Microsoft"],
    "4688": ["4688"],
    "7036": ["7036"],
    "foo-bar": ["foo", "bar"],
    "foo_bar": ["foo", "bar"],
    "Windows PowerShell": ["Windows", "PowerShell"],
    SHA256: [SHA256],
    GUID: ["F4E57C4B", "2036", "45F0", "A9AB", "443BCFE33D9F"],
    "münchen": ["münchen"],
    "MÜNCHEN": ["MÜNCHEN"],
    "Straße": ["Straße"],
    "用户": ["用户"],
    "日本語": ["日本語"],
    "—": ["—"],
    "🔥": ["🔥"],
    "hosté": ["hosté"],
    "powershell🔥": ["powershell🔥"],
    "vchos": ["vchos"],
    "power*": ["power"],
}


def _clause(search):
    params = {}
    sql = build_hunting_search_clause(search, params)
    return sql, params


class TokenizerReplicaTests(unittest.TestCase):
    def test_split_by_non_alpha_matches_server_fixture_matrix(self):
        for raw, expected in TOKENIZER_FIXTURES.items():
            self.assertEqual(split_search_blob_tokens(raw), expected, msg=raw)

    def test_single_alphanumeric_token_equals_input(self):
        self.assertEqual(split_search_blob_tokens("host01"), ["host01"])
        self.assertEqual(split_search_blob_tokens(SHA256), [SHA256])


class ClassifierContractTests(unittest.TestCase):
    def test_token_safe_whole_tokens(self):
        for term in (
            "powershell",
            "PowerShell",
            "Administrator",
            "PCLAPPVM",
            "svchost",
            "host01",
            SHA256,
            "vchos",
            "STRASSE",
        ):
            self.assertEqual(
                classify_hunt_free_text_atom(term),
                HUNT_ATOM_TOKEN_SAFE,
                msg=term,
            )

    def test_substring_required_for_splits_quotes_wildcards(self):
        cases = [
            "cmd.exe",
            "10.0.0.1",
            "host01.domain.local",
            r"C:\Windows\System32\cmd.exe",
            r"DOMAIN\user",
            "user@example.com",
            "foo-bar",
            "foo_bar",
            "power*",
            "host_01",
        ]
        for term in cases:
            self.assertEqual(
                classify_hunt_free_text_atom(term),
                HUNT_ATOM_SUBSTRING_REQUIRED,
                msg=term,
            )
        self.assertEqual(
            classify_hunt_free_text_atom("powershell", quoted=True),
            HUNT_ATOM_SUBSTRING_REQUIRED,
        )
        self.assertEqual(
            classify_hunt_free_text_atom("Windows PowerShell", quoted=True),
            HUNT_ATOM_SUBSTRING_REQUIRED,
        )

    def test_digit_only_is_structured(self):
        self.assertEqual(classify_hunt_free_text_atom("4688"), HUNT_ATOM_STRUCTURED)
        self.assertEqual(classify_hunt_free_text_atom("7036"), HUNT_ATOM_STRUCTURED)

    def test_exclusion_preserve(self):
        self.assertEqual(
            classify_hunt_free_text_atom("powershell", exclusion=True),
            HUNT_ATOM_EXCLUSION_PRESERVE,
        )

    def test_invalid_empty(self):
        self.assertEqual(classify_hunt_free_text_atom(""), HUNT_ATOM_INVALID)
        self.assertEqual(classify_hunt_free_text_atom(None), HUNT_ATOM_INVALID)

    def test_non_ascii_is_substring_required_even_when_tokenizer_yields_one_token(self):
        """Indexed TOKEN_SAFE is ASCII-only; Unicode stays on existing ILIKE."""
        unicode_atoms = (
            "münchen",
            "MÜNCHEN",
            "Straße",
            "用户",
            "日本語",
            "—",
            "–",
            "“quote”",
            "🔥",
            "hosté",
            "powershell🔥",
            "foo\u00a0bar",
        )
        for term in unicode_atoms:
            tokens = split_search_blob_tokens(term)
            self.assertTrue(any(ord(ch) > 127 for ch in term), msg=term)
            if len(tokens) == 1:
                self.assertEqual(tokens[0], term, msg=term)
            self.assertEqual(
                classify_hunt_free_text_atom(term),
                HUNT_ATOM_SUBSTRING_REQUIRED,
                msg=term,
            )


class HuntGrammarMatrixTests(unittest.TestCase):
    def test_empty_and_whitespace_inputs(self):
        sql, params = _clause("")
        self.assertEqual(sql, "")
        self.assertEqual(params, {})

    def test_token_safe_positive_terms(self):
        for term in ("powershell", "PowerShell", "Administrator", "PCLAPPVM", "svchost"):
            sql, params = _clause(term)
            self.assertIn("hasAllTokens(search_blob, {", sql, msg=term)
            self.assertNotIn("lower(search_blob)", sql, msg=term)
            self.assertNotIn("ilike", sql.lower(), msg=term)
            self.assertIn(term, params.values(), msg=term)
            self.assertNotIn(f"%{term}%", params.values(), msg=term)

    def test_implicit_and_uses_two_token_predicates(self):
        sql, params = _clause("powershell administrator")
        self.assertEqual(sql.count("hasAllTokens"), 2)
        self.assertIn(" AND ", sql)
        self.assertNotIn("hasAnyTokens", sql)
        self.assertIn("powershell", params.values())
        self.assertIn("administrator", params.values())

    def test_compact_or_uses_has_any_tokens(self):
        sql, params = _clause("powershell|administrator")
        self.assertIn("hasAnyTokens(search_blob, {", sql)
        self.assertNotIn("ilike", sql.lower())
        self.assertIn("powershell administrator", params.values())

    def test_spaced_pipe_is_not_or_in_current_grammar(self):
        """Existing tokenizer skips a bare ``|`` token, so this stays AND."""
        sql, params = _clause("powershell | administrator")
        self.assertEqual(sql.count("hasAllTokens"), 2)
        self.assertNotIn("hasAnyTokens", sql)
        self.assertIn(" AND ", sql)

    def test_quoted_terms_remain_substring(self):
        sql, params = _clause('"powershell"')
        self.assertIn("search_blob ilike", sql)
        self.assertNotIn("hasAllTokens", sql)
        self.assertIn("%powershell%", params.values())

        sql, params = _clause('"Windows PowerShell"')
        self.assertIn("search_blob ilike", sql)
        self.assertIn("%Windows PowerShell%", params.values())

    def test_substring_required_inputs_keep_ilike(self):
        samples = [
            "cmd.exe",
            "10.0.0.1",
            "host.domain.local",
            r"\Windows\System32\cmd.exe",
            r"DOMAIN\user",
            "user@example.com",
            "foo-bar",
        ]
        for term in samples:
            sql, params = _clause(term)
            self.assertEqual(
                classify_hunt_free_text_atom(term),
                HUNT_ATOM_SUBSTRING_REQUIRED,
                msg=term,
            )
            self.assertIn("search_blob ilike", sql, msg=term)
            self.assertNotIn("hasAllTokens", sql, msg=term)
            self.assertIn(f"%{term}%", params.values(), msg=(term, params))

    def test_drive_letter_path_keeps_existing_field_value_grammar(self):
        """``C:\\...`` still parses as unknown field ``C`` plus blob fallback."""
        sql, params = _clause(r"C:\Windows\System32\cmd.exe")
        self.assertIn("search_blob ilike", sql)
        self.assertNotIn("hasAllTokens", sql)
        self.assertTrue(any("Windows" in str(value) for value in params.values()))

    def test_unquoted_vchos_is_token_safe_quoted_is_substring(self):
        self.assertEqual(classify_hunt_free_text_atom("vchos"), HUNT_ATOM_TOKEN_SAFE)
        sql, params = _clause("vchos")
        self.assertIn("hasAllTokens", sql)
        self.assertIn("vchos", params.values())

        sql, params = _clause('"vchos"')
        self.assertIn("search_blob ilike", sql)
        self.assertIn("%vchos%", params.values())

    def test_wildcard_forms_stay_substring(self):
        sql, params = _clause("power*")
        self.assertIn("search_blob ilike", sql)
        self.assertIn("%power*%", params.values())
        sql, params = _clause("host%")
        self.assertIn("search_blob ilike", sql)

    def test_numeric_terms_stay_event_id(self):
        sql, params = _clause("4688")
        self.assertIn("event_id = {", sql)
        self.assertNotIn("hasAllTokens", sql)
        self.assertIn("4688", params.values())

        sql, params = _clause("eventid:4688")
        self.assertIn("event_id = {", sql)
        self.assertIn("4688", params.values())

        sql, params = _clause("event_id:4688")
        self.assertIn("event_id = {", sql)

    def test_typed_hash_and_plain_hash(self):
        sql, params = _clause(f"sha256:{SHA256}")
        self.assertIn("file_hash_sha256 = {", sql)
        self.assertIn(SHA256, params.values())

        sql, params = _clause(SHA256)
        self.assertIn("hasAllTokens(search_blob, {", sql)
        self.assertIn(SHA256, params.values())

    def test_typed_ip_fields(self):
        sql, params = _clause("src_ip:10.0.0.1")
        self.assertIn("toString(src_ip) = {", sql)
        self.assertIn("search_blob ilike", sql)
        self.assertIn("%src_ip:10.0.0.1%", params.values())

        sql, params = _clause("dst_ip:10.0.0.1")
        self.assertIn("toString(dst_ip) = {", sql)

    def test_unknown_and_blob_fields_stay_substring(self):
        sql, params = _clause("unknownfield:value")
        self.assertIn("search_blob ilike", sql)
        self.assertIn("%unknownfield:value%", params.values())
        self.assertNotIn("hasAllTokens", sql)

        sql, params = _clause("src_nat_ip:10.0.0.1")
        self.assertIn("search_blob ilike", sql)
        self.assertIn("%src_nat_ip:10.0.0.1%", params.values())

    def test_exclusions_remain_not_ilike(self):
        sql, params = _clause("-powershell")
        self.assertIn("NOT search_blob ilike", sql)
        self.assertNotIn("hasAllTokens", sql)
        self.assertIn("%powershell%", params.values())

        sql, params = _clause('-"Windows PowerShell"')
        self.assertIn("NOT search_blob ilike", sql)
        self.assertIn("%Windows PowerShell%", params.values())

    def test_parentheses_and_group_or(self):
        sql, params = _clause("(powershell)|(administrator)")
        self.assertIn(" OR ", sql)
        self.assertIn("hasAllTokens", sql)

        sql, params = _clause("(eventid:4625)|host:dc1")
        self.assertIn(" OR ", sql)
        self.assertIn("4625", params.values())
        self.assertIn("%dc1%", params.values())

    def test_mixed_token_and_substring_or(self):
        sql, params = _clause("powershell|cmd.exe")
        self.assertIn("hasAllTokens(search_blob, {", sql)
        self.assertIn("search_blob ilike", sql)
        self.assertIn(" OR ", sql)
        self.assertNotIn("hasAnyTokens", sql)
        self.assertIn("powershell", params.values())
        self.assertIn("%cmd.exe%", params.values())

    def test_mixed_token_and_event_id_or(self):
        sql, params = _clause("powershell|4688")
        self.assertIn("hasAllTokens", sql)
        self.assertIn("event_id = {", sql)
        self.assertNotIn("hasAnyTokens", sql)

    def test_unicode_atoms_emit_parameterized_ilike_not_token_predicates(self):
        unicode_atoms = (
            "münchen",
            "MÜNCHEN",
            "Straße",
            "用户",
            "日本語",
            "—",
            "–",
            "“quote”",
            "🔥",
            "hosté",
            "powershell🔥",
        )
        for term in unicode_atoms:
            sql, params = _clause(term)
            lowered = sql.lower()
            self.assertEqual(
                classify_hunt_free_text_atom(term),
                HUNT_ATOM_SUBSTRING_REQUIRED,
                msg=term,
            )
            self.assertIn("search_blob ilike", lowered, msg=term)
            self.assertNotIn("hasalltokens", lowered, msg=term)
            self.assertNotIn("hasanytokens", lowered, msg=term)
            self.assertNotIn(term, sql, msg=term)
            self.assertIn(f"%{term}%", params.values(), msg=(term, params))
            for value in params.values():
                self.assertIsInstance(value, str)

    def test_mixed_ascii_token_and_unicode_or_is_per_branch_not_has_any(self):
        samples = (
            "powershell|münchen",
            "powershell|用户",
            "powershell|🔥",
        )
        for search in samples:
            sql, params = _clause(search)
            lowered = sql.lower()
            self.assertIn("hasalltokens(search_blob, {", lowered, msg=search)
            self.assertIn("search_blob ilike", lowered, msg=search)
            self.assertIn(" or ", lowered, msg=search)
            self.assertNotIn("hasanytokens", lowered, msg=search)
            self.assertIn("powershell", params.values(), msg=search)

    def test_all_ascii_compact_or_still_uses_has_any_tokens(self):
        sql, params = _clause("powershell|administrator|STRASSE")
        self.assertIn("hasAnyTokens(search_blob, {", sql)
        self.assertNotIn("ilike", sql.lower())
        self.assertTrue(any("powershell" in str(value) for value in params.values()))

    def test_unicode_exclusions_remain_not_ilike(self):
        for term in ("münchen", "用户"):
            sql, params = _clause(f"-{term}")
            self.assertIn("NOT search_blob ilike", sql, msg=term)
            self.assertNotIn("hasAllTokens", sql, msg=term)
            self.assertNotIn("hasAnyTokens", sql, msg=term)
            self.assertIn(f"%{term}%", params.values(), msg=term)

    def test_quoted_ascii_and_unicode_remain_substring(self):
        for term in ("powershell", "münchen", "用户"):
            sql, params = _clause(f'"{term}"')
            self.assertIn("search_blob ilike", sql, msg=term)
            self.assertNotIn("hasAllTokens", sql, msg=term)
            self.assertNotIn("hasAnyTokens", sql, msg=term)
            self.assertIn(f"%{term}%", params.values(), msg=term)

    def test_large_or_group_is_chunked_not_truncated(self):
        terms = [f"tok{index}" for index in range(HASANY_TOKENS_CHUNK + 40)]
        sql, params = _clause("|".join(terms))
        self.assertIn("hasAnyTokens", sql)
        self.assertIn(" OR ", sql)
        joined_values = [value for value in params.values() if isinstance(value, str) and " " in value]
        emitted = []
        for value in joined_values:
            emitted.extend(value.split())
        self.assertEqual(emitted, terms)

    def test_sql_injection_like_strings_stay_parameterized(self):
        payloads = [
            "foo';DROP",
            r"foo\x",
            "foo}{bar",
            "foo/*comment*/bar",
            'foo"bar',
            "foo'; DROP TABLE events; --",
        ]
        for payload in payloads:
            sql, params = _clause(payload)
            self.assertNotIn(payload, sql, msg=payload)
            self.assertIn("{", sql)
            self.assertIn(":String}", sql)
            self.assertTrue(params, msg=payload)
            for value in params.values():
                self.assertIsInstance(value, str)

    def test_grid_and_export_share_the_same_helper(self):
        from routes import hunting as hunting_routes

        source = inspect.getsource(hunting_routes)
        self.assertEqual(source.count("build_hunting_search_clause("), 2)
        self.assertIn("def get_hunting_events", source)
        self.assertIn("def export_view_events", source)
        view_src = inspect.getsource(hunting_routes.export_view_events)
        tagged_src = inspect.getsource(hunting_routes.export_tagged_events)
        grid_src = inspect.getsource(hunting_routes.get_hunting_events)
        self.assertIn("build_hunting_publication_bridge", view_src)
        self.assertIn("build_hunting_publication_bridge", tagged_src)
        self.assertIn("build_hunting_publication_bridge", grid_src)
        self.assertIn("build_hunting_search_clause", view_src)

    def test_does_not_emit_lower_on_stored_column(self):
        sql, _params = _clause("powershell")
        self.assertNotIn("lower(search_blob)", sql)
        self.assertNotIn("lower(e.search_blob)", sql)


class PublicationBridgeUnchangedTests(unittest.TestCase):
    def test_phase1b_bridge_sql_still_requires_durable_and_visible(self):
        bridge = build_hunting_publication_bridge(alias="e")
        joined = bridge["join_sql"] + bridge["where_sql"]
        self.assertIn("visible_evidence_generations", joined)
        self.assertIn("durable_ingest_batches", joined)
        self.assertIn("dib.state = 'DURABLE'", joined)
        self.assertIn("BUILDING_INITIAL", joined)
        self.assertIn("veg.publishable = 1", joined)
        self.assertNotIn("events_current", joined)
        self.assertNotIn("event_observations_current", joined)


class NoLaterPhaseConsumerTests(unittest.TestCase):
    def test_other_search_blob_consumers_were_not_migrated(self):
        from routes import hunting as hunting_routes
        from utils import sigma_converter
        from utils import ioc_artifact_tagger
        from utils import noise_keywords
        from utils import chat_tools
        from utils import forensic_chat_sources
        from models import network_log
        from models import pattern_rules

        detail = inspect.getsource(hunting_routes.get_hunting_event_detail)
        self.assertIn("position(e.search_blob", detail)
        self.assertNotIn("hasAllTokens", detail)

        for module in (
            sigma_converter,
            ioc_artifact_tagger,
            noise_keywords,
            chat_tools,
            forensic_chat_sources,
            network_log,
            pattern_rules,
        ):
            source = inspect.getsource(module)
            self.assertNotIn("hasAllTokens(search_blob", source, msg=module.__name__)
            self.assertNotIn("hasAnyTokens(search_blob", source, msg=module.__name__)


def _clickhouse_available():
    try:
        import clickhouse_connect

        client = clickhouse_connect.get_client(
            host=os.environ.get("CLICKHOUSE_HOST") or "localhost",
            port=int(os.environ.get("CLICKHOUSE_PORT") or 8123),
            username=os.environ.get("CLICKHOUSE_USER") or "default",
            password=os.environ.get("CLICKHOUSE_PASSWORD") or "",
            database="default",
            autogenerate_session_id=False,
        )
        client.query("SELECT 1")
        return True
    except Exception:
        return False


@unittest.skipUnless(_clickhouse_available(), "live ClickHouse is required")
class LiveTokenizerReplicaTests(unittest.TestCase):
    def test_python_replica_equals_clickhouse_split_by_non_alpha(self):
        import clickhouse_connect

        client = clickhouse_connect.get_client(
            host=os.environ.get("CLICKHOUSE_HOST") or "localhost",
            port=int(os.environ.get("CLICKHOUSE_PORT") or 8123),
            username=os.environ.get("CLICKHOUSE_USER") or "default",
            password=os.environ.get("CLICKHOUSE_PASSWORD") or "",
            database="casescope",
            autogenerate_session_id=False,
        )
        for raw in TOKENIZER_FIXTURES:
            server = [
                token
                for token in (
                    client.query(
                        "SELECT splitByNonAlpha({s:String})",
                        parameters={"s": raw},
                    ).result_rows[0][0]
                    or []
                )
                if token
            ]
            self.assertEqual(split_search_blob_tokens(raw), server, msg=raw)


if __name__ == "__main__":
    unittest.main()
