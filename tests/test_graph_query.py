import unittest
from datetime import datetime
from types import SimpleNamespace

from flask import Flask

from models.case import Case
from models.database import db
from models.graph import GraphEntity, GraphEntityObservation, GraphRelationship, GraphRelationshipEvidence
from utils.graph_identity import GraphDerivationType, GraphEntityType, GraphRelationshipType, GraphValidationState
from utils.graph_query import GraphNotFoundError, GraphQueryError, GraphQueryService


def evidence_key(char):
    return "erk:v2:" + (char * 64)


class _FakeClickHouse:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def query(self, sql, parameters=None):
        self.calls.append((sql, parameters or {}))
        return SimpleNamespace(
            column_names=[
                "timestamp",
                "timestamp_utc",
                "selector_key",
                "artifact_type",
                "source_file",
                "source_path",
                "source_host",
                "event_id",
                "channel",
                "provider",
                "record_id",
                "level",
                "username",
                "domain",
                "sid",
                "logon_type",
                "process_name",
                "process_path",
                "process_id",
                "parent_process",
                "parent_pid",
                "command_line",
                "target_path",
                "file_hash_md5",
                "file_hash_sha1",
                "file_hash_sha256",
                "file_size",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "reg_key",
                "reg_value",
                "reg_data",
                "raw_json",
                "extra_fields",
                "search_blob",
                "parser_version",
                "evidence_record_key",
                "evidence_identity_version",
                "evidence_identity_quality",
            ],
            result_rows=self.rows,
        )


class GraphQueryServiceTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            TESTING=True,
            SECRET_KEY="test-secret",
        )
        db.init_app(self.app)
        self.ctx = self.app.app_context()
        self.ctx.push()
        for table in (
            Case.__table__,
            GraphEntity.__table__,
            GraphRelationship.__table__,
            GraphEntityObservation.__table__,
            GraphRelationshipEvidence.__table__,
        ):
            table.create(db.engine)
        db.session.add(Case(id=1, uuid="case-1", name="Case 1", company="Client", created_by="tester"))
        db.session.add(Case(id=2, uuid="case-2", name="Case 2", company="Client", created_by="tester"))
        db.session.commit()
        self.service = GraphQueryService()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def entity(self, case_id, entity_type, key, display):
        entity = GraphEntity(
            case_id=case_id,
            entity_type=entity_type,
            entity_key=key,
            display_value=display,
            canonical_value=display.upper(),
            first_seen_at=datetime(2026, 1, 1, 12, 0, 0),
            last_seen_at=datetime(2026, 1, 1, 12, 1, 0),
            metadata_json={},
        )
        db.session.add(entity)
        db.session.flush()
        return entity

    def relationship(self, case_id, source, relationship_type, target, *, state=GraphValidationState.ACTIVE):
        relationship = GraphRelationship(
            case_id=case_id,
            source_entity_id=source.id,
            relationship_type=relationship_type,
            target_entity_id=target.id,
            first_seen_at=datetime(2026, 1, 1, 12, 0, 0),
            last_seen_at=datetime(2026, 1, 1, 12, 1, 0),
            confidence=1.0,
            derivation_type=GraphDerivationType.OBSERVED,
            extractor_name="test",
            extractor_version="1",
            validation_state=state,
            metadata_json={},
        )
        db.session.add(relationship)
        db.session.flush()
        return relationship

    def evidence(self, case_id, relationship, key):
        evidence = GraphRelationshipEvidence(
            case_id=case_id,
            relationship_id=relationship.id,
            evidence_record_key=key,
            source_table="events",
            evidence_role="supporting_record",
            extractor_name="test",
            extractor_version="1",
            observed_at=datetime(2026, 1, 1, 12, 0, 0),
            metadata_json={},
        )
        db.session.add(evidence)
        db.session.flush()
        return evidence

    def test_entity_search_is_case_scoped_and_empty_search_does_not_dump(self):
        self.entity(1, GraphEntityType.HOST, "host:wks1", "WKS-1")
        self.entity(2, GraphEntityType.HOST, "host:wks1-other", "WKS-1")
        db.session.commit()

        empty = self.service.search_entities(1, q="")
        result = self.service.search_entities(1, q="wks")

        self.assertEqual(empty["entities"], [])
        self.assertEqual(len(result["entities"]), 1)
        self.assertEqual(result["entities"][0]["display_value"], "WKS-1")

    def test_entity_type_filter_validation_and_search_hard_limit(self):
        for index in range(60):
            self.entity(1, GraphEntityType.HOST, f"host:{index}", f"WKS-{index}")
        db.session.commit()

        with self.assertRaises(GraphQueryError):
            self.service.search_entities(1, q="wks", entity_types=["NOT_A_TYPE"])
        result = self.service.search_entities(1, q="wks", limit=500)
        self.assertEqual(len(result["entities"]), 50)
        self.assertTrue(result["has_more"])

    def test_neighborhood_direction_preserves_real_edge_direction_and_excludes_cross_case(self):
        host = self.entity(1, GraphEntityType.HOST, "host:wks1", "WKS-1")
        user = self.entity(1, GraphEntityType.USER, "user:jsmith", "jsmith")
        process = self.entity(1, GraphEntityType.PROCESS, "proc:cmd", "cmd.exe")
        other_host = self.entity(2, GraphEntityType.HOST, "host:wks1", "WKS-1")
        other_user = self.entity(2, GraphEntityType.USER, "user:other", "other")
        incoming = self.relationship(1, user, GraphRelationshipType.LOGGED_ON_TO, host)
        outgoing = self.relationship(1, host, GraphRelationshipType.OWNS_IP, process)
        self.relationship(2, other_user, GraphRelationshipType.LOGGED_ON_TO, other_host)
        db.session.commit()

        incoming_result = self.service.neighborhood(1, host.id, direction="in")
        outgoing_result = self.service.neighborhood(1, host.id, direction="out")
        both_result = self.service.neighborhood(1, host.id, direction="both")

        self.assertEqual([edge["id"] for edge in incoming_result["edges"]], [incoming.id])
        self.assertEqual([edge["id"] for edge in outgoing_result["edges"]], [outgoing.id])
        self.assertEqual({edge["id"] for edge in both_result["edges"]}, {incoming.id, outgoing.id})
        self.assertEqual(incoming_result["edges"][0]["source_entity_id"], user.id)
        self.assertEqual(incoming_result["edges"][0]["target_entity_id"], host.id)

    def test_high_degree_node_truncates_and_cursor_loads_without_duplicates(self):
        root = self.entity(1, GraphEntityType.HOST, "host:root", "ROOT")
        for index in range(205):
            target = self.entity(1, GraphEntityType.IP_ADDRESS, f"ip:{index}", f"10.0.0.{index}")
            self.relationship(1, root, GraphRelationshipType.OWNS_IP, target)
        db.session.commit()

        first = self.service.neighborhood(1, root.id, direction="out", limit=200)
        second = self.service.neighborhood(1, root.id, direction="out", cursor=first["pagination"]["next_cursor"], limit=200)

        self.assertTrue(first["truncated"])
        self.assertEqual(len(first["edges"]), 200)
        self.assertFalse({edge["id"] for edge in first["edges"]} & {edge["id"] for edge in second["edges"]})
        self.assertEqual(len(second["edges"]), 5)

    def test_relationship_detail_support_count_and_inactive_default(self):
        source = self.entity(1, GraphEntityType.USER, "user:jsmith", "jsmith")
        target = self.entity(1, GraphEntityType.HOST, "host:wks1", "WKS-1")
        active = self.relationship(1, source, GraphRelationshipType.LOGGED_ON_TO, target)
        inactive = self.relationship(1, target, GraphRelationshipType.OWNS_IP, source, state=GraphValidationState.INVALIDATED)
        self.evidence(1, active, evidence_key("a"))
        self.evidence(1, active, evidence_key("b"))
        db.session.commit()

        detail = self.service.relationship_detail(1, active.id)
        neighborhood = self.service.neighborhood(1, source.id)

        self.assertEqual(detail["support_count"], 2)
        self.assertNotIn(inactive.id, [edge["id"] for edge in neighborhood["edges"]])
        with self.assertRaises(GraphNotFoundError):
            self.service.relationship_detail(2, active.id)

    def test_relationship_evidence_listing_is_case_scoped_and_bounded(self):
        source = self.entity(1, GraphEntityType.USER, "user:jsmith", "jsmith")
        target = self.entity(1, GraphEntityType.HOST, "host:wks1", "WKS-1")
        relationship = self.relationship(1, source, GraphRelationshipType.LOGGED_ON_TO, target)
        for char in ("a", "b", "c"):
            self.evidence(1, relationship, evidence_key(char))
        db.session.commit()

        result = self.service.relationship_evidence(1, relationship.id, limit=2)

        self.assertEqual(len(result["evidence"]), 2)
        self.assertTrue(result["truncated"])
        with self.assertRaises(GraphNotFoundError):
            self.service.relationship_evidence(2, relationship.id)

    def test_bounded_path_finds_path_handles_cycles_and_blocks_cross_case(self):
        a = self.entity(1, GraphEntityType.HOST, "a", "A")
        b = self.entity(1, GraphEntityType.HOST, "b", "B")
        c = self.entity(1, GraphEntityType.HOST, "c", "C")
        other = self.entity(2, GraphEntityType.HOST, "c", "C")
        self.relationship(1, a, GraphRelationshipType.REFERENCES, b)
        self.relationship(1, b, GraphRelationshipType.REFERENCES, c)
        self.relationship(1, c, GraphRelationshipType.REFERENCES, a)
        db.session.commit()

        result = self.service.path_search(1, source_entity_id=a.id, target_entity_id=c.id, direction="out", max_depth=3, max_paths=3)

        self.assertEqual(result["paths"][0]["node_ids"], [a.id, b.id, c.id])
        self.assertFalse(result["truncated"])
        with self.assertRaises(GraphQueryError):
            self.service.path_search(1, source_entity_id=a.id, target_entity_id=c.id, max_depth=5)
        with self.assertRaises(GraphNotFoundError):
            self.service.path_search(1, source_entity_id=a.id, target_entity_id=other.id, max_depth=3)

    def test_path_search_rejects_nonnumeric_depth_and_path_limits(self):
        a = self.entity(1, GraphEntityType.HOST, "a", "A")
        b = self.entity(1, GraphEntityType.HOST, "b", "B")
        db.session.commit()

        with self.assertRaises(GraphQueryError):
            self.service.path_search(1, source_entity_id=a.id, target_entity_id=b.id, max_depth="banana")
        with self.assertRaises(GraphQueryError):
            self.service.path_search(1, source_entity_id=a.id, target_entity_id=b.id, max_paths="banana")

    def test_path_response_contains_only_returned_path_union_not_traversal_workspace(self):
        a = self.entity(1, GraphEntityType.HOST, "a", "A")
        b = self.entity(1, GraphEntityType.HOST, "b", "B")
        c = self.entity(1, GraphEntityType.HOST, "c", "C")
        dead = self.entity(1, GraphEntityType.HOST, "dead", "DEAD")
        dead_child = self.entity(1, GraphEntityType.HOST, "dead-child", "DEAD-CHILD")
        path_edge_1 = self.relationship(1, a, GraphRelationshipType.REFERENCES, b)
        path_edge_2 = self.relationship(1, b, GraphRelationshipType.REFERENCES, c)
        dead_edge_1 = self.relationship(1, a, GraphRelationshipType.REFERENCES, dead)
        dead_edge_2 = self.relationship(1, dead, GraphRelationshipType.REFERENCES, dead_child)
        db.session.commit()

        result = self.service.path_search(1, source_entity_id=a.id, target_entity_id=c.id, direction="out", max_depth=3)
        result_node_ids = {node["id"] for node in result["nodes"]}
        result_edge_ids = {edge["id"] for edge in result["edges"]}

        self.assertEqual(result_node_ids, {a.id, b.id, c.id})
        self.assertEqual(result_edge_ids, {path_edge_1.id, path_edge_2.id})
        self.assertNotIn(dead.id, result_node_ids)
        self.assertNotIn(dead_child.id, result_node_ids)
        self.assertNotIn(dead_edge_1.id, result_edge_ids)
        self.assertNotIn(dead_edge_2.id, result_edge_ids)
        self.assertGreaterEqual(result["visited_node_count"], 3)
        self.assertGreaterEqual(result["examined_edge_count"], 3)

    def test_path_traversal_ceiling_reports_truncated_not_global_no_path(self):
        root = self.entity(1, GraphEntityType.HOST, "root", "ROOT")
        target = self.entity(1, GraphEntityType.HOST, "target", "TARGET")
        for index in range(251):
            node = self.entity(1, GraphEntityType.HOST, f"n:{index}", f"N{index}")
            self.relationship(1, root, GraphRelationshipType.REFERENCES, node)
        db.session.commit()

        result = self.service.path_search(1, source_entity_id=root.id, target_entity_id=target.id, max_depth=2)

        self.assertTrue(result["truncated"])
        self.assertIn("limits", result["result_statement"])

    def test_exact_erk_lookup_uses_case_and_erk_and_preserves_selector(self):
        row = (
            "2026-01-01 12:00:00",
            "2026-01-01 12:00:00",
            "selector-1",
            "evtx",
            "Security.evtx",
            "/evidence/Security.evtx",
            "WKS-1",
            "4624",
            "Security",
            "Provider",
            44,
            "info",
            "jsmith",
            "CONTOSO",
            "S-1",
            "2",
            "cmd.exe",
            "C:/Windows/cmd.exe",
            42,
            "",
            0,
            "cmd.exe",
            "",
            "",
            "",
            "",
            0,
            "",
            "",
            0,
            0,
            "",
            "",
            "",
            '{"raw": true}',
            '{"extra": true}',
            "blob",
            "parser",
            evidence_key("a"),
            "2",
            "fingerprinted",
        )
        client = _FakeClickHouse([row, row])

        result = self.service.exact_evidence(1, evidence_key("a"), client=client)

        self.assertEqual(result["selector_key"], "selector-1")
        self.assertTrue(result["duplicates_detected"])
        self.assertEqual(result["event"]["raw_json"], {"raw": True})
        sql, params = client.calls[0]
        self.assertIn("case_id = {case_id:UInt32}", sql)
        self.assertIn("evidence_record_key = {evidence_record_key:String}", sql)
        self.assertEqual(params["case_id"], 1)
        self.assertEqual(params["evidence_record_key"], evidence_key("a"))
        with self.assertRaises(GraphQueryError):
            self.service.exact_evidence(1, "bad-key", client=client)


if __name__ == "__main__":
    unittest.main()
