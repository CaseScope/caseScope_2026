import inspect
import unittest

import routes.main as main_routes


class GraphUIContractTestCase(unittest.TestCase):
    def test_main_case_graph_route_exists_and_is_protected(self):
        source = inspect.getsource(main_routes.case_graph)

        self.assertIn("@main_bp.route('/case/graph')", source)
        self.assertIn("@login_required", source)
        self.assertIn("@case_required", source)
        self.assertIn("case_graph.html", source)

    def test_sidebar_includes_investigation_graph(self):
        with open("/opt/casescope/static/templates/base.html", encoding="utf-8") as handle:
            source = handle.read()

        self.assertIn("Investigation Graph", source)
        self.assertIn("main.case_graph", source)

    def test_graph_page_renders_root_search_without_embedded_graph_data(self):
        with open("/opt/casescope/static/templates/case_graph.html", encoding="utf-8") as handle:
            source = handle.read()

        self.assertIn("Entity Search", source)
        self.assertIn("graph-search-input", source)
        self.assertIn("/summary", source)
        self.assertIn("/neighbors", source)
        self.assertNotIn("graph_entities", source)
        self.assertNotIn("graph_relationships", source)

    def test_graph_page_contains_expand_evidence_and_path_workflows(self):
        with open("/opt/casescope/static/templates/case_graph.html", encoding="utf-8") as handle:
            source = handle.read()

        self.assertIn("Expand", source)
        self.assertIn("Load More", source)
        self.assertIn("Evidence / Provenance", source)
        self.assertIn("Open in Hunt Artifacts", source)
        self.assertIn("Graph Path", source)
        self.assertNotIn("Attack Chain", source)
        self.assertNotIn("Create Thread", source)
        self.assertNotIn("Delete Relationship", source)

    def test_graph_reset_clears_path_start_and_evidence_pages_append(self):
        with open("/opt/casescope/static/templates/case_graph.html", encoding="utf-8") as handle:
            source = handle.read()

        self.assertIn("graphState.pathStartId = null;", source)
        self.assertIn("renderEvidenceRows(edgeId, data.evidence || [], data.pagination || {}, Boolean(cursor));", source)
        self.assertIn("if (!append) graphClear(panel);", source)
        self.assertIn("graph-evidence-more", source)

    def test_hunting_selector_key_deep_link_support_exists(self):
        with open("/opt/casescope/static/templates/case_hunting.html", encoding="utf-8") as handle:
            source = handle.read()

        self.assertIn("selectorKeyParam", source)
        self.assertIn("openEventDetailBySelectorKey", source)
        self.assertIn("/api/hunting/event/detail/", source)

    def test_no_external_graph_dependency_is_required(self):
        with open("/opt/casescope/static/templates/case_graph.html", encoding="utf-8") as handle:
            source = handle.read()

        self.assertIn("<svg id=\"graph-canvas\"", source)
        self.assertNotIn("cdn", source.lower())
        self.assertNotIn("cytoscape", source.lower())


if __name__ == "__main__":
    unittest.main()
