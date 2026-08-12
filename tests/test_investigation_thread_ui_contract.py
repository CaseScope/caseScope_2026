import unittest
from pathlib import Path


TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "static" / "templates"
TEMPLATE_FILES = (
    "case_graph.html",
    "case_investigation_threads.html",
    "case_investigation_thread_detail.html",
)


class InvestigationThreadUIContractTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.templates = {name: (TEMPLATE_DIR / name).read_text(encoding="utf-8") for name in TEMPLATE_FILES}
        cls.combined = "\n".join(cls.templates.values())

    def test_dynamic_content_does_not_use_inner_html_assignment(self):
        for name, content in self.templates.items():
            self.assertNotIn(".innerHTML =", content, f"{name} should use DOM/textContent APIs for dynamic content")

    def test_graph_template_has_selection_and_saved_view_controls(self):
        graph = self.templates["case_graph.html"]

        self.assertIn("Selection Basket", graph)
        self.assertIn("Create Thread from Selection", graph)
        self.assertIn("Save View", graph)
        self.assertIn("Load View", graph)

    def test_saved_view_restore_does_not_replay_neighborhood_expansion(self):
        graph = self.templates["case_graph.html"]
        start = graph.index("async function loadSelectedGraphView()")
        end = graph.index("async function findPathToSelected()", start)
        restore_source = graph[start:end]

        self.assertNotIn("expandNode(", restore_source)
        self.assertIn("fetchGraphEntity", restore_source)
        self.assertIn("fetchGraphRelationship", restore_source)

    def test_thread_detail_has_snapshot_retained_text(self):
        self.assertIn("Snapshot retained", self.templates["case_investigation_thread_detail.html"])

    def test_templates_use_text_content(self):
        for name, content in self.templates.items():
            self.assertIn("textContent", content, f"{name} should render dynamic text with textContent")


if __name__ == "__main__":
    unittest.main()
