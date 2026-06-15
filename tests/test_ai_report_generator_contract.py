from pathlib import Path


REPO_ROOT = Path("/opt/casescope")


def test_ai_report_generator_imports_privacy_alias_helpers():
    source = (REPO_ROOT / "utils/ai_report_generator.py").read_text()

    assert "from utils.privacy_aliases import AIPrivacyContext, rehydrate_for_display" in source
    assert "AIPrivacyContext.case_content" in source
    assert "rehydrate_for_display" in source


def test_ai_report_generator_fails_on_section_error_placeholders():
    source = (REPO_ROOT / "utils/ai_report_generator.py").read_text()

    assert 'AI_SECTION_ERROR_PREFIX = "[Error generating content:"' in source
    assert "def _section_generation_errors" in source
    assert "section_errors = self._section_generation_errors()" in source
    assert "'success': False" in source[source.index("section_errors = self._section_generation_errors()"):]
    assert "'failed_sections': section_errors" in source


def test_ai_report_word_template_render_escapes_xml_entities():
    source = (REPO_ROOT / "utils/ai_report_generator.py").read_text()

    assert "doc.render(template_context, autoescape=True)" in source


def test_ai_timeline_word_template_render_escapes_xml_entities():
    source = (REPO_ROOT / "utils/ai_timeline_generator.py").read_text()

    assert "doc.render(template_context, autoescape=True)" in source


def test_static_report_word_template_render_escapes_xml_entities():
    source = (REPO_ROOT / "utils/report_generator.py").read_text()

    assert "self.template.render(context, autoescape=True)" in source
