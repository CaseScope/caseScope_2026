"""
CaseScope Giga Context Bridge

This file exists because Giga may ignore markdown, Cursor rules, docs, and config files.

Project:
CaseScope is a DFIR analysis system for ingesting artifacts, extracting IOCs,
building timelines, and generating analyst-ready findings.

Core rules:
- Deterministic parsing first, LLM interpretation second.
- Preserve raw artifact values, timestamps, source file paths, and parser provenance.
- Do not invent schema fields.
- Timeline records must follow the timeline schema.
- IOC records must follow the IOC schema.
- Parser changes require regression tests.
- Evidence, uploads, logs, caches, model weights, local training data, and case data must not be indexed.

Active focus:
- Refactor deterministic engine.
- Parser contract stability.
- IOC extraction and enrichment.
- Timeline normalization.
- Route/task/pipeline correctness.
- AI runtime routing with strict contracts.

Prompt improvement:
- Convert vague requests into goal, likely files, constraints, validation, and risk areas.
- Prefer small, testable changes.
- Before editing, identify files likely involved.
- After mistakes, suggest a rule update.
"""