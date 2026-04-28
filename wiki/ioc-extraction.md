# IOC Extraction

CaseScope IOC extraction identifies indicators of compromise from case report text, lets analysts review candidates, saves accepted indicators into the case, and can optionally use AI to find additional candidates that deterministic extraction may miss.

IOC extraction is designed as a review workflow. CaseScope can propose indicators, enrich them, and tag matching events, but analysts decide what should become part of the case record.

## Main Workflow

The normal workflow starts from the case IOC management page:

1. CaseScope checks whether report text is available for the case.
2. The analyst starts extraction.
3. A Celery task runs deterministic IOC extraction.
4. Candidate IOCs are normalized, deduplicated, and prepared for review.
5. The analyst saves selected candidates.
6. Saved IOCs are associated with the case and can be enriched or used for event tagging.
7. If AI enhancement is enabled, a separate AI enhancement run stages additional candidates for analyst accept or reject.

The main API routes live in `routes/iocs.py`, and the user-facing workflow is centered on `static/templates/case_ioc_management.html`.

## Deterministic Extraction

Deterministic extraction runs first. This path does not require an LLM.

CaseScope uses regex and rule-based logic to identify common IOC types, including hashes, IP addresses, domains, URLs, emails, hostnames, and other supported indicator forms. The extraction code normalizes matches, applies type-specific validation, attaches context, and builds structured candidate records.

Key code areas:

- `utils/ioc_extractor.py` orchestrates IOC extraction.
- `utils/deterministic_ioc_extractor.py` wraps deterministic extraction.
- `utils/ioc_regex_extractor.py` performs regex-based extraction.
- `utils/ioc_regex_catalog.py` defines IOC pattern catalogs and related hints.
- `utils/ioc_schema.py` builds structured IOC records.

The deterministic stage is the baseline because it is predictable, fast, and auditable.

## Import Preparation

After raw candidates are extracted, CaseScope prepares them for import. This stage:

- normalizes values and types
- removes duplicates
- compares candidates against existing case IOCs
- identifies known systems and known users
- prepares import actions for analyst review
- preserves supporting context where available

The import preparation logic is handled through `process_extraction_for_import` and related helpers in `utils/ioc_import_processing.py`.

## Saving IOCs

When an analyst saves selected candidates, CaseScope persists them through `utils/ioc_persistence.py`.

Saved IOC data is stored in PostgreSQL using the IOC models:

- `models/ioc.py` stores IOCs, case links, system sightings, and audit records.
- `models/ioc_enhancement.py` stores AI enhancement run state and staged candidates.

Saving can also trigger optional enrichment. For example, new IOCs may be checked against OpenCTI when threat intelligence features are available and enabled.

## Background Tasks And Queues

IOC extraction runs through Celery so long-running work does not block the web UI.

The main IOC-related tasks are defined in `tasks/celery_tasks.py`:

- `tasks.extract_iocs_from_report` runs deterministic extraction and stores progress/results.
- `tasks.enhance_iocs_from_report` runs optional AI enhancement after deterministic extraction.
- `tasks.find_iocs_in_events` searches event data for IOC matches.
- `tasks.tag_iocs_for_case` tags events and artifacts with saved IOC matches.

These tasks use the dedicated `ioc` queue, so the deployed Celery workers must listen to that queue. The install guide starts workers with `-Q celery,ioc`.

Progress and short-lived extraction results are tracked in Redis. Durable IOCs, audit data, and AI enhancement runs are stored in PostgreSQL.

## How AI Enhances Extraction

AI enhancement is optional and runs after deterministic extraction. It is intended to find context-dependent indicators that strict regex rules may miss, not to replace deterministic extraction.

When AI enhancement is requested:

1. CaseScope runs the deterministic extraction baseline.
2. CaseScope checks whether AI features are available through license and runtime checks.
3. The report text is normalized and split into model-sized work units.
4. The AI provider is resolved for the `ioc_extraction` function.
5. The model is asked to return structured IOC candidates.
6. CaseScope validates and normalizes the model output.
7. AI candidates are merged with deterministic results.
8. Candidates already found deterministically are deduplicated.
9. AI-only candidates are staged in an enhancement run for analyst review.

The important safety point is that AI-only candidates are not silently accepted into the case. They are staged as review items on a `CaseIOCEnhancementRun`, and the analyst accepts or rejects them.

## AI Modes

CaseScope supports AI-assisted IOC extraction modes through configuration and system settings.

The default mode is semantic extraction. In this mode, CaseScope builds extraction tasks from report structure and keywords, asks the model for structured output, then validates the response against IOC contracts before merging results.

An audit-style mode can also compare AI output against deterministic extraction and produce candidate deltas. This is useful when the AI is being used as a second-pass reviewer over the deterministic baseline.

Related code areas include:

- `utils/semantic_ioc_extractor.py`
- `utils/ioc_audit.py`
- `utils/ioc_contract.py`
- `utils/ioc_contract_adapter.py`
- `utils/ai/router.py`
- `utils/ai_review.py`

## AI Guardrails

AI output is treated as untrusted until it passes CaseScope validation. The pipeline uses several guardrails:

- schema and contract validation
- type-specific normalization
- duplicate detection
- allowed-field filtering for semantic tasks
- optional structured-output review
- fallback to deterministic extraction if AI is unavailable or fails

If AI is not enabled, unavailable, or not licensed, CaseScope falls back to deterministic extraction and reports the method accordingly.

## Review And Acceptance

Deterministic extraction results are shown to the analyst for saving. AI enhancement results are staged separately so the analyst can review AI-only candidates.

The review flow uses API routes under `routes/iocs.py`, including status and review endpoints for AI enhancement runs. Accepting an AI candidate saves it through the same persistence path used by deterministic results. Rejecting a candidate leaves it out of the case IOC set.

This keeps the final case IOC list analyst-controlled.

## Finding IOCs In Events

After IOCs are saved, CaseScope can search event data for matches and tag related artifacts or events.

The `find_iocs_in_events` task scans ClickHouse event data and applies deterministic IOC matching against event content. This is separate from AI extraction. It is used to locate where known or extracted IOCs appear in ingested evidence.

The `tag_iocs_for_case` task updates event/artifact IOC state so the hunting interface can show IOC context and matches.

## Threat Intelligence Enrichment

Threat intelligence enrichment is related to IOC extraction but separate from AI extraction.

When OpenCTI or other threat-intel features are enabled and licensed, saved IOCs can be enriched after creation. This may add context such as known threat intelligence matches, but it does not decide whether a candidate should be accepted into the case.

## Required Services

IOC extraction relies on:

- PostgreSQL for saved IOCs, case associations, audits, and enhancement runs
- Redis for task progress and short-lived results
- Celery workers listening on the `ioc` queue
- ClickHouse for event matching and tagging workflows

AI enhancement additionally requires:

- valid AI feature availability
- a configured AI provider through `utils/ai/router.py`
- the selected model/runtime to be reachable
- any applicable license activation

OpenCTI enrichment requires the separate threat intelligence feature to be available and configured.

## When To Use IOC Extraction

Use IOC extraction when a case has report text, EDR output, analyst notes, or other narrative content that may contain indicators worth tracking.

Use deterministic extraction for fast, repeatable IOC discovery. Enable AI enhancement when the source text is complex, narrative-heavy, or likely to contain indicators that need semantic understanding.

After saving IOCs, use event matching and tagging to find where those indicators appear across ingested evidence.

## Practical Notes

- Deterministic extraction is the baseline and should be expected to run first.
- AI enhancement adds candidates for review; it should not be treated as ground truth.
- AI-only candidates require analyst acceptance before they become case IOCs.
- Saved IOCs are durable case records in PostgreSQL.
- Event tagging and IOC sightings depend on ingested event data in ClickHouse.
- Threat intelligence enrichment is optional and separately gated.
- If AI services fail, deterministic IOC extraction can still proceed.
