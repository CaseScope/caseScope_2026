# IOC System

CaseScope's IOC system tracks indicators of compromise inside a case, prepares extracted indicators for analyst review, saves accepted indicators as durable case records, and uses those saved indicators for enrichment, event matching, and investigation pivots.

The system is designed around one trust rule: deterministic extraction provides the fast baseline, AI can suggest additional findings, and analysts decide what becomes part of the case IOC record.

## What The IOC System Stores

Saved IOCs live in PostgreSQL through `models/ioc.py`. Each IOC belongs to a case and includes:

- indicator value and normalized value
- IOC type and category
- match type for searching
- aliases for contextual matching
- notes and audit history
- legacy `sources` labels
- structured `source_metadata` contribution history

The legacy `sources` list is kept for compatibility and simple filtering. The structured `source_metadata` field records how each accepted IOC contribution entered the case, such as deterministic report extraction, AI semantic review, AI audit review, manual entry, or import.

AI review state is not stored as permanent top-level IOC state. Pending, accepted, and rejected AI suggestions live on `CaseIOCEnhancementRun.staged_candidates` until reviewed. Accepted AI candidates add a contribution record to the IOC. Rejected candidates remain in the enhancement run history and do not create or update IOC rows.

## Main IOC Workflows

CaseScope supports several IOC workflows:

- **Manual IOC management:** analysts add, edit, hide, or review case-scoped IOCs.
- **Report extraction:** CaseScope extracts candidate IOCs from EDR or analyst report text.
- **AI enhancement:** optional AI review stages extra candidates for analyst approval.
- **Find IOCs in events:** saved or detected IOCs are searched across event data.
- **Tag IOCs for case:** matching events and artifacts are marked so hunting views can show IOC context.
- **Threat intelligence enrichment:** saved IOCs can optionally be enriched through configured threat intelligence integrations.

The main routes are in `routes/iocs.py`. Background work runs through Celery tasks in `tasks/celery_tasks.py`, usually on the dedicated `ioc` queue.

## Extraction Overview

IOC extraction starts from report text stored on a case. The normal flow is:

1. The analyst opens IOC management and starts extraction for a report.
2. CaseScope queues `tasks.extract_iocs_from_report`.
3. The task runs deterministic extraction first.
4. Raw findings are normalized and converted into import-ready candidates.
5. Candidates are shown for analyst review.
6. Selected candidates are saved to the case IOC table.
7. Optional AI enhancement runs separately and stages AI-only suggestions.

This keeps extraction responsive and avoids making saved IOC state depend directly on model output.

## Deterministic Extraction

Deterministic extraction is the canonical baseline. It does not require AI and should be expected to run first.

The deterministic path uses regex patterns, type-specific normalization, and report-aware parsing to extract concrete values such as:

- MD5, SHA1, and SHA256 hashes
- IPv4 and IPv6 addresses
- domains and URLs
- email addresses
- Windows and Unix file paths
- file names
- registry keys
- SIDs and usernames
- hostnames
- services and scheduled tasks
- command lines
- credentials visible in command text
- CVEs and threat names

Important code areas:

- `utils/ioc_extractor.py` exposes the public extraction boundary.
- `utils/deterministic_ioc_extractor.py` runs the deterministic stage.
- `utils/ioc_regex_extractor.py` performs regex extraction.
- `utils/ioc_regex_catalog.py` stores regex patterns and type/category mappings.
- `utils/ioc_schema.py` creates internal records with provenance and trust information.

Deterministic extraction results are immediate candidates, not automatically saved. The analyst still chooses what to save.

## Import Preparation

After extraction, CaseScope converts raw findings into reviewable import rows through `process_extraction_for_import` in `utils/ioc_import_processing.py`.

This stage:

- deduplicates indicators
- maps extracted values to IOC types and categories
- validates and normalizes values
- creates aliases for paths and command lines
- checks whether the IOC already exists in the case
- prepares known-system and known-user actions
- attaches provenance and validation warning metadata

For example, a full file path may become a `File Name` IOC with aliases for contextual matching. A hostname can also produce a known-system action. A username can produce a known-user action.

## Saving Accepted IOCs

Accepted candidates are saved through `utils/ioc_persistence.py`.

Saving does several things:

- creates a new IOC or updates an existing case IOC
- preserves aliases and match type recommendations
- appends structured source metadata
- logs IOC audit entries
- creates or marks related known systems and users when selected
- triggers optional threat intelligence enrichment for newly created IOCs

The structured contribution metadata records fields such as:

- `source_engine`
- `source_route`
- `case_id`
- `report_index`
- `extraction_run_id`
- `task_id`
- `contribution_type`
- `review_result`
- `validation_status`
- `validation_warnings`
- `created_at`

This separates stable IOC state from the history of how the IOC was discovered or confirmed.

## AI Enhancement

AI enhancement is optional. It is a second-pass review layer, not the source of truth.

When enabled:

1. CaseScope still runs deterministic extraction first.
2. A durable `CaseIOCEnhancementRun` is created.
3. A background task runs the configured AI IOC pipeline.
4. AI output is validated, normalized, and guarded.
5. Candidates already found by deterministic extraction are removed.
6. AI-only candidates are staged as pending suggestions.
7. The analyst accepts or rejects each staged candidate.

Accepted AI candidates are saved through the same persistence path as deterministic candidates. Rejected AI candidates remain in the enhancement run and do not affect saved IOCs.

## AI Modes

CaseScope supports two AI extraction concepts:

- **Semantic extraction:** the report is split into targeted semantic tasks, such as users/accounts, process relationships, persistence, credentials/auth, and residual review.
- **Audit extraction:** AI reviews deterministic candidates and proposes additions, corrections, or drops.

The current workflow keeps AI mode configurable and does not require AI for baseline extraction. Audit mode is intended to be safer because it starts from deterministic candidates, but semantic mode can provide broader discovery in narrative-heavy reports.

Related code areas:

- `utils/semantic_ioc_extractor.py`
- `utils/ioc_audit.py`
- `utils/ioc_contract.py`
- `utils/ioc_contract_adapter.py`
- `utils/ioc_normalizer.py`
- `utils/ai/router.py`
- `utils/ai_review.py`

## AI Guardrails

AI output is treated as untrusted until it passes application checks.

Current guardrails include:

- schema validation against the IOC extraction contract
- route-specific field filtering for semantic tasks
- preservation of `affected_hosts` as contextual provenance
- validation warnings when disallowed route fields are stripped
- deterministic hash type correction by value length
- normalized exact command anchoring so inferred command lines are not staged as clean IOCs
- placeholder and invalid-value filtering
- deduplication against deterministic candidates
- non-blocking fallback when AI is unavailable or fails

For commands, AI-provided full command lines must be found in normalized source report text. If a model expands `msiexec.exe` into a full installer command that does not appear in the report, CaseScope records the rejection and keeps it out of import candidates.

For hashes, CaseScope uses value length to correct model mistakes:

- 32 hex characters means MD5
- 40 hex characters means SHA1
- 64 hex characters means SHA256

Corrections are carried as validation warnings.

## Event Matching And Tagging

Saved IOCs can be used to find matching evidence.

The `find_iocs_in_events` task scans ClickHouse event data for IOC-bearing events and prepares matching details. The `tag_iocs_for_case` workflow updates IOC state on events and artifacts so the hunting UI can show which records are associated with case IOCs.

This is separate from report extraction. Extraction creates or proposes IOC records. Event matching finds where accepted indicators appear in ingested evidence.

## Enrichment

Threat intelligence enrichment is separate from extraction. If configured and licensed, saved IOCs can be enriched through OpenCTI or other supported integrations.

Enrichment adds context to accepted IOCs. It does not decide whether an extracted candidate should become part of the case.

## Required Services

Core IOC workflows rely on:

- PostgreSQL for saved IOCs, audits, known users/systems, and enhancement runs
- Redis for Celery task progress and short-lived extraction results
- Celery workers listening on the `ioc` queue
- ClickHouse for event search and tagging workflows

AI enhancement additionally requires:

- AI feature availability
- a configured AI provider
- a reachable model/runtime
- applicable license activation

If AI is unavailable, deterministic extraction can still run.

## Practical Guidance

- Treat deterministic extraction as the baseline.
- Treat AI output as suggestions until reviewed.
- Save only analyst-approved candidates.
- Use `source_metadata` to understand how an IOC entered or was confirmed in a case.
- Use event matching after saving IOCs to locate related evidence.
- Use enrichment for added context, not acceptance decisions.
