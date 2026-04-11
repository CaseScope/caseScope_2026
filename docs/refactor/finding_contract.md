# Finding Contract

## Status
Phase 1 input. This document is a locking spec, not a brainstorming note.

## Source Anchors
- `_REFACTOR/session-f.md:159-181`
- `_REFACTOR/session-f.md:335-371`
- `utils/unified_findings.py` (327 lines at audit time)
- `utils/hayabusa_correlator.py` (745 lines at audit time)
- `utils/case_analyzer.py` (1738 lines at audit time)

## Purpose
Define the minimum stable finding shape that all deterministic producers and later enrichment layers converge on.

This contract is intended to stop schema churn during Phases 2 through 8. If a producer needs extra data, it writes to `detector_metadata` instead of forcing a new top-level field.

## Locked Invariants
- There is one unified finding contract and one downstream read path.
- Deterministic producers write the detector-of-record output.
- AI and TI layers annotate findings; they do not replace the original detector output.
- Producer-specific overflow goes into `detector_metadata`.
- Readers must treat `detector_metadata` as opaque unless they are the producer-specific consumer that wrote it.

## Required Finding Fields
These names come from Session F's Hayabusa-to-Finding translation and are the stable starting set for Phase 1:

- `rule_pack`
- `rule_id`
- `name`
- `severity`
- `confidence`
- `mitre_techniques`
- `event_ids`
- `host`
- `user`
- `process`
- `first_seen`
- `last_seen`
- `dedup_key`
- `detector_metadata`
- `ai_triage`
- `ti_enrichment`

Phase 1 may add surrounding identity or case-scoping fields needed by the live codebase, but these names are the locked baseline and must not be casually renamed.

## detector_metadata
`detector_metadata` is the one additive extension field explicitly carried forward from Session F.

Purpose:
- hold producer-specific metadata that does not belong in the locked top-level contract
- avoid repeated top-level schema churn
- preserve information from Hayabusa, TI rules, and stateful detectors without forcing every consumer to understand every producer

Expected examples:
- Hayabusa:
  - `chain_id`
  - `tactic_progression`
  - `correlation_key`
  - `rule_level`
  - `hayabusa_rule_author`
  - `eventdata_raw`
- TI rule sync:
  - `ti_valid_until`
  - `indicator_source`
  - `indicator_id`
- Stateful detectors:
  - detector kind
  - correlation window
  - triggering bucket or burst metadata

Contract rule:
- writers may write structured JSON into `detector_metadata`
- readers must not depend on any producer-specific key unless they are the producer-specific consumer for that producer

## Confidence Discipline
- `confidence` is the detector-of-record confidence.
- AI output must not overwrite `confidence` directly.
- TI overlays must not overwrite `confidence` directly.
- AI adjustments belong under `ai_triage`, for example `ai_triage.confidence_delta`.
- TI adjustments belong under `ti_enrichment`, for example `ti_enrichment.confidence_delta`.

This keeps the original detector signal auditable even when later layers disagree with it.

## Dedup Discipline
- `dedup_key` is a stable hash-based identity for a logically equivalent finding.
- Producers may use different inputs to derive it, but the output must be deterministic and stable for the same input set.
- Session F's Hayabusa example used a stable hash over `rule_id + host + user + timestamp_bucket_5m`. That exact recipe is not locked globally, but the deterministic-hash approach is.

## Producer Mapping Notes
- Hayabusa must map into the unified finding contract rather than emitting a separate correlated-detection-group shape.
- Stateful detectors must emit findings that match the same contract rather than bespoke gap-detection objects.
- TI rule sync emits findings using the same contract as built-in deterministic rules.
- AI triage consumes the unified finding contract rather than a producer-specific variant.

## Open Questions Reserved For Phase 1
- Final ClickHouse column typing for `detector_metadata`:
  - JSON string
  - map-like structure
  - equivalent supported by the chosen finding table design
- Exact case-scope fields that must be part of the contract for storage and query purposes
- Final field names for host and process identity if the current live codebase requires slightly different names for compatibility

## Non-Negotiable Rule
If a future producer needs more fields, add them to `detector_metadata` first and justify any new top-level field explicitly in Phase 1 review.
