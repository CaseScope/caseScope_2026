# Pattern Check Inventory

## Status
Phase 1 input for Phase 4a implementation. The generator script is the authoritative source of truth for the check-level inventory.

## Source Anchors
- `_REFACTOR/session-f.md:57-157`
- `_REFACTOR/session-f.md:183-314`
- `utils/pattern_check_definitions.py` (2937 lines at audit time)
- `utils/pattern_event_mappings.py` (1618 lines at audit time)
- `utils/hayabusa_correlator.py` (745 lines at audit time)
- `utils/gap_detectors/` (1504 lines total at audit time)

## Locked Reframing
The atomic unit is the `check`, not the `pattern`.

Current live reality from Session F:
- effective unique pattern count: 42
- current live file contains a duplicate key:
  - `security_tool_tampering` at `utils/pattern_check_definitions.py:2117`
  - `security_tool_tampering` at `utils/pattern_check_definitions.py:2533`
- total checks are approximately 180 and must be regenerated from the source code rather than hand-maintained

Implication:
- Phase 4a is not a pattern-level cleanup
- Phase 4a is a check-level normalization and loader-design phase

## Conversion Summary Locked From Session F
- 12 patterns are Sigma-convertible or close enough to live as declarative sigma-pack rules
- 29 patterns remain Python verifiers because they depend on threshold, graduated, burst, or similar aggregation logic
- 1 current pattern entry is a duplicate key and should be removed during cleanup

## Loader Shape
The loader is dual-path, not purely declarative:
- declarative YAML or Sigma-style rules
- Python verifier registration for aggregation-heavy checks

This is the key planning consequence of the check-level reframing.

## gap_detectors Reality Check
`utils/gap_detectors/` exists, but the directory name is misleading.

Current contents:
- `behavioral_anomaly.py`
- `brute_force.py`
- `password_spraying.py`
- `__init__.py`

Session F conclusion:
- these are presence or stateful detectors, not a true gap-detector family
- true gap semantics currently live mainly in the `absence_with_coverage` check type inside `pattern_check_definitions.py`

Planning consequence:
- Phase 4a should rename or conceptually absorb `gap_detectors/` into stateful detectors
- the plan should stop treating `gap_detectors/` as its own clean conceptual category

## Pattern Overlay Quick Win
Session F identified the narrow TI leak:
- `utils/case_analyzer.py:869`
- `utils/case_analyzer.py:924`
- `utils/case_analyzer.py:1323`
- `utils/pattern_overlay.py:249`
- `utils/pattern_overlay.py:307`

This is not the main pattern-check normalization task. It is the small TI-separation quick win that should happen as its own phase after Phase 1.

## Inventory Regeneration
Authoritative regeneration command:

```bash
python3 scripts/refactor/inventory_checks.py
```

Outputs:
- `docs/refactor/pattern_check_inventory.csv`

## Current Verified Inventory Size
- Current generated CSV row count: `246`
- This is sharper than Session F's earlier approximate estimate of `~180` checks.
- Planning consequence: Phase 4a is larger than the earlier transcript-level estimate implied, and should be sized using the generated CSV rather than the transcript summary table.

## Spot-Check Result
Manual spot-checks against `utils/pattern_check_definitions.py` matched the generated CSV for sampled rows across:
- `ntds_credential_dump`
- `remote_registry_sam_access`
- `password_spraying`
- `log_clearing`
- `registry_run_keys`
- `certificate_installation`
- `domain_group_discovery`

This does not replace regeneration, but it is enough to treat the current CSV as trustworthy for planning purposes because the generator is deterministic and the sampled rows matched live code.

## Non-Negotiable Rule
Do not hand-edit the CSV and do not use prose summaries as the source of truth for check counts. The script and the live code are the source of truth.
