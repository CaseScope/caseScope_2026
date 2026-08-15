# Canonical Event Surface Migration

Status: LOCKED for Phase 0B. This converts the Phase 0A reader inventory into the implementation migration matrix.

## Surfaces

| Surface | Meaning |
|---|---|
| `events` | Raw physical/internal only. Product code must not read this directly after Phase 4 cutover. |
| `event_observations_current` | Published physical ERKs, including multiple observations for one LEK. |
| `events_current` | Published logical LEKs with deterministic representative and conflict/provenance metadata. |

Administrative and migration tooling may retain approved direct `events` access. After Phase 4 cutover, direct product reads from raw `events` are a defect.

## Reader Accounting

Phase 0A source authority is `docs/database_flow_phase0/events_reader_inventory.json` plus the Phase 0A full-scan rule: unique production `file::function` locations that contain `FROM events` / `JOIN events`, excluding `tests/` and `scripts/`.

Each location has a stable `phase0a_reader_id` `P0A-R001` .. `P0A-R167`, assigned by sorting `(file, function)`.

Validation is **set equality**, not summed group counts:

```text
set(phase0a_reader_ids)
== set(event_surface_reader_ids)
== set(counting_basis_reader_ids)
```

| Future surface | Direct reader locations (`phase0a_reader_id` count) |
|---|---:|
| `events_current` | 102 |
| `event_observations_current` | 28 |
| `events` administrative/raw | 37 |
| Unresolved | 0 |
| Total | 167 |

The embedded query libraries remain separately accounted and do not add extra IDs. Their owning function/module locations are already in the 167:

| File | Embedded queries | Owning reader ID | Future surface |
|---|---:|---|---|
| `models/pattern_rules.py` | 75 | `P0A-R022` | `events_current` |
| `utils/pattern_check_definitions.py` | approximately 136 | `P0A-R156` | `events_current` |
| `models/rag.py` | 16 | `P0A-R023` | `events_current` |

Graph topology (`CANONICAL_EDGE`) is a counting-basis rule for graph views that do not query `events`. Direct graph `events` readers are ERK observation/support.

Machine-readable records are in `event_surface_consumers.json`: one record per `phase0a_reader_id` with file, function/location, query purpose, future surface, counting basis, migration phase, risk, and required regression test IDs.

## Regression Requirements

- Product readers use `events_current` or `event_observations_current` after cutover.
- Administrative raw access is allowlisted.
- Logical default counts reconcile to LEK.
- Physical evidence/provenance lookups reconcile to ERK.
- Graph topology and support counts remain distinct (topology is not an `events` reader).
- AI/RAG retrieval follows freeze-then-verify, generation filters, and published Qdrant epochs.
- CT-044 proves set equality of the 167 IDs with no missing, extra, or duplicate IDs.
