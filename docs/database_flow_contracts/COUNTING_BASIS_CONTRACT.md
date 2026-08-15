# Counting Basis Contract

Status: LOCKED for Phase 0B. Consumer mapping is machine-readable in `counting_basis_consumers.json`.

## Basis Rules

| Basis | Applies to |
|---|---|
| ERK | Custody, provenance, audit, IOC provenance, evidence-source support, duplicate-observation inspection, physical graph support rows. |
| LEK | Default analyst timeline, default hunt event count, search default, behavioral counts, stateful detections, pattern detections, IOC UI logical count, default AI event context. |
| CANONICAL_EDGE | Graph topology relationship once. Topology consumers read graph tables, not ClickHouse `events`. |
| OTHER | Administrative tools, migrations, source/file metadata, vector catalog sync, caller-governed helpers, or mixed non-event surfaces. |
| UNRESOLVED | Explicit blocker for the phase that migrates that consumer. No silent default is allowed. |

## Ratified v4 Matrix

- Two independently captured 4625s are `2` physical observations and `1` logical failed logon when LEK recipe says they are the same logical event.
- Custody/provenance/audit count by ERK.
- Evidence support strength uses ERK observations and source diversity separately.
- Analyst timeline/search/hunt defaults count by LEK.
- Behavioral, stateful, and pattern detections count by LEK.
- IOC provenance facts count by ERK; IOC UI event counts count by LEK.
- Graph relationship topology counts canonical edge once; support observations count ERKs and independent sources separately.
- "Show all evidence observations" counts by ERK.

## Consumer Mapping Summary

Location-level accounting over the 167 Phase 0A `phase0a_reader_id` values. Set equality is required; `sum(counts) == 167` is not sufficient.

| Basis | Direct reader locations (`phase0a_reader_id` count) |
|---|---:|
| ERK | 28 |
| LEK | 102 |
| CANONICAL_EDGE | 0 among `events` readers |
| OTHER | 37 |
| UNRESOLVED | 0 |
| Total | 167 |

`CANONICAL_EDGE = 0` in this inventory because graph topology views do not query `events`. The basis rule remains locked for those non-`events` consumers. All seven graph `events` readers are ERK observation/support.

The 227+ embedded detection query strings are governed by their owning reader IDs (`P0A-R022`, `P0A-R156`, `P0A-R023`) and default to LEK when migrated to `events_current`.

## Contract Blockers

No production consumer remains `UNRESOLVED` in Phase 0B. If implementation discovers an unmapped direct `events` reader, that migration phase is blocked until it is added with a new ID and both consumer JSON files are updated together.

## Tests

- Analyst default count uses LEK.
- IOC provenance returns ERK observations.
- IOC UI logical count uses LEK.
- Graph topology count and graph support count remain distinct.
- Administrative/raw readers cannot leak into product default counts after Phase 4 cutover.
- CT-044: `set(phase0a_reader_ids) == set(event_surface_reader_ids) == set(counting_basis_reader_ids)` with zero missing, extra, or duplicate IDs.

## Explicit Open Items

- OPEN — ADDITIONAL MEASUREMENT REQUIRED: physical-vs-logical count deltas after LEK computation exists.
- NOT APPLICABLE: Phase 0B does not implement LEK-counting surfaces.
