# ERK API Contract

Status: LOCKED for Phase 0B. No endpoint migration is implemented here.

## Current Baseline

- `events` contains `evidence_record_key`, `evidence_identity_version`, and `evidence_identity_quality`.
- `selector_key` is still a materialized identifier used by hunting, overlays, and Qdrant event vectors.
- `utils.event_selector.build_event_selector_key()` builds selector keys from `(record_id, source_file, source_host)` or timestamp/host/artifact/event/file fallback.
- `utils.clickhouse.get_event_by_evidence_record_key()` can resolve by case and ERK.

## Future API Semantics

- All new event responses expose `evidence_record_key` as `erk`.
- Event mutations accept ERK.
- UI sends ERK for event-state changes after migration.
- `selector_key` remains a temporary compatibility input only.
- Server resolves selector to ERK during compatibility.
- Durable event authority must not key new state on selector.
- ERK remains physical forensic source identity and must never be repurposed into logical identity.

## Selector Resolution

Selector resolution is scoped by `case_id`.

| Selector result | Server behavior |
|---|---|
| Zero ERKs | Return typed `not_found` error. Recommended HTTP status: 404. No mutation. |
| One ERK | Proceed by rewriting the request internally to ERK. Audit records original selector and resolved ERK. |
| Multiple ERKs | Return typed `ambiguous_selector` error. Recommended HTTP status: 409. Include count and safe diagnostic metadata, not raw evidence payload. No mutation. |

The server must never silently pick one ERK when selector mapping is ambiguous.

## Compatibility Stages

1. Stage 0 current: selector accepted and often primary; ERK exists for many rows.
2. Stage 1 dual response: every event response includes ERK and selector.
3. Stage 2 dual input: mutation endpoints prefer ERK, accept selector with explicit server resolution.
4. Stage 3 ERK authority: new state rows and overlays key by ERK; selector retained as display/search convenience.
5. Stage 4 deprecation: selector mutation input disabled after telemetry and migration acceptance.

## Error Shape

Future APIs should use a stable machine-readable error:

```json
{
  "success": false,
  "error_code": "ambiguous_selector",
  "message": "Selector matched multiple evidence records",
  "selector_key": "...",
  "match_count": 2
}
```

## Tests

- Responses expose ERK for event list/detail/export payloads.
- ERK mutation updates exactly one physical observation.
- Selector with zero matches returns `not_found`.
- Selector with one match resolves and audits.
- Selector with multiple matches returns `ambiguous_selector`.
- New durable state cannot be inserted with selector as the authority key.

## Explicit Open Items

- OPEN — ADDITIONAL MEASUREMENT REQUIRED: selector/ERK coverage and collision audit before Stage 2 rollout.
- NOT APPLICABLE: Phase 0B does not modify endpoints.
