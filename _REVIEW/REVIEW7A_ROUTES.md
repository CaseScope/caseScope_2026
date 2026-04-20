# Review 7a — Routes and Request Surface

Date: 2026-04-20

## Scope
Review the route/request surface for auth and license-gating consistency, input validation (especially `case_id` and query params), and error-response shape consistency across `routes/*.py`, `routes/route_helpers.py`, and `routes/hunting_query_helpers.py`.

## Review Outcome
- Most route modules consistently require `@login_required`, and the safer case-scoped pattern is `Case.get_by_id(...)` / `Case.get_by_uuid(...)`, which enforces `current_user.can_access_case(...)` through `models/case.py`.
- Review 7a landed the highest-confidence in-scope fixes in `8aed0596`: viewer-blocking on the remaining hunting write routes, the live `noise_matched` column fix for manual bulk noise tagging, admin/body validation on AI provider model fetching, integer validation on chat `case_id`, and auth-before-query ordering on hunting noise stats.
- `DRIFT-IOC-SHORT-TAG-IDENTITY` does not materially survive Review 7a's auth/gating/input-validation/error-shape scope: the reviewed hunting alert-type filter only checks `length(ioc_types) > 0`, not exact IOC-type identity. Revisit it in Review 7b only if a read/search/presentation surface treats `ioc_types` as canonical IOC evidence.
- `GAP-SCORE-DISPLAY-CONTRACT` was not resolved in Review 7a. It remains a Review 7b concern on response serialization / presentation surfaces, not on the route auth-validation layer itself.

## Findings
### 1. `CORRECTNESS` / `HIGH`
- Location: `routes/hunting.py:926`
- Summary: the manual bulk noise-tag route updated `events.is_noise`, but the live hunting, task, and deterministic-query surfaces all read and write `events.noise_matched`. Manual route-driven noise tagging therefore drifted from the actual authoritative column and could fail to suppress noise in downstream reads and detections.
- Proposed fix: landed in this Review by switching the bulk update route to `noise_matched = true` and adding a regression asserting the emitted ClickHouse update uses the live column. Rough effort: S. Commit: `8aed0596`

### 2. `RISK` / `HIGH`
- Location: `routes/analysis.py:97`, `routes/analysis.py:381`, `routes/analysis.py:507`, `routes/iocs.py:193`, `routes/iocs.py:305`, `routes/iocs.py:410`, `routes/known_users.py:48`, `routes/known_users.py:134`, `routes/known_systems.py:48`, `routes/known_systems.py:134`, `routes/case_files.py:474`, `routes/case_files.py:504`, `routes/case_files.py:576`, `routes/case_files.py:694`
- Summary: viewer-write policy is inconsistent across the route surface. Some modules explicitly fail viewers closed (`routes/hunting.py`, `routes/archive.py`, `routes/reports.py`, `routes/network_hunting.py`, `routes/noise.py`), but several other write/task-triggering case routes still allow any authenticated case viewer to start analyses, mutate IOCs, mutate known users/systems, and trigger case-file maintenance flows.
- Proposed fix: introduce a shared route-level write guard for case mutations/task triggers and apply it consistently to all mutating case routes, not only selected blueprints. Rough effort: M.

### 3. `RISK` / `HIGH`
- Location: `routes/rag.py:274`, `routes/rag.py:327`, `routes/rag.py:382`, `routes/rag.py:796`, `routes/rag.py:832`
- Summary: several case-scoped RAG read endpoints query by numeric `case_id` directly and never resolve the case through `Case.get_by_id(...)`. That bypasses the shared `_enforce_access(...)` path entirely, so these routes do not inherit the same case-authorization contract as the safer route surfaces.
- Proposed fix: require a resolved `Case.get_by_id(case_id)` before any case-scoped RAG query or aggregation, then use the resolved case object's id for downstream queries. Rough effort: M.

### 4. `RISK` / `MEDIUM`
- Location: `routes/ai.py:212`
- Summary: `POST /api/settings/ai/fetch-models` was gated only by login + active AI license, yet it could fall back to decrypting persisted provider keys from `SystemSettings` when the caller omitted an API key. That exposed a provider/network action using stored secrets to any licensed authenticated user, and malformed/non-dict request bodies would fail late instead of returning a clear client error.
- Proposed fix: landed in this Review by requiring administrator access and rejecting non-JSON-object request bodies before any provider selection or stored-key fallback. Rough effort: S. Commit: `8aed0596`

### 5. `CORRECTNESS` / `MEDIUM`
- Location: `routes/chat.py:155`
- Summary: `POST /api/chat/stream` accepted untyped JSON `case_id` values and passed them straight into `Case.get_by_id(...)`. Malformed client payloads could therefore fall through to model lookup behavior instead of failing with a structured 400.
- Proposed fix: landed in this Review by coercing `case_id` to `int` up front and returning `{"success": false, "error": "case_id must be an integer"}` on invalid input. Rough effort: S. Commit: `8aed0596`

### 6. `CORRECTNESS` / `MEDIUM`
- Location: `routes/hunting.py:46`
- Summary: `GET /api/hunting/noise/stats/<case_id>` executed ClickHouse counts before verifying the case exists and before triggering shared case-access enforcement. Unauthorized or stale-case requests still touched the analytical store before the route could fail.
- Proposed fix: landed in this Review by resolving the case first and only querying ClickHouse after the route has either returned a structured 404 or passed the shared access check. Rough effort: S. Commit: `8aed0596`

### 7. `RISK` / `MEDIUM`
- Location: `routes/hunting.py:224`, `routes/hunting.py:256`, `routes/hunting_query_helpers.py:230`
- Summary: the hunting event surface still has weak query-param validation. The `types` query parameter is concatenated directly into an `artifact_type IN ('...')` fragment, custom time-range parse failures silently drop the intended time filter instead of failing closed, and alert-type filters treat any value other than `"exclude"` as opt-in.
- Proposed fix: validate `types` against an allowed artifact list or parameterize each value, reject invalid custom time windows with a 400 instead of silently broadening the query, and normalize alert filter enums to an explicit allowlist. Rough effort: M.

### 8. `DRIFT` / `MEDIUM`
- Location: `models/case.py:170`, `routes/hunting.py:117`, `routes/rag.py:207`
- Summary: JSON route error shapes are not fully consistent even on the reviewed surface. Most routes return `{"success": false, "error": ...}`, but shared case access enforcement still uses `abort(403)` (HTML by default), while async status endpoints mix `success`-based and `state`-only payloads.
- Proposed fix: move case-access denial onto a JSON-aware exception/handler path for API blueprints and standardize task-status envelopes across route modules. Rough effort: M.

## Code Changes Landed During Review 7a
- `routes/hunting.py`
  - authorized `get_noise_stats(...)` before querying ClickHouse, blocked viewers on the remaining hunting write routes, and aligned manual bulk noise tagging with the authoritative `noise_matched` column (`8aed0596`)
- `routes/ai.py`
  - restricted provider model fetching to administrators and rejected non-dict JSON request bodies before using stored provider credentials (`8aed0596`)
- `routes/chat.py`
  - enforced integer validation for `case_id` on the chat streaming route so malformed requests fail with a structured 400 (`8aed0596`)
- `tests/test_route_security_regressions.py`
  - added regression coverage for the new hunting viewer guards, the `noise_matched` update contract, chat `case_id` validation, and the AI fetch-models admin gate (`8aed0596`)

## Verification Run
- `venv/bin/python -m unittest tests.test_route_security_regressions`
- Result: `OK` (16 tests)

## Review 7b Hand-off
- Re-audit all case-scoped RAG read routes against the canonical `routes/findings.py` path; Review 7a verified multiple `case_id`-only query paths that bypass `Case.get_by_id(...)`.
- Pick up the unresolved hunting query-param / query-construction drift (`types`, custom time range, alert filter enums) as part of Review 7b's query-construction/helper-boundary scope.
- Keep `GAP-SCORE-DISPLAY-CONTRACT` open for the Review 7b response-serialization/presentation pass.
- Do not carry `DRIFT-IOC-SHORT-TAG-IDENTITY` forward into 7b unless a concrete route/search/presentation surface is shown to treat `events.ioc_types` as exact IOC identity rather than non-empty IOC presence.
