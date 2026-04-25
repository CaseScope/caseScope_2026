# Review 7b — Routes and Request Surface

Date: 2026-04-20

## Scope
Review the route/request surface for query construction, helper boundaries, response serialization, and `routes/findings.py` unified-read wiring across `routes/*.py`, `routes/route_helpers.py`, and `routes/hunting_query_helpers.py`.

## Review Outcome
- Review 7b verified that `routes/findings.py` is registered in `app.py` and does serve the canonical unified-read payload, but the live hunting UI still fetches the legacy `/api/rag/unified-findings/<case_id>` path. This Review kept the legacy RAG route as a compatibility wrapper over the canonical serializer so the two route surfaces no longer drift.
- Review 7a's `RISK-HIGH` RAG case-authorization drift survived direct verification in 7b scope. Multiple case-scoped RAG read endpoints still queried by raw `case_id` without resolving through `Case.get_by_id(...)`; Review 7b landed the route-level fix.
- Review 7a's `DRIFT-HUNTING-TYPE-FILTER-SQL` also survived direct verification in 7b scope. The live events grid and export-view route were still building overlapping-but-different query/search/time clauses inline. Review 7b landed shared hunting helpers so both surfaces now parameterize artifact types, share one search parser, and fail closed on invalid alert/time filters instead of silently broadening reads.
- `DRIFT-IOC-SHORT-TAG-IDENTITY` still does not materially survive Review 7b route/read/presentation scope. The hunting query/read surfaces only test IOC presence via `length(ioc_types) > 0`, not exact IOC identity.
- `GAP-SCORE-DISPLAY-CONTRACT` remains visible on the live route/read/presentation surface: the unified findings route payloads and the hunting UI still converge on normalized `confidence`/`severity` display, not on a shared analyst-facing score presentation contract.

## Findings
### 1. `RISK` / `HIGH`
- Location: `routes/rag.py:275`, `routes/rag.py:332`, `routes/rag.py:391`, `routes/rag.py:540`, `routes/rag.py:813`, `routes/rag.py:837`, `routes/rag.py:931`, `routes/rag.py:1102`, `routes/rag.py:2307`, `routes/rag.py:2633`
- Summary: several case-scoped RAG read endpoints still loaded rows directly by numeric `case_id` and bypassed the shared `Case.get_by_id(...)` access path. Those routes therefore did not inherit the same case-authorization contract as the safer route surfaces verified in Review 7a.
- Proposed fix: landed in this Review by adding a shared route helper for case resolution and applying it across the affected RAG read endpoints, with all downstream queries using the resolved case id. Rough effort: M. Commit: `cd99df29`

### 2. `CORRECTNESS` / `MEDIUM`
- Location: `routes/hunting.py:195`, `routes/hunting.py:912`, `routes/hunting_query_helpers.py`
- Summary: the live hunting grid and export-view route still owned separate copies of search/type/time/alert query construction. Export-view therefore lagged the live grid's richer search semantics, `types` still interpolated raw values into SQL, invalid custom time windows still widened queries by silently dropping the filter, and alert-mode params still treated any non-`"exclude"` token as opt-in.
- Proposed fix: landed in this Review by moving shared filter/search builders into `routes/hunting_query_helpers.py`, parameterizing artifact types, validating alert/time modes, reusing the same search parser for grid + export, and returning structured 400s for invalid filter input. Rough effort: M. Commit: `cd99df29`

### 3. `DRIFT` / `MEDIUM`
- Location: `routes/findings.py:11`, `routes/rag.py:813`, `static/templates/case_hunting.html:260`, `static/templates/case_hunting_network.html:104`
- Summary: the canonical findings route is registered and live, but the current UI still calls the legacy RAG unified-findings endpoint instead of the canonical `/api/findings/list/<case_uuid>` surface. The codebase therefore still carries two public read routes for the same payload contract.
- Proposed fix: partially landed in this Review by making the legacy RAG route call the canonical serializer so the response shape stays aligned. Remaining work is to migrate live callers to the canonical route and retire the compatibility wrapper afterward. Rough effort: M.

### 4. `GAP` / `MEDIUM`
- Location: `routes/findings.py`, `routes/rag.py:813`, `static/templates/case_hunting.html:283`, `static/templates/case_hunting_network.html:126`
- Summary: Review 7b confirmed that the live unified findings read/presentation surface still exposes only normalized `confidence` and `severity` display. The Scoring 2.0 compact analyst/LLM score display contract is not yet represented as a shared route serialization surface.
- Proposed fix: add one shared presentation payload for analyst-facing score display fields and migrate both findings consumers and case-analysis views onto it. Rough effort: M.

## Code Changes Landed During Review 7b
- `routes/route_helpers.py`
  - added `_load_case_or_404(...)` so case-scoped routes can reuse the shared access-controlled lookup without duplicating 404 handling
- `routes/findings.py`
  - added `_build_unified_findings_payload(...)` so the canonical findings surface owns the shared unified-read serializer
- `routes/rag.py`
  - enforced shared case resolution on the affected case-scoped RAG read endpoints and made the legacy unified-findings route delegate to the canonical findings serializer
- `routes/hunting_query_helpers.py`
  - added shared parameterized type/time/search builders and stricter alert-filter validation for hunting read routes
- `routes/hunting.py`
  - switched both the live grid and export-view route onto the shared hunting query helpers and made invalid filter input fail with structured 400 responses
- `tests/test_query_hardening_regressions.py`
  - added regression coverage for parameterized hunting type filters, alert-mode validation, time-range validation, and shared mixed-OR search parsing; refreshed the `query_events()` fixture to the live 17-column fallback contract
- `tests/test_route_security_regressions.py`
  - added regression coverage for RAG read-route case resolution and the shared unified-findings payload wrapper

## Verification Run
- `venv/bin/python -m unittest tests.test_query_hardening_regressions tests.test_route_security_regressions`
- Result: `OK` (27 tests)

## Review 7b Hand-off
- Review 7 is complete. The remaining route-adjacent cleanup is now cross-cutting rather than route-local:
  - migrate live callers from `/api/rag/unified-findings/<case_id>` to the canonical `/api/findings/list/<case_uuid>` route, then retire the compatibility wrapper
  - decide whether `GAP-SCORE-DISPLAY-CONTRACT` should ship as a shared response contract or remain a template-local presentation concern
  - keep `DRIFT-JSON-403-ERROR-SHAPE` owned by Review 10; Review 7b did not find a new route-local fix beyond the already-known shared `abort(403)` model path
