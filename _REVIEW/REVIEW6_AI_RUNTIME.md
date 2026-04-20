# Review 6 — AI Runtime and Chat

Date: 2026-04-20

## Scope
Review the shared AI runtime and chat surfaces against the live repo, with emphasis on whether intended callers actually route through `utils/ai/router.py`, whether the L0/L1/L2/L3 chat dispatch state machine is implemented as documented, tool-dispatch safety (read-only defaults, approval boundaries, case-scope isolation, prompt-injection resistance), provenance threading through chat outputs, premium-gating consistency, and tool/subagent scoping.

## Review Outcome
- The named Phase 6 runtime callers are now on the shared router path, and Review 6 landed the remaining in-scope router-path fixes in `utils/semantic_ioc_extractor.py`, `utils/ioc_audit.py`, and `utils/ai_review.py` (`ef943b02`).
- The live chat surface is read-only only: the exposed `TOOL_DEFINITIONS` registry contains query/search/read tools only, and the route/session boundary keeps each conversation bound to `(case_id, user_id, conversation_id)`.
- Premium gating is internally consistent on the reviewed chat/runtime paths: `routes/chat.py` fails closed when AI is unavailable, `lookup_threat_intel` is tool-gated through `FeatureAvailability.is_chat_tool_feature_enabled()`, and `lookup_ioc` uses the shared IOC threat-intel gate for optional enrichment.
- L2/L3 permission handling is implemented and returns structured tool results for allow / interrupt / reject / feature-unavailable cases, but the documented L1 boundary is still incomplete in live code.
- The carried-forward provenance drift still survives direct verification: `ToolDispatcher._payload_provenance()` still falls back to policy provenance when emitted tags are missing or invalid.
- Review 6 also found and fixed a real chat-runtime provenance bug: repeated tool-call cache stubs were dropping the original emitted provenance and reverting to the policy default instead of preserving the prior tool result (`ef943b02`).
- No separate subagent runtime exists in the reviewed Phase 6 surfaces. In practice, the scoping question collapses to the chat tool registry only; report/timeline/checkpoint flows do not expose tool execution.

## Verified Behavior
- `utils/chat_agent.py`, `utils/ai_report_generator.py`, `utils/ai_timeline_generator.py`, `utils/ai_checkpoints.py`, `utils/rag_llm.py`, and the now-fixed `utils/ai_review.py` all use `utils/ai/router.py` entry points rather than acquiring providers directly.
- The carried-forward IOC sub-stage drift was real when Review 6 started: `utils/semantic_ioc_extractor.py` and `utils/ioc_audit.py` still called `provider.generate_json(...)` directly. Review 6 corrected both to use `invoke_json(function='ioc_extraction', provider=provider, ...)` (`ef943b02`).
- `routes/chat.py` does not trust the client to reopen arbitrary sessions: `_load_or_create_chat_session()` rejects conversation reuse across case/user boundaries, and tool-approval resumes are reconstructed from persisted interrupt history rather than free-form client-supplied tool names.
- `utils/chat_agent.py` always executes tools against the server-owned case context passed into `chat_stream()`, not a model-supplied case identifier.
- `utils/chat/policy.py` only exposes read tiers on the reviewed tool surface: safe reads auto-allow, selected sensitive reads interrupt for approval, and no write-tier tools are registered in `utils/chat_tools.py`.
- `utils/chat_tools.py` and `utils/forensic_chat_sources.py` do thread parser/producer provenance into payloads via `attach_payload_provenance(...)`, and successful tool results still surface that metadata through `ToolDispatcher.execute()`.

## Findings
### 1. `RISK` / `HIGH`
- Location: `utils/chat/dispatch.py:271`, `utils/chat_agent.py:875`, `utils/chat_tools.py:131`, `utils/chat_tools.py:493`
- Summary: the documented L1 schema / prompt-injection boundary is not actually implemented. Model-supplied tool arguments are JSON-decoded and passed straight into the registered Python callsites; many tools accept `**kwargs`, so unexpected or tainted keys can fail open instead of being rejected as invalid structured tool calls.
- Proposed fix: add strict request-shape validation against `TOOL_DEFINITIONS` before permission checks, reject unknown keys / missing required fields / obvious type mismatches as structured tool results, and make argument-provenance / injection checks explicit rather than policy-only. Rough effort: M.

### 2. `DRIFT` / `MEDIUM`
- Location: `utils/chat/dispatch.py:146`
- Summary: `DRIFT-PROVENANCE-L1-FALLBACK` still survives direct verification. Dispatch prefers producer-emitted `_provenance` when present and valid, but silently falls back to the policy default when tags are missing or invalid instead of enforcing producer-emitted provenance end to end.
- Proposed fix: either fail closed on missing/invalid emitted provenance for successful data-bearing tool payloads, or require all reviewed producers to emit valid provenance and treat absence as a structured runtime error. Rough effort: M.

### 3. `DRIFT` / `MEDIUM`
- Location: `utils/ai/router.py:303`, `utils/ai_providers.py:564`, `docs/refactor/agent_loop.md:119`
- Summary: the shared router still records runtime metadata only for `invoke_text()` / `invoke_json()`. The primary chat streaming path just yields provider chunks and does not record per-call duration or cache-efficiency metrics, so the locked Phase 6 cache/runtime instrumentation contract is still incomplete on the most important runtime surface.
- Proposed fix: wrap `stream_chat()` with the same runtime accounting used by `invoke_text()` / `invoke_json()`, capture a final usage/duration record when the provider finishes, and thread that metadata into the chat loop / aggregate metrics surface. Rough effort: M.

### 4. `DRIFT` / `MEDIUM`
- Location: `utils/ai_review.py:15`
- Summary: the lightweight review helpers previously bypassed the shared router/runtime whenever a provider instance was supplied, so provider metadata and runtime instrumentation were skipped on those review passes.
- Proposed fix: landed in this Review by routing provider-backed review calls through `invoke_text()` / `invoke_json()` while preserving the existing markdown-stripping fallback for providers that only expose plain-text generation. Rough effort: S. Commit: `ef943b02`

### 5. `DRIFT` / `MEDIUM`
- Location: `utils/semantic_ioc_extractor.py:189`, `utils/ioc_audit.py:626`
- Summary: `DRIFT-IOC-ROUTER-INSTRUMENTATION` survived direct verification at Review 6 start. Both IOC semantic/audit sub-stages still called `provider.generate_json(...)` directly after router resolution, bypassing the shared `invoke_json()` runtime path.
- Proposed fix: landed in this Review by routing both sub-stages through `invoke_json(function='ioc_extraction', provider=provider, ...)` so the shared runtime metadata and provider boundary are preserved. Rough effort: S. Commit: `ef943b02`

### 6. `CORRECTNESS` / `MEDIUM`
- Location: `utils/chat_agent.py:667`
- Summary: repeated tool-call cache stubs previously dropped the first tool result's emitted provenance and replaced it with the policy default, so a follow-up cached answer could appear `MODEL_SYNTHESIZED` even when the original tool result was `ARTIFACT_TAINTED` or `ELEVATED_RISK`.
- Proposed fix: landed in this Review by preserving the original tool result provenance when emitting `ToolResultBlock.reused_result(...)` for repeated tool calls. Rough effort: S. Commit: `ef943b02`

## Code Changes Landed During Review 6
- `utils/ai_review.py`
  - routed provider-backed text/JSON review passes through the shared AI router so review helpers no longer bypass runtime metadata and provider instrumentation (`ef943b02`)
- `utils/semantic_ioc_extractor.py`
  - switched semantic IOC task execution from direct `provider.generate_json(...)` calls to `invoke_json(function='ioc_extraction', provider=provider, ...)` (`ef943b02`)
- `utils/ioc_audit.py`
  - switched IOC audit chunk execution from direct `provider.generate_json(...)` calls to `invoke_json(function='ioc_extraction', provider=provider, ...)` (`ef943b02`)
- `utils/chat_agent.py`
  - preserved the original tool result provenance when emitting repeated-result cache stubs so cached follow-up calls no longer downgrade provenance (`ef943b02`)
- `tests/test_phase6_ai_router_contract.py`
  - added source-contract coverage proving the IOC semantic/audit sub-stages now import and use `invoke_json(...)` rather than direct provider JSON calls (`ef943b02`)
- `tests/test_phase6_chat_agent_runtime_flow_contract.py`
  - added a regression covering provenance preservation on repeated tool-call cache stubs (`ef943b02`)

## Verification Run
- `SECRET_KEY=test-secret python3 -m unittest tests.test_phase6_ai_router_contract tests.test_phase6_ai_review_runtime_contract tests.test_phase6_chat_agent_runtime_flow_contract tests.test_forensic_chat_tools`
- Result: `OK` (31 tests)

## Review 7 / 8 Hand-off
- Review 7 should assume the chat/runtime router boundary is now consistent for the reviewed Phase 6 callers, including IOC semantic/audit sub-stages and `utils/ai_review.py`.
- Review 7 should still not assume L1 schema validation or provenance enforcement is complete: the dispatcher/runtime remains permissive on malformed or untagged tool payloads unless a specific producer emits valid `_provenance`.
- Review 8 / 10 should revisit chat-stream runtime metrics if future rollout/ops decisions depend on real cache-hit or stable-prefix telemetry from the streaming chat surface.
