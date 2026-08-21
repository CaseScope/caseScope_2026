# Phase 1B Tranche E2 AI Privacy Freeze → Verify → Alias → Send

## Scope

E2 completes locked Tranche E. It installs the exact-evidence privacy protocol:

retrieve/select → freeze the exact evidence set → verify `privacy_aliases` / `privacy-aliases:v1` coverage for that frozen set → alias that frozen payload → send only that aliased payload.

E2 does not start Tranche F or G. It does not implement readiness UI, completion-tail conversion, `events_current`, LEK reader cutover, graph/Qdrant lifecycle, or MEMORY_JOB/PCAP protocol.

E1 remains the watermark authority. `case_capability_source_state` and `case_capability_batch_completions` are authoritative. Batch completion means every event in that DURABLE batch was scanned for alias candidates. It does not mean every ERK has a `PrivacyAlias` row.

## Strict E2 Feature Flag

`PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED`

Default: **OFF**

When OFF, accepted pre-E2 production behavior is preserved: `AIPrivacyContext.case_content(case_id)` plus `sanitize_for_ai_egress`.

When ON, remote/cloud CASE-CONTENT egress must use the strict protocol. There is no fail-open fallback inside strict mode. Freeze or verification failure blocks the provider call.

## Local vs Remote Provider Policy

Local providers may continue to receive local case content without cloud alias/freeze requirements because data never leaves the host. This preserves the current privacy policy.

Locality uses the existing trustworthy helpers:

- `provider_type() == local`
- `OpenAICompatibleProvider._is_local_endpoint()` for localhost / RFC1918 hosts

An openai-compatible URL is not treated as local merely because the API looks local. If locality cannot be proven, E2 treats the endpoint as remote and fails closed.

## Frozen Evidence Representation

`FrozenAIEvidenceSet` is an immutable request-scoped identity of the exact selected evidence. It stores:

- `case_id`
- selected ERKs
- selected `ingest_batch_id`s from the physical rows
- source identity / generation
- generation `state_version` observed at freeze
- selected evidence count
- required capability / derivation version
- frozen-at timestamp
- canonical identity fingerprint

Raw event bodies are not written to PostgreSQL to freeze identity. Request-local `payload_excerpt` values travel with the freeze object only.

`VerifiedFrozenEgressProof` can be created only by `verify_frozen_privacy_coverage`. Callers cannot construct `verified=True`. `AIPrivacyContext.case_content(case_id)` is not coverage. `AIPrivacyContext.verified_case_content(case_id, proof)` is the verified context.

## Freeze Point / Retrieval Provenance

Freeze happens where candidate evidence is selected. The retrieval result carries ERK, `ingest_batch_id`, source identity, and generation forward.

`select_current_generation_event_rows()` queries ClickHouse once for the current default generation only:

- ACTIVE if present
- otherwise BUILDING_INITIAL when no replacement is open
- never BUILDING_REPLACEMENT, SUPERSEDED, FAILED, or INVALIDATED

The router does not retrieve or rediscover evidence from text.

## ERK / Batch Identity Consistency

E2 freezes the `ingest_batch_id` from the selected physical row. It does not re-derive batch identity from ERK when the selected row already has a batch id.

During freeze construction, ERK, `ingest_batch_id`, `case_id`, source identity, and `source_generation` are checked against PostgreSQL ingest-batch/generation authority. Inconsistent or cross-case provenance fails closed.

## Exact Privacy Coverage Verification

Verification uses E1 `verify_capability_batch_coverage()` for the exact frozen managed batch ids.

Every frozen managed batch must be DURABLE and covered under `privacy_aliases` / `privacy-aliases:v1` for that exact case/source/generation/batch.

One uncovered batch blocks the entire request. Covered A/B are not sent while C is uncovered.

STAGED batches block remote egress. D2 may later mark the batch DURABLE. D2 never records privacy coverage. A later request must retrieve/freeze again.

## Derivation Version Isolation

`privacy-aliases:v1` coverage does not satisfy `privacy-aliases:v2`. No version aliasing.

## Generation Authority / state_version Proof

Default freeze uses current generation authority only. BUILDING_REPLACEMENT privacy progress cannot satisfy ACTIVE authority before activation.

After `N -> SUPERSEDED` and `N+1 -> ACTIVE`, a new request uses N+1 only. Incomplete N+1 coverage does not fall back to N.

The freeze stores generation `state_version`. Final router preflight revalidates that authority. If generation visibility or `state_version` changed, the stale request is blocked. The caller must retrieve/freeze again. No PostgreSQL transaction is held across the provider network call.

Invalidation after verify also fails at the provider-boundary preflight.

## Final Provider-Boundary Preflight

`utils/ai/router.py` (`invoke_text`, `invoke_json`, `stream_chat`) is the last point before `generate` / `generate_json` / `stream_chat`.

In strict E2 remote CASE-CONTENT mode the router requires:

- a verifier-issued frozen proof
- matching case scope
- required derivation version
- exact coverage revalidation
- unchanged raw-payload fingerprint
- valid current generation/watermark authority

A route that forgets to verify cannot bypass this gate.

**Can a remote CASE-CONTENT call reach the provider in strict E2 mode without a valid frozen/verified evidence context? NO.**

## E2 CLOSURE — FAIL-CLOSED PRECHECK INFRASTRUCTURE

Independent review found a real fail-open defect after the original `PHASE1B_TRANCHE_E2_PASS` report.

### Original fail-open defect

`utils/ai/router.py` `_strict_e2_preflight()` wrapped the enforcement import in:

```text
try:
    from utils.ai_privacy_freeze import (...)
except Exception:
    return None, {}
```

If strict E2 was enabled and `utils.ai_privacy_freeze` could not be imported, the router treated the result as "no proof required" and continued toward sanitizer/provider invocation.

### Root cause

The router learned `PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED` only after a successful import of the enforcement module. Import failure therefore disabled the gate.

### Corrected router behavior

The router now reads `Config.PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED` directly. It does not import `utils.ai_privacy_freeze` to decide whether strict mode is on.

- STRICT OFF: accepted pre-E2 behavior is preserved.
- STRICT ON + provably local (`provider_type() == local` under the trusted fallback): local policy is preserved even if the E2 module cannot load.
- STRICT ON + explicit `non_content_admin` / `test_only`: no forensic E2 proof is required. `privacy_context=None` is not treated as non-case.
- STRICT ON + remote / openai / claude / unproven openai-compatible / unknown / uncertain + CASE CONTENT: any inability to import or run E2 preflight BLOCKS. Unknown locality never fails open.

There is no `except Exception: return None, {}` path that disables the gate.

### Import failure behavior

`StrictE2PreflightUnavailable` / `e2_enforcement_unavailable` is raised before `generate`, `generate_json`, or `stream_chat`. Provider invocation count is 0. No raw prompt leaves the process.

### Internal preflight infrastructure failure

If the module imports but `get_preflight_session`, `require_remote_case_content_preflight`, or an equivalent authoritative lookup fails, the failure becomes `preflight_infrastructure_failure`. It is never converted into "no proof required."

### Follow-on proof inheritance audit

Repo-wide, `inherit_verified_proof_for_followon_payload()` is called only from `utils/ai_review.py` second-pass review (`review_text_output`, `review_structured_output`). It is not used by:

- chat tool results
- RAG retrieval
- report/timeline first-pass retrieval
- correlation / event-summary / subagent / checkpoint retrieval

The helper now constrains inheritance to `followon_kind=second_pass_review` only. It re-runs exact coverage/state validation, binds the new payload fingerprint, and BLOCKS when the follow-on payload:

- has a tool/function retrieval shape
- introduces ERK / `ingest_batch_id` identities outside the frozen set
- uses any other follow-on kind

**Can newly retrieved forensic evidence be sent by merely rebinding an older proof? NO.**

### User-text / zero-batch audit

Zero batches is not a universal bypass.

- Genuine `user_text` only may proceed under current sanitizer policy.
- Non-event case metadata is blocked (`non_event_metadata_unsupported`).
- Forensic evidence with missing batch provenance is `legacy_unprovable_evidence`.
- Empty static payload is `empty_forensic_universal_bypass`.
- Setting `user_text_present=True` while including forensic observations does not convert those observations into a user-text proof.

**Can an empty/user_text proof bypass forensic or non-event metadata policy? NO.**

### New closure tests

- E2 module import failure for `invoke_text`, `invoke_json`, and `stream_chat`
- `privacy_context=None` is not non-case under import failure
- authoritative preflight / session infrastructure failure
- unknown provider type / uncertain locality
- local-provider and non-case admin regressions, including under import failure
- sanitizer-unavailable remote block retained
- inherit cannot bind new forensic identities or tool retrievals
- multi-round chat: proof A cannot cover newly retrieved evidence B; a new freeze may proceed
- user-text / missing-batch / metadata audits

### Real PostgreSQL / ClickHouse rerun

Closure re-runs the original disposable PG/CH success and failure matrix: certified managed IIS fixture → generation → DURABLE batches → `privacy-aliases:v1` → watermark → select → freeze → exact verify → alias → capturing remote provider. TOCTOU activation/invalidation and new-ingest-after-freeze remain 0-expansion / 0-call gates.

## Freeze → Verify → Alias → Send Ordering

1. Select evidence
2. Freeze membership and bind request-local excerpts
3. Verify exact E1 coverage
4. Bind the raw provider payload fingerprint
5. Router revalidates
6. Existing `sanitize_for_ai_egress` aliases the same payload
7. Provider receives only that aliased object

Aliasing is transformation, not coverage proof. Successful replacement count is not treated as coverage.

## Actual Provider-Bound Payload Proof

Success tests inspect the exact object passed to a capturing remote provider. Sensitive source values must be replaced, no post-freeze rows may appear, and static instructions remain intact.

A later reconstructed/ requeried payload cannot be sent under an older fingerprint.

## New-Ingest-After-Freeze Race

Rows arriving after freeze cannot expand the outbound request. The proof may revalidate the frozen ids only. New evidence appears only in a future request with a new freeze.

**Can rows arriving after freeze expand the outbound request? NO.**

Retry behavior: an uncovered freeze is not silently sent later. The caller must call `verify_frozen_privacy_coverage` again on the **same** `FrozenAIEvidenceSet` after coverage exists. No re-retrieve.

## Invalidation / Activation TOCTOU

Invalidation or replacement activation after verify blocks the stale proof at the provider boundary.

## Replacement Generation Behavior

Default retrieval/freeze uses published N while N+1 is BUILDING_REPLACEMENT, even if N+1 privacy is COMPLETE.

After activation, new requests resolve N+1. Incomplete N+1 blocks remote egress.

## Legacy / Mixed Evidence Policy

Legacy sources cannot be proven by the E1 exact-set mechanism. E2 does not fabricate coverage or backfill generations.

If a frozen set includes forensic evidence from a legacy/unprovable source, strict E2 remote egress is blocked.

A mixed managed+legacy candidate set is blocked. The managed subset is not sent unless the user selected that subset before freeze.

Because the flag defaults OFF, this is a rollout limitation, not a production behavior change.

## Non-Event Metadata / User Text Policy

Event-batch coverage does not protect arbitrary PostgreSQL case metadata (case name, description, analyst notes, known systems/users, file metadata, stored findings).

In strict E2:

- forensic events require exact batch coverage
- user-entered text may be sent only as an explicit `user_text` freeze with no fabricated ERKs; the sanitizer still runs
- non-event case metadata fails closed until a dedicated privacy mechanism exists
- zero batches is not a universal bypass
- static/non-case admin/test scopes remain outside CASE-CONTENT

Mixed user text + frozen forensic evidence: verify the evidence set and sanitize the whole provider-bound payload.

## Streaming / Multi-Round Tool Calls

`stream_chat` applies the same proof before the first provider/streaming call. Failed preflight yields zero provider chunks.

A later tool call that retrieves new case evidence requires a new selection, freeze, and exact coverage verification. The first verified proof cannot be reused for newly retrieved evidence. Fingerprint mismatch blocks reuse.

## Review / Report / Timeline / Subagent Propagation

Second-pass review may inherit the same frozen identity for a new payload fingerprint via `inherit_verified_proof_for_followon_payload`. It does not retrieve new evidence and does not rehydrate identifiers before a later cloud pass.

Report, timeline, checkpoint, correlation, RAG, chat, and subagent paths all go through the shared router. In strict E2 they fail closed unless they carry a valid proof. Review/report/timeline/checkpoint now pass the same privacy context into the second pass so a verified proof can follow the draft.

Rehydrate only for authorized local display after provider response.

## Error Contract

`AIPrivacyPreflightError` reasons include:

- `missing_frozen_evidence_proof`
- `uncovered_batch`
- `staged_batch`
- `wrong_derivation_version`
- `legacy_unprovable_evidence`
- `generation_authority_changed`
- `generation_invalidated` / `generation_superseded` / `generation_failed`
- `cross_case_or_malformed_freeze`
- `sanitizer_failure` (existing `PrivacyEgressLeakError`)
- `provider_locality_uncertain`
- `payload_fingerprint_mismatch`
- `empty_forensic_universal_bypass`
- `non_event_metadata_unsupported`
- `e2_enforcement_unavailable`
- `preflight_infrastructure_failure`
- `followon_new_forensic_evidence`

Messages do not include raw case content.

## AI Auditability

Existing `ai_audit_log` remains the audit authority. Privacy metadata now records:

case id, function, provider locality/type, strict E2 enabled, frozen evidence fingerprint, ERK count, batch count, source generations, required capability/version, verification passed/failed, failure reason, aliased, aliases applied, final outbound payload fingerprint, provider invoked, occurred_at.

Blocked preflight writes `privacy_preflight_failed`. Audit write failure does not fail open into a provider call.

Raw unaliased evidence is not stored in a new E2 audit table.

## Race Tests

- New durable batch after freeze does not expand the sent payload
- Completing coverage after a failed verify requires an explicit re-verify of the same freeze
- Invalidation after verify blocks the provider
- Replacement activation after verify blocks the stale N request

## Real PostgreSQL / ClickHouse Proof

E2 acceptance uses disposable real PostgreSQL and ClickHouse with the certified-managed IIS parser fixture. No real cloud provider is called. A capturing remote provider records the exact outbound object.

## Performance

Measured on a representative IIS managed freeze (12 events, 3 durable batches) against disposable PostgreSQL and ClickHouse:

| Step | Value |
|---|---|
| Frozen event count | 12 |
| Frozen batch count | 3 |
| Freeze construction | 28.17 ms |
| Exact coverage verification | 13.98 ms |
| Alias + final preflight (includes existing sanitizer/vault upsert) | 258.71 ms |
| PostgreSQL queries during freeze | 3 |
| PostgreSQL queries during verify | 4 |
| ClickHouse queries during freeze | 1 |

No per-ERK N+1 lookups. Coverage verification queries only the frozen batch/generation identities. No case-wide requery after freeze. The largest share of pre-provider time is the existing alias sanitizer, not the E2 coverage gate.

## Final Tranche E Assessment

E1 durable per-source capability watermarks, contiguous prefix, derivation/generation isolation, incremental `privacy_aliases:v1`, and exact batch-set coverage remain in place.

E2 adds retrieve → freeze → verify exact coverage → alias → send.

Correctness does not rely on a case-wide "AI ready" boolean.

## No-F / No-G Audit

- readiness UI: no
- completion-tail conversion: no
- `events_current`: no
- LEK reader cutover: no
- graph Phase 6 lifecycle: no
- Qdrant lifecycle migration: no
- MEMORY_JOB/PCAP protocol: no

## AI Egress Inventory

All production LLM egress is intended to pass `utils/ai/router.py`. Direct eval-only Ollama HTTP in `utils/ioc_model_eval.py` is not a production CaseScope path.

| Path | API | Case content | Evidence source | Strict E2 when flag ON |
|---|---|---|---|---|
| `invoke_text` / `invoke_json` / `stream_chat` | central router | caller-dependent | caller-dependent | remote CASE-CONTENT requires verified freeze |
| Chat / `_stream_llm_chat` | `stream_chat` | yes | CH tools + PG case context | fail closed unless each round has a new proof after new evidence |
| RAG ask / event-summary / review-events | `invoke_text` | yes | CH events + PG | fail closed without freeze |
| AI correlation | `invoke_json` | yes | CH evidence package | fail closed without freeze |
| Report / timeline / event summary | `invoke_text` + review | yes | CH tagged events | fail closed; review can inherit a proof |
| Checkpoints / case narrative | `invoke_json` + review | yes | aggregated PG/CH | fail closed; review can inherit a proof |
| Subagents | `invoke_text` | yes | parent-provided | fail closed without freeze |
| IOC semantic / audit / contract review | `invoke_json` | EDR/report text | PG, not event batches | fail closed as unprovable/non-event unless a user-text/metadata policy applies |
| `rag_llm` wrappers | `invoke_text` / `invoke_json` | caller-dependent | caller-dependent | same router gate |
| Provider health / model list | no prompt egress | no | settings only | not CASE-CONTENT |
| Local embeddings | not LLM chat | n/a | n/a | out of scope |

When the flag is OFF, these paths keep current production behavior.
