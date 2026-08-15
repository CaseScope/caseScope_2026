# CaseScope Database Flow Plan — v4 (LOCKED)

**Supersedes:** v1–v3. Incorporates all fourth-review corrections. This version is frozen; changes now go through the contract documents it mandates, not through plan revisions.
**Verified against live main** (4.18.5 / 8c4c1dd): selector_key as hunting/mutation API identifier; Qdrant point identity from selector; `delete_case_events` as guarded mutation (partition drop unrealized); analyst-state PG authority absent (no-op'd, state on `events`); ERK source-scoping via `case_file_id`; artifact dedup recipes containing `source_file`; Buffer's migration-fence role; pre-parse synchronous DELETE; **destructive rewrite guard fail-open by default when Redis is unavailable (unless `require_lock=True`)**.
**Engines:** PostgreSQL, ClickHouse, Redis, Qdrant — unchanged. Responsibilities move; products don't.
**Governing goal:** ingest maximally so the tech has tools ready to go, under readiness that is durable, generation-aware, hole-aware, publication-safe, and provably race-free (CMMC).

---

## Part I — Identity model

### Core identities (semantic)

**`evidence_record_key` (ERK)** — physical forensic source identity (Evidence Identity v2; source scope anchors on `case_file_id`). Never repurposed. Provenance, custody, evidence support.

**`logical_event_key` (LEK)** — cross-source logical equivalence. **New source-independent semantic identity contracts, informed by — not mechanically derived from — legacy `ARTIFACT_DEDUP_CONFIGS`** (legacy recipes are Phase 0 inputs only; several contain `source_file`, which a source-independent identity must exclude). Candidate EVTX recipe for Phase 0 study (not locked): canonical computer + channel + EventRecordID + timestamp + provider/event ID. Versioned: `lek:v1:<sha256>`, `logical_identity_version`, `logical_identity_quality`. Recipes lock only after Phase 0 collision/equivalence measurement per artifact.

**`source_generation`** — lifecycle identity over the generic source identity `(source_ref_type, source_ref_id, source_generation)` (CASE_FILE first; MEMORY_JOB, PCAP_FILE adopt the same contract later). A generation is a version of the authoritative interpretation of an evidence source.

**Generation visibility/publication states (NEW — resolves progressive-ingest vs reprocess conflict):**

```
BUILDING_INITIAL      no prior authoritative generation exists;
                      durable batches ARE progressively published
                      (first-ever ingest → search live per batch)

BUILDING_REPLACEMENT  a prior ACTIVE generation exists;
                      new generation builds INVISIBLY on the default
                      surfaces; old generation remains published;
                      ATOMIC authority swap on completion

ACTIVE                authoritative complete generation
SUPERSEDED            replaced by a newer ACTIVE generation
INVALIDATED           withdrawn (source deleted / interpretation revoked)
FAILED                build abandoned; never published
```

First ingest gets progressive publication; reprocessing never mixes half of generation 5 with half of generation 4 — the analyst surface flips atomically. This state machine is part of the Phase 0 generation lifecycle contract.

**`derivation_version`** — deterministic semantic interpretation version (`mitre-rules-v8`, `graph-events-v3`, `ioc-engine-v4`). Distinct from execution identity; existing UUID "scan versions" are run IDs, not semantic versions.

### Execution identities

**`ingest_attempt_id`** — one execution attempt at a generation. Crash/timeout/retry → same generation, new attempt. Parser/normalization/contract change or explicit reprocess → new generation.

**`ingest_batch_id`** — deterministic: `stable(case_id, source_ref_type, source_ref_id, generation, batch_ordinal)`, stamped on every CH event row — **plus an integrity contract (NEW):** the generation manifest **freezes for the life of the generation**: `parser_version`, `normalization_version`, `batching_contract_version`, `configured_batch_size`, `ordering_contract`. Every batch records `batch_content_hash`, `first_source_locator`, `last_source_locator`, `row_count`. Retry equivalence requires *same deterministic ID + same expected content hash*; **hash mismatch → fail closed, never treated as a retry** (a mid-generation batch-size or ordering change cannot silently alias a different payload under the same ordinal). This protects the Phase 1 batch-size benchmarking from undermining the ID scheme, and doubles as audit telemetry.

**`derivation_run_id`** — UUID per derivation execution; audit only. Versioned CH current-state facts carry `state_version UInt64` for replacement ordering.

**Idempotency:** `(ingest_batch_id, derivation_version)` per derivation class (Part VI). **Audit:** `derivation_run_id`.

**`principal_key`** — stable machine identity for users/systems; normalization mini-contract (case folding, DOMAIN\user vs UPN vs bare, SID-preferred) is a Phase 0 deliverable.

---

## Part II — Three visibility layers and two canonical surfaces

**Physical presence in `events` does not equal publication.** The architecture has three layers:

```
RAW PHYSICAL             events
                         may contain incomplete/staged batches and
                         building/superseded generations;
                         NEVER queried directly by product code

   ↓ durability + visibility filtering

PUBLISHED PHYSICAL       event_observations_current
                         all published ERKs (incl. multiple observations
                         of one logical event)
                         Consumers: provenance, custody, source support,
                         duplicate-evidence inspection

   ↓ LEK reconciliation

PUBLISHED LOGICAL        events_current
                         one current logical event per LEK, deterministic
                         canonical representative, conflict indicators
                         Consumers: hunting, detectors, profiles, patterns,
                         AI, timelines, search default
```

**Publication filtering requires BOTH control projections in ClickHouse (NEW — closes the partial-batch window):** a worker can die after 35k of 50k rows land while PG still says STAGED; generation filtering alone would publish those rows. PG remains authoritative; both are projected into CH (dictionary/JOIN/projection — benchmark):

```
visible_evidence_generations           durable_ingest_batches
────────────────────────────           ──────────────────────
case_id, source_ref_type/id            ingest_batch_id
generation, visibility state           source_ref + generation
state_version                          expected_row_count
(BUILDING_INITIAL published;           batch_content_hash
 BUILDING_REPLACEMENT hidden;          status = DURABLE
 ACTIVE published; others hidden)      state_version
```

Conceptually: `events ⋈ durable_ingest_batches ⋈ visible_evidence_generations` → `event_observations_current`. Partial/staged rows are harmless because they are unpublished; the reconciler cleans them at leisure. Reader migration to the two surfaces is a tracked workstream (Phase 0 inventory); after Phase 4 cutover, direct `events` reads in product code are a defect.

**LEK canonicalization contract (NEW — no `any()` semantics on the logical surface):**
- **Representative observation:** one physical ERK chosen deterministically per LEK for default display. Selection scoring (parser fidelity, field completeness, source quality, timestamp precision, parser version, deterministic ERK tie-break) is data-driven in Phase 0 and versioned with the LEK contract. Nondeterministic `any()`/merge-order-dependent field selection is prohibited on `events_current`.
- **Conflict surfacing, not hiding:** per LEK expose `observation_count`, `source_count`, `field_conflict`; provenance views show the differing values per field (e.g., `DOMAIN\jsmith` vs `jsmith`; `10:15:00.123` vs `10:15:00`). **Deduplication becomes evidence reconciliation, not evidence deletion** — a strict forensic improvement over today's destructive dedup.

---

## Part III — Storage authority model

| Data class | Authority |
|---|---|
| Raw / source-scoped forensic observation | ClickHouse |
| Machine-derived evidence fact at scale | ClickHouse |
| Machine aggregate / query projection | ClickHouse |
| Analyst decision / business transaction | PostgreSQL |
| Event-scale projection of analyst decision | ClickHouse projection; PG authority |
| Durable workflow / readiness / watermark / publication state | PostgreSQL (projected into CH for filtering) |
| Ephemeral progress, locks, cancellation, UI activity | Redis |
| Vector representations | Qdrant — obeying the same identity/lifecycle model |
| Secrets / credentials | Explicit security design; currently PostgreSQL |

**Qdrant lifecycle rule:** event vector payloads carry ERK, LEK, source_ref, `source_generation`, `derivation_version`, `embedding_version`; point identity migrates off selector (rides Phase 3.0). Default retrieval basis: one vector per LEK with provenance to ERKs (finalized in Phase 0 with the counting contract). Generation invalidation triggers point invalidation/reindex via existing payload indexes. Embedding jobs index only published batches.

---

## Part IV — Manifest + batch commit protocol

```
PG: reserve ingest_batch (deterministic ID + expected content contract) → STAGED
  ↓
CH: INSERT rows carrying ingest_batch_id (+ generation, attempt)
  ↓
verify batch in CH: presence, row_count, content hash contract
  ↓
PG: batch → DURABLE  (projection to durable_ingest_batches publishes it,
                      subject to generation visibility state)
  ↓
queue derivations per Part VI class
```

**Reconciler:** STAGED past deadline → check CH by deterministic ID → present + hash-correct: mark DURABLE, queue derivations; absent/partial/hash-mismatch: purge rows by batch_id, retry under new `ingest_attempt_id`, same generation and batch_id (hash mismatch against the frozen contract = fail closed, alert, human decision). Exactly-once is a property of this protocol, never of task-framework success.

PG manifest: `evidence_source_generation` (source_ref, generation, visibility state, frozen contract fields, producer_version, expected/landed rows, timestamps); `ingest_batch` (batch_id, source_ref, generation, ordinal, content hash, locators, row_count, status, attempt_id).

---

## Part V — Watermarks: contiguous, per-source, freeze-then-verify

Scalar "latest" watermarks are unsafe (holes: batches 101–102 ✓, 103 ✗, 104–105 ✓ → safe watermark 102). Authority is `case_capability_source_state` (case, capability, source_ref, generation, **contiguous_batch_ordinal**, derivation_version, status); `case_capability_state` is a derived UI summary, never a gate. (Equivalent alternative: monotonic case_ingest_sequence with contiguous-prefix advancement.)

**AI gating (CMMC — order is the security property):** select candidate evidence → **freeze** exact ERKs/batch IDs → **verify** alias-derivation coverage for those batches → alias payload → send. Readiness answers "are batches {17,18,22,27} covered by privacy derivation X?" — never "is the case ready?". Check-then-retrieve is prohibited. Covered-batch requests proceed while new files process.

---

## Part VI — Derivation classes

| Class | Examples | Idempotency boundary |
|---|---|---|
| Row-local | aliases, simple MITRE maps, IOC matches, most graph facts | `(batch_id, derivation_version)` |
| Additive aggregate | profile/principal contributions | `(batch_id, derivation_version)` contribution, per generation |
| Windowed / stateful | pattern detection, storyline, temporal correlation | `(window/checkpoint_id, derivation_version)` |
| Whole-source / whole-case | baselines, snapshots, finalization analyses | `(source_generation or case_snapshot, derivation_version)` |

Batch boundaries never silently become detection boundaries; windowed derivations checkpoint on contiguous watermarks and re-open windows when late batches fill holes. Derivations read published surfaces only.

---

## Part VII — Counting basis contract

Two independently captured 4625s = **2 physical observations, 1 logical failed logon**, everywhere, consistently:

| Product | Basis |
|---|---|
| Custody / provenance / audit | ERK |
| Evidence support strength | ERK observations + source diversity |
| Analyst timeline; search default | LEK |
| Behavioral event counts | LEK |
| Stateful / pattern detection | LEK |
| IOC provenance facts | ERK |
| IOC UI event counts | LEK |
| Graph relationship (topology) | canonical edge once |
| Graph support counts | ERKs and independent sources, separately |
| "Show all evidence observations" | ERK |

Every consumer names its basis at migration time. Ratified in Phase 0.

---

## Phase 0 — Measurement + correctness contracts

Baselines (multi-host case: ≥20 EVTX incl. large Security.evtx, memory image, PCAP): ingest wall-clock/GB and /M events; time-to-first-searchable; per-capability time-to-ready; hunt latency percentiles; IOC full-run; per-step completion timings.

Profiling/verification: pre-parse `delete_file_events(wait=True)` cost incl. zero-row mutation behavior and contention; `EXPLAIN indexes=1` on hunts and IOC predicates; py-spy on `parse_file_task`; CH partition/part census (gates per-table partition keys); duplicate classification (artifact; same/cross CaseFile; same/different ERK/generation; retry vs overlap) — gates LEK storage form; LEK recipe collision/equivalence studies; direct-`events`-reader inventory with target-surface assignment.

**Contracts ratified here (standalone repo docs, before dependent code):** LEK recipes + canonicalization/representative scoring + conflict semantics; principal_key normalization; generation lifecycle incl. visibility states; batch commit + integrity (frozen contract, content hash) + reconciliation; watermark contiguity; derivation classes; counting bases; Qdrant payload schema; ERK API contract; fence admission/draining + fail-closed policy.

Upgrade planning: CH ≥26.2 (26.3 LTS preferred) staged; 26.3 async-insert default noted — insertion mode is an explicit Phase 2 decision.

---

## Phase 1 — Immediate performance (current CH; no semantic changes)

**1.1** Per-event alias extraction out of `BatchProcessor.add_event` by refactoring the existing `populate_case_privacy_aliases()` distinct scanner to `(case_id, case_file_id=None, generation=None)` scope; independent per-column `DISTINCT` (never tuple-DISTINCT); `raw_json` stays excluded. Per-file initially; per-batch in 1B.
**1.2** `orjson` in JSONL hot loops.
**1.3** Remove forced-wide-part settings.
**1.4** Buffer removal — fence first (1.4a), then direct inserts; batch-size benchmark 10k/25k/50k/100k (note: production batch-size changes require a new generation per the frozen batching contract); remove Buffer references repo-wide; drop table + OPTIMIZE step.
**1.4a — Exclusive fence with drain, FAIL-CLOSED (strengthened):** normal writers acquire a shared ingest lease around INSERT; admin rewrite blocks new shared leases → waits active-writers = 0 → exclusive fence → recount → rewrite → recount → release. Extends the existing Redis guard **with the fail-open default removed for this architecture**: ordinary inserts fail/retry if admission control is unavailable (never bypass a possible active migration); administrative destructive operations REFUSE TO RUN without the exclusive lease. No fail-open path exists for operations whose correctness depends on the fence.
**1.5** IOC tagger: remove `lower()`; `raw_json` removal from the common path is **gated by recall parity** — legacy matched-ERK set A vs new set B; A − B empty or each miss classified/documented and fixed in blob builder/typed columns. Zero-false-negative correctness gate; recall beats speed.
**1.6** Profiler set-based rewrite preserving semantics (username-OR-SID principal relation; three-hostname role-tagged system relation; aggregate once).
**1.7** Hayabusa `-d`; detections keyed `(source_file, record_id)`; EvtxECmd directory mode per profile.
**1.8** Hot `JSONExtract*` inventory → typed-column promotion; `raw_json`/`extra_fields` remain fidelity.
**1.9** Pre-parse DELETE interim: existence-probe-then-skip (full fix = Phase 4 generations).

**Exit:** baselines re-run; ≥2× ingest on the EVTX case; flame graph clear of aliases/json; 1.5 recall gate green before common-path change ships.

---

## Phase 1B — Progressive orchestration (durable, batch-grained, publication-safe)

**1B.1** Stand up Part IV manifest + Part V watermarks + Part II control projections (`visible_evidence_generations`, `durable_ingest_batches`); Redis becomes ephemeral projection only.
**1B.2** Batch = readiness/publication unit under generation visibility rules: first-ingest (`BUILDING_INITIAL`) publishes durable batches progressively — a 12M-event file becomes searchable mid-parse; replacement builds stay hidden until atomic swap. File/generation = lifecycle unit.
**1B.3** AI gating per Part V freeze-then-verify; boolean readiness deleted from the design.
**1B.4** Completion task = reconciliation: Part IV reconciler + per-class derivation verification for all published generations/batches; re-queue gaps; finalize audit. Hard deliverable.
**1B.5** UI readiness strip from PG watermarks (Redis decorates); search-during-ingest shows a non-blocking coverage note.

---

## Phase 2 — ClickHouse modernization (two independent gates)

**GATE A (text index):** CH ≥26.2; DDL/tests/index migration verified. **GATE B (lightweight UPDATE):** version verified; block-number/block-offset settings enabled on `events` via migration; benchmark done.

**2.1** Text index on `search_blob`: tokenizer + `lower(...)` preprocessor (stored column untouched); term hunts via `hasAllTokens`/`hasAnyTokens`; LIKE for true substrings; drop both bloom indexes after `EXPLAIN` validation; evaluate `command_line` index; test `materialize_skip_indexes_on_insert=0`.
**2.2** Insertion mode chosen explicitly post-26.3 (sync 10–100k vs async + `wait_for_async_insert`), configured on the parser session/user.
**2.3** Lightweight UPDATE bridge (Gate B) for small state paths, batched; classic mutations behind the drain-capable fail-closed fence for large rewrites; audit hooks carried over. Bridge only.
**2.4** Dedup: no engine decision (RMT Option A remains removed). Interim = generation-aware accounting + deterministic-batch retry exclusion. Real design = Phase 4.

---

## Phase 3 — API identity migration + IOC overlay pilot

**3.0** ERK becomes the event API identifier: responses expose ERK; mutation endpoints accept ERK; UI sends ERK; `selector_key` temporarily accepted with server-side resolution; event-state authority stops depending on selectors; selector endures as display/search convenience. Qdrant point-identity migration rides this step.
**3.1** Full `IOCEvidenceMatch` contract → CH facts (IOC UUID, ERK, matched field/value, source refs, support_state lifecycle, observed time, + generation/derivation/run/state versions). Key `(case_id, ERK, ioc_uuid, matched_field)`; `event_ioc_current_summary` per ERK.
**3.2** Readers via `build_ioc_projection()`; lifecycle equivalence proven before authority transfer; stop mutating `events.ioc_types`.
**3.3** Overlay key rule: MITRE `(case_id, ERK, attack_id, source, rule_id)`; noise `(case_id, ERK, rule_id, rule_version)`; analyst-current `(case_id, ERK)` as PG-authority projection; version/lifecycle columns everywhere; summary projections prevent join multiplication.

---

## Phase 4 — Evidence identity & dedup model

**4.1** LEK computed at parse per locked recipes.
**4.2** Storage form from Phase 0 classification (thin LEK column + flag-gated collapse vs full logical/physical split). Duplicates represented, never destroyed; canonical representative + conflict surfacing per Part II; counting per Part VII.
**4.3** Part II surfaces + control projections live **before cutover**; readers migrated per inventory; `events` becomes internal (direct product reads = defect).
**4.4** Generation-based retry/reprocess live (CASE_FILE first) with visibility states; pre-parse synchronous DELETE removed from the parse path; superseded-generation cleanup is background.
**4.5** Whole-case dedup mutation pass deleted.
**4.6 — Events partition purge (reworded; a component, not "case deletion"):** validate replacing the current `delete_case_events` mutation with `DROP PARTITION` for the `events` physical table, and **integrate it into the coordinated whole-case deletion service** — it does not replace deletion/invalidation of the other evidence planes (observations, IOC/MITRE/noise facts, graph support, behavior contributions, memory/network evidence, Qdrant points, PG manifests/watermarks), some of which deliberately will not be case-partitioned. Potentially large win; validated separately.

---

## Phase 5 — Remaining overlays + cheap moves

**5.1** MITRE: `event_mitre_matches` authoritative; selector→ERK identity upgrade; generation/derivation/run/state versions; per-ERK summary; stop rebuilding arrays onto `events`.
**5.2** Noise: machine matches → CH facts; manual overrides → PG authority + CH projection, **with authority-bootstrap migration** (5.3 pattern).
**5.3** Analyst state — authority bootstrap (PG authority does not exist today): create PG decision/current-state tables → backfill from CH columns → validate ERK mapping → dual-write authority + projection → cut readers via `build_analyst_projection()` → freeze `events` columns.
**5.4** Candidate staging: in-memory if one task suffices; else CH TTL table `(analysis_id, pattern, ERK, role)`.
**5.5** Events immutability declared: zero UPDATE/ALTER UPDATE in telemetry; legacy columns frozen (dropped Phase 8).

---

## Phase 6 — Derived evidence plane (deletion-aware)

CH incremental MVs see inserts only → aggregates store per-source-generation contributions; reads aggregate active contributions; retraction = activation flip. Derivations read published surfaces; classes per Part VI; windowed work checkpoints on contiguous watermarks.

**6.1** Observed principals on `principal_key`, per-generation contributions; PG KnownUser/KnownSystem shrink toward curation referencing `principal_key`; eager PG rows retained until integer-ID consumers migrate.
**6.2** Behavioral profiles per-generation over 1.6 semantics; LEK basis; 1.6 queries as backfill/validation.
**6.3** Graph: per-batch CH extraction of deterministic typed facts into `graph_entity_observations` / `graph_relationship_support` (ERK-keyed, generation-carrying); canonicalization stays a bounded Python consumer initially; lifecycle parity with existing pending→invalidate/restore transitions via generation activation; counting per Part VII.
**6.4** Partition keys per table from the census; `case_id` partitioning retained for `events` (lifecycle + 4.6 purge path); not copied by default to fact/summary tables (generation-invalidation cleanup instead); decided per table by measurement.

---

## Phase 7 — Memory evidence migration (three-way benchmark)

ORM-current vs PG COPY/set-based vs CH bulk — separating wrong-mechanism from wrong-destination. Read-side workload is the stronger CH argument; migrate `memory_processes/network/services/malfind/modules/sids` with dual-read only if CH wins reads decisively; adopt `(MEMORY_JOB, id, generation)` lifecycle on migration. Credentials stay PG pending security review; jobs/info stay PG.

---

## Phase 8 — Cleanup (one-way doors)

Drop frozen `events` state columns and superseded PG machine-fact tables only after the full lifecycle test:
**ingest → hunt mid-ingest (BUILDING_INITIAL publication) → reprocess (BUILDING_REPLACEMENT + atomic swap) → delete file (generation invalidation + retraction) → rebuild derivations → delete case (coordinated: PG authority gone, events partition dropped, fact state inactive/gone, memory/network gone, Qdrant points gone, Redis keys gone, audit retained per policy) → report**
— verifying watermarks, publication filtering, overlays, aggregate retraction, canonical-representative determinism, conflict surfacing, counting bases, and audit at each step. Until then, every change retains a reversal path.

---

## Cross-cutting

**Measurement discipline:** baselines re-run at each phase exit; deltas in-repo; measurement beats plan. Benchmark-decided: LEK storage form, surface/projection implementations, partition keys, insertion mode, memory destination, graph SQL scope, partition-drop purge, batch sizes.
**Forensic integrity:** immutable events; ERK pure provenance; duplicates reconciled not destroyed; deterministic canonical representatives; publication ≠ presence; fail-closed fencing; recall-parity gates on detection-path changes; per-fact provenance with run IDs; audit hooks precede legacy removal.
**Out of scope:** no new engines; Redis coordination-only; credentials + alias vault in PG under existing controls.

## The locked core model

```
EVIDENCE SOURCE (source_ref_type, source_ref_id)
   ↓
SOURCE GENERATION — semantic interpretation + lifecycle
   BUILDING_INITIAL publishes durable batches progressively
   BUILDING_REPLACEMENT builds hidden; atomic swap on completion
   ↓
INGEST ATTEMPT — execution/retry identity
   ↓
DETERMINISTIC INGEST BATCH — batch_id + content_hash integrity
   PG: STAGED → DURABLE
   ↓
RAW EVENTS — may contain incomplete/staged/superseded data
   NEVER queried directly by product code
   ↓ durability + visibility filtering
EVENT OBSERVATIONS CURRENT — published physical ERKs
   ↓ LEK reconciliation
EVENTS CURRENT — published logical events
   deterministic canonical representative; conflict/provenance indicators
   ↓
VERSIONED DERIVATIONS — row / aggregate / window / snapshot
   ↓
CONTIGUOUS CAPABILITY COVERAGE — durable, hole-aware, freeze-then-verify
   ↓
TECH WORKS WHILE INGEST CONTINUES

PostgreSQL: authority, generations, publication, decisions, watermarks
ClickHouse: physical + logical evidence, machine facts, projections
Redis:      locks + ephemeral progress (fail-closed for fenced ops)
Qdrant:     vectors obeying the same ERK/LEK/generation lifecycle
```
