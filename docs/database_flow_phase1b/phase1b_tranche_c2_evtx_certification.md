# Phase 1B Tranche C2 EVTX Certification Record

Status: CLOSURE PASS

## Scope

Tranche C2 certifies `EvtxECmdParser` for the Phase 1B manifest protocol:

- single-file EvtxECmd parsing;
- directory/group EvtxECmd parsing;
- Hayabusa enrichment and source attribution;
- bounded managed directory batching per CaseFile;
- managed directory failure to per-file managed recovery.

The source identity invariant remains:

```text
one CaseFile = one source generation = one deterministic per-source event sequence
```

`EvtxFallbackParser` remains uncertified and disabled for manifest ingest.

## Implemented Safety Work

- `EvtxECmdParser.supports_manifest_protocol = True`.
- `EvtxECmdParser.manifest_ordering_contract = evtx:evtxecmd-source-file-json-order:v1`.
- `EvtxFallbackParser.supports_manifest_protocol = False`.
- EvtxECmdParser version remains `EvtxECmdParser-2.2.3`.
- EvtxFallbackParser version remains `EvtxFallbackParser-1.0.2`.
- Hayabusa detections for one EVTX record are canonicalized by severity, rule file, rule title, and MITRE metadata without dropping detections.
- MITRE arrays are emitted in deterministic order for the same semantic detection set.
- EVTX `search_blob` key/value portions are emitted in sorted key order.
- EVTX `raw_json` and `extra_fields` serialization uses sorted keys.
- Managed EVTX parsing treats configured Hayabusa enrichment failure as fatal.
- Managed ingest captures a parser producer signature before parsing and verifies it after parsing.
- Managed EVTX group routing classifies members before legacy cleanup, refuses mixed managed/legacy groups, and never enters broad legacy cleanup for managed members.
- Managed directory ingest uses one directory tool invocation but owns generations, attempts, batches, verification, and projection independently per CaseFile.

## Producer Signature

Algorithm: `evtx-producer-signature:v1`

Compact signature on this host for `EvtxECmdParser-2.2.3`:

```text
evtx:v1:d7b2bd49aef76eefd29621701440d1e258d16158ffb8e9ef314db2585718c3c2
```

Observed inputs:

- EvtxECmd version: `2026.5.0+bfc7f47ccbf65ffc9a3777cde5498db2fdd94664`
- EvtxECmd binary SHA-256: `edb08da376a54e81295450183675ea08797ec067442c229ab39cf3b5068e1eba`
- EvtxECmd Maps digest: `a55ba58eb7a94e15d41e8600556c7fb4f3c11e11c54e7fe55681ccb7d41a51f0`
- Hayabusa version: `Hayabusa v3.7.0 - CODE BLUE Release`
- Hayabusa binary SHA-256: `9de4811539cf253fcc6f672624ad347af9ec7c46da1c3665760569c52b121772`
- Hayabusa rules digest: `32f881cf81063489fa839edb5753902b11385f6ef326d1044edad18244c75907`
- Hayabusa config digest: `c7b6ac9c02eb0c848b56915caf41263d6601575b5048a8e47f32964a3fabbd26`
- Hayabusa profile: `all-field-info-verbose`
- Hayabusa min level: `informational`
- Enrichment configured: `true`

Directory digests canonicalize relative paths, sort the path list, hash file content, and exclude runtime/cache files. Timestamps, process IDs, temp paths, hostnames, and attempt IDs are excluded.

## Real Corpus

Approved non-retained corpus:

```text
/opt/casescope-benchmark/phase0a_evtx
```

Authorization record: benign lab/test Windows event logs, not retained CaseScope evidence, authorized for disposable repeated benchmark processing.

Corpus size: 8 EVTX files, 77,103,104 bytes.

Full current single-vs-directory parity:

- single-file events: 110,742;
- selected eager-first/directory events: 110,742;
- single-file detections: 7,436;
- selected eager-first/directory detections: 7,436;
- parser errors: 0;
- parser warnings: 0;
- all 8 per-source row hash digests, batch IDs, batch hashes, and detection multisets matched.

## Group Invariance

The A/B/C matrix used:

- A: `Microsoft-Windows-WMI-Activity-Operational.evtx`, 1,118,208 bytes, 1,158 events, 323 detections.
- B: `Microsoft-Windows-TerminalServices-LocalSessionManager.evtx`, 1,118,208 bytes.
- C: `Microsoft-Windows-Windows-Defender-Operational.evtx`, 5,312,512 bytes.

A matched single-file identity in every case:

- A alone;
- A first in `[A,B]`;
- A last in `[B,A]`;
- A first in `[A,B,C]`;
- A middle in `[B,A,C]`;
- A last in `[B,C,A]`.

No post-parse sorting was added to force parity.

## Real PG/CH Managed Proof

Disposable resources:

- PostgreSQL database: `phase1b_c2_20260816015851`, dropped after proof.
- ClickHouse database: `phase1b_c2_20260816015851`, dropped after proof.

Managed success proof:

- files: WMI Activity + TerminalServices LocalSessionManager;
- events: 1,158 + 221 = 1,379;
- batch size: 500;
- generations: 2, both `BUILDING_INITIAL`;
- attempts: 2 `SUCCEEDED`;
- batches: 4, all `DURABLE`;
- `countDistinct(case_file_id)` per `ingest_batch_id`: max 1;
- producer version: `evtx:v1:d7b2bd49aef76eefd29621701440d1e258d16158ffb8e9ef314db2585718c3c2`.

Managed recovery proof:

- injected directory failure after a durable batch;
- broad `delete_file_events` was patched to raise if called and was not called;
- existing durable batches survived;
- per-file managed retry reused the same generations;
- final events: 1,379;
- generations: 2, both `BUILDING_INITIAL`;
- attempts: 2 `FAILED` directory attempts + 2 `SUCCEEDED` per-file retry attempts;
- batches: 4, all `DURABLE`;
- `countDistinct(case_file_id)` per `ingest_batch_id`: max 1.

## Performance

Measured on approved corpus:

- full current single-file parser proof: 132.410 seconds, 110,742 events, about 836 events/sec;
- selected eager-first plus directory parser proof: 90.098 seconds, 110,742 events, about 1,229 events/sec;
- A/B/C matrix directory runs: 6.128 to 10.089 seconds;
- real managed PG/CH success proof: 16.771 seconds for 1,379 events;
- real managed PG/CH injected recovery proof: 26.362 seconds for final 1,379 events.

Detailed stage timing continues to be emitted through existing `timed_stage` metrics for EvtxECmd, Hayabusa, transform, hashing, insert, verify, PG protocol, and projection.

## Fallback Parser Verdict

`EvtxFallbackParser` is NOT CERTIFIED for manifest ingest.

It remains a separate producer from EvtxECmdParser and has no manifest capability. An EvtxECmd-managed generation must not silently continue with EvtxFallbackParser.

## Verdict

PHASE1B_TRANCHE_C2_CLOSURE_PASS
