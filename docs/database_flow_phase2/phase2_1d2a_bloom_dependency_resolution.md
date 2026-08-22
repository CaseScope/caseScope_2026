# Phase 2.1D2A Bloom Dependency Attribution and Text-Index Replacement Feasibility

Measurement artifact: `docs/database_flow_phase2/phase2_1d2a_bloom_dependency_resolution.json`.

**Tranche verdict: PHASE2_1D2A_PASS**

Phase 2.1D remains **PHASE2_1_NOT_READY**. D2A did not drop indexes, did not
change production readers, did not alter EVENTS_SCHEMA, did not bump version,
and cannot itself close Phase 2.1.

## 1. Starting state

- HEAD: `078895225eef7f9d08ac8372d7754583b1d1575f`
- origin/main: `078895225eef7f9d08ac8372d7754583b1d1575f`
- HEAD == origin/main: True
- Starting working tree was clean. D2A then added only allowed measurement tests and evidence files.
- Version: 4.25.2 (unchanged)
- Python: `/opt/casescope/venv/bin/python`
- Deployed ClickHouse: 26.7.3.19

Phase 2.1D NOT_READY / BLOOM_DEPENDENCY_BLOCKS_EXIT is preserved.
Accepted 2.1 results were not reopened: TOKEN_SAFE grammar, ASCII-only boundary,
publication bridge, export publication gate, command_line DEFER,
KEEP_PRODUCTION_MATERIALIZE_SKIP_INDEXES_ON_INSERT_1.

## 2. Production index state

Read-only. No production mutation, DROP INDEX, MATERIALIZE INDEX, or OPTIMIZE.

| Index | Expression | Type | Granularity | Compressed bytes |
|---|---|---|---:|---:|
| `idx_search_blob_text` | `search_blob` | `text(tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob))` | 100000000 | 14,603,118,274 (13.60 GiB) |
| `idx_search_ngram` | `search_blob` | `ngrambf_v1(3, 512, 2, 0)` | 4 | 4,049,580 (3.86 MiB) |
| `idx_search_token` | `search_blob` | `tokenbf_v1(32768, 3, 0)` | 4 | 964,699,630 (920.01 MiB) |
| `idx_event_id` | `event_id` | `bloom_filter(0.01)` | 4 | 9,913,034 (9.45 MiB) |
| `idx_selector_key` | `selector_key` | `bloom_filter(0.01)` | 4 | 453,214,994 (432.22 MiB) |
| `idx_evidence_record_key` | `evidence_record_key` | `bloom_filter(0.01)` | 4 | 886,609,005 (845.54 MiB) |

- rows 745,463,991 / active parts 135 / partitions 25
- events compressed 123,153,313,168 (114.70 GiB)
- coverage partitions MATERIALIZED 25 / PARTIAL 0 / UNMATERIALIZED 0 / UNKNOWN 0
- active parts MATERIALIZED 135 / 135
- mutations in progress: 0
- disk free: 74,767,876,096 (69.63 GiB) on `/var/lib/clickhouse/`

Locked text-index expression/type PRESENT:
`search_blob` / `text(tokenizer='splitByNonAlpha', preprocessor=lower(search_blob))`.
Server stores GRANULARITY 100000000.

## 3. Exact search_blob predicate inventory

Repository search covered LIKE / ILIKE / lower(search_blob) LIKE / hasToken /
hasTokenCaseInsensitive / position / positionCaseInsensitive / match.
No `match(search_blob)` production readers were found.

Classification of files that mention search_blob predicates:

- **background-derivation**: `models/rag.py`, `utils/candidate_extractor.py`, `utils/incident_storyline_detector.py`, `utils/ioc_artifact_tagger.py`, `utils/mitre_attack_sync.py`, `utils/mitre_procedure_rules.py`, `utils/pattern_check_definitions.py`, `utils/sigma_converter.py`
- **historical-docs**: `docs/database_flow_phase0/clickhouse_query_baseline.md`, `docs/database_flow_phase0/events_reader_inventory.md`, `docs/database_flow_phase0/phase0a_runtime_closure_report.md`, `docs/database_flow_phase1/phase1_exit_report.md`, `docs/database_flow_phase1/phase1_step3_report.md`, `docs/database_flow_phase1/phase1_step5_candidate_fields.md`, `docs/database_flow_phase2/phase2_1a_text_index_deployment.md`, `docs/database_flow_phase2/phase2_1b_text_index_rollout.md`, `docs/database_flow_phase2/phase2_1c_hunt_token_cutover.md`, `docs/database_flow_phase2/phase2_1c_live_activation.md`, `docs/database_flow_phase2/phase2_1d_final_exit.md`, `docs/database_flow_phase2/phase2_entry_gates.md`
- **offline-admin**: `bin/database_flow_baseline.py`, `migrations/add_events_search_blob_text_index.py`, `migrations/backfill_search_blob_keyvalue.py`, `scripts/phase2_1d2a_bloom_dependency_resolution.py`, `scripts/phase2_entry_gate_qualify.py`
- **other**: `casescope_database_flow_plan_v4_locked.md`, `models/ioc_evidence_match.py`, `utils/ioc_match_provenance.py`, `utils/ioc_timeline_builder.py`, `utils/phase1_step3_ioc_recall.py`, `wiki/NetworkHunting.md`, `wiki/artifact-hunting.md`, `wiki/artifact-uploads.md`, `wiki/noise-tagging.md`
- **production-required**: `models/network_log.py`, `models/pattern_rules.py`, `routes/hunting.py`, `routes/hunting_query_helpers.py`, `utils/chat_tools.py`, `utils/forensic_chat_sources.py`
- **test-only**: `tests/phase2_1d2a_lib.py`, `tests/test_forensic_chat_tools.py`, `tests/test_graph_phase0e_contracts.py`, `tests/test_graph_support_lifecycle.py`, `tests/test_ioc_artifact_tagger.py`, `tests/test_network_log_ip_display.py`, `tests/test_noise_keywords.py`, `tests/test_phase1_step3.py`, `tests/test_phase2_1a_text_index_materialization.py`, `tests/test_phase2_1c_hunt_token_cutover.py`, `tests/test_phase2_1d2a_bloom_dependency_resolution.py`, `tests/test_phase2_1d_final_exit.py`, `tests/test_phase2_entry_gates.py`

Production required vs background:

- production required: Hunt TOKEN_SAFE (`hasAllTokens`/`hasAnyTokens`), Hunt ILIKE substring,
  Hunt detail `position(e.search_blob)`, `models/pattern_rules.py` detection_query,
  chat `positionCaseInsensitive`, network_logs ILIKE (separate table).
- background derivation: IOC tagger `hasTokenCaseInsensitive` / `lower(search_blob) LIKE`,
  Sigma `search_blob ILIKE`, noise keywords, candidate extractor, MITRE sync, RAG,
  pattern_check_definitions.
- offline/admin: baseline scripts, migrations, phase2 materializer.
- test-only / historical docs: tests and `docs/database_flow_phase2/*`.

`models/pattern_rules.py` has **148** distinct search_blob predicate shapes.
They are not merely 'similar LIKE'. Case-sensitive `search_blob LIKE` shapes:

- `search_blob LIKE '%.7z%'` — data_staging — SAFE_LOGICAL_PREFILTER_NO_TEXT_PRUNE alnum `7z` len 2
- `search_blob LIKE '%.ps1%'` — service_persistence — SAFE_LOGICAL_PREFILTER_NO_TEXT_PRUNE alnum `ps1` len 3
- `search_blob LIKE '%.rar%'` — data_staging — SAFE_LOGICAL_PREFILTER_NO_TEXT_PRUNE alnum `rar` len 3
- `search_blob LIKE '%.tar%'` — data_staging — SAFE_LOGICAL_PREFILTER_NO_TEXT_PRUNE alnum `tar` len 3
- `search_blob LIKE '%.zip%'` — data_staging — SAFE_LOGICAL_PREFILTER_NO_TEXT_PRUNE alnum `zip` len 3
- `search_blob LIKE '%0x0%'` — asrep_roasting — SAFE_LOGICAL_PREFILTER_NO_TEXT_PRUNE alnum `0x0` len 3
- `search_blob LIKE '%0x1010%'` — credential_dumping_lsass — SAFE_TEXT_PREFILTER alnum `0x1010` len 6
- `search_blob LIKE '%0x1038%'` — credential_dumping_lsass — SAFE_TEXT_PREFILTER alnum `0x1038` len 6
- `search_blob LIKE '%0x143A%'` — credential_dumping_lsass — SAFE_TEXT_PREFILTER alnum `0x143A` len 6
- `search_blob LIKE '%0x17%'` — kerberoasting — SAFE_TEXT_PREFILTER alnum `0x17` len 4
- `search_blob LIKE '%0x1F0FFF%'` — process_injection — SAFE_TEXT_PREFILTER alnum `0x1F0FFF` len 8
- `search_blob LIKE '%0x1FFFFF%'` — credential_dumping_lsass — SAFE_TEXT_PREFILTER alnum `0x1FFFFF` len 8
- `search_blob LIKE '%ADMIN$%'` — lateral_tool_transfer, psexec_remote_service — SAFE_TEXT_PREFILTER alnum `ADMIN` len 5
- `search_blob LIKE '%C$%'` — lateral_tool_transfer — SAFE_LOGICAL_PREFILTER_NO_TEXT_PRUNE alnum `C` len 1
- `search_blob LIKE '%DCOM%'` — dcom_lateral_movement — SAFE_TEXT_PREFILTER alnum `DCOM` len 4
- `search_blob LIKE '%IPC$%'` — psexec_remote_service — SAFE_LOGICAL_PREFILTER_NO_TEXT_PRUNE alnum `IPC` len 3
- `search_blob LIKE '%Kerberos%'` — pass_the_ticket — SAFE_TEXT_PREFILTER alnum `Kerberos` len 8
- `search_blob LIKE '%NTLM%'` — pass_the_hash — SAFE_TEXT_PREFILTER alnum `NTLM` len 4
- `search_blob LIKE '%NtLmSsp%'` — pass_the_hash — SAFE_TEXT_PREFILTER alnum `NtLmSsp` len 7
- `search_blob LIKE '%PreAuth%0%'` — asrep_roasting — SAFE_TEXT_PREFILTER alnum `PreAuth` len 7
- `search_blob LIKE '%RC4%'` — kerberoasting — SAFE_LOGICAL_PREFILTER_NO_TEXT_PRUNE alnum `RC4` len 3
- `search_blob LIKE '%SeDebugPrivilege%'` — token_manipulation — SAFE_TEXT_PREFILTER alnum `SeDebugPrivilege` len 16
- `search_blob LIKE '%TXT%'` — dns_exfiltration — SAFE_LOGICAL_PREFILTER_NO_TEXT_PRUNE alnum `TXT` len 3
- `search_blob LIKE '%WinRM%'` — winrm_lateral_movement — SAFE_TEXT_PREFILTER alnum `WinRM` len 5
- `search_blob LIKE '%\AppData\%'` — data_staging, dll_hijacking, service_persistence — SAFE_TEXT_PREFILTER alnum `AppData` len 7
- `search_blob LIKE '%\Downloads\%'` — dll_hijacking — SAFE_TEXT_PREFILTER alnum `Downloads` len 9
- `search_blob LIKE '%\ProgramData%'` — lateral_tool_transfer — SAFE_TEXT_PREFILTER alnum `ProgramData` len 11
- `search_blob LIKE '%\Public\%'` — data_staging — SAFE_TEXT_PREFILTER alnum `Public` len 6
- `search_blob LIKE '%\Temp\%'` — data_staging, dll_hijacking, service_persistence — SAFE_TEXT_PREFILTER alnum `Temp` len 4
- `search_blob LIKE '%\Users\%'` — dll_hijacking, service_persistence — SAFE_TEXT_PREFILTER alnum `Users` len 5
- `search_blob LIKE '%\Windows\Temp%'` — lateral_tool_transfer — SAFE_TEXT_PREFILTER alnum `Windows` len 7
- `search_blob LIKE '%\\ADMIN$%'` — smb_admin_shares — SAFE_TEXT_PREFILTER alnum `ADMIN` len 5
- `search_blob LIKE '%\\C$%'` — smb_admin_shares — SAFE_LOGICAL_PREFILTER_NO_TEXT_PRUNE alnum `C` len 1
- `search_blob LIKE '%\\IPC$%'` — smb_admin_shares — SAFE_LOGICAL_PREFILTER_NO_TEXT_PRUNE alnum `IPC` len 3
- `search_blob LIKE '%bypass%'` — uac_bypass — SAFE_TEXT_PREFILTER alnum `bypass` len 6
- `search_blob LIKE '%cmd /c%'` — service_persistence — SAFE_LOGICAL_PREFILTER_NO_TEXT_PRUNE alnum `cmd` len 3
- `search_blob LIKE '%cpassword%'` — gpp_password_theft — SAFE_TEXT_PREFILTER alnum `cpassword` len 9
- `search_blob LIKE '%ms-settings%'` — uac_bypass — SAFE_TEXT_PREFILTER alnum `settings` len 8
- `search_blob LIKE '%mscfile%'` — uac_bypass — SAFE_TEXT_PREFILTER alnum `mscfile` len 7
- `search_blob LIKE '%password%'` — credentials_in_files — SAFE_TEXT_PREFILTER alnum `password` len 8
- `search_blob LIKE '%powershell%'` — service_persistence — SAFE_TEXT_PREFILTER alnum `powershell` len 10
- `search_blob LIKE '%uac%'` — uac_bypass — SAFE_LOGICAL_PREFILTER_NO_TEXT_PRUNE alnum `uac` len 3
- `search_blob LIKE '%wsmprovhost%'` — winrm_lateral_movement — SAFE_TEXT_PREFILTER alnum `wsmprovhost` len 11

NOT LIKE shapes: 9. lower(search_blob) LIKE shapes: 96 (JSON `expr=lower(search_blob)`).
pattern_check_definitions extracted predicates: 242.

## 4. Four-way bloom ablation

Setting verified on 26.7.3.19: `ignore_data_skipping_indices`.
Configs: ALL / NO_NGRAM / NO_TOKEN / NO_BLOOMS. Text index remained available in every config.
Table metadata was not changed. Identity used `count()` + `sum(cityHash64(evidence_record_key))`
+ physical tuple hash. All A/B/C/D identities matched for every representative.

### search_blob LIKE '%NTLM%' (9 samples + warmup)

| Case | n | ALL ngram granules | NO_NGRAM token granules | NO_TOKEN ngram | NO_BLOOMS text | ALL read_rows | NO_NGRAM read_rows | ALL p50 ms | NO_BLOOMS p50 ms |
|---:|---:|---|---|---|---|---:|---:|---:|---:|
| 10 | 2200 | 461/482 | 482/482 | 461/482 | 482/482 | 2336555 | 2447494 | 129.686 | 120.219 |
| 7 | 73510 | 24172/28038 | 28038/28038 | 24172/28038 | 28038/28038 | 119984806 | 139579161 | 4055.434 | 4083.147 |
| 32 | 162596 | 30366/35535 | 35535/35535 | 30366/35535 | 35535/35535 | 149647982 | 174899397 | 4008.799 | 4225.281 |

NO_NGRAM read_rows equals NO_BLOOMS. NO_TOKEN read_rows equals ALL.
When ngram is ignored, idx_search_token does not prune.

## 5. idx_search_ngram independent contribution

YES. On retained required `search_blob LIKE '%NTLM%'`, ignoring only ngram restores a full
partition scan: case 7 24172 → 28038 granules, +19,594,355 read_rows; case 32 30366 → 35535,
+25,251,415 read_rows. Same class of prune on ADMIN$, Kerberos, NtLmSsp, RC4, IPC$, TXT,
and other case-sensitive LIKE representatives. Hunt TOKEN_SAFE / Hunt ILIKE still do not
need ngram (2.1D preserved).

## 6. idx_search_token independent contribution

NO. Across the complete required LIKE matrix, `ignore_data_skipping_indices=idx_search_ngram`
never showed token granule reduction. Token is listed after ngram with identical
granules_after/granules_before. Independent utility is not inferred from that listing.

## 7. Deployed text-index LIKE/ILIKE capability

Proved on 26.7.3.19 with read-only EXPLAIN, not documentation.

| Predicate | idx_search_blob_text | granule prune | `__text_index_*` | notes |
|---|---|---|---|---|
| `LIKE '%NTLM%'` | listed, 482/482 | no | no | ngram prunes |
| `ILIKE '%NTLM%'` | 186/482 | yes | yes ilike | preprocessor lower helps ILIKE |
| `LIKE '%ADMIN%'` | listed, 482/482 | no | no | ngram prunes |
| `ILIKE '%ADMIN%'` | 435/482 | yes | yes ilike | |
| `LIKE '%Kerberos%'` | listed | no | no | ngram prunes |
| `ILIKE '%Kerberos%'` | 55/482 | yes | yes ilike | |
| `ILIKE '%ADMIN$%'` | none | no | no | `$` blocks text ILIKE |
| `ILIKE` length 1-3 (`RC4`,`IPC`,`TXT`,`NTL`) | none | no | no | measured min length 4 |

`preprocessor=lower(search_blob)` is why case-insensitive ILIKE can use the text index
and case-sensitive LIKE cannot. Direct `__text_index_*_ilike_*` is not the same as
granule reduction: OR with a short-token branch can emit `__text_index_*` and still
read 482/482 granules.

## 8. Safe prefilter candidates

Rule: ORIGINAL_MATCH ⇒ PREFILTER_MATCH. Prefilter is never narrower.
Candidate form (not in production code):

`(search_blob ILIKE '%<guaranteed ASCII alnum run>%' AND <original predicate>)`

- `LIKE '%NTLM%'` → `ILIKE '%NTLM%' AND LIKE '%NTLM%'` — SAFE_TEXT_PREFILTER
- `LIKE '%NtLmSsp%'` → `ILIKE '%NtLmSsp%' AND LIKE '%NtLmSsp%'` — SAFE_TEXT_PREFILTER
- `LIKE '%Kerberos%'` → `ILIKE '%Kerberos%' AND LIKE '%Kerberos%'` — SAFE_TEXT_PREFILTER
- `LIKE '%ADMIN$%'` → `ILIKE '%ADMIN%' AND LIKE '%ADMIN$%'` — logical superset; text uses token ADMIN
- `LIKE '%\\ADMIN$%'` → `ILIKE '%ADMIN%' AND original`
- `lower(search_blob) LIKE '%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%'` → `ILIKE '%00c04fc2dcd2%' AND original`
- `LIKE '%RC4%'` / `'%TXT%'` / `'%IPC$%'` / `'%cmd /c%'` → logical ILIKE exists but length < 4 so
  **SAFE_LOGICAL_PREFILTER_NO_TEXT_PRUNE** on 26.7.3.19
- `NOT LIKE` → **NO_SAFE_TEXT_PREFILTER**

OR uses branch-local wrapping, not a single outer prefilter:
`(pre_A AND orig_A) OR (pre_B AND orig_B)` with original parentheses kept.

## 9. Exact event-set parity

All 90 original-vs-candidate comparisons on cases 10/7/32 had
A MINUS B = 0, B MINUS A = 0, equal n, equal ERK fingerprint, equal physical fingerprint.
Zero false negatives. Zero false positives.

## 10. Full detection-output parity

Read-only original vs wrapped `detection_query` for
pass_the_hash, pass_the_ticket, smb_admin_shares, psexec_remote_service,
kerberoasting, dcsync_attack, dns_exfiltration on cases 10/7/32.

Row counts matched in every run. Four raw SHA256 mismatches
(smb_admin_shares 7/32, kerberoasting 7/32) were `groupUniqArray` column order,
not extra/missing groups. Re-query with sorted arrays matched exactly.
pass_the_hash, pass_the_ticket, psexec_remote_service, dcsync_attack, dns_exfiltration
matched on raw fingerprints as well.

## 11. Prefilter EXPLAIN

NTLM candidate with blooms ignored: text index 482→186 (case 10), 28038→9447 (case 7),
35535→7067 (case 32). Better prune than ngram alone (461 / 24172 / 30366 remaining).

RC4 / IPC / TXT / cmd /c candidate with blooms ignored: 482/482, 28038/28038, 35535/35535.
No text prune. Original ngram still prunes those LIKE predicates.

## 12. Prefilter performance

| Query | case | orig p50 ms | candidate+no blooms p50 | orig read_rows | candidate+no blooms read_rows |
|---|---:|---:|---:|---:|---:|
| like_ntlm | 10 | 130.745 | 196.407 | 2336555 | 860538 |
| like_ntlm | 7 | 4104.662 | 6061.888 | 119984806 | 40898066 |
| like_ntlm | 32 | 4073.555 | 3137.793 | 149647982 | 29733346 |
| like_ntlmssp | 10 | 100.387 | 131.485 | 2376809 | 29940 |
| like_ntlmssp | 7 | 3273.369 | 3617.455 | 126550161 | 1080801 |
| like_ntlmssp | 32 | 3631.165 | 1901.396 | 158901394 | 3661328 |
| like_kerberos | 10 | 104.489 | 122.236 | 2376809 | 321650 |
| like_kerberos | 7 | 3904.008 | 5682.905 | 126694235 | 36460822 |
| like_kerberos | 32 | 3955.362 | 2745.605 | 161049990 | 30262446 |
| like_admin_share | 10 | 102.5 | 308.458 | 2403574 | 2237976 |
| like_admin_share | 7 | 3438.836 | 12039.458 | 126361205 | 138983862 |
| like_admin_share | 32 | 3936.764 | 11443.732 | 158010055 | 172523935 |
| like_ipc | 10 | 122.65 | 159.963 | 2447340 | 2447494 |
| like_ipc | 7 | 4475.473 | 5306.276 | 129207909 | 139579161 |
| like_ipc | 32 | 4572.475 | 5806.704 | 163832122 | 174899397 |
| like_rc4 | 10 | 112.85 | 131.279 | 2426320 | 2447494 |
| like_rc4 | 7 | 3414.982 | 4156.392 | 132703131 | 139579161 |
| like_rc4 | 32 | 3900.953 | 5004.371 | 167446856 | 174899397 |
| or_ntlm_ssp | 10 | 152.906 | 237.471 | 2376809 | 860538 |
| or_ntlm_ssp | 7 | 5444.318 | 8195.077 | 128028674 | 40898066 |
| or_ntlm_ssp | 32 | 5259.542 | 4162.051 | 161989532 | 29733346 |

NTLM/Kerberos/NtLmSsp candidates cut read_rows sharply. Latency is mixed: case 32
improves; case 7 NTLM p50 4105→6062 ms despite fewer rows. ADMIN$ ILIKE '%ADMIN%'
regresses both latency and rows on cases 7/32 because ADMIN is a much broader token
than ngram(ADMIN$). Short-token candidates read the full partition once blooms are ignored.

## 13. Index storage / insert cost

Production:
- idx_search_ngram 4,049,580 (3.86 MiB)
- idx_search_token 964,699,630 (920.01 MiB)
- idx_search_blob_text 14,603,118,274 (13.60 GiB)

Disposable 10k-row events-shaped insert, identical source rows,
`materialize_skip_indexes_on_insert=1`, no sync-vs-async (Phase 2.2):

| Arm | insert rows/s | part bytes | index bytes |
|---|---:|---:|---|
| TEXT_ONLY | 229005.3 | 1086345 | `{'idx_search_blob_text': 214892}` |
| TEXT_PLUS_NGRAM | 201378.6 | 1086472 | `{'idx_search_ngram': 77, 'idx_search_blob_text': 214892}` |
| TEXT_PLUS_TOKEN | 260065.0 | 1119310 | `{'idx_search_token': 32915, 'idx_search_blob_text': 214892}` |
| TEXT_PLUS_BOTH | 196216.1 | 1119437 | `{'idx_search_ngram': 77, 'idx_search_token': 32915, 'idx_search_blob_text': 214892}` |

Ngram maintenance is tiny (77 bytes / 10k). Token is the expensive legacy bloom
(32,915 bytes / 10k vs ngram 77). Text index dominates (214,892 bytes / 10k).
Insert elapsed on 10k is too small for a stable CPU ranking; token added measurable
part bytes, ngram did not. Text-index EXPLAIN used `__text_index_*` after insert.

## 14. Query frequency evidence

Status: AVAILABLE. query_log span 2026-08-11 13:28:48 → 2026-08-22 14:03:52 (493197 finished queries).

- `search_blob LIKE` finished queries: 2707, duration_ms 5834592, read_rows 157395546247
- This includes D2A measurement itself and is not a clean production-only rate.
- idx_search_ngram contribution cannot be attributed per historical query_log row without EXPLAIN; D2A EXPLAIN on current plans is authoritative.

## 15. Token bloom decision

**TOKEN_BLOOM_REDUNDANT**

## 16. Ngram decision

**NGRAM_MEASURED_EXCEPTION_REQUIRED**

Required ngram-dependent LIKE predicates with a guaranteed alphanumeric run of length >= 4 (NTLM, NtLmSsp, Kerberos, 0x17, WinRM, etc.) can keep exact match sets behind a redundant search_blob ILIKE prefilter that uses idx_search_blob_text with both blooms ignored. Predicates whose longest guaranteed alphanumeric run is length 1-3 (RC4, TXT, IPC, cmd /c) still use idx_search_ngram and do not get text-index pruning on ClickHouse 26.7.3.19. OR expressions containing those short tokens also fail to replace ngram prune. ADMIN$ has a safe logical ILIKE '%ADMIN%' superset but that prefilter is broader than ngram(ADMIN$) and regressed latency on cases 7 and 32. Therefore ngram remains measurably beneficial for a non-empty required remainder. The locked plan is not changed in D2A.

Exception predicate ids: like_admin_share, like_cmd_c, like_ipc, like_ipc_unc, like_rc4, like_txt, or_admin_ipc, or_rc4.
Replaceable predicate ids: like_0x1010, like_0x17, like_admin_share, like_admin_unc, like_cpassword, like_dcom, like_kerberos, like_ntlm, like_ntlmssp, like_powershell, like_preauth, like_sedebug, like_temp, like_winrm, like_wsmprovhost, or_ntlm_ssp.

## 17. Combined decision / next allowed tranche

Outcome **B**: TOKEN_BLOOM_REDUNDANT + NGRAM_MEASURED_EXCEPTION_REQUIRED.

Next: explicit architecture review of the locked “drop both blooms” sentence.
Do not silently change the gate. Do not start Phase 2.2.

## 18. Accepted 2.1 regression

Required suite plus D2A tests against disposable F2 env `phase2_1c_test`:
**163 passed, 0 skipped**.

`py_compile`, `pyflakes`, and `git diff --check` on changed Python.

Hunt TOKEN_SAFE, ASCII-only, publication bridge, export publication gate,
command_line DEFER, and KEEP_PRODUCTION_MATERIALIZE_SKIP_INDEXES_ON_INSERT_1
were not reopened. 2.1D NOT_READY contract tests still pass.

## 19. Files changed

- `tests/phase2_1d2a_lib.py`
- `tests/test_phase2_1d2a_bloom_dependency_resolution.py`
- `scripts/phase2_1d2a_bloom_dependency_resolution.py`
- `docs/database_flow_phase2/phase2_1d2a_bloom_dependency_resolution.md`
- `docs/database_flow_phase2/phase2_1d2a_bloom_dependency_resolution.json`

## 20. Version

4.25.2. Not bumped. Measurement only.

## 21. No-later-phase audit

{
  "phase_2_2": false,
  "async_insert_change": false,
  "phase_2_3": false,
  "phase_2_4": false,
  "phase_3": false,
  "phase_4": false,
  "events_current": false,
  "event_observations_current": false,
  "search_blob_reader_migration": false,
  "pagination_redesign": false,
  "OPTIMIZE_FINAL_production": false,
  "MATERIALIZE_INDEX_production": false,
  "DROP_INDEX_production": false,
  "production_reader_changes": false,
  "EVENTS_SCHEMA_changed": false,
  "version_bumped": false
}

## 22. Git state

Uncommitted until the closing commit of this tranche. Not pushed until that commit.

## 23. Phase 2.1 state

**PHASE2_1_NOT_READY**

## 24. Verdict

**PHASE2_1D2A_PASS**

