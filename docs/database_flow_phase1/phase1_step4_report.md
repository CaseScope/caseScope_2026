# Phase 1 Step 4 Report

Status: STEP4_ACCEPTED. Phase 1.7 latency closure only. Phase 1.8, Phase 1B, typed columns, Phase 2, generations/manifests/LEK/surfaces, and RecordID-only matching were not started.

## 1. Current Latency Problem

The accepted Step 4 semantic implementation was kept locked:

- Events: 110,742 = legacy
- Detections: 7,436 = legacy
- Deterministic event diffs: 0
- Cross-file detection attachments: 0
- ERK digest unchanged: `6ad87fe76520d18bde4cfb421bbd4fce0b410c00d60abaf642769aa303515b7c`
- Cross-file RecordID collisions in the approved corpus: 5,536

The only unresolved acceptance issue was first-searchable latency. Previous paired ingest median was per-file 18.400 s versus current 8-file directory mode 41.097 s, a +22.697 s / +123% regression.

## 2. Group-Size Benchmark Table

Approved corpus: `/opt/casescope-benchmark/phase0a_evtx`, 8 EVTX, 77,103,104 bytes, 110,742 events.

Parser-only paired/interleaved study, 2 runs per policy:

| Policy | Unit plan | Parser median wall | Parser first event | Second unit first event | Hayabusa launches | EvtxECmd launches |
|---|---|---:|---:|---:|---:|---:|
| 1 file / legacy | 8 per-file units | 123.549 s | 5.779 s | 15.880 s | 8 | 8 |
| 2 files | 4 directory groups | 96.462 s | 6.619 s | 18.029 s | 4 | 4 |
| 4 files | 2 directory groups | 88.093 s | 6.662 s | 38.534 s | 2 | 2 |
| 8 files / current | 1 directory group | 84.046 s | 28.184 s | n/a | 1 | 1 |
| eager 1 + remaining 7 | 1 per-file + 1 directory group | 85.045 s | 5.564 s | 35.764 s | 2 | 2 |
| eager 1 + groups of 2 | 1 per-file + 3 directory groups + final per-file | 93.020 s | 5.806 s | 15.784 s | 5 | 5 |
| eager 1 + groups of 4 | 1 per-file + 2 directory groups | 91.115 s | 5.724 s | 15.659 s | 3 | 3 |
| smallest-first 8 | 1 reordered directory group | 85.753 s | 28.355 s | n/a | 1 | 1 |
| smallest-first eager | 1 small per-file + 1 directory group | 89.868 s | 34.066 s | 34.066 s | 2 | 2 |

Disposable ingest paired/interleaved study, 2 runs per policy:

| Policy | Ingest median wall | First searchable | Events/sec | Peak RSS | Hayabusa launches | EvtxECmd launches |
|---|---:|---:|---:|---:|---:|---:|
| 1 file / legacy | 174.654 s | 18.455 s | 634.065 | 233.085 MB | 8 | 8 |
| 4 files | 139.769 s | 18.429 s | 792.324 | 276.075 MB | 2 | 2 |
| 8 files / current | 136.177 s | 40.231 s | 813.228 | 226.420 MB | 1 | 1 |
| eager 1 + remaining 7 | 138.590 s | 18.271 s | 799.088 | 224.105 MB | 2 | 2 |

## 3. Group-Byte Distribution

| Policy | Unit bytes |
|---|---|
| 1 file | 11,603,968; 15,798,272; 69,632; 1,118,208; 1,118,208; 5,312,512; 21,041,152; 21,041,152 |
| 2 files | 27,402,240; 1,187,840; 6,430,720; 42,082,304 |
| 4 files | 28,590,080; 48,513,024 |
| 8 files / current | 77,103,104 |
| eager 1 + remaining 7 | 11,603,968; 65,499,136 |
| eager 1 + groups of 2 | 11,603,968; 15,867,904; 2,236,416; 26,353,664; 21,041,152 |
| eager 1 + groups of 4 | 11,603,968; 18,104,320; 47,394,816 |

## 4. Eager-First Benchmark

`eager 1 + remaining 7` is the best Pareto point on this corpus:

- First searchable: 18.271 s median, effectively the same as per-file and below the <=25 s target.
- Ingest wall: 138.590 s median, only +2.413 s slower than current 8-file directory mode.
- Ingest improvement over paired per-file: 1.260x, above the >=1.15x target.
- No duplicate processing: the eager first file is excluded from the directory group.

## 5. Group-Fill-Window Findings

No group-fill window was added. `queue_case_files_for_parsing` already receives the currently queued set, and grouping is immediate. Waiting would delay the first unit without adding evidence on this corpus. The explicit group-fill window remains 0 seconds and must not be extended for later uploads.

## 6. Progressive-Searchable Timeline

Selected ingest policy, paired runs:

| Run | Unit 1 searchable | Unit 2 searchable | Final wall |
|---|---:|---:|---:|
| P1 eager 1 + remaining 7 | 18.331 s | 44.792 s | 137.860 s |
| P2 eager 1 + remaining 7 | 18.211 s | 45.777 s | 139.319 s |
| Median | 18.271 s | 45.285 s | 138.590 s |

Events are inserted after each unit. Directory-group output is not accumulated until all queued units finish.

## 7. Ordering Findings

Queue/current ordering remains selected. Smallest-file-first was measurement-only and did not win:

- `smallest-first 8` parser first event was 28.355 s, no better than current 8-file directory behavior.
- `smallest-first eager` made the eager file a zero-event TaskScheduler log, so first useful event came from the directory group at 34.066 s.
- Reordering can break user-visible task/priority expectations, so it was not selected.

## 8. Semantic Parity

Selected policy parity artifact: `docs/database_flow_phase1/phase1_step4_selected_parity.json`.

- Events: 110,742 selected = 110,742 legacy
- Detections: 7,436 selected = 7,436 legacy
- ERK missing/extra: 0 / 0
- Deterministic field differences: 0
- `raw_json`, `search_blob`, and `extra_fields` hashes: identical
- `source_file` identity and `case_file_id` association: identical
- Incorrect cross-file attachments: 0

The directory-mode detection key remains `(source identity, RecordID)`. RecordID-only directory correlation remains forbidden.

## 9. Failure/Fallback Regression

Focused Step 4 tests: 27 tests, OK.

Covered:

- Directory failure falls back to bounded per-file processing.
- Malformed EVTX does not poison unrelated files.
- Duplicate basenames remain safe through `cf_{case_file_id}/{original_basename}` staging.
- Eager-first file is not reprocessed in a directory group.
- Directory fallback does not process the eager file.
- Single EVTX still uses the per-file path.
- Retry remains idempotent under the existing cleanup/fallback path.

## 10. Selected Grouping Policy

Production policy:

- First currently-ready EVTX: per-file path.
- Remaining queued EVTX: bounded directory groups.
- Preferred target group size: 8 files.
- Preferred target bytes: 128 MiB.
- Absolute safety maximum: 32 files / 512 MiB.
- Fill window: 0 seconds.
- Ordering: queue/current ordering.

## 11. Preferred vs Maximum Group Limits

The previous 32-file / 512-MiB values are now safety caps only. They are not treated as preferred production group size. The selected preferred target is 8 files / 128 MiB so small numbers of large EVTX files cannot create oversized directory units solely because the file count is low.

## 12. Final First-Searchable Latency

Final selected first-searchable median: 18.271 s.

This materially reduces the previous directory-mode median of 41.097 s by about 22.826 s and returns latency to the per-file level while preserving source-aware correlation.

## 13. Final Ingest Wall

Final selected ingest wall median: 138.590 s.

Compared with paired per-file median 174.654 s, this retains a 1.260x ingest improvement. Compared with current 8-file directory median 136.177 s, the selected policy costs 2.413 s for a 21.960 s first-searchable improvement.

## 14. Throughput Tradeoff

The selected policy is the Pareto point that satisfies both closure targets:

- First searchable <=25 s: yes, 18.271 s.
- Ingest improvement >=1.15x over per-file: yes, 1.260x.
- Current 8-file directory mode is slightly faster in completion but has a material first-searchable regression.
- 4-file groups also hit first-searchable target, but were slower than selected eager-first and used higher peak RSS on this host.

## 15. Step 4 Final Verdict

**STEP4_ACCEPTED**

Acceptance basis:

- Semantic parity remains exact.
- Cross-file detection attachment remains 0.
- Directory-mode throughput advantage remains meaningful.
- Selected grouping policy is measurement-based.
- First-searchable regression is materially reduced from ~41 s to ~18 s.
- Source-aware correlation is unchanged.
- No Phase 1.8, Phase 1B, typed columns, Phase 2, or lifecycle architecture changes were started.

*Context improved by Giga AI: used the workspace CaseScope architecture and Step 4 constraints from the active project context.*
