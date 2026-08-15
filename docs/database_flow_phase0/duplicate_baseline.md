# Phase 0A Duplicate Baseline

Status: executed bounded read-only.

Scope: OBSERVED ACROSS THE FOUR ANALYZED CASES. This is not a global CaseScope duplicate rate.

Cases analyzed: 3, 23, 1, 37

No destructive deduplication was run. No ALTER DELETE was issued by this diagnostic.

## Totals

- event_count: 20894468
- currently_dedup_eligible_count: 20880291
- duplicate_group_count: 4048681
- duplicate_count_under_legacy_semantics: 9392460
- duplicates_within_same_case_file: 2552676
- duplicates_across_case_files: 6839784
- same_erk_duplicates: 2480028
- different_erk_duplicates: 6912432
- observed duplicate percentage across analyzed cases: 44.952%

## Top Artifact Results

| Artifact | Events | Eligible | Duplicate rows | Same CaseFile | Cross CaseFile | Same ERK | Different ERK |
|---|---:|---:|---:|---:|---:|---:|---:|
| registry | 10341459 | 10341459 | 4924939 | 3 | 4924936 | 3 | 4924936 |
| mft | 5549327 | 5549327 | 2480000 | 2480000 | 0 | 2480000 | 0 |
| srum | 2989816 | 2989800 | 1883822 | 62647 | 1821175 | 0 | 1883822 |
| evtx | 1957105 | 1957105 | 93646 | 0 | 93646 | 0 | 93646 |
| huntress | 25327 | 25327 | 9999 | 9999 | 0 | 0 | 9999 |
| lnk | 1109 | 1109 | 27 | 0 | 27 | 0 | 27 |
| csv_log | 10780 | 5367 | 25 | 25 | 0 | 25 | 0 |
| prefetch | 6638 | 6638 | 2 | 2 | 0 | 0 | 2 |
| browser | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| jumplist | 11282 | 4159 | 0 | 0 | 0 | 0 | 0 |
| scheduled_task | 866 | 0 | 0 | 0 | 0 | 0 | 0 |
| activities_cache | 138 | 0 | 0 | 0 | 0 | 0 | 0 |
| webcache | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| iis | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| firewall | 496 | 0 | 0 | 0 | 0 | 0 | 0 |
| json_log | 125 | 0 | 0 | 0 | 0 | 0 | 0 |
| firefox_session | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| sonicwall | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Interpretation

- This result is a key empirical input to the later LEK contract.
- LEK is not defined here.
- source_generation metrics: NOT CURRENTLY MEASURABLE
- likely retry-created vs overlapping-evidence-created: OPEN - CONTRACT DECISION REQUIRED / PHASE 0 MEASUREMENT REQUIRED
