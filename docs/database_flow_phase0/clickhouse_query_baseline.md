# Phase 0A ClickHouse Query / EXPLAIN Baseline

Status: executed read-only with `EXPLAIN indexes = 1`.

Case used: `3`

Parameters are represented safely; committed docs use benign terms such as `powershell` and omit raw evidence values.

## Results

| Shape | Parts / granules at read | Observed index use | Material pruning |
|---|---|---|---|
| `normal_term_hunt` | Parts: 5 | Granules: 1209 | Partition, PrimaryKey | NOT OBSERVED after case pruning |
| `ioc_token_search` | Parts: 5 | Granules: 617 | Partition, PrimaryKey, idx_search_ngram, idx_search_token | OBSERVED: token/ngram chain pruned case granules to 617 |
| `ioc_substring_search` | Parts: 5 | Granules: 1209 | Partition, PrimaryKey | NOT OBSERVED after case pruning |
| `event_id_filter` | Parts: 2 | Granules: 92 | Partition, PrimaryKey, idx_event_id | OBSERVED: event_id bloom pruned to 92 granules |
| `timestamp_range` | Parts: 5 | Granules: 1209 | Partition, PrimaryKey | NOT OBSERVED after case pruning |
| `source_host` | Parts: 5 | Granules: 1209 | Partition, PrimaryKey | NOT OBSERVED after case pruning |
| `username` | Parts: 5 | Granules: 1209 | Partition, PrimaryKey | NOT OBSERVED after case pruning |
| `process_command_line` | Parts: 5 | Granules: 1209 | Partition, PrimaryKey | NOT OBSERVED after case pruning |
| `combined_hunt` | Parts: 2 | Granules: 92 | Partition, PrimaryKey, idx_event_id | OBSERVED: event_id bloom pruned to 92 granules |
| `lower_search_blob_like` | Parts: 5 | Granules: 1209 | Partition, PrimaryKey | NOT OBSERVED after case pruning |
| `process_name_only` | Parts: 5 | Granules: 1209 | Partition, PrimaryKey | NOT OBSERVED after case pruning |
| `command_line_substring` | Parts: 5 | Granules: 1209 | Partition, PrimaryKey | NOT OBSERVED after case pruning |

## Notes

- `lower(search_blob) LIKE` was OBSERVED to use only case/partition/primary-key pruning; no search skip index pruning was observed for that shape.
- `hasToken(search_blob, ...)` was OBSERVED to consider `idx_search_ngram` and `idx_search_token`, with material granule pruning in this case.
- `positionCaseInsensitive(search_blob, ...)` was NOT OBSERVED to use search skip indexes in this run.
- `event_id` and representative combined hunt were OBSERVED to use `idx_event_id` bloom pruning.
- `username`, `source_host`, `process_name`, and `command_line` did not show dedicated skip-index pruning beyond case/primary-key pruning in this run.
- These are observations for the current deployed ClickHouse/version/schema and selected case only; they are not future architecture claims.
