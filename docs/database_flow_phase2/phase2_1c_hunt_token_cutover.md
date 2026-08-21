# Phase 2.1C Hunt Token-Search Semantic Cutover

Hunt Artifacts free-text term search now uses the materialized
`idx_search_blob_text` index for TOKEN_SAFE atoms. Stored `search_blob` is
unchanged. Bloom indexes remain. No later Phase 2.x / 3+ work.

Measurement artifact: `docs/database_flow_phase2/phase2_1c_hunt_token_cutover.json`.

## Starting state

- origin/main and HEAD: `9fc6802ff3de6fc48d16c9f7d238e6ffb21ac3e3`
- Commit: Recover the discarded case 3 graph task from retained kwargs and stop treating broker deletion as idle
- Baseline version: 4.24.2
- This tranche version: 4.25.0
- Python: `/opt/casescope/venv/bin/python`
- Deployed ClickHouse: `26.7.3.19`

Working tree was clean. HEAD == origin/main.

## Locked scope

Done:

- deterministic Hunt atom classifier in `routes/hunting_query_helpers.py`
- TOKEN_SAFE positive free-text → parameterized `hasAllTokens(search_blob, …)`
- compact TOKEN_SAFE OR → parameterized `hasAnyTokens` (chunked at 256)
- quoted / wildcard / punctuation-split / unknown-field / blob fallback remain ILIKE
- numeric bare terms remain `event_id =`
- SEARCH_FIELD_MAP typed columns unchanged
- negative terms remain `NOT search_blob ilike`
- Phase 1B publication bridge unchanged
- grammar matrix tests and live ERK / EXPLAIN / performance proofs

Not done: bloom drop, production `command_line` text index, other
`search_blob` consumer migrations, Phase 2.2–2.4, Phase 3+.

## Production text-index preconditions

PASS. Read-only inspection of production `casescope.events`:

- `idx_search_blob_text` PRESENT
- expr: `search_blob`
- type: `text(tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob))`
- coverage: MATERIALIZED 25 / PARTIAL 0 / UNMATERIALIZED 0 / UNKNOWN 0
- rows: 745,463,991 / 25 partitions / 135 active parts
- blooms: `idx_search_ngram` PRESENT, `idx_search_token` PRESENT
- `materialize_skip_indexes_on_insert = 1` (server default, unchanged)
- `query_plan_direct_read_from_text_index = 1`

## Existing Hunt grammar (inventory)

`build_hunting_search_clause` callers:

- `routes/hunting.py` `get_hunting_events` (live grid + count + pagination)
- `routes/hunting.py` `export_view_events` (export)

Unchanged and out of scope:

- event-detail `match_search_blob` uses `position(e.search_blob, …)`
- SIGMA converter, IOC tagger, noise keywords, chat tools, network_log,
  pattern_rules, parsers, graph

Grammar preserved:

- implicit AND of whitespace-separated atoms
- compact `a|b` is OR; a bare spaced `|` token is skipped (existing AND)
- parentheses groups and mixed `(field:value)|term` OR
- `field:value` via SEARCH_FIELD_MAP; unknown/blob fields stay
  `search_blob ilike %field:value%`
- `C:\…` still parses as unknown field `C` plus blob fallback
- digit-only ordinary terms: `event_id =`
- quoted strings: substring/phrase ILIKE after quote strip, except digits
  still take the existing structured `event_id` path
- exclusions: `NOT search_blob ilike`

## Tokenizer fixture matrix

Proven on ClickHouse 26.7.3.19 `splitByNonAlpha` (disposable/read-only SQL).
ASCII non `[A-Za-z0-9]` separates tokens. ASCII alphanumerics and every
non-ASCII code point remain inside a token.

| Input | Tokens | Class |
|---|---|---|
| powershell / PowerShell / Administrator / PCLAPPVM / svchost / host01 | exactly one, equals input | EXACTLY_ONE_TOKEN |
| SHA-256 hex | exactly one, equals input | EXACTLY_ONE_TOKEN |
| 4688 / 7036 | exactly one | EXACTLY_ONE_TOKEN (Hunt STRUCTURED event_id) |
| cmd.exe | cmd, exe | MULTIPLE_TOKENS |
| 10.0.0.1 | 10, 0, 0, 1 | MULTIPLE_TOKENS |
| host01.domain.local | host01, domain, local | MULTIPLE_TOKENS |
| DOMAIN\user / user@example.com / paths / HKLM\… / foo-bar / foo_bar / GUID | multiple | MULTIPLE_TOKENS |
| power* | power | one token ≠ input |
| münchen / 用户 / 逄 | one token | EXACTLY_ONE_TOKEN |

Python replica matches the server for this matrix.

`hasAnyTokens` accepted 4096 space-joined tokens and 1024 Array(String)
values. Compiler chunks at 256 and OR-combines chunks. Terms are never dropped.

## Classifier contract

- TOKEN_SAFE: unquoted positive free-text; not digit-only; no `%` `_` `*`;
  tokenizer yields exactly one token equal to the input (casefold)
- SUBSTRING_REQUIRED: quoted, wildcards, tokenizer splits, stripped
  punctuation, unknown/blob field expressions
- STRUCTURED: digit-only ordinary terms (`event_id =`); mapped `field:value`
- EXCLUSION_PRESERVE: negative terms keep `NOT ILIKE`
- INVALID: empty atom

Unquoted `vchos` is TOKEN_SAFE (whole-token). Quoted `"vchos"` remains
substring. That is the language for true substrings after this cutover.

## Implementation

Reader path: `routes/hunting_query_helpers.py` only, inherited by both Hunt
grid/count and export via `build_hunting_search_clause`.

TOKEN_SAFE emits `hasAllTokens(search_blob, {param:String})` on the stored
column. Never `hasAllTokens(lower(search_blob), …)`.

AND of TOKEN_SAFE atoms: AND of individual `hasAllTokens`.
Compact TOKEN_SAFE OR: `hasAnyTokens`. Mixed OR compiles per branch.

All user search text stays in ClickHouse parameters.

## Indexed vs scan token correctness

A = `hasAllTokens(search_blob, term)` (indexed).
B = `hasAllTokens(lower(search_blob), lower(term))` (scan).

ERK and selector_key EXCEPT both empty on every fixture.

| Case | Term | Indexed | Scan | A-only | B-only |
|---|---|---:|---:|---:|---:|
| 14 | sonicwall / SonicWall | 13 | 13 | 0 | 0 |
| 10 | powershell / PowerShell | 19455 | 19455 | 0 | 0 |
| 10 | Administrator | 199 | 199 | 0 | 0 |
| 10 | PCLAPPVM | 0 | 0 | 0 | 0 |
| 7 | powershell | 705353 | 705353 | 0 | 0 |
| 7 | Administrator | 27100 | 27100 | 0 | 0 |
| 32 | powershell | 940117 | 940117 | 0 | 0 |
| 32 | Administrator | 27958 | 27958 | 0 | 0 |

`powershell|administrator` `hasAnyTokens` vs lower() scan: A-only = B-only = 0
on cases 10, 7, 32.

No PHASE2_1C_TOKEN_FALSE_NEGATIVE.

## Old ILIKE difference classification

Token-only vs ILIKE is 0 on every sample (token matches are a subset of old
substring matches). ILIKE-only rows are old substring hits:

- powershell → WindowsPowerShell, PowerShellCore, …
- Administrator → administrators, HyperVAdministrators, …
- svchost → SMSvcHost, McSvchost, …
- truncated sample windows that looked UNKNOWN were `administrators` /
  hex-encoded `Administrators` once classified at the actual match offset

Not index false negatives.

## Retained substring exact parity

Helper vs old `search_blob ilike %atom%` ERK EXCEPT empty for:

cmd.exe, 10.0.0.1, host.domain.local, `\Windows\System32\cmd.exe`,
`"Windows PowerShell"`, `"vchos"`

on cases 14, 10, 7, 32. `exact_parity = true` for every row.

## EXPLAIN

`EXPLAIN indexes = 1` for TOKEN_SAFE production queries on 14 / 10 / 7 / 32:

- Skip `Name: idx_search_blob_text`
- Prewhere `__text_index_idx_search_blob_text_hasAllTokens_*`
- no `hasAllTokens(lower(search_blob))` scan

SUBSTRING_REQUIRED `cmd.exe` Prewhere remains `search_blob ILIKE '%cmd.exe%'`.

## Performance

9 samples, 1 warmup. Result counts differ for TOKEN_SAFE vs ILIKE where
substring extras are intentional.

| Case | Term | OLD ILIKE p50/p95 ms | NEW token p50/p95 ms | OLD rows | NEW rows | OLD count | NEW count |
|---|---|---:|---:|---:|---:|---:|---:|
| 14 | sonicwall | 9.2 / 11.0 | 7.7 / 8.8 | 1341 | 1341 | 13 | 13 |
| 10 | powershell | 102.3 / 113.2 | 11.7 / 343.9* | 1.41M | 1.39M | 19995 | 19455 |
| 7 | powershell | 9144 / 9412 | 55.3 / 59.0 | 139M | 71.0M | 767934 | 705353 |
| 32 | powershell | 6118 / 6170 | 66.5 / 76.0 | 146M | 105M | 989441 | 940117 |
| 7 | Administrator | 3691 / 3770 | 29.1 / 31.3 | 26.5M | 24.3M | 86648 | 27100 |
| 32 | Administrator | 2330 / 2390 | 32.2 / 36.3 | 27.0M | 23.7M | 69766 | 27958 |

\* case 10 powershell token p95 is one outlier sample; p50 is 11.7 ms and the
mixed-case `PowerShell` token p95 is 12.4 ms.

Retained substring `cmd.exe` helper counts equal old ILIKE on every case
(14: 0, 10: 3025, 7: 883843, 32: 104646). Latency unchanged within noise.

## Hunt grid / count / pagination / export

Shared helper. Production-equivalent SQL with the Phase 1B publication
bridge:

- grid count == export count on retained cases 14/10/7/32 (all protocol
  identity NULL / legacy visible)
- page 2 disjoint from page 1 on 14/7/32; case 10 had 5 overlapping keys
  from timestamp ties under OFFSET (existing ORDER BY, not a predicate split)
- event-detail navigation from a search selector succeeded

Services were not restarted. Product validation used the helper + Hunt SQL,
not the still-running pre-cutover web process.

## Search-during-ingest publication

Phase 1B F2 product gate re-run against disposable
`phase2_1c_test` with TOKEN_SAFE search `alpha` at every lifecycle step:

A staged hidden; B first DURABLE BUILDING_INITIAL searchable before EOF;
C remaining durable visible; D BUILDING_REPLACEMENT hidden while ACTIVE
visible; E activation follows new generation; F stale projection cannot
resurrect N. Malformed partial identity stays hidden. Legacy rows stay
visible. Readiness DTOs unchanged.

`8 passed` in `tests/test_phase1b_tranche_f2_product_search_publication_gate.py`.

## Blooms / command_line / insert setting

- `idx_search_ngram` PRESENT
- `idx_search_token` PRESENT
- command_line text index: **DEFER** (not created)
- `materialize_skip_indexes_on_insert` left at production default 1
- Gate A proof that setting 0 does not false-negative empty granules remains
  accepted and was not re-opened

## Regression

207 passed including the required suite plus
`tests/test_phase2_1c_hunt_token_cutover.py`, hunt route contract, and IOC
hunting regressions. `py_compile`, `pyflakes`, `git diff --check` on changed
Python.

## No later phase

No bloom drop, no command_line index, no sigma/IOC/noise/chat/graph/parser
`search_blob` migration, no Phase 2.2 insert-mode change, no 2.3 UPDATE
caller, no 2.4 dedup, no Phase 3 ERK API, no LEK, no `events_current` /
`event_observations_current`, no IOC/MITRE/noise authority migration, no
Qdrant identity migration. Phase 1B publication SQL unchanged.

## Remaining work

Independent Phase 2.1C review.

Do not drop bloom indexes automatically.

Next possible Phase 2.1 tranche after review:

Phase 2.1D — bloom-index retirement / final Phase 2.1 exit.
