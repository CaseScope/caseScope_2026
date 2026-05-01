# Noise Tagging

Noise tagging marks known-good, repetitive, or operationally expected activity so analysts can hide it from default hunting views while keeping the original events available for review.

Noise is not deletion. A noise-tagged event remains in ClickHouse, keeps its original parsed data, and can be shown again when analysts choose to include noise in hunting results.

## Purpose

Noise tagging helps reduce review volume by identifying events that are likely expected in the environment, such as:

- RMM activity
- EDR activity
- backup software
- common administrative tools
- recurring Windows utilities
- known benign service behavior
- case-specific operational chatter

This is conceptually the opposite of IOC tagging. IOC tagging highlights suspicious or important indicators. Noise tagging suppresses known-benign activity from default views so analysts can focus on higher-value events.

## Main Workflow

The normal workflow is:

1. An analyst or administrator configures noise categories and rules in Settings.
2. Categories and rules are enabled or disabled.
3. A case noise scan is started from the hunting workflow.
4. Celery evaluates active rules against the case events in ClickHouse.
5. Matching rows are updated with noise state.
6. Hunting hides noise by default unless **Show noise** is enabled.
7. Analysts can manually mark selected events as noise when needed.

Noise scans are case-scoped. Rules are stored globally, but applying them updates events for a specific case.

## Rule Storage

Noise categories and rules are stored in PostgreSQL.

The main models are in `models/noise.py`:

- `noise_categories`
- `noise_rules`
- `noise_rule_audit`

A category groups related rules and can be enabled or disabled. A rule belongs to a category and can also be enabled or disabled independently.

An active rule requires both:

- category enabled
- rule enabled

If either is disabled, the rule is not used during scans.

## Rule Fields

Noise rules use keyword-style matching rather than a full detection language.

Important fields include:

- `name`
- `description`
- `category_id`
- `pattern`
- `pattern_and`
- `pattern_not`
- `is_enabled`
- `is_system_default`
- `priority`
- `created_by`
- `updated_by`

Rule keyword behavior:

- `pattern` is used for OR-style keywords.
- `pattern_and` is used for terms that must all be present.
- `pattern_not` is used for exclusions.

Legacy fields such as `filter_type`, `match_mode`, and `is_case_sensitive` may exist for compatibility, but the active matching path is keyword-oriented.

## Default Rules

CaseScope includes default noise categories and rules in `models/noise.py`.

Defaults are seeded by `seed_noise_defaults()` when the application initializes and no noise categories exist. Seeded rules are marked as system defaults.

System default rules are meant to provide a starting library, not a final tuning set for every environment. Analysts should review categories and enable only the rules that make sense for the case and customer environment.

System default rules cannot be deleted through normal rule management. They can be enabled, disabled, or adjusted according to the available UI/API behavior.

## Creating And Updating Rules

Rules are managed through the Settings noise tab and the `/settings/noise/api/*` routes in `routes/noise.py`.

Common actions include:

- list categories
- list rules
- add a rule
- edit a rule
- enable or disable a category
- enable or disable a rule
- delete non-system-default rules
- seed default rules
- test matching behavior

There is no separate external feed or scheduled sync for noise rules. Updates come from the database-backed UI/API workflow or from seeded defaults.

## How Matching Works

Noise matching is performed by the Celery task `tasks.noise_tagger.tag_noise_events`.

The task:

1. Loads active noise rules.
2. Clears prior scan-derived rule matches for the case.
3. Builds ClickHouse keyword clauses for each rule.
4. Matches against event text fields such as `raw_json` and `search_blob`.
5. Updates matching ClickHouse event rows.
6. Stores progress for UI polling.
7. Updates case scan metadata when complete.

Keyword SQL helpers live in `utils/noise_keywords.py`.

ClickHouse update helpers live in `utils/event_noise_state.py`.

## ClickHouse Event Fields

Noise state is stored directly on the ClickHouse `events` table.

Important fields:

- `noise_matched`
- `noise_rules`

`noise_matched` indicates whether the row is currently considered noise.

`noise_rules` stores the names of scan-derived rules that matched the event. Multiple rules may match the same event, so the rule list can contain more than one value.

Manual noise tagging may set `noise_matched` without adding rule names. This allows analysts to mark events as noise even when no configured rule was responsible.

## Scan-Derived Versus Manual Noise

There are two main ways an event becomes noise:

- **Rule scan:** active rules match event content and add rule names to `noise_rules`.
- **Manual marking:** an analyst bulk-marks selected hunting results as noise.

Rule scans rebuild scan-derived rule matches. Manual noise state is designed to remain distinct from rule-derived matches.

This distinction matters because a future rule scan can clear and rebuild rule-derived noise while preserving manually marked operational decisions.

## Hunting Behavior

Hunting hides noise by default.

In the events tab, the **Show noise** checkbox controls whether noise-tagged events are included. When **Show noise** is off, event queries add a filter that excludes rows where `noise_matched` is true.

When **Show noise** is on, analysts can review noise-tagged events again. This is useful when validating a rule, checking whether a detection was hidden, or investigating a noisy tool.

The hunting interface can also show noise status and banners, such as indicating that an artifact or event is potential noise.

## Case Dashboard And Stats

Case views and dashboards can report noise-filtered counts using event overlay state.

These counts help analysts understand how much data is being suppressed by active noise rules and whether a case has already been scanned.

Counts should be interpreted carefully because rules can overlap. The number of rule hits is not always the same as the number of distinct noisy events.

## Testing Rules

Noise routes include test matching endpoints so analysts can evaluate rules against event data before relying on them.

Use rule testing when:

- creating a new rule
- tuning keywords
- validating a default rule
- checking whether a rule is too broad
- investigating unexpected hidden events

Good noise rules should be specific enough to suppress expected behavior without hiding suspicious activity that only looks similar.

## Updating Noise Rules

Noise rules are updated by editing them in Settings or through the noise API.

After changing rules:

1. Enable or disable the category and rule as needed.
2. Test matching if the change is broad.
3. Re-run the case noise scan.
4. Review hunting results with and without **Show noise**.
5. Adjust keywords if too many or too few events are matched.

Rule edits do not automatically rewrite every case immediately. Re-run scans for cases where the updated rules should apply.

## Repair And Re-Scan Tools

CaseScope includes repair and overlay tooling for rebuilding event overlay state.

Relevant paths include:

- `bin/repair_event_overlays.py`
- `utils/event_overlay_repair.py`
- `utils/event_noise_state.py`

These tools can be useful after ClickHouse repair, overlay rebuilds, or case maintenance work. Use them carefully because they can modify event overlay state across many rows.

## RAG And Analysis Filters

Some analysis and RAG paths also respect noise state by excluding rows where `noise_matched` is true.

This means noise tagging can affect more than the visible hunting table. It can reduce the event set used by downstream analysis workflows.

Before applying broad noise rules, validate that they do not hide activity that should remain available to detection, AI, or reporting workflows.

## Required Services

Noise tagging depends on:

- PostgreSQL for noise categories, rules, and audit records
- ClickHouse for event rows and noise overlay fields
- Celery workers for background noise scans
- Redis for task progress and status

If Celery is stopped, rules can still be edited, but scans will not complete.

## Operational Guidance

Use this guidance when managing noise:

- Start with rules disabled unless you are confident they are safe.
- Enable categories gradually.
- Test broad rules before scanning a full case.
- Prefer specific keywords over generic tool names when possible.
- Review noisy events periodically with **Show noise** enabled.
- Re-run scans after rule changes.
- Avoid using noise rules to hide unresolved suspicious activity.
- Treat noise rules as case-review accelerators, not evidence deletion.

## Troubleshooting

No events are tagged:

- Confirm the category is enabled.
- Confirm the rule is enabled.
- Confirm the case has indexed events.
- Confirm Celery workers are running.
- Check the noise scan task status.
- Test the rule against ClickHouse events.

Too many events are tagged:

- Review `pattern`, `pattern_and`, and `pattern_not`.
- Add required AND terms.
- Add NOT exclusions.
- Disable the rule and re-run the scan.
- Use **Show noise** to inspect what was hidden.

Rules changed but results did not:

- Re-run the case noise scan.
- Confirm the scan completed.
- Confirm queries are not showing cached or stale results.
- Check worker logs for ClickHouse mutation errors.

Manual noise looks different from rule noise:

- Manual noise may set `noise_matched` without rule names.
- Rule scans add rule names to `noise_rules`.
- This is expected and helps distinguish analyst decisions from rule-derived matches.

## Key Files

- `models/noise.py`
- `routes/noise.py`
- `routes/hunting.py`
- `tasks/noise_tagger.py`
- `utils/event_noise_state.py`
- `utils/noise_keywords.py`
- `migrations/add_events_table.py`
- `bin/repair_event_overlays.py`
- `utils/event_overlay_repair.py`
- `tasks/rag_tasks.py`
- `app.py`
- `static/templates/settings.html`
- `static/templates/case_hunting.html`
- `static/templates/hunting/tab_events.html`
- `static/css/main.css`
