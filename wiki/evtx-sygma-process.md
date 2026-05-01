# EVTX/Sygma Process

This page describes how CaseScope processes Windows EVTX files, how Hayabusa and Sigma-format rules are applied, how detections are stored and tagged, and how the rule set is installed and updated.

The codebase uses the term **Sigma** for Sigma-format detection rules. This page keeps the requested "Sygma" title, but the implementation, UI, and rule references use **Sigma** and **Hayabusa** terminology.

## Overview

EVTX processing is a multi-stage pipeline:

1. An analyst uploads EVTX files through the indexed artifact upload path.
2. CaseScope creates `CaseFile` records and retains originals.
3. Celery queues parser work.
4. The parser registry resolves EVTX files to the EVTX parser.
5. EvtxECmd converts EVTX records into JSON.
6. Hayabusa runs against the same EVTX file with Sigma-format rules.
7. CaseScope merges Hayabusa detections back onto EvtxECmd records by record ID.
8. Parsed and enriched events are written to ClickHouse.
9. Hunting, exports, dashboards, and correlation workflows use the indexed detection fields.

EvtxECmd provides normalized event records. Hayabusa provides detection context, severity, rule titles, rule files, and MITRE ATT&CK metadata.

## Main Components

Important components:

- `parsers/evtx_parser.py` runs EvtxECmd and Hayabusa.
- `parsers/registry.py` resolves `.evtx` files to the EVTX parser.
- `parsers/base.py` maps parsed events into ClickHouse rows.
- `tasks/celery_tasks.py` runs parser work and scheduled rule updates.
- `routes/parsing.py` exposes rule statistics and manual update routes.
- `utils/hayabusa_correlator.py` correlates Hayabusa-enriched events into higher-level findings.
- `pipeline/detect.py` calls Hayabusa correlation during analysis.
- `bin/install_hayabusa.sh` installs Hayabusa and its rules.
- `rules/hayabusa-rules` is the default rule tree.

## Upload And Parse Flow

EVTX files should be uploaded through the indexed case file upload path, not through the non-indexed evidence upload path.

Recommended upload steps:

1. Open the target case.
2. Upload EVTX files through the case upload page or case SFTP upload folder.
3. Review the upload queue.
4. Confirm or correct the hostname.
5. Use auto-detect or choose the appropriate EVTX/log upload type if shown.
6. Start ingest.

The hostname should be the Windows system that produced the event log. Use the same hostname across EVTX, KAPE, CyLR, registry, browser, and other artifacts from the same system so correlation works cleanly.

The case time zone should be set correctly before ingest. EVTX records often carry UTC timestamps, but CaseScope still uses case time zone context where parser behavior requires case-local normalization.

## Parser Resolution

The parser registry detects EVTX files by extension and EVTX magic. If `/opt/casescope/bin/evtxecmd` is available, CaseScope uses the EvtxECmd-based parser.

If EvtxECmd is not available, CaseScope may fall back to the EVTX fallback parser. The fallback parser can still parse records, but it does not provide the same EvtxECmd Maps support or Hayabusa enrichment path.

For full EVTX capability, install and maintain:

- `/opt/casescope/bin/evtxecmd`
- `/opt/casescope/bin/EvtxECmd/EvtxeCmd/Maps`
- `/opt/casescope/bin/hayabusa`
- `/opt/casescope/rules/hayabusa-rules`

## EvtxECmd Processing

CaseScope runs EvtxECmd against each EVTX file and requests JSON output.

EvtxECmd normalizes Windows event records into structured JSON. CaseScope then maps those records into its common event shape, including fields such as:

- event timestamp
- event ID
- channel
- provider
- record ID
- computer or hostname
- user and logon fields where available
- process and network fields where available
- payload fields
- raw JSON
- search text

EvtxECmd Maps improve field extraction by understanding known Windows event layouts. These maps live under the EvtxECmd install path and are installed by the CaseScope tooling installer.

## Hayabusa And Sigma Rules

Hayabusa is used to run detection rules against EVTX data. The Hayabusa rules pack includes Hayabusa-native and Sigma-format rules.

CaseScope invokes Hayabusa using its JSON timeline mode. The parser reads Hayabusa JSONL output and keeps the detection fields that matter for hunting and analysis:

- rule title
- severity level
- rule file
- MITRE tactics
- MITRE tags
- full detection metadata in event extra fields

Hayabusa output is merged back onto the EvtxECmd event rows by record ID. This lets a single Windows event row carry both the normalized event data and the detection metadata from matching rules.

## Detection Fields

When Hayabusa finds a matching rule, CaseScope stores detection metadata on the ClickHouse event row.

Important fields include:

- `rule_title`
- `rule_level`
- `rule_file`
- `mitre_tactics`
- `mitre_tags`
- `extra_fields.has_detection`
- `extra_fields.hayabusa_detections`

If more than one rule matches the same event, CaseScope combines rule titles, levels, and files, and deduplicates MITRE tactics and tags.

Rows with a populated `rule_title` are treated by parts of the UI and stats system as Sigma/Hayabusa-tagged events.

## Hunting And Tagging Behavior

After EVTX records are indexed into ClickHouse, the hunting views can search and filter them like other parsed events.

Hayabusa/Sigma detection metadata gives analysts extra pivots:

- filter on rule title
- filter on severity
- review MITRE tactics and techniques
- find events highlighted as detection hits
- export enriched rows
- include detection metadata in analysis and reporting

The detection tagging described here is different from analyst tags or IOC tags. Hayabusa/Sigma tagging is rule-derived detection metadata attached during EVTX parsing. Analyst tags and IOC tags are separate overlays managed by other workflows.

## MITRE Mapping

Hayabusa rules can include MITRE ATT&CK metadata. CaseScope stores that metadata in `mitre_tactics` and `mitre_tags`.

This supports:

- tactic filtering
- technique-oriented review
- detection summaries
- attack chain correlation
- downstream finding generation

Post-ingest correlation uses `utils/hayabusa_correlator.py` to group Hayabusa-enriched rows into higher-level findings. The correlator considers rule metadata, time windows, correlation keys, severity, and MITRE tactic ordering.

The analysis pipeline can then emit findings built from correlated Hayabusa detections.

## Storage And Indexing

Parsed EVTX events are written to the ClickHouse `events` table.

Core event fields, detection fields, MITRE arrays, raw JSON, extra fields, search text, and overlay fields are stored together so hunting can operate on a single event record.

ClickHouse is the searchable store for these parsed events. The original EVTX files remain retained with the case according to the artifact upload/originals workflow.

## Rule Installation

Hayabusa installation is handled by:

```bash
/opt/casescope/bin/install_hayabusa.sh
```

The installer downloads or updates the Hayabusa binary, clones or prepares the rules tree, runs Hayabusa rule updates, and writes the rule configuration.

Expected paths include:

- `/opt/casescope/bin/hayabusa`
- `/opt/casescope/rules/hayabusa-rules`
- `/opt/casescope/rules/hayabusa.conf`

The README and install guide also install EvtxECmd tooling through:

```bash
/opt/casescope/bin/install_eztools.sh
```

EVTX detection enrichment requires both EvtxECmd and Hayabusa to be installed correctly.

## Rule Updates

CaseScope supports manual and scheduled Hayabusa rule updates.

Manual update:

- Admin-facing parsing routes expose rule statistics and update actions.
- `POST /api/parsing/update-rules` queues `tasks.update_hayabusa_rules`.
- The task calls the parser rule update path, which runs Hayabusa `update-rules`.

Scheduled update:

- Celery Beat schedules `update-hayabusa-rules-weekly`.
- The schedule runs `tasks.update_hayabusa_rules` weekly.
- The update uses the configured Hayabusa binary and rules directory.

Rule statistics:

- `GET /api/parsing/sigma-rules/stats` reports Hayabusa rule counts, Sigma rule counts, total rules, last update information, and Hayabusa version where available.

The settings UI uses these stats and update endpoints to display rule state and trigger updates.

## Sigma Rule Sources

Hayabusa uses the rules under `rules/hayabusa-rules`. That tree contains Hayabusa rules and Sigma-format rules.

CaseScope also has separate Sigma conversion and pattern synchronization logic for hunting patterns and overlays. That path is separate from the per-EVTX Hayabusa subprocess used during EVTX parsing.

In practical terms:

- Hayabusa/Sigma enrichment during EVTX parsing comes from the local Hayabusa rules tree.
- Pattern sync and Sigma conversion support broader hunting/pattern workflows.
- Both can use Sigma-style detection content, but they are different processing paths.

## When Detections Are Applied

Hayabusa detections are applied at EVTX parse time. Existing parsed rows are not automatically re-enriched just because rules are updated.

If new rules are added and you want them applied to older EVTX data, reprocess the affected EVTX files or rebuild the relevant parsed data according to the available case maintenance workflow.

Rule updates affect future EVTX parsing and any explicit reprocessing done after the update.

## Operational Guidance

Use this guidance for clean EVTX/Sigma results:

- Install both EvtxECmd and Hayabusa before ingesting EVTX files.
- Keep Hayabusa rules updated.
- Confirm the case time zone before ingest.
- Use consistent hostnames.
- Upload EVTX files through indexed artifact upload.
- Review detection severity and MITRE tags as leads, not final conclusions.
- Verify important detections against the original event data.
- Reprocess EVTX data when you need newly updated rules applied to old logs.

## Troubleshooting

No detection fields populated:

- Confirm `/opt/casescope/bin/hayabusa` exists and is executable.
- Confirm `/opt/casescope/rules/hayabusa-rules` exists.
- Confirm the EVTX was parsed with the EvtxECmd parser, not only the fallback parser.
- Check Celery worker logs for Hayabusa warnings.

EVTX records are missing or parsing fails:

- Confirm `/opt/casescope/bin/evtxecmd` exists and is executable.
- Confirm EvtxECmd Maps are installed.
- Check worker logs for EvtxECmd errors.
- Confirm the EVTX file is not corrupt.

Rule update fails:

- Confirm the Hayabusa binary exists.
- Confirm the rules directory is writable by the expected user.
- Confirm outbound network access if the update needs to fetch rule changes.
- Check `casescope-workers` logs because the update runs as a Celery task.

Detection counts look stale:

- Confirm the weekly Celery Beat schedule is running.
- Trigger a manual rule update from the settings or parsing API.
- Remember that updated rules apply to future parsing unless older EVTX data is reprocessed.

## Key Files

- `parsers/evtx_parser.py`
- `parsers/base.py`
- `parsers/registry.py`
- `tasks/celery_tasks.py`
- `routes/parsing.py`
- `utils/hayabusa_correlator.py`
- `pipeline/detect.py`
- `migrations/add_events_table.py`
- `config.py`
- `docs/PARSERS.md`
- `bin/install_hayabusa.sh`
- `bin/install_eztools.sh`
- `rules/hayabusa-rules`
- `static/templates/settings.html`
