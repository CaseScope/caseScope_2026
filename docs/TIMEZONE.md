# CaseScope Timezone Handling

This document explains how timezones are handled throughout CaseScope, including timestamp normalization, storage, and display.

## Overview

CaseScope uses a **UTC normalization strategy** for artifact timestamps:

1. **Storage**: All timestamps are stored twice in ClickHouse:
   - `timestamp` - Original timestamp as parsed (forensic integrity)
   - `timestamp_utc` - Normalized to UTC for consistent sorting/filtering/display

2. **Display**: Timestamps are converted from UTC to the case's configured timezone for display in the UI

3. **Source Classification**: Parsers are classified as either **UTC sources** or **ambiguous sources** to determine how to normalize timestamps

---

## Database Schema

### ClickHouse Events Table

```sql
timestamp           DateTime64(3)        -- Original timestamp (forensic record)
timestamp_utc       DateTime64(3)        -- Normalized UTC timestamp (for display/queries)
timestamp_source_tz LowCardinality(String)  -- IANA timezone identifier assumed for source
```

### PostgreSQL Cases Table

```sql
timezone VARCHAR(50) NOT NULL DEFAULT 'UTC'  -- IANA timezone identifier (e.g., 'America/New_York')
```

---

## Parser Classification

### UTC Source Artifacts

These parsers produce timestamps that are **definitively UTC**. No conversion is needed.

| Artifact Type | Format | Notes |
|---------------|--------|-------|
| `evtx` | Windows FILETIME | FILETIME is 100-nanosecond intervals since 1601-01-01 in UTC |
| `prefetch` | FILETIME | Windows Prefetch uses FILETIME |
| `registry` | FILETIME | Registry timestamps are FILETIME |
| `lnk` | FILETIME | LNK shortcut timestamps are FILETIME |
| `jumplist` | FILETIME | JumpList timestamps are FILETIME |
| `mft` | FILETIME | MFT $STANDARD_INFORMATION uses FILETIME |
| `srum` | OLE Automation Date | SRUM ESE database uses OLE dates (UTC-based) |
| `activities_cache` | FILETIME | Windows Timeline uses FILETIME |
| `activity_operation` | FILETIME | Windows Timeline operations use FILETIME |
| `webcache` | FILETIME | IE/Edge WebCache ESE uses FILETIME |
| `webcache_*` | FILETIME | All WebCache container types (history, cookies, downloads, cache) |
| `browser_history` | WebKit/Mozilla | Chrome uses WebKit timestamps (µs since 1601 UTC), Firefox uses PRTime (µs since Unix epoch) |
| `browser_cookies` | WebKit/Mozilla | Same as browser_history |
| `browser_forms` | WebKit/Mozilla | Same as browser_history |
| `browser_logins` | WebKit/Mozilla | Same as browser_history |
| `browser_autofill` | WebKit/Mozilla | Same as browser_history |
| `browser_download` | WebKit/Mozilla | Same as browser_history |
| `firefox_session` | Unix epoch | JSON files use Unix timestamps |
| `firefox_addon` | Unix epoch | Same as firefox_session |
| `firefox_search_engine` | Unix epoch | Same as firefox_session |
| `firefox_handler` | Unix epoch | Same as firefox_session |
| `huntress` | ISO8601 | Huntress EDR exports use ISO8601 with explicit UTC indicator (`Z`) |
| `json_log` | ISO8601 | Generic JSON logs typically use ISO8601 (assumed UTC) |

### Ambiguous Source Artifacts

These parsers produce timestamps in an **unknown or local timezone**. The case timezone is used for conversion to UTC.

| Artifact Type | Notes |
|---------------|-------|
| `iis` | IIS logs typically use server local time (W3C format: `date time`) |
| `firewall` | Firewall/syslog logs vary by vendor; often local time |
| `sonicwall` | SonicWall CSV exports use appliance local time (`MM/DD/YYYY HH:MM:SS`) |
| `csv_log` | Generic CSV logs have unknown timezone |
| `scheduled_task` | XML registration dates use local time |

---

## Conversion Flow

### At Parse Time

```
┌─────────────────────┐
│  Parser reads file  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Parse timestamp     │
│ (various formats)   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐     ┌──────────────────────┐
│ Is artifact type in │─Yes─▶ timestamp_source_tz = │
│ UTC_SOURCE_ARTIFACTS│      │ 'UTC'                │
└──────────┬──────────┘     └──────────────────────┘
           │ No
           ▼
┌─────────────────────┐     ┌──────────────────────┐
│ Is artifact type in │─Yes─▶ timestamp_source_tz = │
│ AMBIGUOUS_ARTIFACTS │      │ case_tz (e.g.,       │
└──────────┬──────────┘      │ 'America/New_York')  │
           │ No              └──────────────────────┘
           ▼
┌─────────────────────┐
│ Default to 'UTC'    │
└─────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────┐
│ compute_utc_timestamp()                      │
│ - If source_tz != UTC: convert to UTC        │
│ - Store result in timestamp_utc              │
│ - Handles DST automatically via zoneinfo     │
└──────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────┐
│ Insert to ClickHouse│
│ - timestamp (orig)  │
│ - timestamp_utc     │
│ - timestamp_source_tz│
└─────────────────────┘
```

### At Display Time

```
┌─────────────────────┐
│ Query ClickHouse    │
│ ORDER BY timestamp_utc │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Get case timezone   │
│ (from PostgreSQL)   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ from_utc() converts │
│ timestamp_utc →     │
│ case timezone       │
│ (DST-aware)         │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ format_for_display()│
│ Returns formatted   │
│ string in case TZ   │
└─────────────────────┘
```

---

## Utility Functions

### `utils/timezone.py`

| Function | Purpose |
|----------|---------|
| `to_utc(naive_dt, source_tz)` | Convert naive datetime from source timezone to UTC |
| `from_utc(utc_dt, display_tz)` | Convert UTC datetime to display timezone |
| `format_for_display(utc_dt, display_tz, fmt)` | Format UTC datetime for UI display in target timezone |
| `parse_time_window(from_str, to_str, case_tz)` | Parse user-entered time range and convert to UTC for queries |
| `get_source_tz_for_artifact(artifact_type, case_tz)` | Determine source timezone based on artifact type |
| `is_valid_timezone(tz_name)` | Validate IANA timezone identifier |

---

## Parser Implementation

### UTC Source Parser Example (EVTX)

EVTX timestamps are always UTC, so no conversion is performed. The parser uses default `timestamp_source_tz = 'UTC'`:

```python
yield ParsedEvent(
    case_id=self.case_id,
    artifact_type='evtx',
    timestamp=timestamp,          # Already UTC
    # timestamp_source_tz defaults to 'UTC'
    # timestamp_utc is computed by compute_utc_timestamp() (returns same value)
    ...
)
```

### Ambiguous Source Parser Example (IIS)

IIS timestamps are in server local time. The parser explicitly sets `timestamp_source_tz` to the case timezone:

```python
yield ParsedEvent(
    case_id=self.case_id,
    artifact_type='iis',
    timestamp=timestamp,                      # Local time as parsed
    timestamp_source_tz=self.get_source_tz(), # Returns case_tz (e.g., 'America/New_York')
    ...
)
# compute_utc_timestamp() will convert: 09:36 EST → 14:36 UTC
```

### Browser Parser Example

Browser timestamps use WebKit (Chrome) or PRTime (Firefox) which are UTC-based:

```python
def webkit_to_datetime(webkit_timestamp: int) -> Optional[datetime]:
    """Convert WebKit/Chrome timestamp to datetime (UTC)
    
    WebKit timestamps are microseconds since 1601-01-01 in UTC
    """
    epoch_diff = 11644473600000000  # µs from 1601 to 1970
    unix_timestamp = (webkit_timestamp - epoch_diff) / 1000000
    return datetime.utcfromtimestamp(unix_timestamp)  # Returns UTC
```

---

## Case Timezone Configuration

### System Default

Set in **Settings → General** tab:
- Default timezone applied to newly created cases
- API: `GET/PUT /api/settings/timezone`

### Per-Case Setting

Set in **Case Edit** page:
- Dropdown with common IANA timezone identifiers
- Used for:
  - Converting ambiguous source timestamps to UTC during parsing
  - Displaying UTC timestamps in the case timezone in the UI

---

## Backfill Script

For cases indexed before timezone support was added:

```bash
# Preview what would be updated
python migrations/backfill_timestamp_utc.py --dry-run

# Backfill specific case
python migrations/backfill_timestamp_utc.py --case-id 5

# Backfill all cases
python migrations/backfill_timestamp_utc.py
```

The backfill script:
1. Gets case timezone from PostgreSQL
2. Updates `timestamp_utc` using ClickHouse `addHours()` function
3. Sets `timestamp_source_tz` to the case timezone

**Note**: DST is not handled in backfill (timestamps may be off by 1 hour during DST transitions). For accurate timestamps, re-index the case.

---

## Common IANA Timezone Identifiers

| Timezone | UTC Offset | Notes |
|----------|------------|-------|
| `UTC` | +0:00 | Coordinated Universal Time |
| `America/New_York` | -5:00 / -4:00 | Eastern (EST/EDT) |
| `America/Chicago` | -6:00 / -5:00 | Central (CST/CDT) |
| `America/Denver` | -7:00 / -6:00 | Mountain (MST/MDT) |
| `America/Los_Angeles` | -8:00 / -7:00 | Pacific (PST/PDT) |
| `America/Phoenix` | -7:00 | Arizona (no DST) |
| `Europe/London` | +0:00 / +1:00 | GMT/BST |
| `Europe/Paris` | +1:00 / +2:00 | CET/CEST |
| `Asia/Tokyo` | +9:00 | JST (no DST) |
| `Australia/Sydney` | +10:00 / +11:00 | AEST/AEDT |

---

## Troubleshooting

### Timestamps showing wrong time

1. **Check case timezone**: Ensure case has correct timezone set (Case Edit page)
2. **Check artifact type classification**: Is it in the right category (UTC vs Ambiguous)?
3. **Re-index if needed**: If case was indexed before timezone support, re-index via Case Files → Reindex Case

### All timestamps show UTC

- Case timezone may be set to 'UTC' (default)
- Set appropriate timezone in Case Edit page

### Ambiguous source events off by hours

- The source was in a different timezone than the case setting
- Correct the case timezone and re-index

### DST boundary issues (1-hour off)

- Backfill script doesn't handle DST transitions
- Re-index the case for accurate DST handling

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 3.96.00 | 2026-01-16 | Initial timezone support |
| 3.96.01 | 2026-01-16 | Default timezone system setting |
| 3.96.02 | 2026-01-16 | Timezone display in case dashboard |
| 3.97.00 | 2026-01-16 | Case Statistics layout update |
| 3.97.01 | 2026-01-16 | Fixed Hunting Events/Process Analysis/Browser Downloads timezone display |
| 3.97.02 | 2026-01-16 | Parsers properly set timestamp_source_tz; WebCache moved to UTC category |
| 3.97.03 | 2026-01-16 | Backfill script uses addHours() for reliable conversion |
| 3.97.04 | 2026-01-16 | Browser parsers skip entries without valid timestamps |
