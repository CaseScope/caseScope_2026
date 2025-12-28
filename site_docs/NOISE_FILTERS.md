# Noise Filter System

**Added:** 2025-12-28  
**Version:** 2026.2.0

## Overview

The Noise Filter System allows administrators to define rules that filter out known good software and tools from event searches and displays. This helps reduce noise in investigations by hiding events from legitimate RMM tools, EDR platforms, remote access software, and other known benign applications.

## Features

### 1. Filter Categories

Organize noise filter rules into logical categories:

- **RMM Tools**: Remote Monitoring and Management platforms (ConnectWise, Datto, Kaseya, NinjaRMM, etc.)
- **EDR/MDR Platforms**: Security platforms (BlackPoint, Huntress, SentinelOne, CrowdStrike, etc.)
- **Remote Access Tools**: Legitimate remote support tools (TeamViewer, AnyDesk, ScreenConnect, etc.)
- **Backup Software**: Backup and recovery solutions
- **System Software**: Known good system utilities
- **Monitoring Tools**: Performance monitoring tools

Each category can be enabled/disabled independently.

### 2. Filter Rules

Each rule specifies:

- **Category**: Which category this rule belongs to
- **Name**: Human-readable name (e.g., "ConnectWise Automate")
- **Description**: Optional explanation of what is filtered
- **Filter Type**: What type of data to match against
  - `process_name`: Match against process/executable names
  - `file_path`: Match against file paths
  - `command_line`: Match against command line arguments
  - `hash`: Match against file hashes (SHA256)
  - `guid`: Match against GUIDs or session IDs
  - `network_connection`: Match against IP addresses
- **Pattern**: The text/pattern to match
- **Match Mode**: How to match the pattern
  - `exact`: Exact match only
  - `contains`: Pattern appears anywhere in value
  - `starts_with`: Value starts with pattern
  - `ends_with`: Value ends with pattern
  - `wildcard`: Use * and ? wildcards
  - `regex`: Regular expression matching
- **Case Sensitive**: Whether matching is case-sensitive
- **Priority**: Execution order (lower number = higher priority)
- **Status**: Enabled/Disabled

### 3. System Defaults vs Custom Rules

- **System Defaults** (24 rules): Built-in rules covering common tools, cannot be deleted (only disabled)
- **Custom Rules**: User-defined rules that can be fully edited or deleted

## Usage

### Accessing Noise Filters

1. Navigate to **Settings** → **Noise Filters** (`/settings/noise-filters`)
2. Requires **Administrator** role

### Managing Categories

- View all categories with rule counts and status
- Enable/disable entire categories at once
- Click "View Rules" to filter by category

### Managing Rules

- **Search**: Find rules by name, description, or pattern
- **Filter**: By category, status (enabled/disabled/system/custom), or filter type
- **Add Rule**: Click "Add Filter Rule" button
- **Edit Rule**: Click "Edit" button on any rule
- **Toggle**: Enable/disable individual rules with "Enable"/"Disable" button
- **Delete**: Remove custom rules (system defaults cannot be deleted)

### Pattern Syntax

**NEW:** Enhanced pattern matching with multiple options:

#### OR Logic (Comma-Separated)
Match if **ANY** pattern is found:
```
Pattern: rmm,agent,service
Matches: "rmm.exe" OR "rmmAgent" OR "service_monitor"
```

#### AND Logic (&&)
Match only if **ALL** patterns are found:
```
Pattern: screenconnect&&123456
Matches: Only when BOTH "screenconnect" AND "123456" appear
Use case: Filter specific ScreenConnect session ID
```

#### Combined Logic
You can combine both:
```
Pattern: veeam,backup&&server123
Matches: "veeam" OR (both "backup" AND "server123")
```

### Default State

⚠️ **Important:** All filters are **disabled by default**. This prevents accidental filtering of legitimate events until you explicitly enable the filters you need.

### Adding Custom Rules

Example: Filter out a specific ScreenConnect relay server by GUID

```
Category: Remote Access Tools
Name: ScreenConnect Relay ABC123
Filter Type: guid
Pattern: abc123-def456-789012
Match Mode: contains
Case Sensitive: No
Priority: 100
Enabled: Yes
```

## Technical Implementation

### Database Tables

- `noise_filter_categories`: Category definitions (6 categories)
- `noise_filter_rules`: Filter rule definitions (29 default rules)
- `noise_filter_stats`: Track filtering statistics per case
- `active_tasks`: Track running noise tagging tasks for UI persistence

### Models

Located in `app/models.py`:

- `NoiseFilterCategory`: Category model with enable/disable flag
- `NoiseFilterRule`: Rule model with pattern matching configuration
- `NoiseFilterStats`: Statistics tracking model
- `ActiveTask`: Task persistence for reconnectable long-running operations

### Celery Tasks

Located in `app/tasks/task_tag_noise.py`:

- `tag_noise_events()`: Main task for tagging events as noise
  - Uses **dynamic parallel processing** with OpenSearch slice scrolling
  - Worker threads configured via `TASK_PARALLEL_PERCENTAGE` (default: 50% of Celery workers)
  - Thread-safe progress tracking with shared dictionary
  - Typical performance: ~7,000 events/second using 4 parallel slices

### Utility Functions

Located in `app/utils/noise_filter.py`:

- `build_noise_filter_query()`: Build OpenSearch query with must_not clauses (for hiding noise)
- `apply_noise_filters_to_query()`: Apply filters to existing queries
- `_event_matches_rule()`: Check individual events against rules (Python-level)
- `_value_matches_pattern()`: Pattern matching with OR/AND logic support
- `_get_nested_field()`: Extract nested field values from events
- `record_filter_match()`: Track filter statistics
- `get_filter_stats_for_case()`: Get filtering stats for a case

### Integration Points

The noise filter system is integrated into:

1. **Event Search** (`/search/events`): 
   - Noise filter checkboxes in UI (unchecked by default)
   - Cumulative filtering: checking a category adds those noise events to results
   - Default behavior: hides all noise events

2. **Event Tagging** (`/hunting/dashboard`):
   - "Software Noise Tagging" button
   - Background task with progress modal
   - Shows events tagged, rules matched, and breakdown by category

3. **OpenSearch Event Storage**:
   - Tagged events have: `noise_matched=true`, `noise_rules=[]`, `noise_categories=[]`
   - Enables efficient filtering without database queries

4. **Settings Management** (`/settings/noise-filters`):
   - Category and rule management interface
   - Enable/disable categories and individual rules
   - Add custom rules for organization-specific tools

## Default Filters Included

### RMM Tools (10 rules)
- ConnectWise Automate (LabTech) - `labtech,ltsvc,lttray`
- Datto RMM - `datto,dattoagent,dattobackup`
- Kaseya VSA - `kaseya,agentmon`
- N-able N-central - `n-central,n-able,solarwinds`
- NinjaRMM - `ninjarmm,ninjaone`
- Atera - `atera,ateraagent`
- Syncro - `syncro`
- Level (Pulseway) - `pulseway,level`
- MeshCentral - `meshcentral,meshagent`
- TacticalRMM - `tacticalrmm,tacticalagent`

### EDR/MDR Platforms (8 rules)
- BlackPoint Cyber MDR - `blackpoint,bpagent`
- Huntress EDR - `huntress,huntressagent`
- SentinelOne - `sentinel,sentinelagent,sentinelone`
- CrowdStrike Falcon - `crowdstrike,csagent,csfalcon`
- Microsoft Defender - `msmpeng,mssense,defender`
- Carbon Black - `carbonblack,cb`
- Cylance - `cylance,cylancesvc`
- Sophos - `sophos,savservice`

### Remote Access Tools (8 rules)
- ConnectWise Control (ScreenConnect) - `screenconnect&&24a22b9fc261d141,connectwisecontrol`
- TeamViewer - `teamviewer`
- AnyDesk - `anydesk`
- LogMeIn - `logmein`
- GoToMyPC - `gotomypc,gotoassist`
- Splashtop - `splashtop`
- Chrome Remote Desktop - `remoting_host,chromeremotedesktop`
- Windows RDP - `mstsc,rdp`

### Backup Software (3 rules)
- Veeam Backup - `veeam,veeamagent,veeambackup`
- Datto Backup - `dattobackup,dattocontinuity`
- StorageCraft - `storagecraft,shadowprotect,spxservice`

**Total: 29 default rules** (all disabled by default)

## Migration

Database migration: `/opt/casescope/migrations/add_noise_filters.sql`

To apply:
```bash
sudo -u postgres psql casescope -f /opt/casescope/migrations/add_noise_filters.sql
```

## Event Storage Format

When events are tagged as noise, they receive these OpenSearch fields:

```json
{
  "noise_matched": true,
  "noise_rules": ["ConnectWise Automate", "Huntress EDR"],
  "noise_categories": ["RMM Tools", "EDR/MDR Platforms"]
}
```

This enables:
- Fast filtering without database queries
- Multi-category classification (one event can match multiple categories)
- Rule-level attribution (know exactly which rules matched)

## Troubleshooting

### No Events Tagged (0 Matches)

**Symptom**: Noise tagging completes but reports 0 events tagged

**Common Causes**:
1. **No enabled rules**: Check Settings → Noise Filters and enable relevant rules
2. **No enabled categories**: Ensure category is enabled, not just individual rules
3. **Missing search_blob**: Events without structured `event_data` won't match unless `search_blob` field is checked
4. **Pattern mismatch**: Your environment may not use the default tools

**Solution**: 
- Enable appropriate categories and rules in Settings
- Add custom rules for your specific environment
- Verify events exist that match the patterns (test with OpenSearch query)

### Wrong Categories in UI

**Symptom**: Checking a noise filter category shows 0 new events

**Cause**: Category has no tagged events in current case

**Solution**: Only categories with actual tagged events will affect results

### Threading Errors During Tagging

**Symptom**: `Working outside of application context` error

**Cause**: Database queries in worker threads without Flask app context

**Solution**: Fixed in current implementation - rules are pre-loaded in main thread and passed to workers

## Benefits

1. **Reduced Noise**: Hide known good software from searches (e.g., 64,676 noise events hidden from 483,338 total)
2. **Faster Analysis**: Focus on suspicious events only (13% noise reduction in typical cases)
3. **Customizable**: Add organization-specific tools with custom rules
4. **Categorized**: Organized by software type for intelligent filtering
5. **Flexible**: Multiple match modes, OR/AND logic, and 6 filter types
6. **Trackable**: Statistics show what was filtered and which rules matched
7. **Fast**: Parallel processing tags ~7,000 events/second
8. **Selective Display**: Choose which noise categories to view during investigation

## Performance & Scalability

### Parallel Processing

The noise tagging task uses **dynamic parallel processing** for optimal performance:

**Configuration** (`app/config.py`):
```python
TASK_PARALLEL_PERCENTAGE = 50  # Use 50% of Celery workers for parallel slices
TASK_PARALLEL_MIN = 2          # Minimum parallel slices
TASK_PARALLEL_MAX = 8          # Maximum parallel slices
```

**Calculation**:
- 8 workers × 50% = 4 parallel slices
- Each slice processes ~120,000 events independently
- Progress aggregated from all slices in real-time

**Performance**:
- **483,000 events** tagged in **~70 seconds** = ~7,000 events/second
- Uses OpenSearch slice scrolling for parallel index access
- Thread-safe progress tracking via shared dictionary
- Main thread aggregates and reports progress to avoid Celery context issues

### Field Matching Strategy

The filter checks multiple fields to support both EVTX and NDJSON formats:

**Process Name Matching** (most common):
1. `event_data.Image` - EVTX full path
2. `event_data.ProcessName` - EVTX process name
3. `event_data.ParentImage` - EVTX parent process
4. `process.name` - NDJSON/ECS process name
5. `process.executable` - NDJSON executable path
6. **`search_blob`** - ⚠️ CRITICAL: Catches unparsed/raw events

**Important**: The `search_blob` field is essential for events without structured `event_data` fields. Without it, 0 events would be matched.

## Future Enhancements

Potential improvements:

- Time-based filters (only filter during certain hours)
- Case-specific overrides
- Import/export filter rule sets
- Machine learning to suggest new filters
- Integration with threat intelligence feeds
- Whitelist/blacklist toggle per case
- Dynamic category discovery (auto-populate UI with only categories that have data)

## Hunting Dashboard Integration

### New Tile Layout

The hunting dashboard (`/hunting/dashboard`) features a 3-tile layout:

**Tile 1: AI / Regex Hunting**
- IOC Extract
- MITRE
- Behavioral  
- Network

**Tile 2: Event Hunting**
- Failed Logins
- Success Logins
- Hunt IOCs
- Hunt SIGMA
- Found Downloads

**Tile 3: Event Tagging** ⭐ NEW
- **Software Noise** button - Apply noise filter rules and tag events

### Noise Tagging Process

1. User clicks "Software Noise" button
2. Modal displays with progress tracking:
   - Events scanned counter
   - Total events
   - Events tagged counter
   - Rules matched counter
3. Background Celery task runs with parallel processing
4. Results shown:
   - Events tagged count
   - Total matches count
   - Top rules matched table (rule name, category, match count)

### Event Search Integration

Noise filters appear in event search page (`/search/events`) as third filter group:

- **File Types** (left column)
- **Event Tags** (middle column)
- **Noise Filters** (right column)

**Default State**: All noise filters unchecked → hides all noise events

**When Checked**: Adds those specific noise categories to search results (cumulative)

**Example**:
- Default: 418,662 events (non-noise only)
- Check "RMM Tools": 418,662 + 16,724 = 435,386 events
- Check "EDR/MDR": 418,662 + 64,370 = 483,032 events

## API Endpoints

### Settings Management (Administrator only)

- `GET /settings/noise-filters/` - Main management page
- `GET /settings/noise-filters/api/categories` - List categories
- `GET /settings/noise-filters/api/rules` - List rules (paginated)
- `POST /settings/noise-filters/api/rules/add` - Add new rule
- `POST /settings/noise-filters/api/rules/<id>/edit` - Edit rule
- `POST /settings/noise-filters/api/rules/<id>/toggle` - Enable/disable rule
- `POST /settings/noise-filters/api/rules/<id>/delete` - Delete rule (custom rules only)
- `POST /settings/noise-filters/api/categories/<id>/toggle` - Enable/disable category
- `GET /settings/noise-filters/api/stats` - Get statistics

### Event Tagging (Analyst or Administrator)

- `POST /hunting/api/tag_noise` - Start noise tagging task
  - Parameters: `case_id`, `clear_previous` (default: true)
  - Returns: `task_id` for progress tracking
- `GET /hunting/api/tag_noise/status/<task_id>` - Check tagging progress
  - Returns: Progress percentage, events scanned, events tagged, rules matched

### Event Search Filters (All authenticated users)

- Integrated into `/search/api/events` endpoint
- Parameter: `noise_categories` (comma-separated category names)
- Example: `?noise_categories=RMM Tools,EDR/MDR Platforms`

