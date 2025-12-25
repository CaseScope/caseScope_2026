# Event Tagging System

**Last Updated**: December 25, 2025  
**Status**: Production Ready

## Overview

The Event Tagging System allows analysts to mark events of interest during investigation. Tags are stored at the OpenSearch level for optimal performance and can be filtered alongside file type filters.

## Architecture

### Storage: OpenSearch (Not Database)

Tags are stored in OpenSearch documents for:
1. **Performance**: No database joins needed
2. **Scalability**: Handles millions of events without DB bloat  
3. **Simplicity**: Tags stored with event data
4. **Query Efficiency**: Native OpenSearch boolean filters

### OpenSearch Fields

```python
'analyst_tagged': {'type': 'boolean'},
'analyst_tagged_by': {'type': 'keyword'},
'analyst_tagged_at': {'type': 'date'}
```

## API Endpoints

### Tag/Untag Events

**Tag**: `POST /search/api/event/<event_id>/tag`  
**Untag**: `POST /search/api/event/<event_id>/untag`

Response:
```json
{"success": true, "message": "Event tagged successfully"}
```

### Query Tagged Events

**Count**: `GET /search/api/tagged_events/count`  
**Get All**: `GET /search/api/tagged_events` (max 10,000)

### Search with Filters

`GET /search/api/events?event_tags=other,tagged,ioc,sigma`

Parameters: `file_types`, `event_tags`, `q`, `page`, `per_page`

## Event Tag Filters

### Four Filter Types (Default: All Checked)

1. **📄 Other Events** - Events without tags, IOCs, or Sigma hits
2. **⭐ Tagged Events** - Analyst-tagged events  
3. **🔴 IOC Events** - Events with IOC hits
4. **🟣 SIGMA Events** - Events matching Sigma rules

### Filter Behavior

**Checked** = Include those events  
**Unchecked** = Exclude those events

Works exactly like File Type filters using exclusion logic.

### Common Filter Scenarios

| Filters Checked | Result |
|----------------|--------|
| All 4 ✓ | Shows all events (no filtering) |
| Other + Tagged ✓ | Hides IOC and Sigma events |
| Tagged + IOC ✓ | Shows only analyst-tagged and IOC events |
| SIGMA only ✓ | Shows only Sigma rule matches |
| Other only ✓ | Shows only regular events |
| None ✓ | Shows nothing (all excluded) |

### Combining with File Types

File Type and Event Tag filters work together (AND):

```
EVTX ✓ + Tagged ✓ = Tagged EVTX events only
NDJSON ✓ + IOC ✓ = NDJSON events with IOCs
EVTX ✓ + SIGMA ✓ = EVTX events with Sigma hits
```

## UI Features

### Star Column
- **☆** = Not tagged (click to tag)
- **⭐** = Tagged (click to untag)
- **⏳** = Loading state during API call

### Filter Panel
Located in Event Search page, right side:
- Other Events checkbox
- Tagged Events checkbox
- IOC Events checkbox
- SIGMA Events checkbox

All work together with exclusion logic.

## Technical Implementation

### Event Classification

- **Other**: `analyst_tagged != true` AND `NOT IN ioc_event_ids` AND `NOT IN sigma_event_ids`
- **Tagged**: `analyst_tagged == true`
- **IOC**: `opensearch_doc_id IN ioc_event_ids`
- **SIGMA**: `opensearch_doc_id IN sigma_event_ids`

Events can overlap (tagged + IOC + Sigma).

### OpenSearch Query

```python
# All checked = No filter

# If 'other' unchecked:
must_not: [bool: {must_not: [tagged, ioc, sigma]}]

# If 'tagged' unchecked:
must_not: [{term: {analyst_tagged: true}}]

# If 'ioc' unchecked:
must_not: [{ids: {values: [ioc_event_ids]}}]

# If 'sigma' unchecked:
must_not: [{ids: {values: [sigma_event_ids]}}]
```

### Frontend (JavaScript)

```javascript
// Collect checked filters
eventTagFilters = [];
if ($('#filterOtherEvents').checked) eventTagFilters.push('other');
if ($('#filterTaggedEvents').checked) eventTagFilters.push('tagged');
if ($('#filterIOCEvents').checked) eventTagFilters.push('ioc');
if ($('#filterSigmaEvents').checked) eventTagFilters.push('sigma');

// Pass to API
params.append('event_tags', eventTagFilters.join(','));
```

## Usage Examples

### For Analysts

**Tag an event:**
1. Click star (☆) next to event
2. Star fills (⭐) and tag is saved

**Filter view:**
1. Uncheck "Other Events" to see only tagged/IOC/Sigma events
2. Uncheck "IOC Events" to hide IOC hunting results
3. Check only "SIGMA Events" to see Sigma rule matches

### For Automation

```python
import requests

# Get all tagged events
response = requests.get(
    'https://casescope.local/search/api/tagged_events',
    cookies={'session': session}
)

events = response.json()['events']
for event in events:
    print(f"Event {event['event_id']} on {event['computer']}")
    print(f"Tagged by: {event['tagged_by']}")
```

### Use Cases

1. **Pivot Analysis**: Start hunting from tagged events
2. **Timeline Creation**: Generate timelines from tagged events
3. **IOC Extraction**: Extract IOCs from analyst-selected events
4. **Report Generation**: Include tagged events in reports

## Permissions

| Role | Tag/Untag | View Tagged |
|------|-----------|-------------|
| Admin | ✓ | ✓ |
| Analyst | ✓ | ✓ |
| Read-only | ✗ | ✓ |

All tag operations are audited automatically.

## Performance

- **Tag operation**: < 200ms (OpenSearch update)
- **Query tagged**: < 50ms (boolean filter)
- **Count tagged**: < 10ms (count API)
- **No database overhead**
- **Scales linearly**

## Best Practices

### For Analysts
1. Tag only significant events
2. Review tagged events periodically
3. Use consistent tagging strategy
4. Coordinate with team

### For Developers
1. Use bulk API for automation
2. Handle API errors gracefully
3. Respect filter state
4. Test with large datasets

## Troubleshooting

### Tag Not Persisting
- Check OpenSearch connectivity
- Verify user permissions
- Check browser console for errors

### Filter Not Working
- Verify events are actually tagged
- Clear conflicting filters
- Check OpenSearch refresh (5s interval)

### Performance Issues
- Check OpenSearch cluster health
- Monitor network latency
- Verify index isn't over-sharded

## Future Enhancements

Possible additions:
- Tag categories (critical, suspicious, etc.)
- Tag comments/notes
- Bulk tagging
- Tag export to CSV/JSON
- Tag analytics/visualization
- Cross-case tag sharing

## Related Documentation

- [SEARCH_SYSTEM.md](SEARCH_SYSTEM.md) - Event search
- [THREAT_HUNTING.md](THREAT_HUNTING.md) - IOC and Sigma hunting
- [AUDIT.MD](AUDIT.MD) - Audit logging

## Testing

Test script: `/opt/casescope/scripts/test_event_tagging.py`

```bash
sudo -u casescope /opt/casescope/venv/bin/python3 \
  /opt/casescope/scripts/test_event_tagging.py
```

Expected: All tests pass ✓
