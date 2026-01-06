# Parser Index Verification
## All Parsers Correctly Routed (V2 System)

**Active Task:** `tasks.process_individual_file_v2`  
**System:** Parser Factory with Automatic Routing

---

## ✅ Parser → Index Mapping (Verified Correct)

### Events & Logs → `case_X`
- ✅ EVTX (evtx_parser)
- ✅ NDJSON (ndjson_parser)
- ✅ Firewall CSV (firewall_csv_parser)

### Browser Activity → `case_X_browser`
- ✅ Browser History (browser_history_parser)
- ✅ WebCache (webcache_parser)

### Execution Artifacts → `case_X_execution`
- ✅ Prefetch (prefetch_parser_dissect)
- ✅ Activities Cache (activities_parser)
- ✅ SRUM (srum_parser)

### Filesystem Timeline → `case_X_filesystem`
- ✅ MFT (eztools_mft_parser)
- ✅ Thumbcache (thumbcache_parser)
- ✅ Windows Search (winsearch_parser)

### User Activity → `case_X_useractivity` ⭐ NEW
- ✅ Jump Lists (eztools_jumplist_parser)
- ✅ LNK Shortcuts (eztools_lnk_parser, lnk_parser)

### Communications → `case_X_comms` ⭐ NEW
- ✅ PST/OST Email (pst_parser)
- ✅ Teams/Skype (teams_skype_parser)
- ✅ Notifications (notifications_parser)

### Network Activity → `case_X_network` ⭐ NEW
- ✅ BITS Transfers (bits_parser)

### Persistence → `case_X_persistence` ⭐ NEW
- ✅ Scheduled Tasks (schtasks_parser)
- ✅ WMI Subscriptions (wmi_parser)

### Devices → `case_X_devices` ⭐ NEW
- ✅ USB History (usb_history_parser)
- ✅ SetupAPI Logs (setupapi_parser)

### Cloud Storage → `case_X_cloud` ⭐ NEW
- ✅ OneDrive (onedrive_parser)

### Remote Sessions → `case_X_remote` ⭐ NEW
- ✅ RDP Cache (rdp_cache_parser)

---

## How V2 Works

**Automatic Routing:**
```python
# 1. Detect parser type
parser_type = detect_parser_type(filename, parent_dir)
# Returns: 'evtx', 'lnk', 'bits', 'pst', etc.

# 2. Get parser function
parser_func = get_parser(parser_type)
# Lazy-loads: evtx_parser.parse_evtx_file, etc.

# 3. Get correct index
index_name = get_index_name(parser_type, case_id)
# Returns: 'case_4', 'case_4_useractivity', 'case_4_comms', etc.

# 4. Parse and index
events = list(parser_func(file_path))
indexer.bulk_index(index_name, events, ...)
```

**Benefits:**
- No manual if/elif chains (300+ lines reduced to 100)
- Automatic routing via parser_routing.py
- All new parsers automatically supported
- Single source of truth for index mapping
- Logs which parser and index used for debugging

---

## Monitoring During Upload

Watch for these log messages:

```
[Worker abc12345] Processing filename.ext
Using <parser_type> parser for filename.ext
Source system: HOSTNAME
Indexing 1234 events to case_4_<index>
Moved to storage: filename.ext → filename.ext.gz
[Worker abc12345] Completed filename.ext: 1234 events
```

Verify correct routing:
```bash
# Check which indices were created
curl -s "http://localhost:9200/_cat/indices/case_4*"

# Check counts per index
curl -s "http://localhost:9200/case_4*/_count" | python3 -m json.tool

# Watch worker logs in real-time
tail -f /opt/casescope/logs/celery_worker.log | grep "Using\|Indexing"
```

---

## Test Checklist

When upload completes, verify:
- [ ] All file types detected correctly
- [ ] Each parser called for appropriate files
- [ ] Events indexed to correct OpenSearch index
- [ ] Source system extracted (when available)
- [ ] Artifact tracking dashboard shows all 11 indices
- [ ] Type breakdowns accurate
- [ ] No "unsupported file type" errors for known formats

---

## Verified: January 6, 2026
All parsers correctly routing via parser factory system.
Ready for comprehensive upload test.
