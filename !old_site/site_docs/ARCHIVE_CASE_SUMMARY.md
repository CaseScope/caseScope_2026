# Archive Case Feature - Executive Summary

## Quick Answer to Your Question

> "I assume re-hunt IOCs would work since I dont think that requires the sources files but please correct me if I am wrong"

**✅ YOU ARE CORRECT!** 

IOC re-hunting will work perfectly on archived cases. I analyzed the `hunt_iocs` function in `file_processing.py` (lines 1500-1857) and confirmed it **ONLY uses OpenSearch** - it never accesses source files.

---

## What Works WITHOUT Source Files ✅

These functions work on archived cases:

| Feature | Status | Why |
|---------|--------|-----|
| **IOC Re-Hunting** | ✅ WORKS | Uses OpenSearch only |
| **Search Events** | ✅ WORKS | Uses OpenSearch only |
| **View Events** | ✅ WORKS | Uses OpenSearch only |
| **Export CSV** | ✅ WORKS | Uses OpenSearch only |
| **AI Reports** | ✅ WORKS | Uses OpenSearch data |
| **AI Timelines** | ✅ WORKS | Uses OpenSearch data |
| **Login Analysis** | ✅ WORKS | Uses OpenSearch only |
| **View Systems/IOCs** | ✅ WORKS | Uses database only |

---

## What REQUIRES Source Files ❌

These functions would be disabled on archived cases:

| Feature | Status | Why |
|---------|--------|-----|
| **Re-Index Files** | ❌ DISABLED | Reads EVTX/NDJSON files |
| **Re-SIGMA** | ❌ DISABLED | Reads EVTX files |
| **Upload Files** | ❌ DISABLED | Adds files to case |
| **Delete Files** | ❌ DISABLED | Modifies case files |

---

## How It Would Work

### Archive Process
1. User changes case status to "Archived"
2. System creates ZIP: `{archive_path}/{date} - {case_name}_case{id}/archive.zip`
3. ZIP contains all files from `/opt/casescope/uploads/{case_id}/`
4. Original folder structure preserved (for restore)
5. ZIP verified (test extraction)
6. Original files deleted
7. Case shows "ARCHIVED" warning banner

### What Analysts See
- **Top of case page**: Big red/orange banner saying "ARCHIVED CASE"
- **Warning text**: "Source files archived. Search/IOC hunting work. Re-index/upload disabled."
- **Disabled buttons**: Re-Index, Re-SIGMA, Upload (grayed out with tooltip)
- **Working buttons**: Search, IOC Hunt, AI Reports, Export

### Restore Process
1. User clicks "Restore Case" button
2. Confirmation popup with status selection
3. System extracts ZIP to original location
4. Verifies all files restored
5. Sets ownership to casescope:casescope
6. Deletes archive ZIP
7. Case returns to normal (all buttons enabled)

---

## Implementation Feasibility

### Can This Be Done? 
**✅ YES - Very feasible.**

### Why?
1. **Architecture Supports It**: OpenSearch data is separate from source files
2. **Clean Separation**: File operations already modular (`tasks.py`, `file_processing.py`)
3. **Database Ready**: Case model already has status field, just need to add archive fields
4. **No Breaking Changes**: Feature is additive-only (new status, new fields, new guards)
5. **Similar Patterns Exist**: Progress modals already implemented for AI Reports/Deletion

### Complexity: **Medium** ⭐⭐⭐

- Simple concepts (ZIP files, status checks)
- Moderate file operations (preserve structure, verify integrity)
- Standard UI patterns (progress modals, confirmation dialogs)
- Well-defined boundaries (source files vs indexed data)

### Estimated Implementation Time: **24 hours**

| Phase | Hours |
|-------|-------|
| Database & Settings | 4 |
| Archive/Restore Functions | 8 |
| UI Integration | 6 |
| Guards & Validation | 4 |
| Audit & Documentation | 2 |

---

## Safety Features

### Data Protection
- ✅ ZIP verified before originals deleted
- ✅ Restore verifies all files extracted
- ✅ Permissions corrected after restore
- ✅ Audit log tracks all operations

### Error Handling
- ✅ Disk full detection
- ✅ ZIP corruption handling
- ✅ Permission error recovery
- ✅ Progress tracking for long operations

### Rollback Plan
- ✅ Can restore all archived cases
- ✅ Can disable feature without code changes
- ✅ Can revert database changes
- ✅ No permanent data loss risk

---

## Recommendation

**✅ PROCEED WITH IMPLEMENTATION**

This feature is:
- **Feasible** - Architecture supports it, no major obstacles
- **Safe** - Multiple verification steps, clear rollback plan
- **Valuable** - Frees SSD space, reduces costs, enables long-term retention
- **Non-Breaking** - Additive-only, existing cases unchanged
- **User-Friendly** - Clear UI, progress tracking, seamless restore

The full implementation plan is in `ARCHIVE_CASE_IMPLEMENTATION_PLAN.md` (57 pages, comprehensive detail).

---

## Next Steps

If you want to proceed:

1. **Review** - Read the full implementation plan
2. **Decide** - Confirm you want this feature
3. **Configure** - Identify archive path (e.g., `/archive` or `/mnt/archive_drive`)
4. **Test Case** - Pick a small case for testing (10-100 files)
5. **Implement** - Follow 5-phase plan in document

**Questions?** Ask before I start coding.

