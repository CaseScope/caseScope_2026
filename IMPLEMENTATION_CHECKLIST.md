# Automated Detection Implementation Checklist

## Pre-Implementation Fixes (30 minutes)

### Fix 1: Update Sonicwall Field Names
**File**: `detection_patterns.py`  
**Patterns Affected**: #001, #010, #017, #022

- [ ] Replace `"Event"` with `"fw_event"`
- [ ] Replace `"Src. IP"` with `"src_ip"`
- [ ] Replace `"Dst. IP"` with `"dst_ip"`
- [ ] Replace `"User Name"` with `"user_name"`
- [ ] Replace `"timestamp"` with `"normalized_timestamp"`

**Test Command**:
```bash
# Should return VPN brute force from IP 185.93.89.38
curl 'http://localhost:9200/case_5/_search' -H 'Content-Type: application/json' -d '{
  "query": {
    "bool": {
      "must": [
        {"match": {"fw_event": "Unknown User Login Attempt"}},
        {"term": {"src_ip": "185.93.89.38"}}
      ]
    }
  },
  "size": 5
}'
```

---

### Fix 2: Add Source File Filters
**File**: `detection_patterns.py`  
**Patterns Affected**: ALL EDR patterns (#002-005, #009, #011-12, #020, #023-30)

Add to each EDR pattern's filter array:
```python
"filter": [
    {"range": {"normalized_timestamp": {"gte": "now-7d"}}},
    {"wildcard": {"source_file": "*.ndjson"}}  # ← ADD THIS
]
```

---

### Fix 3: Add Pattern Metadata
**File**: `detection_patterns.py`

Add to each pattern:
```python
{
    "id": "001",
    "target_index": "case_{case_id}",     # ← ADD
    "source_file_pattern": "*.csv",        # ← ADD
    "tested_cases": ["case_5"],            # ← ADD
    "last_verified": "2026-01-07",         # ← ADD
    # ... existing fields
}
```

---

## Week 1: Core Infrastructure (5 days)

### Day 1: Setup Detection Module
- [ ] Create `/opt/casescope/app/detection/` directory
- [ ] Copy corrected `detection_patterns.py` to `/app/detection/patterns.py`
- [ ] Create `/app/detection/__init__.py`
- [ ] Create `/app/detection/detector.py` (pattern executor)

**File**: `/app/detection/detector.py`
```python
"""
Pattern detection executor
Runs aggregation queries and extracts findings
"""

from opensearchpy import OpenSearch
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

class PatternDetector:
    def __init__(self, opensearch_client):
        self.client = opensearch_client
    
    def execute_pattern(self, pattern: Dict, case_id: int) -> Dict:
        """
        Execute single detection pattern
        Returns: findings dict or None
        """
        index = pattern.get('target_index', 'case_{case_id}').format(case_id=case_id)
        query = pattern['query']
        
        try:
            result = self.client.search(
                index=index,
                body=query,
                request_timeout=60
            )
            
            # Check if pattern matched
            if self.has_findings(result):
                return self.extract_findings(pattern, result, case_id)
            
            return None
            
        except Exception as e:
            logger.error(f"Pattern {pattern['id']} failed: {e}")
            return None
    
    def has_findings(self, result: Dict) -> bool:
        """Check if aggregation shows suspicious activity"""
        if 'aggregations' not in result:
            return False
        
        # If any aggregation has buckets, we have findings
        for agg_name, agg_data in result['aggregations'].items():
            if 'buckets' in agg_data and len(agg_data['buckets']) > 0:
                return True
        
        return False
    
    def extract_findings(self, pattern: Dict, result: Dict, case_id: int) -> Dict:
        """Extract actionable findings from aggregation result"""
        # ... (implementation)
```

---

### Day 2: Create Celery Task
- [ ] Create `/opt/casescope/app/tasks/task_automated_detection.py`
- [ ] Import detection patterns
- [ ] Implement progress tracking
- [ ] Add to Celery task registry

**File**: `/app/tasks/task_automated_detection.py`
```python
from celery import Task
from app import celery_app
from app.detection.patterns import DETECTION_PATTERNS
from app.detection.detector import PatternDetector

@celery_app.task(bind=True)
def run_automated_detection(self, case_id: int, user_id: int, tier: int = 1):
    """
    Run automated detection patterns against case
    
    Args:
        case_id: Case ID to analyze
        user_id: User who initiated detection
        tier: Which tier to run (1, 2, or 3)
    """
    # Filter patterns by tier
    if tier == 1:
        patterns = [p for p in DETECTION_PATTERNS if int(p['id']) <= 10]
    elif tier == 2:
        patterns = [p for p in DETECTION_PATTERNS if 10 < int(p['id']) <= 20]
    else:
        patterns = DETECTION_PATTERNS
    
    findings = []
    total = len(patterns)
    
    for i, pattern in enumerate(patterns):
        # Update progress
        self.update_state(
            state='PROGRESS',
            meta={
                'current': i + 1,
                'total': total,
                'pattern_name': pattern['name'],
                'findings_count': len(findings)
            }
        )
        
        # Execute pattern
        result = detector.execute_pattern(pattern, case_id)
        
        if result:
            findings.append(result)
    
    # Generate LLM report (if findings exist)
    if findings:
        report = generate_threat_report(findings, case_id)
    else:
        report = "No suspicious patterns detected. Case appears clean."
    
    return {
        'patterns_checked': total,
        'findings_count': len(findings),
        'report': report,
        'findings': findings
    }
```

---

### Day 3: Create API Endpoint
- [ ] Add route to `/app/routes/hunting.py`
- [ ] Create start endpoint: `/api/automated_detection/start`
- [ ] Create status endpoint: `/api/automated_detection/status/<task_id>`
- [ ] Add permission checks

---

### Day 4: Frontend Integration
- [ ] Add button to `templates/hunting/dashboard.html`
- [ ] Create modal for progress tracking
- [ ] Add results display UI
- [ ] Test end-to-end flow

---

### Day 5: Testing & Validation
- [ ] Run against case_5
- [ ] Verify Pattern #004 detects PSExec (2 events)
- [ ] Verify Pattern #009 detects Office→Shell (1 event)
- [ ] Verify Pattern #001 detects VPN brute force
- [ ] Check runtime < 5 minutes
- [ ] Review LLM-generated report quality

---

## Validation Tests

### Test 1: Pattern #004 (PSExec)
**Expected**: 2 events on Engineering1 host  
**Command**:
```bash
curl 'http://localhost:9200/case_5/_search' -d '{
  "query": {"match": {"process.name": "psexesvc.exe"}},
  "size": 5
}'
```
**Pass Criteria**: Returns 2 events with PSEXESVC.exe

---

### Test 2: Pattern #009 (Office → Shell)
**Expected**: 1 event (Office app spawning cmd.exe)  
**Command**:
```bash
curl 'http://localhost:9200/case_5/_search' -d '{
  "query": {
    "bool": {
      "must": [
        {"match": {"event.category": "process"}},
        {"terms": {"process.name": ["cmd.exe", "powershell.exe"]}},
        {"terms": {"process.parent.name": ["winword.exe", "excel.exe", "outlook.exe"]}}
      ]
    }
  },
  "size": 5
}'
```
**Pass Criteria**: Returns 1 event with Office parent process

---

### Test 3: Pattern #001 (VPN Brute Force)
**Expected**: IP 185.93.89.38 with multiple failures  
**Command**: (After applying field name fixes)
```bash
curl 'http://localhost:9200/case_5/_search' -d '{
  "query": {
    "bool": {
      "must": [
        {"match": {"fw_event": "Unknown User Login Attempt"}},
        {"term": {"src_ip": "185.93.89.38"}}
      ]
    }
  },
  "size": 0,
  "aggs": {
    "failures": {
      "value_count": {"field": "src_ip"}
    }
  }
}'
```
**Pass Criteria**: Returns count > 10

---

## Week 2-4: Expansion (Optional)

### Week 2: Add Tier 2 Patterns
- [ ] Implement patterns #011-020
- [ ] Test against case_5
- [ ] Build whitelists for noisy patterns (#013 scheduled tasks)
- [ ] Tune thresholds based on false positive rate

### Week 3: Add Tier 3 Patterns  
- [ ] Implement patterns #021-030
- [ ] Skip patterns without data (#021 web shells, #018 prefetch)
- [ ] Focus on EDR-based detections (#025-30)

### Week 4: Production Hardening
- [ ] Performance optimization
- [ ] Error handling
- [ ] User documentation
- [ ] Training materials

---

## Acceptance Criteria

### Minimum Viable Product (Week 1)
- [x] Patterns verified against actual data ✓
- [ ] 10 Tier 1 patterns implemented in code
- [ ] Celery task executes all patterns
- [ ] UI button triggers detection
- [ ] Results displayed in modal
- [ ] Runtime < 5 minutes
- [ ] No crashes or errors

### Production Ready (Week 4)
- [ ] 27 patterns implemented (all feasible ones)
- [ ] False positive rate < 5%
- [ ] Whitelists for known benign activity
- [ ] LLM report includes:
  - Executive summary
  - Detailed findings per pattern
  - Attack chain reconstruction
  - Prioritized recommendations
- [ ] Saved to database for audit trail
- [ ] Integration with existing hunting workflow

---

## Current Status

**Phase**: ✅ Verification Complete  
**Next Phase**: Implementation  
**Blockers**: None  
**Ready to Start**: Yes

**Files Created**:
- ✅ `PATTERN_VERIFICATION_REPORT.md` - Detailed verification results
- ✅ `VERIFICATION_SUMMARY.md` - Executive summary
- ✅ `IMPLEMENTATION_CHECKLIST.md` - This file

**Files to Update**:
- ⚠️ `detection_patterns.py` - Apply field name corrections
- ⚠️ `detection_patterns_analysis.md` - Update Sonicwall fields

**Decision**: Proceed? **YES** ✅

