# CaseScope RAG System - Consolidated Improvement Plan
**Review Date**: November 26, 2025  
**Version**: 1.27.17  
**Based On**: RAG_SYSTEM_EVALUATION.md + RAG_IMPROVEMENT_RECOMMENDATIONS.md

---

## Executive Summary

Two comprehensive RAG system reviews have been conducted:
1. **RAG_SYSTEM_EVALUATION.md** - External architecture and operational review
2. **RAG_IMPROVEMENT_RECOMMENDATIONS.md** - Internal scoring and context improvements

**Combined Grade: B+ → A- with recommended fixes**

This document consolidates both reviews, evaluates all recommendations, prioritizes them, and provides an actionable implementation roadmap.

---

## Critical Analysis: Additive vs. Multiplicative Boosting

### 🔴 HIGHEST PRIORITY ISSUE (Both Reviews Agree)

**Current Problem** (from RAG_IMPROVEMENT_RECOMMENDATIONS):
```python
# Current: Additive boosting in OpenSearch query
"should": [
    {"term": {"is_tagged": {"value": True, "boost": 5.0}}},  # Additive
    {"term": {"has_ioc": {"value": True, "boost": 3.5}}},    # Additive
    {"term": {"has_sigma": {"value": True, "boost": 2.5}}},  # Additive
]

# Then normalized away during re-ranking:
combined_scores = 0.4 * os_scores_norm + 0.6 * similarities
#                      ^^^^^^^^^^^^^^
#                      Normalization kills the boosts!
```

**Why This is Broken**:
1. OpenSearch returns events with scores (e.g., tagged=15, untagged=10)
2. These scores are **normalized** to 0-1 range: `os_scores / os_scores.max()`
3. Normalization **erases the boost advantage**:
   - Before: [15, 10, 8] → After: [1.0, 0.67, 0.53]
   - Tagged event only has 0.33 advantage instead of 5.0x
4. Then semantic similarity (0-1 range) gets 60% weight, further diluting the boost

**Result**: Analyst-tagged events can be pushed out by semantically-similar but less important events.

### ✅ SOLUTION: Multiplicative Boosting After Re-Ranking

```python
def calculate_event_relevance(event: Dict, semantic_sim: float, os_score_norm: float) -> float:
    """
    Calculate event relevance with multiplicative boosting that survives normalization.
    """
    source = event.get('_source', {})
    
    # Base score (balanced keyword + semantic)
    base_score = 0.5 * os_score_norm + 0.5 * semantic_sim
    
    # Multiplicative boosts (applied AFTER normalization)
    boost = 1.0
    
    if source.get('is_tagged'):
        boost *= 2.5  # Tagged events get 2.5x final score
    
    if source.get('has_ioc'):
        ioc_count = source.get('ioc_count', 1)
        boost *= (1.0 + 0.3 * min(ioc_count, 5))  # 1.3x to 2.5x
    
    if source.get('has_sigma'):
        sigma_level = source.get('sigma_level', 'medium')
        sigma_boosts = {'critical': 1.8, 'high': 1.5, 'medium': 1.3, 'low': 1.1}
        boost *= sigma_boosts.get(sigma_level, 1.2)
    
    return base_score * boost
```

**Impact**: Tagged events will ALWAYS rank higher than untagged events with similar semantic/keyword scores.

---

## Consolidated Recommendations

### 🔴 **BLOCK v1.27.17 RELEASE** (Must Fix)

#### 1. Fix Multiplicative Boosting (30 min) ⭐ CRITICAL
**Source**: RAG_IMPROVEMENT_RECOMMENDATIONS.md (Issue #1)  
**Problem**: Normalization erases OpenSearch boosts  
**Impact**: HIGH - Analyst-tagged events not prioritized correctly  
**Fix**: Implement `calculate_event_relevance()` with post-normalization multiplicative boosts

#### 2. Add Rate Limiting (30 min) ⭐ CRITICAL
**Source**: RAG_SYSTEM_EVALUATION.md (Issue #1)  
**Problem**: No rate limiting on `/ai-search/ask` endpoint  
**Impact**: HIGH - DoS potential, GPU exhaustion  
**Fix**:
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app, key_func=get_remote_address)

@ai_search_bp.route('/case/<int:case_id>/ai-search/ask', methods=['POST'])
@limiter.limit("10 per minute")
@login_required
def ai_search_ask(case_id):
    ...
```

#### 3. Add Context Size Check (20 min) ⭐ CRITICAL
**Source**: RAG_SYSTEM_EVALUATION.md (Issue #2)  
**Problem**: No check on total context size → LLM overflow  
**Impact**: HIGH - Truncated/bad AI responses  
**Fix**:
```python
MAX_CONTEXT_TOKENS = 6000
CHARS_PER_TOKEN = 4

event_context = []
total_length = 0
for i, event in enumerate(events[:15], 1):
    summary = create_event_summary_enhanced(event)
    estimated_tokens = len(summary) // CHARS_PER_TOKEN
    
    if total_length + estimated_tokens > MAX_CONTEXT_TOKENS:
        logger.info(f"Context limit reached at {i} events ({total_length} tokens)")
        break
        
    event_context.append(f"[Event {i}]\n{summary}")
    total_length += estimated_tokens
```

**Total Time**: ~80 minutes to unblock release

---

### 🟡 **SHIP, THEN FIX** (v1.27.18 - Next Sprint)

#### 4. Enhanced Event Summaries (60 min)
**Source**: RAG_IMPROVEMENT_RECOMMENDATIONS.md (Issue #2)  
**Problem**: LLM context lacks DFIR semantics (logon types, event ID meanings)  
**Impact**: MEDIUM - AI responses less accurate/useful  
**Fix**: Implement `create_event_summary_enhanced()` with:
- Event ID descriptions (4624 = "Successful logon")
- Logon type descriptions (Type 10 = "RDP")
- Parent process chains
- Detection flag details (which SIGMA rule triggered, which IOCs matched)

**Example Output**:
```
**Time**: 2025-11-24T14:32:05
**Computer**: WS01
**Event ID**: 4688 (Process created)
**User**: SYSTEM
**Process**: powershell.exe → net.exe
**Command Line**: net user admin P@ssw0rd /add
**Flags**: ⚠️ SIGMA: User Account Creation | 🎯 IOC: suspicious_commands.txt
```

#### 5. Improved LLM Prompt (20 min)
**Source**: RAG_IMPROVEMENT_RECOMMENDATIONS.md (Issue #3)  
**Problem**: Prompt lacks DFIR domain guidance  
**Impact**: MEDIUM - Misses attack pattern context  
**Fix**: Add MITRE ATT&CK reference and logon type legend to prompt

#### 6. Preload Embedding Model (10 min)
**Source**: RAG_SYSTEM_EVALUATION.md (Issue #3)  
**Problem**: 90MB model downloads on first request (30s delay)  
**Impact**: MEDIUM - Poor first-use UX  
**Fix**:
```python
# app/__init__.py
def create_app():
    app = Flask(__name__)
    # ... config ...
    
    with app.app_context():
        from app.ai_search import _load_embedding_model
        logger.info("Preloading embedding model...")
        _load_embedding_model()
        logger.info("Embedding model ready")
    
    return app
```

#### 7. Add Relevance Threshold (5 min)
**Source**: RAG_SYSTEM_EVALUATION.md (Issue #6)  
**Problem**: Low-relevance events passed to LLM (noise)  
**Impact**: MEDIUM - Diluted AI responses  
**Fix**:
```python
MIN_RELEVANCE_SCORE = 0.3

relevant_indices = [i for i in ranked_indices if combined_scores[i] >= MIN_RELEVANCE_SCORE]
candidates = [candidates[i] for i in relevant_indices[:max_results]]
```

#### 8. Add Redis Query Caching (30 min)
**Source**: RAG_SYSTEM_EVALUATION.md (Issue #5)  
**Problem**: Repeated queries regenerate embeddings/LLM responses  
**Impact**: MEDIUM - Wasted compute  
**Fix**:
```python
import redis
import hashlib

r = redis.Redis(host='localhost', port=6379, decode_responses=True)

def get_cached_ai_response(question: str, case_id: int, event_ids: list) -> Optional[str]:
    cache_key = hashlib.sha256(f"{case_id}:{question}:{sorted(event_ids)}".encode()).hexdigest()
    return r.get(f"ai_response:{cache_key}")

def cache_ai_response(question: str, case_id: int, event_ids: list, response: str, ttl=3600):
    cache_key = hashlib.sha256(f"{case_id}:{question}:{sorted(event_ids)}".encode()).hexdigest()
    r.setex(f"ai_response:{cache_key}", ttl, response)
```

**Total Time**: ~125 minutes for v1.27.18

---

### 🟢 **BACKLOG** (v1.28.0+ - Post-Release)

#### 9. Query-Aware Weighting (2 hours)
**Source**: RAG_IMPROVEMENT_RECOMMENDATIONS.md (Issue #4)  
**Problem**: All questions use same keyword/semantic weights  
**Impact**: LOW - Some query types could be more accurate  
**Fix**: Detect query type and adjust weights:
- Entity lookup: 70% keyword, 30% semantic
- Threat hunting: 40% keyword, 60% semantic
- Summary: 30% keyword, 70% semantic

**Assessment**: Nice to have, but current balanced approach works well.

#### 10. Time-Related Keyword Extraction (15 min)
**Source**: RAG_SYSTEM_EVALUATION.md (Issue #4)  
**Problem**: Time references ("2pm", "yesterday") dropped from keywords  
**Impact**: LOW - UI date picker already handles time filtering  
**Fix**: Add regex patterns for time/date terms

**Assessment**: Skip - UI already handles this better.

#### 11. Prompt Injection Sanitization (30 min)
**Source**: RAG_SYSTEM_EVALUATION.md (Security section)  
**Problem**: User input goes directly into prompt  
**Impact**: LOW - Authenticated users only, no data exfiltration risk  

**Assessment**: **SKIP THIS** - Security theater for our use case:
- Analysts are trusted users with full case access
- Pattern matching would break legitimate queries ("ignore this event")
- Focus on rate limiting instead

#### 12. Conversation Memory (4 hours)
**Source**: RAG_SYSTEM_EVALUATION.md (Issue #7)  
**Problem**: Each question is independent  
**Impact**: LOW - Nice UX, but adds complexity  
**Fix**: Store conversation context in session for follow-ups

**Assessment**: Good future feature for v1.28.0+

#### 13. Structured Output Extraction (8 hours)
**Source**: RAG_SYSTEM_EVALUATION.md (Issue #9)  
**Problem**: LLM output is free-form text  
**Impact**: LOW - Would enable auto-tagging, dashboards  
**Fix**: Parse MITRE ATT&CK techniques, confidence scores, key events

**Example**:
```python
{
    "attack_techniques": ["T1021.002", "T1059.001"],
    "key_events": [5, 8, 12],
    "confidence": "high",
    "summary": "...",
    "iocs": ["192.168.1.50", "malware.exe"]
}
```

**Assessment**: Excellent feature for v1.28.0+ (AI-powered auto-tagging)

#### 14. Unit Tests for RAG Pipeline (6 hours)
**Source**: RAG_SYSTEM_EVALUATION.md (Code Quality section)  
**Problem**: No unit tests for RAG components  
**Impact**: LOW - But important for maintainability  

**Assessment**: Add to technical debt backlog

---

## Review Assessment: Which Document is Better?

| Aspect | RAG_SYSTEM_EVALUATION | RAG_IMPROVEMENT_RECOMMENDATIONS | Winner |
|--------|----------------------|--------------------------------|--------|
| **Architecture Understanding** | ✅ Excellent flow diagram | ⚠️ Assumes knowledge | EVALUATION |
| **Root Cause Analysis** | ⚠️ Notes symptoms | ✅ Identifies boosting bug | RECOMMENDATIONS |
| **Operational Issues** | ✅ Rate limiting, caching | ❌ Not covered | EVALUATION |
| **DFIR Domain Expertise** | ✅ Good | ✅ Excellent (event IDs, logon types) | RECOMMENDATIONS |
| **Actionable Code** | ✅ Good examples | ✅ Production-ready code | TIE |
| **Prioritization** | ✅ Clear HIGH/MED/LOW | ⚠️ All treated equal | EVALUATION |

**Verdict**: Both reviews are **complementary and excellent**:
- **EVALUATION** → Better for operational/security issues
- **RECOMMENDATIONS** → Better for scoring/context improvements

---

## Implementation Roadmap

### Phase 1: v1.27.18 (This Week)
**Goal**: Fix critical bugs blocking production use

| Task | Time | Priority | Source |
|------|------|----------|--------|
| Fix multiplicative boosting | 30 min | 🔴 CRITICAL | RECOMMENDATIONS #1 |
| Add rate limiting | 30 min | 🔴 CRITICAL | EVALUATION #1 |
| Add context size check | 20 min | 🔴 CRITICAL | EVALUATION #2 |
| **TOTAL** | **80 min** | | |

**Test Plan**:
1. Tag 5 events in case_11
2. Ask: "What lateral movement occurred?"
3. Verify tagged events appear in top 10 results
4. Verify rate limiting kicks in after 10 requests/min
5. Verify large contexts don't overflow LLM

---

### Phase 2: v1.27.19 (Next Week)
**Goal**: Improve AI response quality

| Task | Time | Priority | Source |
|------|------|----------|--------|
| Enhanced event summaries | 60 min | 🟡 MEDIUM | RECOMMENDATIONS #2 |
| Improved LLM prompt | 20 min | 🟡 MEDIUM | RECOMMENDATIONS #3 |
| Preload embedding model | 10 min | 🟡 MEDIUM | EVALUATION #3 |
| Relevance threshold | 5 min | 🟡 MEDIUM | EVALUATION #6 |
| Redis query caching | 30 min | 🟡 MEDIUM | EVALUATION #5 |
| **TOTAL** | **125 min** | | |

**Test Plan**:
1. Compare "before/after" AI responses for same question
2. Measure first-request latency improvement
3. Test cache hit rate over 24 hours

---

### Phase 3: v1.28.0 (Future Sprint)
**Goal**: Advanced features

| Task | Time | Priority | Source |
|------|------|----------|--------|
| Query-aware weighting | 2 hrs | 🟢 LOW | RECOMMENDATIONS #4 |
| Conversation memory | 4 hrs | 🟢 LOW | EVALUATION #7 |
| Structured output extraction | 8 hrs | 🟢 LOW | EVALUATION #9 |
| Unit tests | 6 hrs | 🟢 LOW | EVALUATION |
| **TOTAL** | **20 hrs** | | |

---

## Key Insights from Reviews

### What We're Doing Right ✅
1. **Hybrid search** (keyword + semantic) - Industry best practice
2. **Streaming responses** - Great UX, mitigates perceived latency
3. **Event grounding** - Prevents hallucination
4. **Resource separation** - CPU embeddings, GPU LLM
5. **Fallback mechanisms** - Graceful degradation
6. **Audit logging** - Compliance ready

### What Needs Fixing 🔧
1. **Boosting strategy** - Use multiplicative, not additive
2. **LLM context** - Add DFIR semantics (event IDs, logon types)
3. **Rate limiting** - Prevent GPU exhaustion
4. **Context overflow** - Dynamic truncation
5. **Caching** - Avoid redundant compute

### What We Should Skip ❌
1. **Prompt injection sanitization** - Security theater for authenticated users
2. **Time keyword extraction** - UI already handles this
3. **Cross-encoder re-ranking** - Too slow for real-time UX
4. **Pre-computed vector store** - Events change too frequently

---

## Final Recommendation

**For v1.27.17 Release**:
- ⏸️ **HOLD RELEASE** - Implement Phase 1 (80 minutes)
- 🧪 Test on case_11 (121K events, tagged events)
- 📦 Release as v1.27.18

**For v1.27.18**:
- 🚀 Implement Phase 2 (125 minutes)
- 📊 A/B test AI response quality
- 📦 Release as v1.27.19

**For v1.28.0**:
- 🎯 Structured output → Auto-tagging pipeline
- 💬 Conversation memory → Multi-turn Q&A
- 🧪 Unit test coverage → 80%+

---

## Metrics to Track

| Metric | Current | Target (v1.27.18) | Target (v1.27.19) |
|--------|---------|-------------------|-------------------|
| Avg response time | 15-35s | 15-35s | 10-25s (caching) |
| First request time | 45-65s | 15-35s | 15-35s (preload) |
| Tagged events in top 10 | ~60% | >95% | >95% |
| Cache hit rate | N/A | N/A | >40% |
| Questions/min per user | Unlimited | Max 10 | Max 10 |
| LLM context overflow | Possible | 0 | 0 |

---

## Conclusion

**Grade Progression**:
- Current (v1.27.17): **B+** (Good, but boosting bug)
- After Phase 1 (v1.27.18): **A-** (Production-ready, critical bugs fixed)
- After Phase 2 (v1.27.19): **A** (High-quality AI responses with DFIR context)
- After Phase 3 (v1.28.0): **A+** (Industry-leading DFIR RAG system)

Both review documents are **excellent and actionable**. The consolidated plan above provides a clear path from B+ to A+ over 3 releases.

**Recommendation**: Proceed with Phase 1 implementation NOW (80 minutes) to unblock v1.27.18 release.

