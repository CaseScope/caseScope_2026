# Vector Index Implementation Plan

## Overview

Implement a 2-stage indexing system where:
1. **Stage 1 (Fast)**: Normal event indexing to OpenSearch (current system)
2. **Stage 2 (Background)**: Vector embedding generation for semantic search

This enables analysts to start working immediately while semantic search capabilities build in the background.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     FILE UPLOAD FLOW                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  User uploads file                                               │
│         │                                                        │
│         ▼                                                        │
│  ┌─────────────────┐                                            │
│  │ STAGE 1: INDEX  │  ← Fast (current system)                   │
│  │ Parse → OpenSearch                                           │
│  │ is_indexed = TRUE                                            │
│  └────────┬────────┘                                            │
│           │                                                      │
│           │ User can start working immediately                  │
│           │                                                      │
│           ▼                                                      │
│  ┌─────────────────┐                                            │
│  │ Queue for       │                                            │
│  │ Stage 2         │                                            │
│  └────────┬────────┘                                            │
│           │                                                      │
│           ▼                                                      │
│  ┌─────────────────┐                                            │
│  │ STAGE 2: EMBED  │  ← Background worker                       │
│  │ Generate vectors │                                           │
│  │ Store in OpenSearch                                          │
│  │ embedding_status = COMPLETED                                 │
│  └────────┬────────┘                                            │
│           │                                                      │
│           ▼                                                      │
│  ┌─────────────────┐                                            │
│  │ Check all files │                                            │
│  │ If all done:    │                                            │
│  │ vector_ready=TRUE                                            │
│  └─────────────────┘                                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## System States

```
┌─────────────────────────────────────────────────────────────────┐
│ STATE: vector_ready = FALSE                                      │
│                                                                  │
│ AI Question uses: KEYWORD SEARCH (current stratified system)    │
│ Banner: "Semantic index building: 45% (2.3M / 5M events)"       │
│         "ETA: ~1 hour 15 minutes"                               │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ STATE: vector_ready = TRUE                                       │
│                                                                  │
│ AI Question uses: VECTOR SEARCH (new semantic system)           │
│ Banner: None (or "✓ Semantic search ready")                     │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ TRANSITION: New file added to vector_ready=TRUE case            │
│                                                                  │
│ Action: Set vector_ready = FALSE                                │
│ AI Question uses: KEYWORD SEARCH (until new file embedded)      │
│ Banner: "Semantic index updating: new file being processed"     │
└─────────────────────────────────────────────────────────────────┘
```

---

## TODO List

### Phase 1: Database Schema Changes

- [ ] **TODO 1.1**: Add fields to `Case` model in `models.py`
  ```python
  # Vector search status
  vector_ready = db.Column(db.Boolean, default=False, index=True)
  vector_started_at = db.Column(db.DateTime)
  vector_completed_at = db.Column(db.DateTime)
  ```

- [ ] **TODO 1.2**: Add fields to `CaseFile` model in `models.py`
  ```python
  # Embedding status
  embedding_status = db.Column(db.String(50), default='Pending')  # Pending, Queued, Processing, Completed, Failed
  embedding_count = db.Column(db.Integer, default=0)
  embedding_started_at = db.Column(db.DateTime)
  embedding_completed_at = db.Column(db.DateTime)
  embedding_error = db.Column(db.Text)
  ```

- [ ] **TODO 1.3**: Create database migration
  ```bash
  flask db migrate -m "Add vector indexing fields"
  flask db upgrade
  ```

---

### Phase 2: OpenSearch Mapping Changes

- [ ] **TODO 2.1**: Update OpenSearch index mapping to include vector field
  ```python
  # In opensearch_utils.py or index creation code
  "embedding_vector": {
      "type": "knn_vector",
      "dimension": 384,  # all-MiniLM-L6-v2 output dimension
      "method": {
          "name": "hnsw",
          "space_type": "cosinesimil",
          "engine": "nmslib",
          "parameters": {
              "ef_construction": 128,
              "m": 24
          }
      }
  }
  ```

- [ ] **TODO 2.2**: Create function to add vector field to existing indices
  ```python
  def add_vector_field_to_index(index_name):
      """Add knn_vector field to existing index via reindex."""
      pass
  ```

- [ ] **TODO 2.3**: Update event indexing to include placeholder for vector
  ```python
  # Initially null, filled by background worker
  "embedding_vector": None
  ```

---

### Phase 3: Embedding Worker

- [ ] **TODO 3.1**: Create new Celery task `generate_file_embeddings` in `tasks.py`
  ```python
  @celery.task(bind=True)
  def generate_file_embeddings(self, file_id: int):
      """
      Generate embeddings for all events in a file.
      Updates OpenSearch documents with vector field.
      """
      pass
  ```

- [ ] **TODO 3.2**: Implement batch embedding generation
  ```python
  def embed_events_batch(opensearch_client, index_name, event_ids, batch_size=500):
      """
      Fetch events, generate embeddings, update documents.
      Process in batches to manage memory.
      """
      pass
  ```

- [ ] **TODO 3.3**: Implement progress tracking
  ```python
  def update_embedding_progress(file_id, events_done, events_total):
      """Update CaseFile with progress for UI display."""
      pass
  ```

- [ ] **TODO 3.4**: Implement completion handler
  ```python
  def on_file_embedding_complete(file_id):
      """
      Called when file embedding finishes.
      Check if all files in case are done, if so set vector_ready=True.
      """
      pass
  ```

---

### Phase 4: Fair Queue System

- [ ] **TODO 4.1**: Create `EmbeddingQueue` model for tracking
  ```python
  class EmbeddingQueueItem(db.Model):
      id = db.Column(db.Integer, primary_key=True)
      case_id = db.Column(db.Integer, db.ForeignKey('case.id'))
      file_id = db.Column(db.Integer, db.ForeignKey('case_file.id'))
      priority = db.Column(db.Integer, default=0)  # Higher = more urgent
      events_total = db.Column(db.Integer)
      events_processed = db.Column(db.Integer, default=0)
      status = db.Column(db.String(20))  # queued, processing, completed
      queued_at = db.Column(db.DateTime)
      started_at = db.Column(db.DateTime)
      completed_at = db.Column(db.DateTime)
  ```

- [ ] **TODO 4.2**: Implement round-robin batch processing
  ```python
  EMBEDDING_BATCH_SIZE = 10000  # Process 10K events per case, then rotate
  
  def get_next_embedding_batch():
      """
      Get next batch to process using round-robin across cases.
      Returns (case_id, file_id, event_ids) or None if queue empty.
      """
      pass
  ```

- [ ] **TODO 4.3**: Create dedicated embedding worker configuration
  ```python
  # In celery_config.py or similar
  # Separate queue for embedding tasks
  CELERY_QUEUES = {
      'default': {},
      'embedding': {'routing_key': 'embedding.#'}
  }
  ```

- [ ] **TODO 4.4**: Create systemd service for embedding worker
  ```ini
  # /etc/systemd/system/casescope-embedding.service
  [Service]
  ExecStart=/opt/casescope/venv/bin/celery -A celery_app.celery worker 
            --queues=embedding --concurrency=1 --loglevel=info
  ```

---

### Phase 5: Vector Search Implementation

- [ ] **TODO 5.1**: Create `semantic_search_vector()` function in `ai_search.py`
  ```python
  def semantic_search_vector(
      opensearch_client,
      case_id: int,
      question: str,
      max_results: int = 50
  ) -> Tuple[List[Dict], str]:
      """
      True semantic search using k-NN on embedding vectors.
      Only used when case.vector_ready = True.
      """
      pass
  ```

- [ ] **TODO 5.2**: Update `ai_question_search()` to route based on vector_ready
  ```python
  def ai_question_search(...):
      case = Case.query.get(case_id)
      
      if case.vector_ready:
          yield from ai_question_search_vector(...)
      else:
          yield from ai_question_search_keyword(...)  # Current system
  ```

- [ ] **TODO 5.3**: Implement k-NN query
  ```python
  def knn_search(opensearch_client, index_name, query_vector, k=100):
      """Execute k-NN search on OpenSearch."""
      return opensearch_client.search(
          index=index_name,
          body={
              "query": {
                  "knn": {
                      "embedding_vector": {
                          "vector": query_vector,
                          "k": k
                      }
                  }
              }
          }
      )
  ```

---

### Phase 6: Flag Management

- [ ] **TODO 6.1**: Flip flag on new file upload
  ```python
  # In file upload handler
  def on_file_upload(case_id, file):
      case = Case.query.get(case_id)
      if case.vector_ready:
          case.vector_ready = False
          db.session.commit()
          logger.info(f"[VECTOR] Case {case_id}: New file, vector_ready=FALSE")
  ```

- [ ] **TODO 6.2**: Set flag when all files complete
  ```python
  def check_case_vector_ready(case_id):
      """Check if all files have embeddings, set flag if so."""
      files = CaseFile.query.filter_by(
          case_id=case_id, 
          is_indexed=True, 
          is_deleted=False
      ).all()
      
      all_done = all(f.embedding_status == 'Completed' for f in files)
      
      if all_done:
          case = Case.query.get(case_id)
          case.vector_ready = True
          case.vector_completed_at = datetime.utcnow()
          db.session.commit()
  ```

- [ ] **TODO 6.3**: Queue new file for embedding automatically
  ```python
  # After Stage 1 indexing completes
  def on_file_indexed(file_id):
      queue_file_for_embedding(file_id)
  ```

---

### Phase 7: UI - Progress Banners

- [ ] **TODO 7.1**: Create `get_embedding_status()` API endpoint
  ```python
  @main.route('/case/<int:case_id>/embedding-status')
  def get_embedding_status(case_id):
      """Return embedding progress for UI banner."""
      return jsonify({
          'vector_ready': case.vector_ready,
          'files_total': 5,
          'files_done': 3,
          'events_total': 5000000,
          'events_done': 3200000,
          'eta_minutes': 45,
          'current_file': 'security.evtx',
          'queue_position': 2,  # If waiting behind other cases
          'other_users_processing': ['user@example.com']  # Fair queue info
      })
  ```

- [ ] **TODO 7.2**: Add banner component to `base.html` or header template
  ```html
  <div id="embeddingBanner" class="embedding-banner" style="display: none;">
      <span class="icon">🔄</span>
      <span id="embeddingMessage">Semantic index building...</span>
      <span id="embeddingProgress">45%</span>
      <span id="embeddingETA">ETA: ~1h 15m</span>
  </div>
  ```

- [ ] **TODO 7.3**: Add JavaScript to poll and update banner
  ```javascript
  function pollEmbeddingStatus() {
      fetch(`/case/${caseId}/embedding-status`)
          .then(r => r.json())
          .then(data => {
              updateEmbeddingBanner(data);
          });
  }
  setInterval(pollEmbeddingStatus, 30000);  // Every 30 seconds
  ```

- [ ] **TODO 7.4**: Show banner on case dashboard, case files, and search pages
  - `case_dashboard.html`
  - `case_files.html`
  - `search_events.html`

- [ ] **TODO 7.5**: Add "other users processing" indicator in header
  ```html
  <!-- In header template -->
  <div id="systemLoadIndicator" style="display: none;">
      <span>⏳ 2 other cases in embedding queue</span>
  </div>
  ```

---

### Phase 8: UI - AI Question Updates

- [ ] **TODO 8.1**: Update AI Question modal to show search mode
  ```html
  <div id="aiSearchMode" class="search-mode-indicator">
      <span class="mode-icon">🔍</span>
      <span class="mode-text">Using: Keyword Search</span>
      <span class="mode-note">(Semantic search building: 45%)</span>
  </div>
  ```

- [ ] **TODO 8.2**: Update AI response to indicate search method used
  ```python
  # In generate_ai_answer
  if vector_search_used:
      method_note = "🎯 Searched using semantic similarity (vector search)"
  else:
      method_note = "🔍 Searched using keyword matching"
  ```

---

### Phase 9: Testing

- [ ] **TODO 9.1**: Unit tests for embedding generation
- [ ] **TODO 9.2**: Unit tests for fair queue round-robin
- [ ] **TODO 9.3**: Integration test: file upload → index → embed → vector search
- [ ] **TODO 9.4**: Test flag flip on new file upload
- [ ] **TODO 9.5**: Load test with multiple concurrent users

---

### Phase 10: Documentation

- [ ] **TODO 10.1**: Update user documentation with semantic search info
- [ ] **TODO 10.2**: Add admin documentation for embedding worker management
- [ ] **TODO 10.3**: Document OpenSearch k-NN requirements

---

## Estimated Timeline

| Phase | Description | Effort |
|-------|-------------|--------|
| 1 | Database schema | 1 hour |
| 2 | OpenSearch mapping | 2 hours |
| 3 | Embedding worker | 4 hours |
| 4 | Fair queue system | 3 hours |
| 5 | Vector search | 3 hours |
| 6 | Flag management | 1 hour |
| 7 | UI banners | 3 hours |
| 8 | AI Question updates | 1 hour |
| 9 | Testing | 4 hours |
| 10 | Documentation | 2 hours |
| **Total** | | **~24 hours** |

---

## Performance Estimates

Based on benchmarks on this server (~736 events/second):

| Case Size | Embedding Time | Notes |
|-----------|---------------|-------|
| 100K events | ~2 minutes | Quick |
| 500K events | ~11 minutes | Reasonable |
| 1M events | ~23 minutes | Background |
| 5M events | ~2 hours | Overnight |
| 20M events | ~7.5 hours | Weekend job |

With fair queue (3 users, 5M each):
- All users see progress immediately
- Each gets ~245 events/second (1/3 of capacity)
- All complete in ~6 hours total

---

## Rollback Plan

If issues arise:
1. Set `vector_ready = FALSE` for all cases (forces keyword search)
2. Disable embedding worker service
3. AI Question continues working with keyword search
4. No data loss - vectors are additive, not replacing

---

## Files to Modify

1. `app/models.py` - Add new fields
2. `app/tasks.py` - Add embedding tasks
3. `app/ai_search.py` - Add vector search, routing
4. `app/main.py` - Add status endpoint, file upload hook
5. `app/templates/base.html` - Add banner
6. `app/templates/search_events.html` - Update AI modal
7. `app/templates/case_dashboard.html` - Add banner
8. `app/templates/case_files.html` - Add banner
9. `app/opensearch_utils.py` - Update mapping
10. New: `app/embedding_worker.py` - Dedicated embedding logic
11. New: `/etc/systemd/system/casescope-embedding.service`

---

## Notes

- Embedding model: `all-MiniLM-L6-v2` (384 dimensions)
- OpenSearch k-NN plugin required (usually included)
- Single embedding worker recommended (CPU-bound)
- Fair queue prevents user starvation
- Flag-based switching keeps code paths clean and testable

