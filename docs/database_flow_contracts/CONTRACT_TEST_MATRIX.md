# Contract Test Matrix

Status: LOCKED for Phase 0B as test specifications. These tests are not implemented here because the target schema/projections do not exist yet. Phase 0B adds no executable production tests and no tests requiring DB writes.

## Required Future Scenarios

| ID | Scenario | Required before |
|---|---|---|
| CT-001 | Same source + retry -> same generation | Phase 1B |
| CT-002 | Explicit reprocess allocates generation N+1; N remains ACTIVE during build | Phase 1B |
| CT-003 | Initial generation publishes durable batches progressively | Phase 1B |
| CT-004 | Replacement generation N+1 remains invisible until activation | Phase 1B |
| CT-005 | Failed replacement N+1 leaves old ACTIVE generation N visible | Phase 1B |
| CT-006 | Partial STAGED CH batch is not published | Phase 1B |
| CT-007 | Exact STAGED batch reconciles to DURABLE | Phase 1B |
| CT-008 | Hash mismatch fails closed | Phase 1B |
| CT-009 | Out-of-order batches do not advance through holes | Phase 1B |
| CT-010 | Late hole completion advances contiguous watermark | Phase 1B |
| CT-011 | AI freeze-then-verify blocks uncovered frozen batch | Phase 1B |
| CT-012 | New ingest after freeze does not alter the frozen AI request | Phase 1B |
| CT-013 | Duplicate physical observations remain independently retrievable | Phase 4 |
| CT-014 | LEK logical count collapses valid duplicates | Phase 4 |
| CT-015 | LEK collisions are detected by recipe fixtures | Phase 4 |
| CT-016 | Canonical representative is deterministic | Phase 4 |
| CT-017 | Field conflicts are surfaced | Phase 4 |
| CT-018 | Analyst default count uses LEK | Phase 4 |
| CT-019 | IOC provenance uses ERK | Phase 3 |
| CT-020 | Graph topology/support counting remains distinct | Phase 6 |
| CT-021 | Selector ambiguity never silently selects an ERK | Phase 3.0 |
| CT-022 | Qdrant unpublished/superseded publication_epoch cannot surface | Phase 3.0 |
| CT-023 | Fence refuses correctness-sensitive operation if Redis unavailable | Phase 1.4a |
| CT-024 | Exclusive fence waits for active writers to drain | Phase 1.4a |
| CT-025 | Writer cannot enter after exclusive acquisition begins | Phase 1.4a |
| CT-026 | Investigation Graph acceptance behavior is preserved | Any graph migration |
| CT-027 | Generation N never becomes BUILDING_REPLACEMENT | Phase 1B |
| CT-028 | Atomic activation: N ACTIVE->SUPERSEDED and N+1 BUILDING_REPLACEMENT->ACTIVE in one PG transaction | Phase 1B |
| CT-029 | Reconciler reconstructs batch_content_hash from CH ingest_row_ordinal + ingest_row_hash | Phase 1B |
| CT-030 | Duplicate ordinal identical hash is retry-equivalent only after collapse proof | Phase 1B |
| CT-031 | Duplicate ordinal different hash fails closed | Phase 1B |
| CT-032 | Missing ordinal fails closed | Phase 1B |
| CT-033 | Extra ordinal fails closed | Phase 1B |
| CT-034 | IIS, firewall, SonicWall, and Huntress do not cross-source collapse | Phase 4 |
| CT-035 | EVTX recipe still collapses cross-CaseFile same record | Phase 4 |
| CT-036 | BUILDING_REPLACEMENT Qdrant writes do not overwrite the published point ID | Phase 3.0 |
| CT-037 | One Qdrant support superseded while another ACTIVE still surfaces the LEK | Phase 3.0 |
| CT-038 | One Qdrant support invalidated while another ACTIVE still surfaces the LEK | Phase 3.0 |
| CT-039 | Representative source replacement updates Qdrant payload without dropping remaining support | Phase 3.0 |
| CT-040 | Delete-file prunes only that source's Qdrant support | Phase 3.0 |
| CT-041 | Delete-case removes all case event vectors | Phase 3.0 |
| CT-042 | Re-embedding creates a new revision; old embedding_version is not default | Phase 3.0 |
| CT-043 | principal_key never includes KnownSystem.id | Phase 6 |
| CT-044 | phase0a / event_surface / counting_basis reader ID sets are equal with no duplicates | Phase 4 |

Machine-readable details are in `contract_test_matrix.json`.
