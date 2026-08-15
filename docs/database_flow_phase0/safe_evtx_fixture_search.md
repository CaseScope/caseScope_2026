# Phase 0A Safe EVTX Fixture Search

Status: SAFE_EVTX_FIXTURE_NOT_AVAILABLE.

No safe disposable EVTX fixtures exist locally. All real on-disk EVTX files found are retained case evidence and were excluded.

## Retained EVTX Files Excluded

| Path | CaseFile | Case | Status | Reason |
|---|---:|---|---|---|
| `/opt/casescope/staging/20036ce9-42ca-45f4-933b-2862d8994cda/sec.evtx` | 538677 | 2024-12-28 - Ransomware | ingesting | retained staging copy referenced by CaseFile |
| `/originals/20036ce9-42ca-45f4-933b-2862d8994cda/originals/sec.evtx` |  | 2024-12-28 - Ransomware |  | retained originals copy |
| `/originals/20036ce9-42ca-45f4-933b-2862d8994cda/originals/app.evtx` | 538676 | 2024-12-28 - Ransomware | done | retained evidence |
| `/originals/20036ce9-42ca-45f4-933b-2862d8994cda/originals/sys.evtx` | 538678 | 2024-12-28 - Ransomware | done | retained evidence |
| `/originals/ed32ffaa-037e-4fa7-b80a-3104da3ef01d/originals/SecurityLogs.evtx` | 538673 | 2024-12-09 - Reverse shell | done | retained evidence |
| `/originals/ed32ffaa-037e-4fa7-b80a-3104da3ef01d/originals/ApplicationLogs.evtx` | 538672 | 2024-12-09 - Reverse shell | done | retained evidence |
| `/originals/ed32ffaa-037e-4fa7-b80a-3104da3ef01d/originals/SystemLogs.evtx` | 538674 | 2024-12-09 - Reverse shell | done | retained evidence |

## Searched Locations Without Safe Fixture

- `/opt/casescope repository tree excluding retained storage`
- `/opt/casescope/tests`
- `/opt/casescope/scripts`
- `/opt/casescope/bin/EvtxECmd`
- `/opt/casescope/bin/hayabusa`
- `/opt/casescope/rules/hayabusa-rules`
- `/opt/casescope/venv`
- `/opt/casescope/storage`
- `/opt/casescope/uploads`
- `/opt/casescope/evidence_uploads`
- `/tmp`
- `/var/tmp`

## Conclusion

Do not use currently on-disk EVTX files for Phase 0A benchmarking. Provide or approve a benign non-retained EVTX benchmark corpus outside retained evidence storage.
