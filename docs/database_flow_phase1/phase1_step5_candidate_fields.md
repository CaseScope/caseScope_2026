# Phase 1 Step 5 Candidate Fields

## Decision Summary

`KeyLength` is the only `PROMOTE_NOW` field for Phase 1.8.

It is not already represented by an existing typed column, is used by current pass-the-hash readers, has a safe bounded type (`Nullable(UInt16)`), is populated from already-decoded EVTX `EventData`, and showed typed-path query benefit on representative rows. `raw_json`, `search_blob`, and `extra_fields` coverage remain intact.

## Measured Evidence

Representative read-only cases:

- Case 33: 131,512 total rows. `KeyLength` non-empty in 7,991 EVTX rows, 7,950 event 4624 rows, 41 event 4625 rows, 2 distinct values.
- Case 10: 2,447,494 total rows. `KeyLength` non-empty in 2,924 EVTX rows, 2,921 event 4624 rows, 3 event 4625 rows, 2 distinct values.

The same measurement pass confirmed several candidate fields were already covered by existing typed columns (`IpAddress` -> `src_ip`, `WorkstationName` -> `workstation_name`, `AuthenticationPackageName` -> `auth_package`, `LogonProcessName` -> `logon_process`, `SubjectUserName` / `TargetUserName` -> `username` with event-specific raw context retained).

## PROMOTE_NOW

### `KeyLength` -> `key_length Nullable(UInt16)`

Justification:

- Current readers directly use `JSONExtractString(raw_json, 'EventData', 'KeyLength')` in `utils/candidate_extractor.py`, `models/pattern_rules.py`, and `utils/mitre_attack_sync.py`.
- It is a low-cardinality numeric field used in pass-the-hash detection (`KeyLength=0`).
- It can be populated during EVTX normalization from the already-decoded `event_data` dict.
- Malformed or out-of-range values remain `NULL` in the typed column while legacy raw JSON/search tokens preserve the source value.
- Historical rows are handled with `if(key_length IS NULL, JSONExtractString(...), key_length)` fallback.

## DEFER

- `SubStatus`: detection-relevant but sparse in measured cases (41 rows in case 33, 3 rows in case 10) and not enough measured query pressure for Phase 1.8.
- `ServiceName`: present in measured cases, but current use is mixed between display/search and candidate context. Defer until there is a specific migrated consumer with measurable benefit.
- `TicketEncryptionType`: repeatedly referenced by candidate logic but had zero non-empty rows in the measured cases.
- `AccessMask`, `Properties`, `ObjectName`: relevant to specific object-access/DCSync patterns, but low or uneven measured presence and not broad enough for this final Phase 1 pass.
- `ShareName`, `RelativeTargetName`: present in case 10 only and better revisited with broader SMB/share reader work.
- `SourceImage`, `TargetImage`, `ParentImage`, `Image`, `ImageLoaded`, `TargetProcessId`, `TargetFilename`, `GrantedAccess`, `DestinationPort`: deferred because the representative measurements showed zero non-empty rows for these fields in the selected cases.

## REJECT

Already promoted equivalents were not duplicated:

- `IpAddress` -> `src_ip`
- `WorkstationName` -> `workstation_name`
- `AuthenticationPackageName` -> `auth_package`
- `LogonProcessName` -> `logon_process`
- `SubjectUserName`, `TargetUserName`, `TargetDomainName`, SID variants -> existing actor/domain/SID columns plus raw JSON for event-specific semantics
- `LogonType` -> `logon_type`
- Process, command line, target path, hash, and registry fields already represented by existing typed columns where the parser can safely normalize them

## Scope Notes

IOC common-path matching still searches `raw_json` and `search_blob`. No IOC reader was migrated away from `raw_json`.

No Phase 1B, Phase 2 text index, LEK, generations, manifests, watermarks, event surfaces, Qdrant, or overlay migration work was started.
