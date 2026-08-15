# Principal Identity Contract

Status: LOCKED for Phase 0B. This contract defines `principal_key` semantics only.

## Scope

`principal_key` is the stable machine identity for users and systems. It is not a display label and is not a universal string normalization.

Current evidence shows separate normalization paths in `KnownUser`, `KnownSystem`, `utils.graph_identity`, event parsing, hunting, and behavioral readers. Phase 0B locks a shared semantic contract while preserving current behavior until implementation.

## Authority Direction

```text
evidence / authority identity  ->  principal_key
KnownUser / KnownSystem curation  ->  references, merges, and aliases principal_key(s)
```

`KnownSystem.id` and `KnownUser.id` are PostgreSQL surrogate row IDs. They are curation/provenance metadata only. They are **not** inputs to `principal_key`. Using them as identity would create circular authority: curation rows would mint the keys that those rows are later supposed to reference.

## Key Versioning

- User key version: `principal:user:v1`.
- System key version: `principal:system:v1`.
- Keys include `case_id` until a cross-case trust boundary and directory authority are explicitly versioned.

## User Identity Rules

Priority order:

1. Actual SID evidence: `principal:user:v1:case:<case_id>:sid:<SID_UPPER>`.
2. Domain authority and username: `principal:user:v1:case:<case_id>:authority:<DOMAIN_UPPER>:user:<USER_UPPER>`.
3. UPN: normalize into authority domain and username, then use the authority/username key.
4. Machine-local account: `principal:user:v1:case:<case_id>:local:<system_principal_key>:user:<USER_UPPER>`.
5. Bare username without SID, domain, or host authority: `principal:user:v1:case:<case_id>:unscoped-user:<USER_UPPER>` with quality `weak_unscoped`.

Rules:

- SID is preferred only when observed as identity evidence in `sid` or a parser-declared authoritative SID field. Do not infer SID equality from username.
- `DOMAIN\user` and `user@domain` may be aliases for the same authority only after both normalize to the same authority and username.
- Bare usernames do not merge across domains or machine-local scopes.
- Machine accounts ending in `$`, well-known service accounts, and built-in SIDs are classified as service/system principals, not normal users.
- Missing domain does not imply local account unless a host authority is present.
- Observed alias relationships are stored as aliases/provenance, not as proof of equality unless they satisfy one of the key rules.
- `KnownUser.id` is not part of any user `principal_key`.

## System Identity Rules

Priority order **without** PostgreSQL surrogate IDs:

1. Machine identifier from authoritative parser/source, when available: `principal:system:v1:case:<case_id>:machine-id:<TYPE>:<VALUE>`.
   - `TYPE` is a closed parser-declared set such as `agent-id`, `machine-guid`, `serial`, `mac-authority`. Values are trimmed, case-normalized per type contract, and must be observed evidence — not a KnownSystem row id.
2. Hostname/FQDN observation: `principal:system:v1:case:<case_id>:host:<NETBIOS_OR_FQDN_NORMALIZED>`.
3. IP-only observation: `principal:system:v1:case:<case_id>:ip-observed:<IP>` with quality `weak_ip_only`.

Prohibited key form:

- `principal:system:v1:case:<case_id>:known-system:<known_system_id>`

Rules:

- Hostnames are trimmed, trailing-dot stripped, and uppercase for Windows host identity.
- FQDN may be an alias of a hostname only when the NETBIOS portion matches or KnownSystem curation records the alias **against existing principal_keys**.
- `source_host`, `workstation_name`, `remote_host`, and UNC destination hosts are role-bearing observations. Role is provenance and must not be discarded.
- IP address does not equal hostname identity merely because one observation relates them. IPs are attributes/evidence unless an authoritative machine identifier proves ownership.
- KnownSystem `host_ip` and `host_mac` from EDR may support attributes but do not override hostname identity without a machine identifier.
- KnownSystem may merge two `principal_key`s as aliases. The merge writes curation rows that **reference** both keys. It does not mint a new key from `KnownSystem.id`.

## Quality Tiers

- `strong_sid`: user SID evidence.
- `strong_machine_id`: system machine identifier from parser/source evidence.
- `authority_scoped`: domain/UPN username authority. Not KnownSystem surrogate identity.
- `host_scoped`: hostname/FQDN system identity, or a local account scoped to a system key.
- `observed_alias`: known alias relationship without independent authority.
- `weak_unscoped`: bare username or IP-only observation.

## Current-State Mapping

- `KnownUser.normalize_username()` strips domain and uppercases; future implementation must preserve authority in `principal_key`.
- `KnownUser.find_by_username_sid_alias_or_email()` may match by username before SID; future key construction must prefer actual SID identity.
- `KnownSystem.extract_netbios_name()` strips FQDN; future key construction must retain alias/provenance.
- `utils.graph_identity.build_user_entity()` already requires SID, authority, or host scope and is aligned with this contract.
- `utils.graph_identity.build_host_entity()` uses source context for observed host identity and must not be weakened to a global hostname merge.
- Future KnownSystem rows store `principal_key` (and aliases) rather than exporting `id` into identity strings.

## Tests

- SID equality beats username spelling differences.
- Same bare username in two domains produces two keys.
- `DOMAIN\user` and `user@domain` produce the same key only when authority matches.
- Machine-local account is scoped to system key.
- Well-known/service accounts are classified and not merged into normal users.
- Hostname and FQDN alias relationship preserves provenance.
- IP-only observation does not merge with hostname-only observation.
- CT-043: `principal_key` never includes `KnownSystem.id` / `known-system:<id>`; two KnownSystem rows for the same hostname evidence produce the same host-scoped key.

## Explicit Open Items

- OPEN — ADDITIONAL MEASUREMENT REQUIRED: retained-case collision rates for bare usernames, duplicate hostnames, and IP reuse.
- NOT APPLICABLE: no database migration or consumer migration in Phase 0B.
