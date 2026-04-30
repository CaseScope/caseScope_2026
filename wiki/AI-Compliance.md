# AI Compliance

This page explains how CaseScope handles AI privacy, auditability, and compliance-oriented controls. It describes what happens at each Cloud AI Privacy Mode slider level, how local rehydration works, and how the AI Audit system records prompt and response evidence.

## Scope

CaseScope can use local models, OpenAI-compatible endpoints, OpenAI, or Anthropic providers for AI-assisted analysis. These features may process case content such as event summaries, hostnames, usernames, paths, indicators, report text, and analyst prompts.

The compliance controls are designed to reduce and document AI data exposure. They do not by themselves make every external AI provider suitable for CMMC, CUI, FedRAMP, CJIS, HIPAA, or other regulated workloads. Administrators must still choose an authorized provider, configure the right region and account boundary, review contractual terms, and follow their organization's data handling policy.

## Control Layers

CaseScope uses several layers together:

- **Provider selection** controls where AI requests are sent: local/OpenAI-compatible, OpenAI, or Anthropic.
- **Cloud AI Privacy Mode** aliases protected case values before case content leaves the CaseScope server.
- **Case-scoped alias vaults** map original values to generated aliases such as `ACCOUNT_0009` or `HOSTNAME_0004`.
- **Local rehydration** restores aliases only inside authorized local display, review, and persistence boundaries.
- **AI Audit** records AI prompt and response evidence with tamper-evident hashes.
- **Strict audit mode** can block AI responses if CaseScope cannot write the audit record.
- **Forensic Audit Log** records changes to AI audit policy and chain verification results.

## Cloud AI Privacy Mode

The AI settings page includes a four-level slider: `Off`, `Basic`, `CMMC/CUI`, and `Strict`. The active level is stored as `ai_privacy_obfuscation_level`.

When a case-content AI call is prepared, CaseScope builds an `AIPrivacyContext` for the case and runs the outbound prompt, system prompt, messages, or structured payload through the privacy aliaser. If the selected level requires aliasing, CaseScope discovers protected values in the payload, stores or updates aliases in the case alias vault, replaces matching originals with aliases, and records privacy metadata such as level, case ID, alias count, categories, and sanitizer duration.

### Off

`Off` applies no privacy aliases. Raw case values can be sent to the configured AI provider.

Use this only for fully local testing, non-sensitive data, or environments where the selected AI provider is explicitly approved for the data being processed. Saving `Off` records an administrator acknowledgement so the decision is visible later.

At this level:

- Usernames, accounts, hosts, IPs, domains, paths, case names, and report text remain unchanged.
- AI Audit can still record prompts and responses if enabled.
- Compliance depends almost entirely on the provider and deployment boundary.
- This is the highest exposure setting.

### Basic

`Basic` aliases the common identifiers most likely to appear in Windows event and DFIR data.

Protected categories include:

- Usernames
- Windows accounts
- Email addresses
- Hostnames
- Fully qualified domain names
- Domains
- Internal IPv4 addresses

At this level, a prompt that contains a real account or host is transformed before provider egress. For example, `DAFL\BDALENE$` may become an account alias and `BDALENE` may become a hostname alias. The provider sees the alias tokens, while CaseScope keeps the original mapping locally.

This level is useful for reducing routine identity and infrastructure disclosure when the provider is outside the local server boundary, but it does not alias every possible sensitive value.

### CMMC/CUI

`CMMC/CUI` is the default compliance-oriented level. It includes everything in `Basic` and expands aliasing to additional organization, tenant, path, and case-identifying values.

Additional protected categories include:

- Client public IPv4 addresses
- Tenant IDs
- Object IDs
- SIDs
- UNC paths
- Share names
- File paths
- Client names
- Person names
- Company names
- Case names

This level is intended for case-content AI usage where administrators want strong reduction of direct client and case identifiers before using a cloud or hosted AI provider. It is still a best-effort technical control, not a replacement for using an authorized environment when CUI or regulated data is in scope.

The AI settings page warns that CMMC and CUI workloads may require FedRAMP-authorized systems. For Anthropic, that may mean an approved Amazon Bedrock deployment in AWS GovCloud regions. For OpenAI, that may mean an approved government offering. Organizations should verify the exact provider path and authorization before sending regulated data.

### Strict

`Strict` includes everything in `CMMC/CUI` and also aliases external network indicators and URLs.

Additional protected categories include:

- External IPv4 addresses
- External domains
- URLs

This level provides the strongest cloud isolation. It is appropriate when the organization wants to minimize disclosure of client infrastructure, external destinations, callback domains, URLs, and other potentially sensitive indicators to the AI provider.

Strict mode may reduce some provider context because more evidence is replaced with neutral aliases. CaseScope rehydrates the returned result locally, but the remote model only reasons over the aliased values.

## Alias Vault And Rehydration

Aliases are case-scoped. The same original value in the same case maps to a stable alias, while another case has its own alias namespace. This keeps model prompts internally consistent without exposing the original identifiers to the provider.

The outbound path is:

1. CaseScope builds the AI request.
2. The privacy aliaser scans string fields and structured payload leaves.
3. Matching protected values are inserted or updated in the alias vault.
4. Original values are replaced with alias values.
5. The aliased request is sent to the configured provider.
6. AI Audit records the aliased prompt and response evidence.

The return path is:

1. CaseScope receives the provider response.
2. Local code rehydrates aliases before analyst display or local persistence where appropriate.
3. The analyst sees case-native values in reasoning, IOCs, reports, reviews, and pattern results.
4. The audit log remains evidence of what actually crossed the AI boundary.

This separation is intentional. The audit log answers "what was sent to and returned from the provider"; the analyst UI answers "what does this mean in the local case."

## AI Audit

AI Audit is an administrator-only evidence log for AI prompt and response activity. It is separate from the general forensic audit log.

Each AI Audit record includes:

- Timestamp
- Client and case context when available
- User and username
- AI function such as `pattern_matching`, `chat`, `case_review`, `report`, `timeline`, or `ioc_extraction`
- Invocation mode such as text, JSON, or stream chat
- Provider type, provider display, provider path, and model
- Request payload
- Response payload when available
- Status and response completeness
- Error class and message for failures
- Duration and usage metadata when available
- Privacy metadata, including aliasing level and categories
- Prompt hash, response hash, previous record hash, and record hash

AI Audit records are append-only at the model layer. Update and delete attempts are blocked so records cannot be silently modified through normal ORM operations.

## Hash Chain Verification

AI Audit uses versioned SHA-256 hashes:

- `prompt_hash` covers the canonical request payload.
- `response_hash` covers the canonical response payload or an empty response sentinel.
- `record_hash` covers the explicit audit metadata set, including the previous record hash.
- `previous_record_hash` links each record to the prior global AI Audit record.

Administrators can run **Verify Chain Integrity** from Settings > AI Audit. Verification walks records in order and reports whether hashes, payload hashes, and previous-record links are consistent.

The verification result is also written to the general forensic audit log with:

- Verification scope
- Record count checked
- Start and end timestamps
- First and last record timestamps
- First inconsistent record ID, if any
- Expected and actual hashes, if inconsistent
- Verifying username

This gives administrators a reviewable attestation that the AI evidence log was checked at a point in time.

## Strict Audit Mode

AI Audit has two policy toggles:

- **Enable AI Audit logging** controls whether AI calls are written to the AI Audit log.
- **Strict mode** blocks AI responses if the audit write fails.

Strict mode is designed for compliance-sensitive deployments where an AI answer should not be delivered unless the corresponding evidence record is captured. If strict mode is disabled or AI Audit is disabled, an administrator must provide a reason. That policy change is written to the general forensic audit log.

## General Forensic Audit Integration

The general forensic audit log records administrative changes and verification events related to AI compliance controls. Examples include:

- AI Audit enabled or disabled
- AI Audit strict mode degraded or restored
- Required reason for disabling or degrading AI Audit policy
- AI Audit chain verification success or failure
- Fallback records if an AI Audit write fails

This creates a second review path: AI Audit stores prompt/response evidence, while the general audit log stores policy and verification activity.

## Archive Boundary Metadata

During case archive workflows, CaseScope summarizes the case's AI Audit boundary. The archive manifest can include the number of AI Audit records for the case, the first and last case AI Audit hashes, timestamps, and the live global tail hash at the time of archive.

This helps reviewers understand what AI evidence existed for a case at archive time and how that case-specific evidence related to the global AI Audit chain.

## Operational Guidance

Recommended defaults for most compliance-sensitive deployments:

- Keep Cloud AI Privacy Mode at `CMMC/CUI` or `Strict`.
- Prefer approved local models or authorized government cloud AI offerings for regulated data.
- Keep AI Audit enabled.
- Keep strict audit mode enabled.
- Periodically verify AI Audit chain integrity.
- Review AI Audit records by function, case, status, model, and hash.
- Treat `Off` as an exception that requires documented administrator acknowledgement.
- Confirm provider credentials, regions, and contractual terms before enabling cloud AI.

## Limitations

Alias-based privacy controls reduce disclosure but cannot prove that no sensitive concept is inferable from context. Free-text evidence can contain unusual identifiers, prose descriptions, or domain-specific terms that are not covered by a configured entity category. Strict provider governance, data classification, and organizational approval are still required.

AI Audit proves what CaseScope recorded and can detect changes to the hash chain. It does not independently verify the provider's internal retention, training, access, or deletion behavior. Those assurances must come from the selected provider and the organization's compliance program.
