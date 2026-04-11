# Silent Default Audit

## Status
Phase 0 verification artifact.

## Purpose
Check for case-scoped fields that silently inherit from context or other fallbacks in a way that could bypass future `L0` case-scope protections.

## Source Anchors
- `_REFACTOR/session-b.md:254-269`
- `_REFACTOR/session-c.md:28`
- `_REFACTOR/session-c.md:56`
- `routes/memory.py:254-269`

## Exact Dangerous Pattern Searched
The canonical dangerous example from the transcript specs was:

```python
target_case = call.arguments.get("case_id", self.ctx.case_id)
```

This pattern is dangerous because a missing case identifier silently inherits the active conversation case instead of failing schema validation.

## Reproduction Commands
The audit used repo-wide grep patterns aimed at defaulted case-scoped lookups and fallback chaining. Representative commands:

```bash
rg "\.get\((['\"]case(_id|_uuid)?['\"]|[^\n)]*case[^\n)]*),\s*[^\)]" /opt/casescope
rg "kwargs\.get\((['\"]case(_id|_uuid)?['\"]|[^\n)]*case[^\n)]*),\s*[^\)]" /opt/casescope
rg "arguments\.get\((['\"]case(_id|_uuid)?['\"]|[^\n)]*case[^\n)]*),\s*[^\)]" /opt/casescope
rg "case_(id|uuid)\s*=\s*[^\n]*\bor\b[^\n]*get\(['\"]case_(id|uuid)['\"]" /opt/casescope
```

These are not the only possible audit queries, but they are enough to reproduce the specific findings recorded below.

## Audit Result

### Transcript-only findings
The exact dangerous defaulting pattern appears in transcript specs:
- `_REFACTOR/session-b.md`
- `_REFACTOR/session-c.md`

It does **not** currently appear in the live runtime codebase.

### Live-code grep result
The direct `arguments.get("case_id", ...)` shape was not found in live code.

The one meaningful live fallback discovered was:

```python
routes/memory.py:259
case_uuid = case_uuid or meta.get('case_uuid', '')
```

Context:
- this occurs during upload-metadata recovery for memory processing
- the handler later validates the recovered `case_uuid` using `Case.get_by_uuid(case_uuid)`
- missing values still fail with `Missing required fields`

Assessment:
- not the same class of cross-case dispatch vulnerability as the transcript example
- still worth keeping on the audit list because it is a case-scoped fallback and could become riskier if similar patterns spread into chat, tool-dispatch, or background automation flows

### Safe Pattern Example
`routes/memory.py` is the safe shape of fallback:
- fallback recovery happens during upload metadata reconstruction
- the recovered `case_uuid` is later validated via `Case.get_by_uuid(case_uuid)`
- the handler fails if required values are still missing

Rule of thumb:
- dangerous pattern: silent fallback with no downstream authorization or scope validation
- safe pattern: silent fallback followed by explicit case lookup and authorization or existence validation before use

### Other grep hits
Other `case_id` and `case_uuid` `.get(...)` usages found during the audit were display or request-parse paths rather than silent security-sensitive inheritance:
- `routes/chat.py`
- `routes/noise.py`
- `utils/chat_agent.py`
- migration and licensing helper lookups

These did not match the dangerous silent-inheritance shape.

## Current Conclusion
- The dispatch `L0` protections described in `docs/refactor/dispatch_state_machine.md` are currently protecting against a **hypothetical-to-nearby** class of bug rather than a clearly active live exploit path.
- That lowers immediate emergency pressure on Phase 6, but it does **not** remove the need to enforce explicit case-scoped schema validation before a shared tool runtime is introduced.

## Follow-Up Rule
Any new chat, tool-dispatch, or background-agent code added during the refactor should be rejected in review if it defaults missing case-scoped fields from runtime context rather than failing validation explicitly.
