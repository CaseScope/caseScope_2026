# Agent Loop

## Status
Phase 1 input for Phase 6 implementation. This is a concrete runtime spec, not a general design discussion.

## Source Anchors
- `_REFACTOR/session-a.md:493-661`
- `claude-code` runtime analysis captured in Session A

## Purpose
Lock the reusable chat and agent loop shape so all AI features build on one runtime instead of each feature inventing its own prompt assembly, caching strategy, and message mutation behavior.

## Locked Decisions

### Exactly One Cache Marker
- add exactly one `cache_control` marker per request
- default location: last message
- fork or fire-and-forget mode may shift the marker to second-to-last message
- do not scatter cache markers across tool schemas, system blocks, and final messages

### Frozen ConversationContext
The following must be captured once at conversation start and not re-read mid-session:
- license tier
- enabled features
- enabled TI sources
- available agents
- model selection
- any capability flags that affect the prompt prefix

Required property:
- `ConversationContext` is immutable for the life of the conversation

### Stable System Blocks
System prompt content is not one giant mutable string. It is an ordered set of stability-tiered blocks:
- static role and identity
- tool documentation
- methodology or skill instructions
- license-capability disclosure
- case-static context

Anything that changes turn-to-turn does not belong in these blocks.

### Dynamic Attachments
Turn-variable context must be injected as ordered attachments or messages rather than baked into the system prompt.

Examples:
- available artifact summary
- finding count and severity summary
- conversation delta
- current case context changes

### Cache Reference Injection
Previously emitted tool results that sit before the cache marker should be referred to by `cache_reference` rather than re-emitted in full.

### Clone Discipline
Message arrays must be shallow-cloned before mutation.

Reason:
- prevent duplicate cache markers
- prevent duplicated attachments
- prevent cross-contamination between parent and subagent requests

### Repeated Tool Call Stubs
Repeat tool calls with unchanged arguments should return a stub that points the model back to the earlier result rather than re-reading or re-querying the same content.

## Locked Attachment Order
The exact names may vary in implementation, but this ordering concept is locked:

- `SYSTEM_REMINDER`
- `CASE_STATIC_CONTEXT`
- `LICENSE_CAPABILITIES`
- `AVAILABLE_ARTIFACTS`
- `FINDING_SUMMARY`
- `CONVERSATION_DELTA`
- `USER_QUERY`

Rule:
- attachment order is deterministic
- attachment order is part of cache behavior
- do not reorder casually

## Locked Runtime Components
Phase 6 should implement these concepts directly:
- `ConversationContext`
- `AttachmentScheduler`
- `AttachmentOrder`
- `add_cache_breakpoints`
- `inject_tool_result_cache_refs`
- `ChatLoop`

## ChatLoop Skeleton
The reusable loop shape from Session A is:
1. build user message with ordered attachments
2. append to message history
3. apply cache breakpoints
4. inject tool result cache references
5. call the model using stable system blocks and frozen tool schemas
6. execute tool calls through the dispatcher
7. append tool results
8. recurse or continue until the model stops requesting tools

## Feature Reuse Rule
This one loop is the substrate for:
- AI chat
- AI IOC extraction
- AI report generation
- AI timeline narration
- nearby-artifact search subagents
- case-analysis subagents

Differences between these features should come from:
- tool registry
- system prompt blocks
- attachment mix
- subagent scoping

They should not come from six separate runtime implementations.

## Metrics To Instrument
These two metrics are part of the spec, not optional nice-to-haves:
- cache hit rate on the stable prefix
- `cache_creation_input_tokens` versus `cache_read_input_tokens`

Reason:
- this runtime is intended to be cache-efficient
- without these metrics, the implementation can drift while still appearing to work

## Non-Negotiable Rule
If a future feature needs special runtime behavior, it should extend the shared loop through configuration or bounded subagent behavior rather than forking a new ad hoc agent runtime.
