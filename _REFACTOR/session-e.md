SESSION E




casescope.zip
ZIP
casescope.zip zip Session D — routes/api.py Split Plan Context I'm rewriting caseScope, a DFIR platform (~97k lines Python, Flask, ClickHouse + Postgres). Deterministic core unlicensed; AI/OpenCTI/MISP/RAG license-gated. Layered architecture: L1 detection → L2 TI enrichment → L3 RAG → L4 LLM ada
PASTED

2:05 PM



I see you've uploaded a zip and a transcript of a prior session where I (a previous Claude instance) produced a Session D split plan for routes/api.py. What would you like me to do with this? A few possibilities:
1. Verify the plan against the actual casescope.zip contents — re-extract, re-count the 144 routes, and sanity-check the block assignments and line anchors.
2. Investigate the flagged bugs — specifically the high-priority one: whether IOC enrichment routes #105–107 (lines 8708–8823) actually lack license checks, and the MISP-uses-opencti-flag question.
3. Resolve the "needs discussion" items — #1 dashboard placement, #7 case-statistics boundary, #93–95 potential collision with existing routes/noise.py, and #88/#89 tag-artifacts duplicate.
4. Execute the migration (or step 1 of it — extracting admin.py) against the actual code.
5. Produce the compressed deliverables (D2/D4/D7) in more detail if the prior pass shortchanged them.
6. Something else — e.g., start Session E, or review the plan critically for mistakes.
My guess is you want #2 first (verify the license-check gap, since the prior plan called it "the highest-priority finding in the whole session") and then #3 to unblock the migration. But tell me which, and I'll dig into the zip accordingly.




That Claude's guess is good but I'd adjust the ordering. Here's how I'd rank the six options for your situation (vibe coding, limited sessions, want this to actually ship):
Do #2 first. Definitely.
The license-check gap finding is the only thing on that list that is a live security bug in your running product. Everything else is about making the rewrite cleaner. If IOC enrichment routes #105–107 really are missing license checks, that's an unlicensed user getting a feature you're gating. That's not a refactor concern — that's a "fix this week regardless of the rewrite" concern. You want it verified now so you either (a) know it's a false alarm and stop worrying, or (b) have a patch queued that doesn't depend on the full split landing.
Tell that Claude: "Do #2. Read the actual route handlers for #105–107 end to end, trace what decorators they have, trace what feature_availability calls (if any) happen inside the handler body, compare against a known-correctly-gated route like one of the OpenCTI ones for contrast, and tell me definitively: is this a bug, a false alarm, or 'it depends.' If it's a bug, give me the minimum patch to close it — not the full refactor, just a one-or-two-line fix I can ship today."
Then do #3.
The "needs discussion" items are the things blocking the actual file extraction from starting. Four small decisions unstick the whole migration. Each one is a 2-minute call once the context is in front of someone — you don't even have to make the calls yourself, you can let that Claude recommend and you just say yes/no. Specifically:
* #1 dashboard placement — just pick a home. Likely routes/search.py or a new routes/dashboard.py. Trivial.
* #7 case-statistics boundary — does it go with findings or with cases? Pick one based on what it actually queries.
* #93–95 collision with noise.py — either merge into existing noise.py or rename. Whichever requires less line shuffling.
* #88/#89 tag-artifacts duplicate — confirm it's actually a duplicate, pick one to keep, flag the other for deletion.
Tell that Claude: "After #2, do #3. For each of the four items give me: the recommendation, the one-sentence reason, and whatever I need to look at to confirm (like 'glance at noise.py's existing blueprint prefix'). I'll accept your recommendations unless something jumps out."
Skip #1 (verify the plan).
You don't need a pre-flight check. The plan is already the output of a careful read. Re-verifying it burns a session turn for marginal value. If something's wrong, you'll find out when extraction starts (#4) and you can fix it then.
Skip #5 (more detail on D2/D4/D7) for now.
Those are supporting deliverables. You don't need them to start shipping. If you hit a specific question during extraction ("where does this helper go?") you ask it then as a targeted question, not as a full deliverable rewrite.
Save #4 (execute the migration) for after #2 and #3.
Executing the migration inside a Claude session is actually a reasonable use of sessions — but only after the bug is triaged and the four unblockers are resolved. Otherwise you're extracting files while a live bug exists and while four ambiguities are still hanging. Do those first, then extraction is a clean pass.
Definitely not #6 (start Session E) in this conversation. Session E is its own fresh-conversation job with its own brief (the one I just wrote you). Don't mix them.
So your reply to that Claude is basically:
Do #2 first — verify the IOC enrichment license-check gap definitively, and if it's a real bug give me the minimum patch, not the full refactor. Then do #3 — resolve all four "needs discussion" items with your recommendations, I'll accept unless something jumps out. Skip #1 and #5. We'll do #4 after those two are done, in this same session if there's budget, otherwise a fresh one.
That keeps the session focused, gets the one real-world risk triaged, and unblocks extraction — in that order. Exactly the order a careful engineer would do it in if it were their own code.

Show more
2:06 PM



Got it. Starting with #2 — verifying the IOC enrichment license-check gap on routes #105–107 (lines 8708–8823).
Ran a command, viewed a file

Ran a command, viewed a file

Now I need to check what FeatureAvailability.is_threat_intel_enabled() actually does — specifically whether it checks license activation or only provider reachability/config.
Ran a command, viewed a file

Ran a command, viewed a file

Now I need to see whether is_opencti_enabled() / is_misp_enabled() check the license or only provider config/reachability.
Check whether opencti/misp enabled checks reference license at all

Check whether opencti/misp enabled checks reference license at all

That's definitive. Let me confirm by viewing the relevant lines:
Confirm opencti and misp enabled check license first

Confirm opencti and misp enabled check license first

I have the full picture. Here's the verdict on #2, then #3.
#2 — IOC Enrichment License Gap: FALSE ALARM ✅
The prior Claude's grep was too narrow — it searched for _is_license_feature_active (the module-local helper at api.py:106) and missed that routes #105 and #107 use a different, better mechanism: FeatureAvailability.is_threat_intel_enabled() from utils/feature_availability.py. That function delegates to is_opencti_enabled() / is_misp_enabled(), both of which check cls.is_activated('opencti') — i.e., valid license — as the first gate, before any config or connectivity check (feature_availability.py:192–196 and 207–210).
Concretely:
* #105 /ioc/<id>/enrich POST (api.py:8718): gated via FeatureAvailability.is_threat_intel_enabled() → license-checked ✅
* #107 /iocs/bulk-enrich POST (api.py:8791): same gate ✅
* #106 /ioc/<id>/enrichment GET (api.py:8748): no license check, but this is a read of already-persisted ioc.opencti_enrichment data on the IOC row. It returns data the system generated when the license was active. That's the same read-vs-write asymmetry as #96 /settings/opencti GET, and is defensible: you don't re-gate reads of historical data when a license lapses. Worth a one-line confirmation from the product owner but not a bug.
One real finding worth noting (not a gap, a style inconsistency to clean up in Session E): there are now three different license-check mechanisms in api.py for threat-intel routes:
1. _is_license_feature_active('opencti') — lines 8401, 8441 (OpenCTI settings/test)
2. _is_threat_intel_license_active() — lines 8605, 8642 (MISP settings/test)
3. FeatureAvailability.is_threat_intel_enabled() — lines 8718, 8791 (enrichment actions)
Mechanisms 1 and 2 check only license state. Mechanism 3 checks license and provider reachability. The enrichment routes picked the stricter one, which is correct — you can't enrich against an unreachable OpenCTI. The unified @requires_feature decorator proposed in D3 should preserve this distinction (probably @requires_feature('opencti', check_availability=True)).
No patch needed. Nothing to ship today. Stop worrying about it.
Also, while I was in feature_availability.py: line 242's is_threat_intel_enabled has dead code after the return (lines 244–274 — an entire unreachable second implementation that was clearly the original body before it was replaced with the one-liner return cls.is_opencti_enabled() or cls.is_misp_enabled()). Not a bug, just cruft. Flag for Session E cleanup.

#3 — Four "Needs Discussion" Items
Gather data for the four unblockers

Gather data for the four unblockers

All four unblockers resolved. Recommendations below — accept unless something jumps out.
#1 — Dashboard placement (/dashboard/stats, api.py:514)
Recommendation: routes/admin.py. Reason: it's a system-wide rollup (not case-scoped), and the other system-wide settings/status endpoints are already going to admin.py — co-locating keeps one file for "global view" surface. To confirm: glance at the body of /dashboard/stats (line 514ff) — if it queries per-user or per-case data rather than global counts, flip it to main.py instead. I didn't re-read it; prior plan already had it pencilled to admin. Cheap to verify when you extract admin.py.
#7 — /case/statistics/<case_uuid> vs /files/stats/<case_uuid>
Recommendation: cases.py, keep separate from /files/stats. Reason: I read the handler — it's a case dashboard rollup that pulls from CaseFile, IOC, KnownSystem, KnownUser, PcapFile, MemoryJob, EvidenceFile, network_log, and ClickHouse. That's case-wide state across eight models, not file-level counters. It belongs with the case object, not with ingest/file management. /files/stats/<case_uuid> stays in ingest.py as planned — it's the narrower file-table view. Two endpoints, two purposes, no consolidation needed. To confirm: nothing — the handler docstring literally says "comprehensive statistics for a case dashboard."
#93–95 — Collision with existing routes/noise.py
Recommendation: put them in search.py, NOT noise.py. Reason: routes/noise.py exists and uses url_prefix='/settings/noise' — it's the noise rules configuration surface (categories, rules CRUD at /settings/noise/api/...). The api.py endpoints #93–95 are /hunting/noise/stats|tag|status/<case_id> — case-scoped hunting operations that apply noise rules to events, not rule management. Different prefix, different purpose, different blueprint. Merging them would force either a prefix change (breaks URLs) or a second blueprint in the same file (ugly). They're "hunting" routes; search.py is the hunting home. To confirm: nothing — the prefix mismatch (/settings/noise vs /hunting/noise) decides it unilaterally.
#88/#89 — tag-artifacts duplicate
Recommendation: NOT a duplicate. Keep both. Rename one for clarity in Session E. Reason: I read both handlers end to end:
* #88 /iocs/tag-artifacts/<case_uuid> POST — calls tag_all_iocs_globally(case.id) synchronously and returns full results in the response. This is the blocking path.
* #89 /iocs/tag-artifacts/start/<case_uuid> POST — calls tag_iocs_for_case.delay(case.id) and returns a task_id. This is the Celery/async path, paired with #90 progress and #91 results.
They're two different execution models for the same operation. Both are probably live (the sync one for small cases, the async one for big cases). No deletion. But the naming is terrible — /tag-artifacts vs /tag-artifacts/start doesn't telegraph sync-vs-async. Flag for Session E: rename #88 to /iocs/tag-artifacts/sync/<case_uuid> or fold it into the async path and delete it if UI only calls #89. Grep static/ and templates/ for tag-artifacts before the Session E rename — that's the confirmation step. To confirm: one grep in static/ and templates/ for tag-artifacts — tells you whether #88 has any callers. If zero, it's dead and moves to _legacy.py in D; if any, both stay.
Check if sync tag-artifacts endpoint has any callers

Check if sync tag-artifacts endpoint has any callers

Bonus confirmation while I had the data: the sync /iocs/tag-artifacts/<case_uuid> (without /start, /progress, /results) has zero callers in static/ or templates/. The only matches after filtering are CSS classes and a modal container name — no fetch/URL references. The async flow (#89→#90→#91) is the only one actually wired up.
Revised #88/#89 recommendation: #88 is dead. Move it to _legacy.py in D (or just delete it in the same commit that moves the async trio to ingest.py). That flips one entry in the plan:
* _legacy.py goes from 0 entries → 1 entry (#88), OR
* ingest.py goes from 22 → 21 (if you just delete).
My vote: delete outright, don't bother with _legacy.py for a single dead sync variant. Git history preserves it if anyone needs it back.

Summary — where we are
#2 (license gap): False alarm. No patch. The prior Claude's grep missed that #105/#107 use FeatureAvailability.is_threat_intel_enabled() which checks license first. #106 is a read of historical data and is defensibly ungated. One style inconsistency (three different license-check mechanisms) logged for Session E. One piece of dead code in feature_availability.py:244–274 also logged.
#3 (unblockers):
1. Dashboard → admin.py (verify when extracting)
2. /case/statistics → cases.py, separate from /files/stats (confirmed by reading handler)
3. /hunting/noise/* → search.py, NOT noise.py (confirmed by prefix mismatch)
4. tag-artifacts #88 is dead (zero callers) — delete it; #89–91 go to ingest.py as planned
All four resolved. Nothing jumped out that should make you override.

Budget check for #4
I've used a meaningful chunk of this session on verification and have roughly enough headroom to do one migration step cleanly — probably step 1 (admin.py extraction, 27 endpoints, lowest coupling) — but not more without risking a truncated result mid-extraction. Given that admin.py is also where the dashboard-placement verification needs to happen (and where _update_worker_service_concurrency needs to move with it), it's a natural unit.
My recommendation: stop here, open a fresh session for #4 with this verification summary + the updated plan as context. The reasons:
1. Extraction is mechanical but touchy — you want full budget for it, not a rushed pass
2. Fresh session = fresh context window = room for me to actually read admin-related helpers, write the new file, update the blueprint registration, and do the url_for grep across templates in one shot
3. Session D as originally scoped was planning, not execution. Mixing them risks an incomplete commit
If you'd rather I push on admin.py extraction right now anyway, say so and I'll start — but I'd rather hand you a clean "Session D.5: extract admin.py" brief for a new conversation. Your call.




Yes, do step 1 — extract admin.py cleanly. 27 endpoints plus _update_worker_service_concurrency and the dashboard placement resolved inline. I'm doing the actual code edits in Cursor, so I don't need you to write files — give me the output as: (1) the full admin.py contents ready to paste, (2) the exact blocks to remove from api.py with line ranges, (3) the blueprint registration line for wherever blueprints get registered, and (4) any import changes needed in api.py after the removal. If you have budget left after that, list anything I should verify in Cursor after pasting (e.g., "check that _update_worker_service_concurrency isn't imported anywhere else"). If budget runs short, prioritize the admin.py file and the removal ranges — I can figure out the blueprint wiring myself.
2:11 PM



Tight budget — I'm going to be ruthlessly efficient. Prioritizing admin.py + removal ranges.
Get api.py imports and blueprint definition

Get api.py imports and blueprint definition

Now I need the exact line ranges for each admin endpoint — I have the decorator lines from the plan but need the end of each function. Let me grab them efficiently.
Sanity check admin endpoint start lines

Sanity check admin endpoint start lines

All 27 endpoint decorators confirmed + 3 helpers (get_folder_size_gb, get_software_version, _update_worker_service_concurrency). Now I need to determine the end line of each block. Blocks are contiguous where the plan shows consecutive endpoint numbers; let me identify the gaps and find end-of-block lines by looking at what follows each terminal block.
The contiguous blocks in api.py (by endpoint #) mapping to admin.py:
* Helpers: 480–513 (get_folder_size_gb, get_software_version)
* Block 1: /dashboard/stats at 514 → ends before #2 /upload/scan/<case_uuid> at 758. But _default_upload_type_label (80) and upload helpers are between. Let me check what's at 514 and what follows.
* Block 2 (AI+workers+timezone): 6902 → 7698 (before #78 IOC extraction at 7699), includes _update_worker_service_concurrency at 7660
* Block 3 (logs/audit/paths): 8946 → 9481 (before #121 /hunting/field-enhancers at 9482)
* Block 4 (report templates): 9526 → 9791 (before #130 /reports/generate at 9792)
* Block 5 (archive/jobs): 10694 → end-of-file (10739)
Let me verify the exact end lines of the single endpoints at 514 and 10694, and the boundaries:
Verify block boundaries

Verify block boundaries

Clean boundaries. Wait — I need to double-check #120 /audit-log/entity/... block and whether /dashboard/stats block runs clean to 757 (no other non-admin code interleaved). Let me also verify the /dashboard block doesn't interleave with upload helpers.
Check for non-admin code interleaving in dashboard block

Check for non-admin code interleaving in dashboard block

Interleaving confirmed — /dashboard/stats ends somewhere before 739 (where ensure_upload_dirs starts per earlier grep), then upload helpers follow. Let me find the exact end of dashboard_stats:
Find exact end of dashboard_stats

Find exact end of dashboard_stats

So dashboard_stats runs 514–727, then a section-header comment block at 728–731, then upload helpers 732–757 (which stay in api.py, moving with ingest). Similar check needed on 6902 block for interleaving:
Check AI/workers block for interleaving

Check AI/workers block for interleaving

Gap between 6902 (detect-gpu) and 7150 (get_ai_settings) — 248 lines. Large gap, likely dead code or other routes that the inventory missed. Let me verify:
Check 6902-7150 gap

Check 6902-7150 gap

Clean — detect_gpu() is just 246 lines long (GPU detection is involved). No interleaving. The AI/workers block is 6902–7694 contiguous, then _update_worker_service_concurrency at 7660 is already inside that block (it's a helper between the timezone route at 7626 and the next section header at 7695).
Similarly check logs/audit and report templates blocks:
Check logs, templates, archive blocks

Check logs, templates, archive blocks

All clean. Logs/audit has /hunting/field-enhancers at 9482 inside what looked like the admin block — it lives between admin endpoints (ends at 9476 with audit-log/entity, then field-enhancers at 9482, then reports at 9526). So there's a one-endpoint gap at 9482–9524 that goes to search.py, not admin.py.
Final block structure for admin.py:
Block	Lines in api.py	Contents
H1	480–513	get_folder_size_gb, get_software_version helpers
B1	514–727	dashboard_stats
B2	6902–7694	detect-gpu, 6×ai, 3×workers, 2×timezone, _update_worker_service_concurrency
B3	8946–9476	audit-logs, logging×3, paths×3, log-view, case-logs, audit-log×2
B4	9526–9790	report templates ×8
B5	10694–10739	archive/jobs/active
Now I need the actual content. This is too large to paste inline — let me extract it and build the file:
Extract admin block contents

Extract admin block contents

1,883 lines / ~75KB. That's way too large to paste into chat. I need to write it as a file and present it — that's the right call regardless of the user saying "I'm editing in Cursor." They can download the file from the chat and paste its contents into Cursor.
Let me figure out which imports admin.py needs, then assemble the file. I'll scan the extracted blocks for symbols used:
Identify symbols used in admin body

Identify symbols used in admin body

Good signal. Note: 33 @api_bp.route hits but the plan says 27 endpoints. Let me recount — that's 6 extra. The helpers block has 0 routes, so that means some block has more routes than I counted. Probably the line-range boundaries are slightly off. Let me recount inside my extracted blocks:
Recount routes per block

Recount routes per block

33 routes, but the plan said 27. The discrepancy:
* Block 6902–7694: 12 (plan counted 11: #66 detect-gpu + #67–72 ai ×6 + #73–75 workers ×3 + #76–77 timezone ×2 = 12 ✓ — I miscounted the plan as 11)
* Block 8946–9476: 11 (plan: #110 + #111–113 logging ×3 + #114–116 paths ×3 + #117 log-view + #118 case-logs + #119–120 audit-log ×2 = 11 ✓)
* Block 9526–9790: 8 (plan: #122–129 = 8 ✓)
So: 1 + 12 + 11 + 8 + 1 = 33 routes total, not 27. The prior plan's "27" was wrong arithmetic. Recount from the original block listing: #1 + #66–77 (12) + #110–120 (11) + #122–129 (8) + #144 (1) = 33. Confirmed — the blocks are right, the plan's summary count was off by 6.
Good thing we're verifying. 33 endpoints, all accounted for, no interleaving. Now let me build admin.py:
Build admin.py output file

Build admin.py output file

1,939 lines, 33 routes, zero leftover @api_bp.route references. Clean. Let me verify the file parses as valid Python before presenting:
Syntax-check admin.py

Syntax-check admin.py

Parses clean.
Presented file

Presented file

(1) admin.py — attached above
1,939 lines, 33 routes, AST-valid. Download from the file link. Note the route count is 33, not 27 — the prior plan's summary arithmetic was off (#66–77 is 12 endpoints not 11, and the block totals add to 1+12+11+8+1=33). All 33 are accounted for and there's no interleaving with non-admin code in any block.
(2) Blocks to remove from api.py
Remove these six contiguous line ranges (inclusive, 1-indexed, matching the file you uploaded):
#	Lines	Content
1	480–513	get_folder_size_gb, get_software_version helpers
2	514–727	dashboard_stats route (214 lines — detect-gpu is the big one)
3	6902–7694	detect-gpu + AI settings ×6 + workers ×3 + timezone ×2 + _update_worker_service_concurrency helper
4	8946–9476	audit-logs/<category> + logging ×3 + paths ×3 + log-view + case-logs + audit-log ×2
5	9526–9790	report templates ×8
6	10694–10739	/archive/jobs/active (end of file)
Order matters: delete from bottom to top (6→5→4→3→2→1) so earlier line numbers don't shift under you while you're working. Cursor's multi-cursor or sequential range-delete will handle this; just do it in reverse.
Total removed: 1,883 content lines. After removal, api.py drops from 10,739 → 8,856 lines.
⚠ Do not remove lines 728–757 (the section-header comment between dashboard_stats and the upload helpers) — that's ensure_upload_dirs / _viewer_upload_error / _allowed_case_upload_roots, which stay in api.py for now (they move later with ingest.py in step 4).
⚠ Do not remove lines 9482–9524 (/hunting/field-enhancers) — it sits inside what visually looks like the audit-log block but goes to search.py later.
(3) Blueprint registration
Find where api_bp is currently registered (probably in app.py or main.py — search for register_blueprint(api_bp) or from routes.api import api_bp). Add alongside:

python
from routes.admin import admin_bp
app.register_blueprint(admin_bp)
Both blueprints coexist at url_prefix='/api' — Flask handles that fine.
(4) Import changes in api.py after removal
After the deletions, these module-level imports in api.py may become unused. Verify and remove only if truly unused (grep within the trimmed api.py):
* import platform — only used by get_software_version and possibly dashboard_stats. Likely removable.
* import zipfile — grep api.py after removal; if no other use, remove.
* from utils.forensic_chat_sources import get_browser_download_rows — used by /hunting/browser/downloads (#92, line 8224) which stays in api.py until step 3. Keep.
* from models.audit_log import AuditAction, AuditEntityType, AuditLog — used heavily by cases/iocs/etc. Keep.
* from models.file_audit_log import FileAuditLog — used by _log_case_file_audit and ingest routes. Keep.
Recommended: after deletion, run python3 -c "import ast; ast.parse(open('routes/api.py').read())" then python3 -m pyflakes routes/api.py to auto-surface unused imports. Don't remove by hand.
Things to verify in Cursor after pasting
1. url_for breakage. Grep templates/ and static/ for url_for('api.dashboard_stats, url_for('api.get_ai_settings, url_for('api.get_audit_logs, etc. — any url_for('api.<admin_func_name>') needs to become url_for('admin.<func_name>'). Faster version: grep -rn "url_for('api\." templates/ static/ | grep -E "dashboard_stats|ai_settings|worker_settings|timezone|logging_settings|folder_path|audit_log|report_template|archive_job|detect_gpu|log_file|case_logs". Update each hit.
2. The temporary circular import. admin.py does from routes.api import _is_license_feature_active. This works today but is ugly — it'll be replaced when routes/_decorators.py lands in migration step 7. If Cursor's linter complains about the circular shape, ignore for now (Flask blueprint modules import each other all the time and Python handles it as long as nothing at module-import-time runs the imported function).
3. _update_worker_service_concurrency is not referenced from anywhere else. I didn't grep the whole repo during extraction. Quick sanity check: grep -rn _update_worker_service_concurrency routes/ utils/ tasks/ app.py main.py — expect exactly two hits, both in admin.py (definition + caller inside set_worker_settings). If any hit is outside admin.py, that caller needs its import updated.
4. get_folder_size_gb and get_software_version. Same check: grep -rn "get_folder_size_gb\|get_software_version" routes/ utils/ tasks/ app.py main.py. If only used inside admin.py (expected), you're fine. If anything else imports them from routes.api, that importer needs updating to from routes.admin import ... — or, better, promote them to utils/system.py as the plan called for (but that's a follow-up commit, not this one).
5. Run the app, hit three endpoints. Smoke-test: GET /api/dashboard/stats, GET /api/settings/ai/status, GET /api/audit-log. If all three return their normal payloads (not 404s, not 500s), the extraction worked and blueprint registration is wired correctly.
6. The _is_license_feature_active import is load-bearing for AI endpoints. If step 1 accidentally removes it from api.py (it's defined at line 106, well above the removed ranges — should be safe), the AI settings endpoints in admin.py will break at request time. Verify line 106 is still present in api.py after your deletions.
That's the full step 1. Good luck in Cursor — ping me in a fresh session for step 2 (enrichment.py, 12 endpoints, much smaller) whenever you're ready.
AdminPY 


















Claude is AI and can make mistakes. Please double-check responses.



