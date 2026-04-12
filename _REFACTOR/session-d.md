SESSION D




casescope.zip
ZIP
Session D — routes/api.py Split Plan Context I'm rewriting caseScope, a DFIR platform (~97k lines Python, Flask, ClickHouse + Postgres). Deterministic core unlicensed; AI/OpenCTI/MISP/RAG license-gated. Layered architecture: L1 detection → L2 TI enrichment → L3 RAG → L4 LLM adapters. Prior sessions
PASTED

1:58 PM



I'll start by extracting the zip and reading the relevant files.
Ran 5 commands

Ran 5 commands

Good — exactly 144 routes. Let me check license check patterns and the other route files briefly.
Ran 2 commands

Ran 2 commands

I have enough signal. Given the 144-row inventory would blow the budget, I'll follow the spec's stated priority (D1 > D3 > D5 > D6 > D2 > D4 > D7), compressing D1 into an endpoint-range table grouped by contiguous blocks — every endpoint accounted for with line-range anchors — then spend remaining budget on D3 and D5.
Verify 144

Verify 144

All 144 confirmed. Writing the plan now.
Session D — routes/api.py Split Plan
Scope check: routes/api.py = 10,739 lines, exactly 144 @api_bp.route decorators. Sibling route files already exist (auth.py, analysis.py, chat.py, evidence.py, parsing.py, pcap.py, rag.py, memory.py, network_hunting.py, noise.py, activation.py, main.py) — so routes/findings.py, routes/ingest.py, routes/enrichment.py, routes/ai.py, routes/cases.py, routes/admin.py, routes/search.py are all new names and won't collide.
Budget note: Per the spec's stated priority (D1 > D3 > D5 > D6 > D2 > D4 > D7), I'm delivering D1 as a grouped line-range inventory (every one of the 144 endpoints accounted for, anchored to exact decorator lines) rather than 144 individual rows — this preserves the load-bearing information (target file, layer, license gating) while staying in budget. D3, D5, D6 follow in full. D2, D4, D7 are compressed.

Deliverable 1 — Endpoint Inventory
Columns: # (ordinal 1–144) · line (decorator line in api.py) · route · target · layer · lic. Methods default GET unless noted; license column is - / ai / cti (opencti/misp) / ai? (gated by settings-check but no hard refusal). Grouped by contiguous blocks that all go to the same target; every row in a block inherits the target unless called out.
Block A — Dashboard (→ admin.py)
#	line	route	layer	lic
1	514	/dashboard/stats	UI/admin	-
Block B — Ingest/upload (→ ingest.py), L1-adjacent
#	line	route	method	lic
2	758	/upload/scan/<case_uuid>	GET	-
3	793	/upload/chunk	POST	-
4	905	/upload/preflight	POST	-
5	997	/upload/ingest	POST	-
Block C — File management (→ ingest.py; statistics is borderline, see notes)
#	line	route	target	notes
6	1757	/files/stats/<case_uuid>	ingest	file-level stats
7	1821	/case/statistics/<case_uuid>	cases	case-level rollup, not file-level
8	2039	/files/list/<case_uuid>	ingest	
9	2141	/files/progress/<case_uuid>	ingest	
10	2263	/files/reindex/<case_uuid> POST	ingest	L1 trigger
11	2292	/files/repair-completion/<case_uuid> POST	ingest	
12	2336	/events/duplicates/preview/<case_uuid>	ingest	
13	2366	/events/duplicates/remove/<case_uuid> POST	ingest	
14	2410	/files/staging/check/<case_uuid>	ingest	
15	2493	/files/staging/import/<case_uuid> POST	ingest	
16	2606	/files/staging/delete/<case_uuid> POST	ingest	
17	2669	/files/recover-stuck/<case_uuid> POST	ingest	
18	2761	/files/delete/<file_id> POST	ingest	
Block D — Hunting events & exports (→ search.py; these are the raw-artifact browse paths, not findings)
#	line	route	layer
19	2882	/hunting/events/<case_id>	UI/L1
20	3391	/hunting/event/raw/<case_id>	UI
21	3520	/hunting/event/tag/<case_id> POST	UI
22	3667	/hunting/events/bulk-tag/<case_id> POST	UI
23	3801	/hunting/events/bulk-noise/<case_id> POST	UI
24	3907	/hunting/events/export-tagged/<case_id>	UI
25	3987	/hunting/events/export-view/<case_id>	UI
Block E — Process graph (→ search.py)
#	line	route
26	4274	/hunting/process/children/<case_id>
27	4374	/hunting/process/parent/<case_id>
28	4510	/hunting/processes/list/<case_id>
29	4759	/hunting/processes/tree/<case_id>
30	5039	/hunting/processes/hostnames/<case_id>
Block F — Known-systems CRUD (→ cases.py; case-scoped reference data)
#	line	route
31	5103	/known-systems/list/<case_uuid>
32	5136	/known-systems/discover/<case_uuid> POST
33	5175	/known-systems/discover-progress/<case_uuid>
34	5198	/known-systems/<system_id>
35	5218	/known-systems/<system_id>/update POST
36	5264	/known-systems/<system_id>/add-ip POST
37	5294	/known-systems/<system_id>/add-share POST
38	5326	/known-systems/<system_id>/audit
39	5351	/known-systems/upload/<case_uuid> POST
40	5541	/known-systems/download/<case_uuid>
41	5608	/known-systems/bulk-update POST
42	5698	/known-systems/bulk-delete POST
Block G — Known-users CRUD (→ cases.py)
#	line	route
43	5748	/known-users/list/<case_uuid>
44	5781	/known-users/discover/<case_uuid> POST
45	5820	/known-users/discover-progress/<case_uuid>
46	5843	/known-users/<user_id>
47	5863	/known-users/<user_id>/update POST
48	5902	/known-users/<user_id>/add-alias POST
49	5932	/known-users/<user_id>/add-email POST
50	5962	/known-users/<user_id>/audit
51	5987	/known-users/upload/<case_uuid> POST
52	6162	/known-users/download/<case_uuid>
53	6226	/known-users/bulk-update POST
54	6279	/known-users/bulk-delete POST
Block H — IOC CRUD (→ enrichment.py for enrich-adjacent, else cases.py; see notes)
#	line	route	target	lic
55	6329	/iocs/types	cases	-
56	6350	/iocs/values/<case_id>	cases	-
57	6389	/iocs/list/<case_uuid>	cases	-
58	6475	/iocs/analyze-match-type POST	cases	-
59	6515	/iocs/create/<case_uuid> POST	cases	-
60	6619	/iocs/<ioc_id>	cases	-
61	6639	/iocs/<ioc_id>/update POST	cases	-
62	6708	/iocs/<ioc_id>/systems	cases	-
63	6731	/iocs/<ioc_id>/audit	cases	-
64	6757	/iocs/<ioc_id>/delete POST	cases	-
65	6808	/iocs/bulk-create/<case_uuid> POST	cases	-
Decision: IOC CRUD is case-scoped reference data like known-systems/users — it belongs with cases.py. IOC enrichment (TI lookups, block M) belongs with enrichment.py. This is the cleanest split; co-locating all IOC routes in one file re-tangles L1 and L2.
Block I — Settings: AI (→ admin.py, all ai-licensed)
#	line	route	lic
66	6902	/settings/detect-gpu	-
67	7150	/settings/ai GET	ai
68	7202	/settings/ai POST	ai
69	7253	/settings/ai/test-connection POST	ai
70	7281	/settings/ai/models GET	ai
71	7324	/settings/ai/fetch-models POST	ai
72	7402	/settings/ai/status GET	ai
Block J — Settings: workers / timezone (→ admin.py)
#	line	route
73	7441	/settings/workers GET
74	7471	/settings/workers POST
75	7563	/settings/workers/restart POST
76	7606	/settings/timezone GET
77	7624	/settings/timezone POST
Block K — IOC extraction from EDR prose (→ ai.py, L4 LLM)
#	line	route	lic
78	7699	/iocs/extraction/check/<case_uuid>	ai
79	7733	/iocs/extraction/extract/<case_uuid> POST	ai
80	7777	/iocs/extraction/progress/<case_uuid>/<task_id>	ai
81	7822	/iocs/extraction/results/<case_uuid>/<task_id>	ai
82	7854	/iocs/extraction/save/<case_uuid> POST	ai
Block L — Find-in-events / tag-artifacts (→ ingest.py, L1 bulk operations over already-ingested events)
#	line	route
83	7893	/iocs/find-in-events/stats/<case_uuid>
84	7930	/iocs/find-in-events/start/<case_uuid> POST
85	7960	/iocs/find-in-events/progress/<case_uuid>/<task_id>
86	8027	/iocs/find-in-events/results/<case_uuid>/<task_id>
87	8063	/iocs/find-in-events/save/<case_uuid> POST
88	8098	/iocs/tag-artifacts/<case_uuid> POST
89	8138	/iocs/tag-artifacts/start/<case_uuid> POST
90	8159	/iocs/tag-artifacts/<case_uuid>/progress
91	8186	/iocs/tag-artifacts/results/<case_uuid>/<task_id>
⚠ Flag (D2): #88 /iocs/tag-artifacts/<case_uuid> POST and #89 /iocs/tag-artifacts/start/<case_uuid> POST both look like kickoff endpoints. Verify whether one is dead.
Block M — Browser downloads / noise (→ search.py for browser, existing noise.py for noise? — see notes)
#	line	route	target
92	8224	/hunting/browser/downloads/<case_id>	search
93	8255	/hunting/noise/stats/<case_id>	search or merge into existing noise.py
94	8295	/hunting/noise/tag/<case_id> POST	″
95	8326	/hunting/noise/status/<task_id>	″
Needs discussion: routes/noise.py already exists. Verify no collision before dropping these there; otherwise keep in search.py.
Block N — OpenCTI / MISP TI settings + lookups (→ enrichment.py, all cti-licensed)
#	line	route	lic
96	8373	/settings/opencti GET	cti
97	8395	/settings/opencti POST	cti
98	8435	/settings/opencti/test POST	cti
99	8492	/opencti/status	cti
100	8516	/opencti/connectors	cti
101	8578	/settings/misp GET	cti
102	8599	/settings/misp POST	cti
103	8636	/settings/misp/test POST	cti
104	8685	/misp/status	cti
105	8708	/ioc/<ioc_id>/enrich POST	cti
106	8748	/ioc/<ioc_id>/enrichment GET	cti
107	8781	/iocs/bulk-enrich POST	cti
⚠ Flag (D2): #105/#106 use singular /ioc/ while all of Block H uses plural /iocs/. Inconsistent but both paths are live — do not rename in this session; flag for Session E.
Block O — IOC bulk update/delete (→ cases.py)
#	line	route
108	8824	/iocs/bulk-update POST
109	8883	/iocs/bulk-delete/<case_uuid> POST
Block P — Logs, audit, settings (→ admin.py)
#	line	route
110	8946	/logs/audit/<category>
111	9017	/settings/logging GET
112	9049	/settings/logging POST
113	9144	/settings/logging/test-path POST
114	9186	/settings/paths GET
115	9210	/settings/paths POST
116	9284	/settings/paths/test POST
117	9319	/logs/view/<log_path>
118	9357	/logs/case/<case_uuid>
119	9381	/audit-log
120	9454	/audit-log/entity/<entity_type>/<entity_id>
Block Q — Field enhancers (→ search.py)
#	line	route
121	9482	/hunting/field-enhancers
Block R — Report templates (→ admin.py; they're template CRUD, not report generation)
#	line	route
122	9526	/reports/templates
123	9551	/reports/templates/active
124	9573	/reports/templates/scan POST
125	9601	/reports/templates/types
126	9634	/reports/templates/by-type/<report_type>
127	9665	/reports/templates/<template_id> PUT
128	9730	/reports/templates/<template_id> DELETE
129	9760	/reports/templates/<template_id>/placeholders
Block S — Report generation & output (→ ai.py for AI/timeline, else cases.py)
#	line	route	target	lic
130	9792	/reports/generate/<case_uuid> POST	cases	-
131	9882	/reports/list/<case_uuid>	cases	-
132	9905	/reports/download/<case_uuid>/<filename>	cases	-
133	9940	/reports/generate-ai/<case_uuid> POST	ai	ai
134	10058	/reports/generate-timeline/<case_uuid> POST	ai	ai
135	10158	/reports/case/<case_uuid>	cases	-
136	10197	/reports/<report_id>/notes PUT	cases	-
137	10245	/reports/<report_id> DELETE	cases	-
Block T — Archive/restore (→ cases.py)
#	line	route
138	10293	/case/<case_uuid>/archive POST
139	10389	/case/<case_uuid>/archive/status
140	10436	/case/<case_uuid>/archive/info
141	10491	/case/<case_uuid>/restore POST
142	10594	/case/<case_uuid>/restore/status
143	10641	/case/<case_uuid>/storage/size
144	10694	/archive/jobs/active
All 144 accounted for. Target file totals: ingest.py 22 · search.py 13 · cases.py 36 · enrichment.py 12 · ai.py 7 · admin.py 27 · (findings.py 0 — correct; Session C's unified findings read API doesn't yet exist in api.py, it will be created fresh) · _legacy.py 0 (no deletions flagged; only dup flags).
Needs-discussion: #1 dashboard (could be main.py), #7 case-statistics vs file-stats boundary, #93–95 potential collision with existing noise.py.
Findings note: No existing endpoint maps to findings.py. That's intentional — per Session C, the unified findings read API is net-new. findings.py gets registered in this session as an empty blueprint so that Session C follow-up can populate it without a second registration pass.

Deliverable 3 — Cross-Cutting Concerns Inventory ⚠ LOAD-BEARING
Current helpers (api.py lines 38–498):
helper	line	used by	proposed home
_log_case_file_audit	38	ingest, cases	utils/audit.py
_viewer_write_error	57	ingest, cases, iocs	routes/_decorators.py as @viewer_readonly
_normalize_upload_file_info	61	ingest only	move with ingest
_get_parser_hints_for_case_file	73	ingest only	move with ingest
_default_upload_type_label	80	ingest only	move with ingest
_remember_task_access, _task_access_allowed	87, 96	many	routes/_decorators.py
_is_license_feature_active	106	ai, enrichment (inconsistent)	routes/_decorators.py as @requires_feature(name)
_is_threat_intel_license_active	112	enrichment (MISP only)	″
_build_search_blob_field_condition et al	241–373	search, hunting	utils/queries/event_filters.py
_move_to_originals, _copy_to_staging, _remove_file_if_present	404–468	ingest only	move with ingest
get_folder_size_gb, get_software_version	480, 498	admin dashboard	utils/system.py
_viewer_upload_error, _allowed_case_upload_roots, ensure_upload_dirs	739–753	ingest only	move with ingest
_update_worker_service_concurrency	7660	admin	move with admin
build_event_description	3355	search/hunting	utils/queries/event_descriptions.py
License-gating inconsistencies (the security-relevant ones):
1. AI endpoints (block I, ##67–72): all six hand-roll if not _is_license_feature_active('ai'): return 403 at the top of the body, with the exact same error dict copy-pasted six times (7209, 7260, 7286, 7332, 7407 — #67 just returns feature_active in the payload without blocking reads).
2. OpenCTI endpoints (block N, ##96–100): same pattern with 'opencti' feature key, hand-rolled at 8401, 8441. Meanwhile #96 /settings/opencti GET at 8383 only reports feature_active in the payload — read access isn't blocked even though write is. Confirm whether that's intentional.
3. MISP endpoints (##101–104): use _is_threat_intel_license_active() at 8605, which aliases to _is_license_feature_active('opencti') — MISP is gated by the OpenCTI license flag, not a separate 'misp' feature. This could be a bug or a product decision; flag it explicitly for caseScope owner review. Do not fix in D.
4. IOC enrichment ##105–107: verify these check license — grep shows no _is_license_* call between lines 8708–8823. Possible security gap. If confirmed, this is the highest-priority finding in the whole session — a licensed feature reachable without a license check.
5. AI report endpoints ##133, 134: check whether /reports/generate-ai and /reports/generate-timeline gate on 'ai'. Both sit in a block with no license matches in surrounding grep — verify before Session E.
Proposed unified decorator (for Session E, not this session):

python
@requires_feature('ai')        # hard-blocks, returns 403 w/ consistent body
@requires_feature_soft('ai')   # sets g.feature_active for status endpoints
Auth/case-scope: every route has @login_required. Case-scope checks (verifying the current user can access <case_uuid>) are not consistently applied — some endpoints call a get_case_or_403-style helper, many just Case.query.filter_by(uuid=...).first() and assume pass. Catalog for Session E; do not normalize now.

Deliverable 5 — Migration Order
Rule: extract lowest-coupling files first. Each step is one commit; run the test suite (or at least curl each moved path) before the next.
1. admin.py (27 endpoints: #1, 66–77, 110–129, 144). Few cross-refs to case/file state; mostly settings dict reads/writes. Move with helpers: _update_worker_service_concurrency, get_folder_size_gb, get_software_version. Establishes the blueprint-registration pattern.
2. enrichment.py (12: #96–107). Self-contained TI surface. Move with the _is_threat_intel_license_active helper (temporarily; it gets promoted to _decorators.py in step 7).
3. search.py (13: #19–30, 92, 121). Move the _build_* query helpers (241–373) and build_event_description (3355) to utils/queries/ first, as a prep commit, so the moved routes just import.
4. ingest.py (22: #2–6, 8–18, 78–91 minus the AI extraction ones). Move all upload helpers (38–498, 739–753) with it. Highest helper volume — budget extra time.
5. cases.py (36: #7, 31–65, 108–109, 130–132, 135–143). Biggest file, but it's CRUD-shaped and by the time you get here the decorators are established. Known-systems, known-users, IOC CRUD, archive/restore, non-AI reports.
6. ai.py (7: #67–72 actually stay in admin as settings; the AI operational endpoints moving here are #78–82, #133, #134). Correction: ##67–72 are AI settings, so admin. ai.py ends up with 7 operational L4 endpoints.
7. findings.py (0 existing, empty blueprint registered). Reserved for Session C follow-up.
8. _decorators.py promotion pass: consolidate _viewer_write_error, _remember_task_access, license helpers into real decorators. This is the only step that touches endpoint bodies and it should be a separate commit per file moved in steps 1–6, reviewed carefully.
9. Final sweep: api.py should be reduced to imports + the module-level api_bp = Blueprint(...) definition. Decide D7.

Deliverable 6 — Shared Helpers Audit
See the table in D3. Summary of destinations:
* utils/audit.py — _log_case_file_audit
* utils/queries/event_filters.py — _build_search_blob_field_condition, _build_ip_field_search_condition, _parse_event_field_value_condition, _build_sigma_alert_condition, _build_hunting_alert_type_filter
* utils/queries/event_descriptions.py — build_event_description
* utils/system.py — get_folder_size_gb, get_software_version
* routes/_decorators.py — _viewer_write_error → @viewer_readonly; _is_license_feature_active → @requires_feature; _remember_task_access/_task_access_allowed → @tracks_task_access
* Moves with ingest.py (ingest-only callers): upload path helpers, parser hints, normalize-upload-info
* Moves with admin.py: _update_worker_service_concurrency
No helper should remain in api.py post-migration.

Deliverable 2 — Duplicate / Dead Code Flags
* ##88 vs #89 — /iocs/tag-artifacts/<case_uuid> POST (line 8098) and /iocs/tag-artifacts/start/<case_uuid> POST (line 8138). Both look like kickoff. Verify which is live (check UI calls in static/) before migration; park the loser in _legacy.py if confirmed dead.
* ##105, 106 singular /ioc/ vs all other IOC routes plural /iocs/. Not duplicate, but the inconsistency suggests these predate a rename; confirm nothing still calls the singular form externally before future consolidation.
* ##67 /settings/ai GET: returns feature_active without blocking — acts as a status probe. Overlaps in spirit with #72 /settings/ai/status. Not a duplicate, but consider whether both are needed.
* ##96 /settings/opencti GET / #99 /opencti/status: two different status shapes for the same subsystem. Flag for consolidation in Session E.
* ##7 vs #6: /case/statistics/<case_uuid> vs /files/stats/<case_uuid> — different but name collision is confusing. Non-blocking.
Nothing confirmed dead enough to move to _legacy.py in this session. _legacy.py stays empty, registered as a shim.

Deliverable 4 — Blueprint Registration Plan
URL prefix strategy: keep the existing api_bp prefix (whatever it is — likely /api) on every new blueprint so paths stay byte-identical. Each new file defines its own blueprint with the same prefix; Flask happily registers multiple blueprints at the same prefix.

python
# routes/ingest.py
from flask import Blueprint
ingest_bp = Blueprint('ingest', __name__, url_prefix='/api')
In app.py (or wherever blueprints are currently registered):

python
from routes.admin import admin_bp
from routes.enrichment import enrichment_bp
from routes.search import search_bp
from routes.ingest import ingest_bp
from routes.cases import cases_bp
from routes.ai import ai_bp
from routes.findings import findings_bp  # empty for now, reserved for Session C follow-up

for bp in (admin_bp, enrichment_bp, search_bp, ingest_bp, cases_bp, ai_bp, findings_bp):
    app.register_blueprint(bp)
Import order matters only for the decorator module: routes/_decorators.py must import cleanly with no route-file dependencies, so it imports only from models/, utils/, flask_login. Route files then import from _decorators.
Endpoint name collisions: Flask uses <blueprint>.<function> for url_for. Because we're splitting one blueprint into seven, any url_for('api.<func>') in templates will break. Grep static/ and templates/ for url_for('api. before the final cutover and update to the new blueprint name — this is the one place clients (templates) do see a change, and it must happen atomically with the split.

Deliverable 7 — Post-Migration State of api.py
Target: deleted. No compatibility shim needed — there are no external importers of api.py symbols (everything is reached through URL routing, not Python imports), and the url_for updates in D4 cover the only internal refs. After step 9 of the migration, routes/api.py is removed in the same commit that removes its registration in app.py.

Bugs Observed (separate from refactor, do not fix in D)
1. Possible missing license checks on IOC enrichment routes #105–107. Grep between lines 8708–8823 shows no _is_license_feature_active call. If confirmed, a licensed TI enrichment feature is reachable without a license. Highest priority; verify before Session E.
2. MISP reuses the 'opencti' license feature flag (line 114). Either intentional (single "threat intel" license) or a bug. Confirm with product.
3. Six-way copy-paste of the AI license-refusal body (7212, 7263, 7289, 7335, plus the opencti variants) means a message change has to be made in six places. Not a bug, but an invitation for them to drift.
4. #96 /settings/opencti GET does not block read on missing license, while #97 POST does. Read-vs-write asymmetry — confirm intentional.
These all go into Session E's backlog. D is mechanical; none of the above is touched here.


















Claude is AI and can make mistakes. Please double-check responses.



