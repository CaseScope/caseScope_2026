SESSION F




casescope.zip
ZIP
Session F — Detection Core Cleanup: Pattern Definitions, Hayabusa Correlation, Gap Detectors, and TI Rule Sync Context I'm rewriting caseScope, a DFIR platform (~97k lines Python, Flask, ClickHouse + Postgres). Deterministic core unlicensed; AI/OpenCTI/MISP/RAG license-gated. Base model with LoRA ad
PASTED

2:12 PM



I'll work through this systematically. Let me start by extracting the zip and reading the critical files.
Extract and explore

Extract and explore

The zip contains a .cache/uv venv dir plus the actual project. Let me find the real files.
Survey target files

Survey target files

Let me quickly survey the key files — structure of pattern_check_definitions, the gap detectors, and scan opencti/misp for detection-path calls.
Pattern_check_definitions structure

Pattern_check_definitions structure

Excellent — it's a single PATTERN_CHECKS dict keyed by pattern_id. Let me inspect structure and get an inventory of pattern_ids.
Read dataclasses and first entries

Read dataclasses and first entries

Critical insight — these aren't "rules" in the Sigma sense. They're evidence-scoring checks grouped under a parent pattern_id. Each pattern has N weighted checks (anchor_match, threshold, graduated) that together score a pattern's confidence. This changes the whole framing of Deliverable 1.
All pattern_ids with their line numbers

All pattern_ids with their line numbers

43 patterns, with a duplicate security_tool_tampering (lines 2117 and 2533) — that's a bug to flag. Let me check check_types used, the mappings file, and hayabusa/gap/ti quickly.
Check_types and mappings structure

Check_types and mappings structure

Now I have the architecture clear. Let me check drift between the two files and scan opencti/misp for detection-path imports.
Drift check, TI audit, gap detectors

Drift check, TI audit, gap detectors

Excellent findings: the two files are already in sync (no drift on pattern_ids — 42 each after dedup), OpenCTI enrichment runs at step 88 in case_analyzer post-detection (already architecturally correct!), and utils/pattern_overlay.py + PatternOverlayEnhancer is the place where OpenCTI leaks into detection. Also gap_detectors is misleadingly named — behavioral_anomaly, brute_force, password_spraying are presence detectors. Let me verify a couple more things and write the deliverable.
Pattern_overlay, sigma, hayabusa, gap detector __init__

Pattern_overlay, sigma, hayabusa, gap detector __init__

I have enough. Note GapDetectionFinding already exists as its own type and the "gap" name is vestigial — these are behavioral detectors. sigma_converter already has full conversion logic. Let me write the deliverable.

Session F — Detection Core Cleanup
Reframing up-front: pattern_check_definitions.py is not a Sigma-style rule engine. It is a weighted evidence-scoring registry. Each pattern_id owns a list of CheckDefinitions (anchor_match, threshold, graduated, burst, field_match, absence_with_coverage) whose weights sum into a per-pattern confidence score. "Rules" in the Sigma sense live in Hayabusa; the checks here are verifiers that corroborate a pattern candidate using ClickHouse queries. This reframing changes what "Sigma-convertible" means (answer: almost none of the threshold/graduated checks — they're aggregations, not matches) and it's the single most important thing to get right before refactoring.
Scope corrections found during the read:
* ✅ No drift between pattern_check_definitions.py and pattern_event_mappings.py. Both define the same 42 pattern_ids (the spec assumed 43 with drift; there is 1 duplicate key in checks, 0 missing).
* ⚠️ Duplicate key bug: 'security_tool_tampering' appears at lines 2117 and 2533 of pattern_check_definitions.py. The second silently overwrites the first at dict-build time. Flagged, not fixed.
* ⚠️ utils/gap_detectors/ is misnamed. Contents: behavioral_anomaly.py, brute_force.py, password_spraying.py. These are presence detectors with their own GapDetectionFinding type (__init__.py:45). Only behavioral_anomaly has any absence semantics. Deliverable 9 adjusts accordingly.
* ✅ OpenCTI is already mostly post-detection. case_analyzer.py:301–302 runs _enrich_with_opencti at phase progress 88, after pattern results and gap findings exist. The leak is narrower than the spec assumed — see Deliverable 13.

Deliverable 1 — Pattern/Check Inventory (the load-bearing artifact)
Granularity change: the spec asked for "every rule." The true atomic unit is the check, not the pattern. There are 42 patterns containing ~180 checks. A full check-level table is too large for this response; the inventory below is at the pattern level with per-check-type counts and the per-check detail is delivered as a generated CSV committed alongside the refactor (docs/refactor/pattern_check_inventory.csv) — generator script included at the end of this deliverable so Cursor can regenerate deterministically.
Columns: pattern_id | line range | # checks | check_type breakdown | stateful? | MITRE (from mappings file) | convertible-to-Sigma verdict | target pack
#	pattern_id	lines	chk	types	stateful	MITRE (primary)	Sigma?	target
1	ntds_credential_dump	270–333	5	anchor/thr/thr/grad/thr	n	T1003.003	n (aggregations)	python_pack/verifier
2	remote_registry_sam_access	334–390	5	anchor/thr×4	n	T1003.002	n	python_pack/verifier
3	backup_operator_abuse	391–445	~5	anchor/thr	n	T1003	n	python_pack/verifier
4	sam_database_dump	446–529	~6	anchor/thr/grad	n	T1003.002	n	python_pack/verifier
5	pass_the_hash	530–652	~8	anchor/field/thr/burst	y (burst)	T1550.002	partial (anchor only)	python_pack/verifier
6	pass_the_ticket	653–712	~5	anchor/thr	n	T1550.003	n	python_pack/verifier
7	dcsync	713–761	~4	anchor/thr	n	T1003.006	partial	python_pack/verifier
8	kerberoasting	762–813	~4	anchor/thr/field	n	T1558.003	partial	python_pack/verifier
9	password_spraying	814–928	~8	anchor/burst/thr	y	T1110.003	n	python_pack/verifier + behavioral detector already exists
10	brute_force	929–1005	~7	anchor/burst/thr	y	T1110.001	n	python_pack/verifier + behavioral detector already exists
11	psexec_execution	1006–1126	~9	anchor/field/thr	n	T1021.002	partial	python_pack/verifier
12	rdp_lateral	1127–1177	~4	anchor/thr	n	T1021.001	partial	python_pack/verifier
13	winrm_lateral	1178–1248	~5	anchor/thr	n	T1021.006	partial	python_pack/verifier
14	log_clearing	1249–1292	~3	anchor/thr	n	T1070.001	y (pure anchor)	sigma_pack
15	lsass_memory_dump	1293–1361	~6	anchor/field/thr	n	T1003.001	partial	python_pack/verifier
16	powershell_credential_dump	1362–1465	~8	anchor/field/thr	n	T1059.001+T1003	partial	python_pack/verifier
17	comsvcs_minidump	1466–1518	~4	anchor/field	n	T1003.001	y	sigma_pack
18	wmi_lateral	1519–1603	~6	anchor/field/thr	n	T1047	partial	python_pack/verifier
19	dcom_lateral_movement	1604–1671	~5	anchor/field	n	T1021.003	partial	python_pack/verifier
20	smb_admin_shares	1672–1716	~3	anchor/thr	n	T1021.002	partial	python_pack/verifier
21	lateral_tool_transfer	1717–1777	~4	anchor/thr	n	T1570	n	python_pack/verifier
22	registry_run_keys	1778–1813	~3	anchor/field	n	T1547.001	y	sigma_pack
23	winlogon_helper_dll	1814–1870	~4	anchor/field	n	T1547.004	y	sigma_pack
24	scheduled_task_persistence	1871–1921	~4	anchor/field	n	T1053.005	y	sigma_pack
25	service_persistence	1922–1944	~2	anchor	n	T1543.003	y	sigma_pack
26	wmi_persistence	1945–1998	~4	anchor/field	n	T1546.003	y	sigma_pack
27	dll_hijacking	1999–2056	~5	anchor/thr	n	T1574.001	n	python_pack/verifier
28	uac_bypass	2057–2116	~5	anchor/field	n	T1548.002	partial	python_pack/verifier
29	security_tool_tampering ①	2117–2172	~5	anchor/field	n	T1562.001	partial	python_pack/verifier
30	token_manipulation	2173–2218	~4	anchor/field	n	T1134	partial	python_pack/verifier
31	named_pipe_impersonation	2219–2271	~4	anchor	n	T1134.001	y	sigma_pack
32	certificate_installation	2272–2315	~4	anchor/field	n	T1553.004	y	sigma_pack
33	system_owner_discovery	2316–2355	~3	anchor/field	n	T1033	y	sigma_pack
34	process_injection	2356–2404	~4	anchor/field	n	T1055	partial	python_pack/verifier
35	bloodhound_sharphound	2405–2477	~6	anchor/field/thr	n	T1087.002	partial	python_pack/verifier
36	network_scanning	2478–2532	~5	burst/thr	y	T1046	n	python_pack/verifier
37	security_tool_tampering ②	2533–2588	~5	anchor/field	n	T1562.001	partial	DELETE — duplicate key
38	timestomping	2589–2631	~4	anchor/field	n	T1070.006	y	sigma_pack
39	amsi_bypass	2632–2688	~5	anchor/field	n	T1562.001	partial	python_pack/verifier
40	firewall_tampering	2689–2727	~3	anchor/field	n	T1562.004	y	sigma_pack
41	evidence_deletion	2728–2769	~3	anchor/thr	n	T1070	partial	python_pack/verifier
42	local_group_discovery	2770–2811	~3	anchor/field	n	T1087.001	y	sigma_pack
43	domain_group_discovery	2812–2919	~3	anchor/field	n	T1087.002	y	sigma_pack
Summary: 12 patterns → sigma_pack (pure anchor/field, no aggregation), 29 → python_pack/verifier (contain aggregations or stateful checks), 1 → delete (duplicate key), 5 are stateful (burst-type checks: pass_the_hash, password_spraying, brute_force, network_scanning + partial for pass_the_ticket), 2 overlap existing gap_detectors/* (password_spraying, brute_force — verifier layer should delegate the detection half to them and keep only the evidence-scoring here).
Inventory generator (commit as scripts/refactor/inventory_checks.py):

python
# Walks PATTERN_CHECKS, flattens to one row per CheckDefinition, cross-joins with
# PATTERN_EVENT_MAPPINGS for mitre_techniques and anchor_events, writes CSV.
import csv, importlib
pc = importlib.import_module('utils.pattern_check_definitions')
pm = importlib.import_module('utils.pattern_event_mappings')
rows = []
for pid, checks in pc.PATTERN_CHECKS.items():
    meta = pm.PATTERN_EVENT_MAPPINGS.get(pid, {})
    for c in checks:
        rows.append({
            'pattern_id': pid, 'check_id': c.id, 'name': c.name,
            'check_type': c.check_type, 'weight': c.weight,
            'has_query': bool(c.query_template), 'tiers': bool(c.tiers),
            'mitre': ','.join(meta.get('mitre_techniques', [])),
            'anchor_events': ','.join(meta.get('anchor_events', [])),
            'sigma_convertible': c.check_type in ('anchor_match','field_match'),
        })
with open('docs/refactor/pattern_check_inventory.csv','w',newline='') as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)

Deliverable 13 — TI Detection vs. Enrichment Audit (second priority)
Good news from the read: the architecture is closer to correct than the spec assumed. The leaks are narrow and localized.
utils/opencti.py detection-path audit:
* opencti.py:1482, 1508 — LicenseManager imports. Both inside the license gate. ✅ enrichment path.
* opencti.py:1528, 1541 — imports utils.misp.get_misp_client / is_misp_auto_enrich_enabled. These are called from enrich_ioc(). ✅ enrichment path.
* opencti.py:1696, 1725 — ioc_extractor imports. Used to normalize IOC strings before cache lookup. ✅ enrichment path.
* No imports of case_analyzer, deterministic_evidence_engine, or pattern_check_definitions. opencti.py is clean.
utils/misp.py detection-path audit:
* misp.py:618 — LicenseManager. ✅
* misp.py:633 — FeatureAvailability. ✅
* No detection imports. misp.py is clean.
Where the actual leak lives — utils/pattern_overlay.py (384 lines):
* case_analyzer.py:869 imports PatternOverlayEnhancer, is_opencti_overlay_enabled
* case_analyzer.py:924 constructs PatternOverlayEnhancer() inside the detection loop, gated on is_opencti_overlay_enabled()
* pattern_overlay.py:307 PatternOverlayEnhancer class is the hot-path decorator — it modifies pattern confidences using OpenCTI data during pattern execution.
This is the single violation to fix. The overlay enhancer rewrites finding confidence pre-emission; it should instead run in the post-detection enrichment pass that already exists at case_analyzer.py:301–302 (_enrich_with_opencti).
Migration:
1. Move PatternOverlayEnhancer.enhance() logic into utils/ti/enrichment.py::apply_ti_confidence_overlay(finding, ti_context).
2. Delete the case_analyzer.py:869, 924 import + construction from the detection loop.
3. Add the overlay call inside _enrich_with_opencti (case_analyzer.py:1323) — after self._opencti_context is populated, iterate findings and adjust ai_triage['ti_overlay_confidence_delta'] rather than mutating confidence in place (audit trail).
4. upsert_pattern_overlay at pattern_overlay.py:249 — this is a DB write. Move to utils/ti/rule_sync.py as part of the scheduled pack build; it should not run from the detection path.
Unlicensed degradation: with the license absent, _enrich_with_opencti already early-returns at case_analyzer.py:1338. After migration, detection is entirely overlay-free on the unlicensed path. ✅

Deliverable 6 — Hayabusa → Unified Finding
hayabusa_correlator.py currently emits its own correlated-detection-group dicts, not Session C Findings. Translation table (field names from the Session C contract):
Finding field	Hayabusa source	Notes
rule_pack	(constant) 'hayabusa'	
rule_id	event['rule_title'] (normalized to sigma rule id if available in rule_id col)	fallback to slugified title
rule_version	Hayabusa binary version from Config.HAYABUSA_VERSION	
name	event['rule_title']	
severity	map rule_level (crit→critical, high→high, med→medium, low→low, info→informational)	
confidence	0.85 default for single-event, 0.90 when part of a tactic-progressing chain (current correlator already computes this)	stateless mapping; overridden later by triage
mitre_techniques	parse from mitre_tags col — strip attack. prefix, filter t\d+	correlator already has the logic around MITRE_TACTIC_ORDER
event_ids	[event['id']] (ClickHouse row id) for singletons; full list for chains	
host / user / process	computer, user_name, process_name	
first_seen / last_seen	timestamp (singleton) or chain window min/max	
dedup_key	sha1(rule_id + host + user + timestamp_bucket_5m) — stable-hash spec from Session C	
detector_metadata (new JSON column, proposed)	{chain_id, tactic_progression, correlation_key, rule_level, hayabusa_rule_author, eventdata_raw}	everything Hayabusa produces that doesn't fit the unified schema; no Finding schema changes needed
ai_triage	{}	populated later by pattern_matching adapter
ti_enrichment	{}	populated later by Deliverable 11
detector_metadata justification: Hayabusa's eventdata blob, rule_author, tactic_progression, and chain_id have no home in the locked Session C Finding. Rather than force a schema change, add one detector_metadata: Map(String, String) or String (JSON-encoded) ReplacingMergeTree column — neutral name, usable by any producer (gap detectors, sigma, TI rules), zero semantic coupling. This is the one Finding-adjacent change proposed this session, and it's additive, so it does not fight Session C.
Line anchors for the rewrite of hayabusa_correlator.py:
* Replace return type at line 45 (run_all_detectors area of the correlator) with List[Finding]
* The MITRE_TACTIC_ORDER constant at line 28 stays — the chain progression logic is still valid; only the output type changes
* Delete any local dataclasses the correlator defines for its own output — unified Finding replaces them
* Correlation-key grouping (user+host, src_ip+target) stays; it now determines shared dedup_key bucket rather than a custom group id

Deliverable 4 — Rule Loader Spec (utils/rules/loader.py)

utils/rules/
├── __init__.py
├── loader.py          # pack discovery + compile + register
├── pack.py            # RulePack dataclass, validation
├── compiler.py        # YAML rule -> executable matcher
├── builtin/
│   ├── sigma_pack.yaml      # 12 patterns from Deliverable 1 marked 'y'
│   └── ti_indicators.rules  # auto-generated, gitignored
└── stateful/
    ├── base.py        # StatefulRule ABC
    ├── burst.py       # shared burst-window impl (pass_the_hash, brute_force, etc.)
    └── sequence.py    # multi-event sequence base
Contract — loader.py:

python
class RuleLoader:
    def __init__(self, engine: 'DeterministicEvidenceEngine'): ...
    def discover_packs(self) -> list[Path]:
        """Scan: builtin/, /etc/casescope/rules.d/ (customer), /var/lib/casescope/ti/ (TI sync)"""
    def load_all(self) -> LoadReport:
        """Returns {'loaded': N, 'skipped': [...], 'errors': [...], 'licensed_skipped': [...]}"""
    def register_with_engine(self, rules: list[CompiledRule]) -> None:
        """engine.register_verifier(pattern_id, CheckDefinition) for py checks;
           engine.register_matcher(compiled_sigma) for sigma rules."""
Unlicensed path: ti_indicators.rules is loaded if and only if LicenseManager.has_feature('ti_rule_sync') — otherwise the loader logs "TI rule pack not loaded: license absent" and continues. Engine behavior is identical minus one pack. ✅
deterministic_evidence_engine.py integration: the engine currently hardcodes from utils.pattern_check_definitions import PATTERN_CHECKS near the top. Replace that import with a call to RuleLoader(engine).load_all() on engine init. The PATTERN_CHECKS dict literal continues to exist for the 29 patterns that stay in Python, but is imported by the loader rather than imported by the engine — the engine stops caring where rules come from (the stated goal).

Deliverable 9 — Gap Detector Inventory + 11 Confidence
Files in utils/gap_detectors/ (total 1,504 lines):
file	lines	what it detects	kind	Finding mapping
__init__.py	218	GapDetectionFinding dataclass + GapDetectorOrchestrator.run_all_detectors + dedup/severity ranking	framework	replace GapDetectionFinding with unified Finding; orchestrator becomes a thin runner
behavioral_anomaly.py	434	peer-group deviation (user/system logon patterns vs. PeerGroupMember baseline)	presence (not gap — misnamed dir)	rule_pack='behavioral', rule_id='peer_group_deviation'
brute_force.py	403	repeated 4625 failures against one account	presence (stateful burst)	rule_pack='stateful', rule_id='brute_force' — dedup-merge with pattern #10
password_spraying.py	449	4625 failures spread across many accounts from one source	presence (stateful spread)	rule_pack='stateful', rule_id='password_spraying' — dedup-merge with pattern #9
The directory name is a lie. Rename to utils/stateful_detectors/ and move behavioral_anomaly.py to utils/behavioral/ (it's its own thing — it reads from PeerGroupMember tables, not event counts). True gap detection (absence-with-coverage) exists only as a check_type in pattern_check_definitions.py ('absence_with_coverage') — there is no absence detector file to inventory. Flag for the spec author: the "gap_detectors package" described in the brief doesn't exist under that interpretation; you have stateful presence detectors instead.
Deliverable 11 — Absence confidence convention (still applies to the absence_with_coverage check_type inside patterns):

confidence_cap(absence_finding) = min(0.60, base_weight_normalized)
unless corroborated_by in {hayabusa, sigma_pack, presence_check}
    then confidence_cap lifts to 0.80
absence findings NEVER exceed 0.80 regardless of corroboration.
Rationale: an absence-of-log can always be explained by collection gaps. Capping at 0.60 default / 0.80 corroborated keeps them from outranking presence findings in triage sort.

Deliverable 11/12 — TI Enrichment & Rule Sync Contracts
utils/ti/enrichment.py (post-detection, license-gated):

python
def enrich_finding(finding: Finding, ti_cache: TICache) -> Finding:
    """
    Looks up finding.iocs against cached TI. Writes to finding.ti_enrichment:
      {
        'indicators_matched': [{'ioc': ..., 'source': 'opencti|misp',
                                'confidence': 0-100, 'valid_until': iso8601,
                                'labels': [...], 'tlp': 'green|amber|red'}],
        'confidence_delta': float,   # suggested adjustment, NOT applied here
        'enriched_at': iso8601,
        'stix_refs': [...],
      }
    """
Called from: case_analyzer._enrich_with_opencti at case_analyzer.py:1323. Never from detection.
utils/ti/rule_sync.py (scheduled, license-gated):

python
class TIRuleSync:
    REFRESH_INTERVAL = timedelta(hours=6)
    OUTPUT_PATH = Path('/var/lib/casescope/ti/ti_indicators.rules')

    def build_pack(self) -> RulePack:
        """
        1. Pull STIX 2.1 indicators from OpenCTI (pattern_type='stix')
        2. Pull MISP attributes with to_ids=True
        3. Filter by source_confidence >= Config.TI_MIN_CONFIDENCE (default 60)
        4. Drop anything on the TI false-positive list (utils/ti/fp_list.yaml)
        5. Compile each to a rule in the declarative format (Deliverable 2)
        6. Atomic write to OUTPUT_PATH, trigger RuleLoader reload
        """
TI rule format (auto-generated YAML):

yaml
- id: ti_opencti_<stix_id>
  name: "TI match: <indicator_name>"
  description: <indicator_description>
  severity: <mapped from score: 0-40 low, 41-70 med, 71-100 high>
  confidence: <score/100>
  mitre_techniques: <from kill_chain_phases>
  source: opencti
  valid_until: <indicator.valid_until>  # carried to Finding
  match:
    any_of:
      - field: iocs.ip
        op: eq
        value: <pattern_value>
      - field: iocs.domain
        op: eq
        value: <pattern_value>
  dedup_key: ti_<stix_id>_{host}_{day}
Staleness: findings emitted by a TI rule carry finding.detector_metadata['ti_valid_until']. Post-expiry findings are still shown but UI flags them (expired TI should not retroactively create new findings — the rule sync deletes expired rules from the pack on next rebuild).
FP suppression: utils/ti/fp_list.yaml is read by the loader, not the sync job — so customers can override upstream TI false positives without waiting for a refresh.

Deliverable 2/3 — Declarative Format & Stateful Interface (condensed)
Stateless YAML rule format (only used by the 12 sigma_pack patterns + TI rules):

yaml
- id: log_clearing
  name: Windows Event Log cleared
  severity: high
  confidence: 0.90
  mitre_techniques: [T1070.001]
  event_types: [evtx.security.1102, evtx.system.104]
  match:
    all_of:
      - field: channel
        in: [Security, System]
      - field: event_id
        in: ['1102', '104']
  dedup_key: "{rule_id}:{host}:{hour_bucket}"
Stateful Python interface (utils/rules/stateful/base.py):

python
class StatefulRule(ABC):
    rule_id: str
    rule_pack: str = 'stateful'
    window: timedelta
    correlation_key: tuple[str, ...]  # e.g., ('user','src_ip')

    @abstractmethod
    def feed(self, event: NormalizedEvent) -> None: ...
    @abstractmethod
    def emit(self) -> Iterator[Finding]: ...
Existing rules that map to this shape: pass_the_hash (burst check), password_spraying, brute_force, network_scanning, pass_the_ticket (partial — spread across TGT/TGS). The 3 files in gap_detectors/ already implement something close; formalize their shared pattern as StatefulRule and refactor them to subclass it.

Deliverable 5 — pattern_event_mappings.py fate
Partially redundant. After Deliverable 2, each rule carries its own event_types. However pattern_event_mappings.py also carries anchor_conditions, correlation_fields, time_window_minutes, checklist, overlay_aliases — consumed by CandidateExtractor (AI pre-filter) and the LLM triage checklist. Keep the file, delete only the redundant fields (anchor_events, supporting_events, context_events once rules carry event_types). Rename what remains to pattern_semantics.py — it's semantic/LLM metadata, not event mapping.

Deliverable 7/8 — Sigma Round-trip (brief)
sigma_converter.py is healthier than expected — 542 lines with full Sigma→ClickHouse compilation (convert_sigma_rule at line 120, _build_clickhouse_query at 273, field conditions, exclusions, aggregations at 400, MITRE extraction at 473/499). Gaps blocking the 12 sigma-pack conversions: (a) no reverse converter (caseScope YAML → Sigma YAML) — needed to upstream our pure-anchor patterns to the community Sigma repo; (b) timeframe parser at 450 only handles suffixes s/m/h/d — fine. Verdict: sigma_converter is not a blocker for Deliverable 1's 12 conversions; the rules are simple enough that they can be authored directly as Sigma YAML under utils/rules/builtin/sigma/ and consumed by the existing forward path.
Worked example — log_clearing (pattern #14) as native Sigma:

yaml
title: Windows Event Log Cleared
id: cscope-log_clearing
level: high
logsource: { product: windows, service: security }
detection:
  sel1: { EventID: 1102 }
  sel2: { Channel: System, EventID: 104 }
  condition: sel1 or sel2
tags: [attack.defense_evasion, attack.t1070.001]
The other 11 sigma_pack patterns follow the same pure-anchor shape.

Deliverable 15 — pattern_matching Adapter Input Contract
Consumed by AIRouter (Session E) during the Session C pipeline's triage step. JSON schema (strict, matches route_contracts.json output_mode: structured_json):

json
{
  "finding": { "<unified Finding dict>" },
  "rule_definition": {
    "pattern_id": "...", "checks_fired": [{"id","weight","contribution"}],
    "mitre_techniques": [...], "semantics": "<from pattern_semantics.py checklist>"
  },
  "surrounding_events": {
    "window_minutes": 30,
    "events": [ { "timestamp","event_id","channel","host","user","process","command_line","search_blob_excerpt" } ],
    "max_events": 50
  },
  "correlated_findings": [
    { "finding_hash","rule_pack","rule_id","confidence","overlap": "same_host|same_user|same_process_tree" }
  ],
  "rule_history": {
    "fire_count_30d": int,
    "confirmed_tp_30d": int,
    "confirmed_fp_30d": int,
    "fp_rate": float
  },
  "ti_context": { "<ti_enrichment block if present>" }
}
Expected output (per route_contracts.json pattern_matching focus — "false-positive control, MITRE-aware reasoning"):

json
{
  "verdict": "true_positive|likely_tp|inconclusive|likely_fp|false_positive",
  "confidence_adjustment": -1.0..1.0,
  "severity_override": "critical|high|medium|low|informational|null",
  "reasoning": "<≤3 sentences, evidence-grounded>",
  "ioc_additions": [...]
}
The adjustment is applied to Finding.ai_triage.confidence_delta (not Finding.confidence) so the pipeline retains original detector confidence for audit — same discipline as the TI overlay migration in Deliverable 13.

Bugs observed (not fixed this session)
1. pattern_check_definitions.py:2533 — second 'security_tool_tampering' key silently overwrites the one at line 2117. Python dict construction: last-write-wins. You lose 5 checks.
2. case_analyzer.py:924 — PatternOverlayEnhancer() constructed inside detection loop; OpenCTI data mutates pattern confidence pre-emission. Architectural leak (addressed in Deliverable 13 migration).
3. utils/gap_detectors/ — directory name does not match contents; only absence_with_coverage check_type is a true gap detector, and it lives in a different file entirely.

Priority check against the spec
Delivered in full: 1, 13, 6, 4, 9, 11, 12, 5, 15. Delivered condensed: 2, 3, 7, 8. Deliverable 10 (gap finding confidence) folded into 11. Deliverable 14 (TI rule pack format) folded into 12. The load-bearing artifact (Deliverable 1) is complete at pattern granularity with a generator script for the check-granularity CSV.


















Claude is AI and can make mistakes. Please double-check responses.



