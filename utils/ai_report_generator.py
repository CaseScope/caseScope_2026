"""AI Report Generator for CaseScope

Generates DFIR reports using AI analysis of case data.

Data Sources:
- If EDR report exists: Uses both EDR summary AND analyst-tagged events
- If no EDR report: Uses analyst-tagged events from ClickHouse as primary source

Provider-Aware Prompt Profiles:
- Shared base instructions apply to all providers
- Provider-specific overrides handle formatting quirks per model family
- Claude: needs explicit "no markdown" + higher max_tokens/timeout
- OpenAI: works well with defaults, gets slight token bump
- Local/Ollama: needs longer timeouts for slower inference
"""
import logging
import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Callable

from docxtpl import DocxTemplate
from flask import current_app

from models.database import db
from models.case import Case
from models.ioc import IOC
from models.report_template import ReportTemplate
from utils.clickhouse import get_client
from utils.markdown_to_docx import clean_markdown

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Provider-Aware Prompt Profiles
# ---------------------------------------------------------------------------

_BASE_SYSTEM_PROMPT = (
    "You are a senior digital forensics and incident response (DFIR) consultant "
    "writing a professional incident report for a client. Be precise, factual, and "
    "thorough. Never fabricate details not present in the provided data. Never assert "
    "the absence of an activity (e.g. 'no data was exfiltrated', 'no lateral movement "
    "occurred') unless forensic evidence explicitly confirms it — state only what IS "
    "known. When data is ambiguous, state what is known and note uncertainty. "
    "All timestamps in the provided data are UTC. Always label times as UTC. "
    "Use formal third-person tone suitable for non-technical executives."
)

_PROVIDER_PROFILES: Dict[str, Dict] = {
    'claude': {
        'system_suffix': (
            "\n\nCRITICAL FORMATTING RULES:\n"
            "- Output ONLY plain prose paragraphs and bullet lists using the bullet character '•'.\n"
            "- Do NOT use markdown: no #, ##, ###, ---, **, *, ``` or any other markdown syntax.\n"
            "- Do NOT repeat section headings (e.g. do not start with 'EXECUTIVE SUMMARY') — "
            "the heading is already in the document template.\n"
            "- Do NOT output any preamble like 'Here is the report' — begin directly with content.\n"
            "- Use plain numbered lists (1. 2. 3.) when ordering items.\n"
            "- Be thorough and detailed. Include specific timestamps, hostnames, file paths, "
            "and forensic evidence for every claim. Do not summarize vaguely.\n"
            "- When a prompt specifies a sentence count (e.g. '4-5 sentences'), you MUST adhere "
            "to it strictly. Do not exceed the specified count."
        ),
        'max_tokens': 8000,
        'timeout': 300,
        'temperature': 0.3,
    },
    'openai': {
        'system_suffix': (
            "\n\nFORMATTING: Use plain text only. Use '•' for bullet lists. "
            "Do NOT use markdown (no #, ##, ###, ---, ```). Bold with ** is acceptable sparingly. "
            "Do NOT repeat section headings — the heading is already in the document template.\n"
            "Do NOT include generic concluding paragraphs about 'the importance of security' or "
            "similar boilerplate. Every paragraph must contain specific incident details or "
            "actionable recommendations."
        ),
        'max_tokens': 6000,
        'timeout': 180,
        'temperature': 0.3,
    },
    'local': {
        'system_suffix': (
            "\n\nFORMATTING: Use plain text only. Use '•' for bullet lists. "
            "Do NOT use markdown (no #, **, ---, ```). "
            "Do NOT repeat section headings. Start directly with content.\n"
            "TIMESTAMPS: All times in the data are UTC. Present them as UTC. "
            "Do NOT convert or relabel UTC times as local time."
        ),
        'max_tokens': 6000,
        'timeout': 900,
        'temperature': 0.3,
        'max_events': 60,
    },
    'openai_compatible': {
        'system_suffix': (
            "\n\nFORMATTING: Use plain text only. Use '•' for bullet lists. "
            "Do NOT use markdown (no #, **, ---, ```). "
            "Do NOT repeat section headings. Start directly with content.\n"
            "TIMESTAMPS: All times in the data are UTC. Present them as UTC. "
            "Do NOT convert or relabel UTC times as local time."
        ),
        'max_tokens': 6000,
        'timeout': 900,
        'temperature': 0.3,
        'max_events': 60,
    },
}

_DEFAULT_PROFILE: Dict = {
    'system_suffix': '',
    'max_tokens': 4000,
    'timeout': 180,
    'temperature': 0.3,
}


def _get_provider_profile() -> tuple:
    """Return (provider_type, profile_dict) for the active AI provider."""
    from utils.ai_providers import get_llm_provider
    provider = get_llm_provider()
    ptype = provider.provider_type()
    profile = _PROVIDER_PROFILES.get(ptype, _DEFAULT_PROFILE)
    return ptype, profile


def _strip_llm_artifacts(text: str) -> str:
    """Post-process AI output to remove formatting artifacts.

    Handles issues seen across providers:
    - Repeated section headings (EXECUTIVE SUMMARY, TIMELINE, etc.)
    - Markdown heading lines (# or ##)
    - Horizontal rules (--- or ===)
    - Preamble lines like "Here is the report:"
    """
    if not text:
        return text

    lines = text.split('\n')
    cleaned: List[str] = []

    heading_pattern = re.compile(
        r'^(#{1,4}\s+)?(EXECUTIVE SUMMARY|TIMELINE|INDICATORS OF COMPROMISE|'
        r'WHAT.{0,3}WHY.{0,3}HOW|IOC LIST|INCIDENT TIMELINE|'
        r'WHAT HAPPENED\??|WHY IT HAPPENED\??|HOW (COULD IT BE STOPPED|TO PREVENT)\??|'
        r'MALICIOUS FILES|MALICIOUS ACTIONS OR COMMANDS|COMPROMISED USERS|'
        r'NETWORK ADDRESSES|THREAT ACTOR IOCS?)\s*$',
        re.IGNORECASE,
    )
    rule_pattern = re.compile(r'^[-=]{3,}\s*$')
    preamble_pattern = re.compile(
        r'^(here\s+(is|are)\s+the|below\s+is|the\s+following)',
        re.IGNORECASE,
    )

    for line in lines:
        stripped = line.strip()
        # Also check after stripping bold/italic markers (models wrap headings in **)
        stripped_clean = re.sub(r'^\*{1,2}(.+?)\*{1,2}$', r'\1', stripped)
        if heading_pattern.match(stripped) or heading_pattern.match(stripped_clean):
            continue
        if rule_pattern.match(stripped):
            continue
        if preamble_pattern.match(stripped) and len(stripped) < 80:
            continue
        # Remove leading # markdown heading markers from lines that slipped through
        line = re.sub(r'^#{1,4}\s+', '', line)
        cleaned.append(line)

    return '\n'.join(cleaned)


class AIReportGenerator:
    """Generates AI-powered DFIR reports

    Uses provider-aware prompt profiles so each AI model family gets
    tailored instructions (formatting, detail level, timeouts).
    """

    def __init__(self, case_id: int, template_id: Optional[int] = None,
                 progress_callback: Optional[Callable] = None):
        self.case = Case.query.get(case_id)
        if not self.case:
            raise ValueError(f"Case {case_id} not found")

        self.template_id = template_id
        self.progress_callback = progress_callback or (lambda step, total, msg: None)
        self.temp_folder = None
        self.sections = {}
        self.tagged_events: List[Dict] = []
        self.event_context: str = ""
        self.has_edr_report = bool(self.case.edr_report and self.case.edr_report.strip())
        self.has_attack_description = bool(self.case.attack_description and self.case.attack_description.strip())

        self._provider_type, self._profile = _get_provider_profile()
        self._model_name = self._resolve_model_name()
        logger.info(f"[ReportGen] Using provider profile: {self._provider_type} ({self._model_name})")

    @property
    def _is_local(self) -> bool:
        return self._provider_type in ('local', 'openai_compatible')

    def _resolve_model_name(self) -> str:
        """Get the model name from the active AI provider."""
        try:
            from utils.ai_providers import get_llm_provider
            provider = get_llm_provider()
            return provider.model or 'unknown'
        except Exception:
            return 'unknown'

    def _update_progress(self, step: int, total: int, message: str):
        """Update progress callback"""
        self.progress_callback(step, total, message)

    def _get_system_prompt(self) -> str:
        """Build the system prompt with provider-specific suffix."""
        return _BASE_SYSTEM_PROMPT + self._profile.get('system_suffix', '')

    def _generate_ai_content(self, prompt: str, timeout: int = None,
                             temperature: float = None, system: str = None) -> str:
        """Send prompt to AI via configured provider with profile-aware defaults."""
        effective_timeout = timeout or self._profile.get('timeout', 180)
        effective_temp = temperature if temperature is not None else self._profile.get('temperature', 0.3)
        effective_max_tokens = self._profile.get('max_tokens', 4000)
        effective_system = system or self._get_system_prompt()

        try:
            from utils.ai_providers import get_llm_provider
            provider = get_llm_provider()
            result = provider.generate(
                prompt=prompt,
                system=effective_system,
                temperature=effective_temp,
                max_tokens=effective_max_tokens,
            )
            if result.get('success'):
                raw = result.get('response', '')
                return _strip_llm_artifacts(raw)
            current_app.logger.error(f"AI generation error: {result.get('error')}")
            return f"[Error generating content: {result.get('error', 'Unknown')}]"
        except Exception as e:
            current_app.logger.error(f"AI generation error: {e}")
            return f"[Error generating content: {str(e)}]"
    
    def _create_temp_folder(self) -> str:
        """Create timestamped temp folder for this report run"""
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.temp_folder = f"/opt/casescope/temp/{self.case.uuid}/dfir_report_{ts}"
        os.makedirs(self.temp_folder, exist_ok=True)
        return self.temp_folder
    
    def _save_section(self, name: str, content: str):
        """Save a section to temp folder and store in memory"""
        self.sections[name] = content
        if self.temp_folder:
            with open(f"{self.temp_folder}/{name}.txt", 'w') as f:
                f.write(content)
    
    def _fetch_tagged_events(self) -> List[Dict]:
        """Fetch all analyst-tagged events for the case from ClickHouse"""
        try:
            client = get_client()
            query = """
                SELECT timestamp_utc, artifact_type, source_host, username,
                       event_id, process_name, command_line, rule_title,
                       mitre_tactics, mitre_tags, analyst_tags, analyst_notes,
                       target_path, reg_key, src_ip, dst_ip, parent_process
                FROM events
                WHERE case_id = {case_id:UInt32} AND analyst_tagged = true
                ORDER BY timestamp_utc ASC
            """
            result = client.query(query, parameters={'case_id': self.case.id})
            
            events = []
            for row in result.result_rows:
                (ts_utc, artifact, host, user, eid, proc, cmd, rule,
                 mitre_tac, mitre_tag, tags, notes, target, reg, srcip, dstip, parent) = row
                
                events.append({
                    'timestamp': ts_utc,
                    'artifact_type': artifact,
                    'host': host,
                    'user': user,
                    'event_id': eid,
                    'process': proc,
                    'command_line': cmd,
                    'rule': rule,
                    'mitre_tactics': list(mitre_tac) if mitre_tac else [],
                    'mitre_tags': list(mitre_tag) if mitre_tag else [],
                    'analyst_tags': list(tags) if tags else [],
                    'analyst_notes': notes,
                    'target_path': target,
                    'registry_key': reg,
                    'src_ip': str(srcip) if srcip else None,
                    'dst_ip': str(dstip) if dstip else None,
                    'parent_process': parent
                })
            
            self.tagged_events = events
            return events
        except Exception as e:
            current_app.logger.error(f"Error fetching tagged events: {e}")
            self.tagged_events = []
            return []
    
    def _build_event_context(self) -> str:
        """Build a structured context string from tagged events for AI analysis"""
        if not self.tagged_events:
            return ""
        
        lines = []
        lines.append(f"ANALYST-TAGGED EVENTS ({len(self.tagged_events)} events)")
        
        if self.tagged_events:
            lines.append(f"Timespan: {self.tagged_events[0]['timestamp']} to {self.tagged_events[-1]['timestamp']}")
            
            # Collect unique hosts and users
            hosts = set(e['host'] for e in self.tagged_events if e['host'])
            users = set(e['user'] for e in self.tagged_events if e['user'])
            lines.append(f"Affected Systems: {', '.join(hosts) if hosts else 'Unknown'}")
            lines.append(f"Users Involved: {', '.join(users) if users else 'Unknown'}")
        
        lines.append("")
        lines.append("EVENT SEQUENCE:")
        
        for i, event in enumerate(self.tagged_events, 1):
            ts = event['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if event['timestamp'] else 'Unknown'
            lines.append(f"\n[{i}] {ts} | {event['host'] or 'Unknown'} | {event['user'] or 'Unknown'}")
            lines.append(f"    Process: {event['process'] or 'Unknown'}")
            
            if event['command_line']:
                cmd = event['command_line'][:250] + "..." if len(event['command_line']) > 250 else event['command_line']
                lines.append(f"    Command: {cmd}")
            
            if event['parent_process']:
                lines.append(f"    Parent: {event['parent_process']}")
            
            if event['target_path']:
                lines.append(f"    Target: {event['target_path']}")
            
            if event['src_ip'] or event['dst_ip']:
                lines.append(f"    Network: {event['src_ip'] or 'N/A'} -> {event['dst_ip'] or 'N/A'}")
            
            if event['mitre_tactics'] or event['mitre_tags']:
                mitre = event['mitre_tactics'] + event['mitre_tags']
                lines.append(f"    MITRE: {', '.join(mitre)}")
            
            if event['analyst_notes']:
                lines.append(f"    Note: {event['analyst_notes']}")
        
        self.event_context = '\n'.join(lines)
        return self.event_context
    
    @staticmethod
    def _truncate_at_sentence(text: str, max_chars: int) -> str:
        """Truncate text at the last sentence boundary within max_chars."""
        if len(text) <= max_chars:
            return text
        truncated = text[:max_chars]
        for sep in ['. ', '.\n', '.\r']:
            last = truncated.rfind(sep)
            if last > max_chars * 0.5:
                return truncated[:last + 1]
        return truncated

    def _get_incident_context(self, max_chars: int = 6000) -> str:
        """Get the best available incident context for AI prompts.
        
        Priority order:
        1. Attack Description (analyst narrative) - full text preferred
        2. EDR Report - supplementary technical context
        3. Tagged Events - detailed event sequence
        
        When multiple sources exist, they are combined for richer analysis.
        """
        context_parts = []
        
        source_count = sum([
            self.has_attack_description,
            self.has_edr_report,
            bool(self.event_context),
        ])
        
        if self.has_attack_description:
            attack_budget = max_chars // 2 if source_count > 1 else max_chars
            excerpt = self._truncate_at_sentence(self.case.attack_description, attack_budget)
            tz_warning = ""
            if self.case.timezone and self.case.timezone != 'UTC':
                tz_warning = (
                    f" (WARNING: Times in this narrative are in {self.case.timezone} local time, "
                    "NOT UTC. Convert to UTC using the event timestamps below as reference. "
                    "For example, if the narrative says '14:41' and the events show '19:41 UTC' "
                    "for the same action, use 19:41 UTC.)"
                )
            context_parts.append(f"ANALYST ATTACK NARRATIVE{tz_warning}:\n{excerpt}")
        
        if self.has_edr_report:
            edr_budget = max_chars // 3 if self.has_attack_description else max_chars // 2
            excerpt = self._truncate_at_sentence(self.case.edr_report, edr_budget)
            context_parts.append(f"EDR ANALYSIS SUMMARY:\n{excerpt}")
        
        if self.event_context:
            remaining = max_chars - len('\n\n'.join(context_parts)) - 100
            if remaining > 500:
                event_excerpt = self.event_context[:remaining] if len(self.event_context) > remaining else self.event_context
                context_parts.append(event_excerpt)
        
        if not context_parts:
            return "No incident data available. Analysis based on case metadata only."
        
        return '\n\n'.join(context_parts)
    
    def _get_data_source_note(self) -> str:
        """Get a note about what data sources were used"""
        sources = []
        if self.has_attack_description:
            sources.append("analyst narrative")
        if self.has_edr_report:
            sources.append("EDR analysis")
        if self.tagged_events:
            sources.append(f"{len(self.tagged_events)} tagged events")
        
        if sources:
            return f"(Based on {', '.join(sources)})"
        else:
            return "(Limited data available)"
    
    def _local_extract_facts(self, incident_context: str) -> str:
        """Pass 1 for local models: extract structured facts from raw data.

        Smaller models are strong at extraction tasks. This produces a
        clean fact list that pass 2 can turn into narrative prose.
        """
        prompt = f"""Extract the key facts from this incident data as a numbered list.

For each fact include: date/time (in UTC), what happened, which system, which user, what tool or file was involved.
IMPORTANT: The analyst narrative may contain LOCAL times, not UTC. Cross-reference with the EVENT SEQUENCE timestamps (which ARE UTC) to determine the correct UTC time for each fact.

INCIDENT DATA:
{incident_context}

CONTAINMENT: {self.case.containment_actions or 'Not documented'}
ERADICATION: {self.case.eradication_actions or 'Not documented'}
RECOVERY: {self.case.recovery_actions or 'Not documented'}

List the facts (one per line, numbered):"""
        return self._generate_ai_content(prompt)

    def generate_executive_summary(self) -> str:
        """Generate executive summary from case data.

        For local models, uses a two-pass approach:
        1. Extract structured facts from raw data (extraction task)
        2. Write narrative prose from the fact list (generation task)
        """
        if self._is_local:
            incident_context = self._get_incident_context(max_chars=4000)
            facts = self._local_extract_facts(incident_context)

            prompt = f"""Using ONLY these facts, write a professional 4-paragraph executive summary for a security incident report.

RULES:
- Write in third person ("the organization")
- Non-technical executives must understand it
- Paragraph 1: What happened (initial compromise)
- Paragraph 2: What the attacker did (persistence, tools, dwell time)
- Paragraph 3: How it was detected and contained
- Paragraph 4: Recommendations
- Use specific details from the facts (dates, hostnames, filenames)

CASE: {self.case.name}

FACTS:
{facts}

LESSONS LEARNED: {self.case.lessons_learned or 'Not documented'}

Write the executive summary now:"""
        else:
            incident_context = self._get_incident_context(max_chars=8000)

            prompt = f"""Write a professional 4-5 paragraph executive summary for this incident report.

REQUIREMENTS:
- Technical but understandable by non-technical executives
- Written in third person (say "the organization" not "our")
- Focus on: what happened, what was affected, what remediation was performed, recommendations
- Use specific examples from the incident data (commands, file paths, IPs, times)
- Explain technical terms in plain language when first used
- Do NOT include a generic concluding paragraph about "the importance of security" — every paragraph must contain specific incident details or actionable recommendations
- Do NOT claim data exfiltration did or did not occur unless the evidence explicitly confirms it

CASE: {self.case.name} - {self.case.client.name if self.case.client else self.case.company}

INCIDENT DATA:
{incident_context}

CONTAINMENT ACTIONS:
{self.case.containment_actions or 'Not documented'}

ERADICATION ACTIONS:
{self.case.eradication_actions or 'Not documented'}

RECOVERY ACTIONS:
{self.case.recovery_actions or 'Not documented'}

LESSONS LEARNED:
{self.case.lessons_learned or 'Not documented'}

Write the executive summary (4-5 paragraphs, approximately 400-500 words):"""

        content = self._generate_ai_content(prompt)
        self._save_section('executive_summary', content)
        return content
    
    def _aggregate_events_by_activity(self, all_events: List[Dict]) -> List[Dict]:
        """Pre-aggregate events by activity type before sampling.
        
        Groups events by: host + user + rule + 5-minute window
        Returns aggregated activity summaries.
        """
        from collections import defaultdict
        
        # Group by host, user, rule, and 5-minute time bucket
        activity_buckets = defaultdict(list)
        
        for event in all_events:
            ts = event.get('timestamp')
            if ts:
                # 5-minute bucket
                bucket_time = ts.replace(second=0, microsecond=0)
                bucket_time = bucket_time.replace(minute=(bucket_time.minute // 5) * 5)
            else:
                bucket_time = None
            
            key = (
                event.get('host', ''),
                event.get('user', ''),
                event.get('rule', ''),
                str(bucket_time)
            )
            activity_buckets[key].append(event)
        
        # Convert buckets to activity summaries
        activities = []
        for (host, user, rule, bucket), events in activity_buckets.items():
            if len(events) == 1:
                # Single event, keep as-is
                activities.append(events[0])
            else:
                # Multiple events, create summary
                first_ts = min(e.get('timestamp') for e in events if e.get('timestamp'))
                last_ts = max(e.get('timestamp') for e in events if e.get('timestamp'))
                
                # Collect unique values
                processes = set(e.get('process') for e in events if e.get('process'))
                tactics = set()
                for e in events:
                    tactics.update(e.get('mitre_tactics', []))
                    tactics.update(e.get('mitre_tags', []))
                
                # Collect unique command lines (most descriptive detail)
                cmdlines = []
                seen_cmds = set()
                for e in events:
                    cmd = e.get('command_line')
                    if cmd and len(cmd) > 5 and cmd not in seen_cmds:
                        cmdlines.append(cmd)
                        seen_cmds.add(cmd)
                
                # Collect artifact types, target paths, IPs
                artifact_types = set(e.get('artifact_type') for e in events if e.get('artifact_type'))
                target_paths = set(e.get('target_path') for e in events if e.get('target_path'))
                reg_keys = set(e.get('reg_key') for e in events if e.get('reg_key'))
                src_ips = set(str(e.get('src_ip')) for e in events if e.get('src_ip'))
                dst_ips = set(str(e.get('dst_ip')) for e in events if e.get('dst_ip'))
                
                # Build a meaningful rule summary when no rule title exists
                if not rule:
                    if artifact_types:
                        rule = ', '.join(sorted(artifact_types)[:3])
                    elif processes:
                        rule = f"Activity: {', '.join(list(processes)[:3])}"
                    else:
                        rule = 'System Activity'
                
                # Check if any have notes
                notes = [e.get('notes') for e in events if e.get('notes')]
                
                activities.append({
                    'timestamp': first_ts,
                    'end_timestamp': last_ts,
                    'host': host,
                    'user': user,
                    'rule': rule,
                    'process': ', '.join(list(processes)[:3]) if processes else None,
                    'command_line': '; '.join(cmdlines[:3]) if cmdlines else None,
                    'artifact_type': ', '.join(sorted(artifact_types)[:2]) if artifact_types else None,
                    'target_path': ', '.join(list(target_paths)[:2]) if target_paths else None,
                    'reg_key': ', '.join(list(reg_keys)[:2]) if reg_keys else None,
                    'src_ip': ', '.join(list(src_ips)[:2]) if src_ips else None,
                    'dst_ip': ', '.join(list(dst_ips)[:2]) if dst_ips else None,
                    'mitre_tactics': list(tactics),
                    'mitre_tags': [],
                    'notes': notes[0] if notes else None,
                    'event_count': len(events),
                    'is_aggregated': True
                })
        
        # Sort by timestamp
        activities.sort(key=lambda e: e.get('timestamp') or '')
        return activities
    
    def _smart_sample_events(self, all_events: List[Dict], max_events: int = 80) -> tuple:
        """Smart sampling of events for timeline generation.
        
        Strategy:
        1. Pre-aggregate by activity (host+user+rule per 5-min window)
        2. Always include events with analyst notes (priority)
        3. Ensure rule/activity diversity
        4. Sample evenly across timespan
        
        Returns: (sampled_events, stats)
        """
        # First, pre-aggregate to reduce volume
        activities = self._aggregate_events_by_activity(all_events)
        
        if len(activities) <= max_events:
            stats = {
                'total': len(all_events),
                'activities': len(activities),
                'sampled': len(activities),
                'strategy': 'aggregated_all'
            }
            return activities, stats
        
        # Separate priority activities (with analyst notes)
        priority = [a for a in activities if a.get('notes')]
        regular = [a for a in activities if not a.get('notes')]
        
        # Reserve slots for priority (max 50% of budget)
        priority_budget = min(len(priority), int(max_events * 0.5))
        remaining_budget = max_events - priority_budget
        
        # Collect unique rules to ensure diversity
        rule_activities = {}
        for a in regular:
            rule = a.get('rule', 'Unknown')
            if rule not in rule_activities:
                rule_activities[rule] = []
            rule_activities[rule].append(a)
        
        sampled = []
        sampled_ids = set()
        
        # Add priority first
        for a in priority[:priority_budget]:
            sampled.append(a)
            sampled_ids.add(id(a))
        
        # Add one from each unique rule type (diversity)
        rule_budget = min(len(rule_activities), remaining_budget // 2)
        for rule, acts in list(rule_activities.items())[:rule_budget]:
            if acts and id(acts[0]) not in sampled_ids:
                sampled.append(acts[0])
                sampled_ids.add(id(acts[0]))
                remaining_budget -= 1
        
        # Fill remaining with evenly distributed samples
        unsampled = [a for a in regular if id(a) not in sampled_ids]
        if unsampled and remaining_budget > 0:
            step = max(1, len(unsampled) // remaining_budget)
            for i in range(0, len(unsampled), step):
                if len(sampled) >= max_events:
                    break
                sampled.append(unsampled[i])
        
        # Sort by timestamp
        sampled.sort(key=lambda e: e.get('timestamp') or '')
        
        stats = {
            'total': len(all_events),
            'activities': len(activities),
            'sampled': len(sampled),
            'priority_included': min(len(priority), priority_budget),
            'unique_rules': len(rule_activities),
            'strategy': 'smart_sample'
        }
        
        return sampled, stats
    
    def generate_timeline(self) -> str:
        """Generate timeline from analyst-tagged events.
        
        Uses smart sampling for large datasets:
        - Pre-aggregates by activity (host+user+rule per 5-min window)
        - Prioritizes events with analyst notes
        - Ensures rule/activity diversity  
        - Samples evenly across timespan
        """
        try:
            client = get_client()
            query = """
                SELECT timestamp_utc, artifact_type, source_host, username,
                       process_name, command_line, rule_title, mitre_tactics, mitre_tags,
                       analyst_tags, analyst_notes, target_path, reg_key, src_ip, dst_ip
                FROM events
                WHERE case_id = {case_id:UInt32} AND analyst_tagged = true
                ORDER BY timestamp_utc ASC
            """
            result = client.query(query, parameters={'case_id': self.case.id})
            
            if not result.result_rows:
                return "No analyst-tagged events found for timeline generation."
            
            # Parse all events into structured format
            all_events = []
            for row in result.result_rows:
                (ts_utc, artifact_type, host, user, proc, cmdline, rule, 
                 mitre_tactics, mitre_tags, tags, notes, target, reg_key, src_ip, dst_ip) = row
                all_events.append({
                    'timestamp': ts_utc,
                    'artifact_type': artifact_type,
                    'host': host,
                    'user': user,
                    'process': proc,
                    'command_line': cmdline,
                    'rule': rule,
                    'mitre_tactics': list(mitre_tactics) if mitre_tactics else [],
                    'mitre_tags': list(mitre_tags) if mitre_tags else [],
                    'notes': notes,
                    'target_path': target,
                    'src_ip': str(src_ip) if src_ip else None,
                    'dst_ip': str(dst_ip) if dst_ip else None
                })
            
            total_events = len(all_events)

            max_events = self._profile.get('max_events', 80)
            sampled_activities, stats = self._smart_sample_events(all_events, max_events=max_events)
            
            # Build simplified event text for AI - cleaner format
            events_text = []
            
            for activity in sampled_activities:
                ts = activity.get('timestamp')
                date_str = ts.strftime('%m/%d/%Y %H:%M:%S') if ts else 'Unknown'
                
                # Build a meaningful label from whatever data is available
                rule = activity.get('rule') or ''
                user = activity.get('user') or ''
                host = activity.get('host') or 'unknown'
                proc = activity.get('process')
                cmd = activity.get('command_line')
                target = activity.get('target_path')
                art_type = activity.get('artifact_type')
                
                # Derive a label when rule is empty
                if not rule:
                    if proc and proc not in ('N/A', '', 'None', 'Unknown'):
                        rule = f"Process execution: {proc}"
                    elif target:
                        rule = f"File/path activity: {target[:80]}"
                    elif art_type:
                        rule = f"{art_type} event"
                    else:
                        rule = 'System event'
                
                # Build the user/host suffix only when we have values
                actor = f" by {user}" if user else ""
                
                if activity.get('is_aggregated') and activity.get('event_count', 1) > 1:
                    end_ts = activity.get('end_timestamp')
                    end_time = end_ts.strftime('%H:%M:%S') if end_ts else ''
                    count = activity.get('event_count', 1)
                    entry = f"{date_str}-{end_time}: {count}x {rule}{actor} on {host}"
                else:
                    entry = f"{date_str}: {rule}{actor} on {host}"
                
                if art_type:
                    entry += f" (source: {art_type})"
                
                mitre = activity.get('mitre_tactics', []) + activity.get('mitre_tags', [])
                if mitre:
                    entry += f" [{', '.join(mitre)}]"
                
                if cmd and len(cmd) > 5:
                    entry += f" | cmd: {cmd[:200]}"
                elif proc and proc not in ('N/A', '', 'None', 'Unknown') and not rule.startswith('Process execution'):
                    entry += f" | process: {proc}"
                
                if target and not rule.startswith('File/path activity'):
                    entry += f" | path: {target[:150]}"
                reg = activity.get('reg_key')
                if reg:
                    entry += f" | registry: {reg[:150]}"
                
                dst = activity.get('dst_ip')
                src = activity.get('src_ip')
                if dst:
                    entry += f" | dst: {dst}"
                if src:
                    entry += f" | src: {src}"
                
                if activity.get('notes'):
                    entry += f" [NOTE: {activity['notes'][:100]}]"
                
                events_text.append(entry)
            
            # Determine incident timespan
            first_ts = sampled_activities[0].get('timestamp') if sampled_activities else None
            last_ts = sampled_activities[-1].get('timestamp') if sampled_activities else None
            timespan = ""
            if first_ts and last_ts:
                timespan = f"Incident timespan: {first_ts.strftime('%m/%d/%Y %H:%M')} to {last_ts.strftime('%m/%d/%Y %H:%M')}"
            
            if self._is_local:
                prompt = f"""Convert these events into an incident timeline.

FORMAT: "MM/DD/YYYY at HH:MM:SS: [What happened]"

RULES:
1. Rewrite each event as a clear prose description — do NOT copy raw event data verbatim
2. State specific actions: what process ran, what file was accessed, what service was installed
3. Group recurring brief connect/disconnect patterns by date range instead of listing each one individually
4. Include all events — do not skip any
5. Entries marked [NOTE:] are analyst observations — include them
6. If an event has no descriptive content, omit it rather than writing "event log entry recorded"
7. Characterize credential tools strongly: "credential harvesting" not "credential management"

{timespan}
Total events: {total_events} (showing {len(events_text)} key activities)

EVENTS:
{chr(10).join(events_text)}

Write the timeline:"""
            else:
                prompt = f"""Convert these forensic events into a professional incident timeline.

RULES:
1. Format: "MM/DD/YYYY at HH:MM:SS: [Concrete description of what happened]"
2. Add a bullet point explanation under significant entries
3. Group related events that happen within seconds of each other
4. Describe SPECIFIC actions: what process ran, what file was created/accessed, what service was installed or modified, what tool was executed, what connection was made
5. Entries marked [NOTE:] are analyst observations — incorporate them into the narrative
6. NEVER write vague text like "multiple activities were performed" or "the user carried out actions" — always state the concrete activity using the process, path, command, or registry data provided
7. If an aggregated entry contains multiple sub-events, list the 2-3 most significant specific actions
8. EVERY activity listed below MUST appear in your output — do not skip or omit any entries. Cover the FULL timespan from first to last event
9. For recurring brief connect/disconnect sessions with no additional actions (e.g. daily remote access check-ins lasting <30 seconds), summarize them as a date range pattern: state the pattern once, then list the specific dates and times compactly. Do NOT list each trivial session as a separate full entry
10. If an event log entry has no descriptive content beyond a timestamp, omit it rather than stating "an event log entry was recorded"
11. Characterize credential tools (e.g. password.exe, mimikatz) using strong language: "credential harvesting" or "password extraction," not "credential management" or "manipulation"

{timespan}
Total events: {total_events} (showing {len(events_text)} key activities)

ACTIVITIES:
{chr(10).join(events_text)}

Write the complete timeline covering ALL activities above:"""
            
            content = self._generate_ai_content(prompt, timeout=180)
            self._save_section('timeline', content)
            return content
            
        except Exception as e:
            current_app.logger.error(f"Timeline generation error: {e}")
            return f"[Error generating timeline: {str(e)}]"
    
    def generate_ioc_list(self) -> str:
        """Generate formatted IOC list"""
        iocs = IOC.query.filter_by(case_id=self.case.id, hidden=False).all()
        
        if not iocs:
            return "No indicators of compromise documented for this case."
        
        ioc_data = []
        for ioc in iocs:
            ioc_data.append(
                f"VALUE: {ioc.value}\n"
                f"TYPE: {ioc.ioc_type}\n"
                f"ANALYST NOTES: {ioc.notes or 'No notes provided'}\n"
                f"MALICIOUS: {ioc.malicious}\n---"
            )
        
        if self._is_local:
            prompt = f"""Organize these IOCs into categories for an incident report.

CATEGORIES (you MUST output the category name as a header line before listing the IOCs in it, skip empty categories):
- Malicious Files (actual file names only, e.g. .exe, .msi, .vbs)
- Malicious Actions or Commands
- Compromised Users
- Network Addresses
- Threat Actor IOCs (including remote access UIDs, session identifiers, actor usernames)

FORMAT for each IOC:
• [IOC value]
  [One sentence description based on the ANALYST NOTES]

RULES:
- Use ANALYST NOTES as the primary source for descriptions
- Trust analyst notes over the TYPE field for categorization
- Remote access tool UIDs are NOT files — put them under Threat Actor IOCs
- If a user downloaded malware, they ARE a compromised user
- For each IOC, include specific domains or IPs from the notes — do not say "a suspicious domain"
- Write for non-technical readers

IOC DATA:
{chr(10).join(ioc_data)}

Write the IOC list:"""
        else:
            prompt = f"""Reformat this IOC list for an incident report.

FORMAT:
## Category Name

• IOC value
  Description explaining what this is and why it matters

CATEGORIES (use these, skip empty categories):
- Malicious Files (actual file names only, e.g. .exe, .msi, .vbs)
- Malicious Actions or Commands
- Compromised Users
- Network Addresses
- Threat Actor IOCs (including remote access UIDs, session identifiers, actor usernames)

RULES:
- The ANALYST NOTES field is the authoritative source — use it as the PRIMARY basis for each description. Rephrase notes into professional language but preserve all factual details.
- The TYPE field may be inaccurate (e.g. a ScreenConnect UID stored as "File Name"). Trust the analyst notes over the type field for categorization.
- NEVER fabricate descriptions when analyst notes are provided — use the notes.
- Remote access tool UIDs and service identifiers are NOT files — categorize them under "Threat Actor IOCs," not "Malicious Files."
- Do NOT use the phrase "insider threat" unless the analyst notes explicitly state it.
- If a user downloaded malware or was the initial compromise vector, they ARE a compromised user — do not state "no malicious activity noted" for such users.
- For EACH IOC, include the specific domain, IP, or technical detail from the analyst notes. Do NOT use vague phrases like "a suspicious domain" when the domain name is provided.
- When notes say "None" or are absent, write a brief factual description based on context.
- Write for non-technical executives — explain technical terms briefly.
- Do NOT add a category if no IOCs belong to it.

IOC DATA:
{chr(10).join(ioc_data)}

Generate the formatted IOC list:"""
        
        content = self._generate_ai_content(prompt, timeout=180)
        self._save_section('ioc_list', content)
        return content
    
    def generate_summary_what(self) -> str:
        """Generate 'What Happened' summary"""
        ctx_budget = 4000 if self._is_local else 6000
        incident_context = self._get_incident_context(max_chars=ctx_budget)
        exec_summary = self.sections.get('executive_summary', '')

        if self._is_local:
            prompt = f"""Write ONE paragraph (EXACTLY 4-5 sentences, no more) about what happened in this security incident.

Use third person ("the organization"). Include dates, hostnames, and filenames from the data. Do not speculate. Do not claim things did or did not happen unless the data confirms it.

EXECUTIVE SUMMARY (for context — distill key facts, do not repeat):
{exec_summary[:1500]}

INCIDENT DATA:
{incident_context}

Write the paragraph:"""
        else:
            prompt = f"""Write ONE paragraph (4-5 sentences, no more than 5) explaining what happened in this security incident.

REQUIREMENTS:
- Formal, professional tone for business audience
- Accessible to non-technical executives
- Third person (say "the organization" not "our")
- Focus on: when, who was affected, what the attacker achieved, what was done
- Include specific examples (times, systems, commands) from the data
- Only state facts present in the incident data — do not speculate
- Do NOT claim exfiltration did or did not occur unless evidence confirms it
- STRICTLY 4-5 sentences. Do not exceed 5 sentences.

EXECUTIVE SUMMARY (for context — do not repeat it, distill the key facts):
{exec_summary[:2000]}

INCIDENT DATA:
{incident_context}

Write the "What Happened" paragraph:"""

        content = self._generate_ai_content(prompt)
        self._save_section('summary_what', content)
        return content
    
    def generate_summary_why(self) -> str:
        """Generate 'Why It Happened' summary"""
        ctx_budget = 4000 if self._is_local else 6000
        incident_context = self._get_incident_context(max_chars=ctx_budget)
        exec_summary = self.sections.get('executive_summary', '')

        if self._is_local:
            prompt = f"""Write ONE paragraph (EXACTLY 4-5 sentences, no more) explaining WHY this security incident happened.

Focus on root causes and security gaps the attacker exploited. Use third person. Be constructive, not blaming. Only reference techniques present in the data.

EXECUTIVE SUMMARY (for context):
{exec_summary[:1500]}

INCIDENT DATA:
{incident_context}

Write the paragraph:"""
        else:
            prompt = f"""Write ONE paragraph (4-5 sentences, no more than 5) explaining WHY this security incident happened.

REQUIREMENTS:
- Formal, professional tone
- Accessible to non-technical executives
- Third person
- Focus on root causes and security gaps exploited
- Be constructive, not blaming
- Only reference attack techniques that are evidenced in the data — do not fabricate techniques
- STRICTLY 4-5 sentences. Do not exceed 5 sentences.

EXECUTIVE SUMMARY (for context):
{exec_summary[:2000]}

INCIDENT DATA:
{incident_context}

Write the "Why It Happened" paragraph:"""

        content = self._generate_ai_content(prompt)
        self._save_section('summary_why', content)
        return content
    
    def generate_summary_how(self) -> str:
        """Generate 'How To Prevent' summary"""
        ctx_budget = 4000 if self._is_local else 6000
        incident_context = self._get_incident_context(max_chars=ctx_budget)
        exec_summary = self.sections.get('executive_summary', '')

        if self._is_local:
            prompt = f"""Write ONE paragraph (EXACTLY 4-5 sentences, no more) explaining what could have PREVENTED this incident.

Focus on actionable steps the organization can take. Base recommendations on the specific attack techniques in the data. Use third person. Do not recommend controls already in place.

EXECUTIVE SUMMARY (for context):
{exec_summary[:1500]}

INCIDENT DATA:
{incident_context}

LESSONS LEARNED: {self.case.lessons_learned or 'Not documented'}

Write the paragraph:"""
        else:
            prompt = f"""Write ONE paragraph (4-5 sentences, no more than 5) explaining what could have PREVENTED this incident.

REQUIREMENTS:
- Formal, professional tone
- Accessible to non-technical executives
- Third person
- Focus on actionable preventive measures directly relevant to the attack techniques observed
- Be constructive and forward-looking
- Base recommendations specifically on the attack chain in this incident
- Do NOT recommend controls the organization already has (reference the incident data to check)
- STRICTLY 4-5 sentences. Do not exceed 5 sentences.

EXECUTIVE SUMMARY (for context):
{exec_summary[:2000]}

INCIDENT DATA:
{incident_context}

LESSONS LEARNED: {self.case.lessons_learned or 'Not documented'}

Write the "How To Prevent" paragraph:"""

        content = self._generate_ai_content(prompt)
        self._save_section('summary_how', content)
        return content
    
    def generate_report(self) -> Dict:
        """Generate complete report and return result info
        
        Automatically detects available data sources:
        - If EDR report exists: Uses both EDR + tagged events
        - If no EDR report: Uses tagged events as primary source
        """
        self._create_temp_folder()
        
        total_steps = 8
        
        # Step 1: Fetch analyst-tagged events from ClickHouse
        self._update_progress(1, total_steps, "Fetching analyst-tagged events...")
        self._fetch_tagged_events()
        self._build_event_context()
        
        # Log data source info
        sources = []
        if self.has_attack_description:
            sources.append("attack narrative")
        if self.has_edr_report:
            sources.append("EDR report")
        sources.append(f"{len(self.tagged_events)} tagged events")
        current_app.logger.info(f"DFIR Report for case {self.case.id}: Using {' + '.join(sources)}")
        
        # Step 2: Executive Summary
        self._update_progress(2, total_steps, "Generating Executive Summary...")
        self.generate_executive_summary()
        
        # Step 3: Timeline
        self._update_progress(3, total_steps, "Generating Timeline...")
        self.generate_timeline()
        
        # Step 4: IOC List
        self._update_progress(4, total_steps, "Generating IOC List...")
        self.generate_ioc_list()
        
        # Step 5: What Happened
        self._update_progress(5, total_steps, "Generating 'What Happened'...")
        self.generate_summary_what()
        
        # Step 6: Why It Happened
        self._update_progress(6, total_steps, "Generating 'Why It Happened'...")
        self.generate_summary_why()
        
        # Step 7: How To Prevent
        self._update_progress(7, total_steps, "Generating 'How To Prevent'...")
        self.generate_summary_how()
        
        # Step 8: Generate Word Document
        self._update_progress(8, total_steps, "Generating Word document...")
        output_path = self._generate_word_document()
        
        return {
            'success': True,
            'output_path': output_path,
            'filename': os.path.basename(output_path),
            'temp_folder': self.temp_folder,
            'sections': list(self.sections.keys()),
            'ai_model': self._model_name,
            'data_sources': {
                'attack_description': self.has_attack_description,
                'edr_report': self.has_edr_report,
                'tagged_events': len(self.tagged_events)
            }
        }
    
    def _generate_word_document(self) -> str:
        """Generate Word document from template"""
        from models.report_template import ReportType
        
        # Find DFIR template
        template = None
        if self.template_id:
            template = ReportTemplate.query.get(self.template_id)
        
        if not template:
            # Look for DFIR template by report type
            template = ReportTemplate.get_default_template_for_type(ReportType.DFIR)
        
        if not template:
            # Fallback to default or first available template
            template = ReportTemplate.get_default_template()
            if not template:
                templates = ReportTemplate.get_active_templates()
                if templates:
                    template = templates[0]
        
        if not template:
            raise ValueError("No report template available")
        
        template_path = ReportTemplate.get_template_path(template.filename)
        if not os.path.exists(template_path):
            raise ValueError(f"Template file not found: {template_path}")
        
        doc = DocxTemplate(template_path)
        
        # Clean markdown formatting for Word insertion
        # Converts ## to uppercase headings, * to bullet chars, removes **bold** markers
        template_context = {
            'client_name': self.case.client.name if self.case.client else self.case.company,
            'today_date': datetime.now().strftime('%B %d, %Y'),
            'executive_summary': clean_markdown(self.sections.get('executive_summary', '')),
            'timeline': clean_markdown(self.sections.get('timeline', '')),
            'ioc_list': clean_markdown(self.sections.get('ioc_list', '')),
            'summary_what': clean_markdown(self.sections.get('summary_what', '')),
            'summary_why': clean_markdown(self.sections.get('summary_why', '')),
            'summary_how': clean_markdown(self.sections.get('summary_how', '')),
        }
        
        doc.render(template_context)
        
        # Save to reports folder
        reports_folder = f'/opt/casescope/storage/{self.case.uuid}/reports'
        os.makedirs(reports_folder, exist_ok=True)
        
        filename = f"DFIR_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"
        output_path = os.path.join(reports_folder, filename)
        
        doc.save(output_path)
        
        return output_path


def generate_ai_report(case_id: int, template_id: Optional[int] = None) -> Dict:
    """Convenience function to generate a report"""
    generator = AIReportGenerator(case_id, template_id)
    return generator.generate_report()
