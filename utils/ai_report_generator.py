"""AI Report Generator for CaseScope

Generates DFIR reports using AI analysis of case data.

Data Sources:
- If EDR report exists: Uses both EDR summary AND analyst-tagged events
- If no EDR report: Uses analyst-tagged events from ClickHouse as primary source
"""
import os
import requests
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
from config import Config


class AIReportGenerator:
    """Generates AI-powered DFIR reports
    
    Intelligently uses available data sources:
    - Analyst-tagged events from ClickHouse (always fetched)
    - EDR report from case (if available)
    
    When both are available, combines them for richer analysis.
    When only events exist, generates report purely from event data.
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
    
    def _update_progress(self, step: int, total: int, message: str):
        """Update progress callback"""
        self.progress_callback(step, total, message)
    
    def _generate_ai_content(self, prompt: str, timeout: int = 120) -> str:
        """Send prompt to AI and get response"""
        try:
            response = requests.post(
                f"{Config.OLLAMA_HOST}/api/generate",
                json={
                    "model": Config.OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=timeout
            )
            return response.json().get('response', '')
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
    
    def _get_incident_context(self, max_chars: int = 4000) -> str:
        """Get the best available incident context for AI prompts.
        
        Priority order:
        1. Attack Description (analyst narrative) - primary context if available
        2. EDR Report - supplementary technical context
        3. Tagged Events - detailed event sequence
        
        When multiple sources exist, they are combined for richer analysis.
        """
        context_parts = []
        
        # Attack description is the analyst's narrative of what occurred
        if self.has_attack_description:
            attack_chars = max_chars // 3 if (self.has_edr_report or self.event_context) else max_chars // 2
            attack_excerpt = self.case.attack_description[:attack_chars] if len(self.case.attack_description) > attack_chars else self.case.attack_description
            context_parts.append(f"ANALYST ATTACK NARRATIVE:\n{attack_excerpt}")
        
        # EDR report provides technical analysis from EDR tool
        if self.has_edr_report:
            edr_chars = max_chars // 3 if self.has_attack_description else max_chars // 2
            edr_excerpt = self.case.edr_report[:edr_chars] if len(self.case.edr_report) > edr_chars else self.case.edr_report
            context_parts.append(f"EDR ANALYSIS SUMMARY:\n{edr_excerpt}")
        
        if self.event_context:
            # Allocate remaining space to events
            remaining = max_chars - len('\n\n'.join(context_parts)) - 100
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
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary from case data
        
        Uses EDR report if available, otherwise uses analyst-tagged events.
        When both exist, combines them for comprehensive analysis.
        """
        incident_context = self._get_incident_context(max_chars=5000)
        
        prompt = f"""You are a digital forensics consultant writing a final incident report for a CLIENT.
Write a professional 4-5 paragraph executive summary.

REQUIREMENTS:
- Technical but understandable by non-technical executives
- Written in third person (say "the organization" not "our")
- Focus on: what happened, what was affected, what remediation was performed, recommendations
- Use specific examples from the incident data (commands, file paths, IPs, times)
- Explain technical terms in plain language when first used

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
        
        content = self._generate_ai_content(prompt, timeout=180)
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
                
                # Check if any have notes
                notes = [e.get('notes') for e in events if e.get('notes')]
                
                activities.append({
                    'timestamp': first_ts,
                    'end_timestamp': last_ts,
                    'host': host,
                    'user': user,
                    'rule': rule or 'Multiple Activities',
                    'process': ', '.join(list(processes)[:3]) if processes else None,
                    'command_line': None,
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
            
            # Smart sample with pre-aggregation
            sampled_activities, stats = self._smart_sample_events(all_events, max_events=80)
            
            # Build simplified event text for AI - cleaner format
            events_text = []
            
            for activity in sampled_activities:
                ts = activity.get('timestamp')
                date_str = ts.strftime('%m/%d/%Y %H:%M:%S') if ts else 'Unknown'
                
                # Handle aggregated vs single events
                if activity.get('is_aggregated') and activity.get('event_count', 1) > 1:
                    end_ts = activity.get('end_timestamp')
                    end_time = end_ts.strftime('%H:%M:%S') if end_ts else ''
                    count = activity.get('event_count', 1)
                    entry = f"{date_str}-{end_time}: {count}x {activity.get('rule', 'events')} by {activity.get('user', 'unknown')} on {activity.get('host', 'unknown')}"
                else:
                    entry = f"{date_str}: {activity.get('rule', 'Event')} by {activity.get('user', 'unknown')} on {activity.get('host', 'unknown')}"
                
                # Add MITRE if present
                mitre = activity.get('mitre_tactics', []) + activity.get('mitre_tags', [])
                if mitre:
                    entry += f" [{', '.join(mitre)}]"
                
                # Add process/command if meaningful
                proc = activity.get('process')
                cmd = activity.get('command_line')
                if cmd and len(cmd) > 5:
                    entry += f" - {cmd[:100]}"
                elif proc and proc not in ['N/A', '', 'None'] and ':' not in proc:
                    entry += f" - {proc}"
                
                # Mark analyst notes
                if activity.get('notes'):
                    entry += f" [NOTE: {activity['notes'][:60]}]"
                
                events_text.append(entry)
            
            # Determine incident timespan
            first_ts = sampled_activities[0].get('timestamp') if sampled_activities else None
            last_ts = sampled_activities[-1].get('timestamp') if sampled_activities else None
            timespan = ""
            if first_ts and last_ts:
                timespan = f"Incident timespan: {first_ts.strftime('%m/%d/%Y %H:%M')} to {last_ts.strftime('%m/%d/%Y %H:%M')}"
            
            prompt = f"""You are a DFIR analyst writing an incident timeline for a security report.

Convert these events into a professional narrative timeline.

RULES:
1. Write each entry as: "MM/DD/YYYY at HH:MM:SS: [Description of what happened]"
2. Add a bullet point explanation under significant entries
3. Group related events that happen within seconds
4. Focus on WHAT the attacker/user DID, not raw technical data
5. Entries marked [NOTE:] are analyst observations - incorporate these

{timespan}
Total events: {total_events} (showing {len(events_text)} key activities)

ACTIVITIES:
{chr(10).join(events_text)}

Write the timeline (each entry on its own line, most significant events get bullet explanations):"""
            
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
            ioc_data.append(f"VALUE: {ioc.value}\nTYPE: {ioc.ioc_type}\nNOTES: {ioc.notes or 'None'}\nMALICIOUS: {ioc.malicious}\n---")
        
        prompt = f"""Reformat this IOC list for an incident report. Make descriptions professional but human-readable.

FORMAT:
## Category Name

• IOC value
  Description explaining what this is and why it matters

CATEGORIES (use these, skip if empty):
- Malicious Files
- Malicious Actions or Commands
- Compromised Users
- Compromised Systems
- Network Addresses
- Threat Actor IOCs

RULES:
- Write for non-technical executives
- Be concise but informative
- Mark malicious items clearly

IOC DATA:
{chr(10).join(ioc_data)}

Generate the formatted IOC list:"""
        
        content = self._generate_ai_content(prompt, timeout=180)
        self._save_section('ioc_list', content)
        return content
    
    def generate_summary_what(self) -> str:
        """Generate 'What Happened' summary
        
        Uses combined incident context from EDR report and/or tagged events.
        """
        incident_context = self._get_incident_context(max_chars=3000)
        
        prompt = f"""Write ONE paragraph (4-5 sentences) explaining what happened in this security incident.

REQUIREMENTS:
- Formal, professional tone for business audience
- Accessible to non-technical executives
- Third person (say "the organization" not "our")
- Focus on: when, who was affected, what the attacker achieved, what was done
- Include specific examples (times, systems, commands) when available

INCIDENT DATA:
{incident_context}

Write the "What Happened" paragraph:"""
        
        content = self._generate_ai_content(prompt)
        self._save_section('summary_what', content)
        return content
    
    def generate_summary_why(self) -> str:
        """Generate 'Why It Happened' summary
        
        Uses combined incident context from EDR report and/or tagged events.
        """
        incident_context = self._get_incident_context(max_chars=3000)
        
        prompt = f"""Write ONE paragraph (4-5 sentences) explaining WHY this security incident happened.

REQUIREMENTS:
- Formal, professional tone
- Accessible to non-technical executives
- Third person
- Focus on root causes and gaps exploited
- Be constructive, not blaming
- Reference specific attack techniques observed if available

INCIDENT DATA:
{incident_context}

Write the "Why It Happened" paragraph:"""
        
        content = self._generate_ai_content(prompt)
        self._save_section('summary_why', content)
        return content
    
    def generate_summary_how(self) -> str:
        """Generate 'How To Prevent' summary
        
        Uses combined incident context from EDR report and/or tagged events.
        """
        incident_context = self._get_incident_context(max_chars=3000)
        
        prompt = f"""Write ONE paragraph (4-5 sentences) explaining what could have PREVENTED this incident.

REQUIREMENTS:
- Formal, professional tone
- Accessible to non-technical executives
- Third person
- Focus on actionable preventive measures
- Be constructive and forward-looking
- Base recommendations on the specific attack techniques observed

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
