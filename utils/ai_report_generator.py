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
        
        Returns:
        - If EDR report exists: Combined EDR summary + event context
        - If no EDR report: Event context only
        """
        context_parts = []
        
        if self.has_edr_report:
            edr_excerpt = self.case.edr_report[:max_chars // 2] if len(self.case.edr_report) > max_chars // 2 else self.case.edr_report
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
        if self.has_edr_report and self.tagged_events:
            return f"(Based on EDR analysis and {len(self.tagged_events)} analyst-tagged events)"
        elif self.has_edr_report:
            return "(Based on EDR analysis)"
        elif self.tagged_events:
            return f"(Based on {len(self.tagged_events)} analyst-tagged events)"
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
    
    def generate_timeline(self) -> str:
        """Generate timeline from analyst-tagged events"""
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
            
            events_text = []
            for row in result.result_rows:
                (ts_utc, artifact_type, host, user, proc, cmdline, rule, 
                 mitre_tactics, mitre_tags, tags, notes, target, reg_key, src_ip, dst_ip) = row
                mitre_list = list(mitre_tactics) if mitre_tactics else []
                mitre_ids = list(mitre_tags) if mitre_tags else []
                mitre_str = ', '.join(mitre_list + mitre_ids) if (mitre_list or mitre_ids) else 'None'
                event_info = f"TIME:{ts_utc}|HOST:{host}|USER:{user}|RULE:{rule}|MITRE:{mitre_str}|PROC:{proc}|CMD:{cmdline[:300] if cmdline else 'N/A'}"
                events_text.append(event_info)
            
            prompt = f"""Create an incident timeline. Output ONLY the timeline entries.

FORMAT - each entry must be:
01/21/2026 at 17:08:37: User Bill executed cmd.exe to copy finger.exe - MITRE (Execution, T1059)
* The attacker used command prompt to stage a renamed copy of finger.exe

GROUPING: If multiple similar events occur within seconds, combine them:
01/21/2026 at 17:10:23-17:10:41: Multiple PowerShell commands executed (8 events on ENGINEERING by Bill) - MITRE (Discovery, T1082)
* The attacker gathered system information

EVENTS:
{chr(10).join(events_text)}

Output timeline (chronological, no headers):"""
            
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
        data_source = "EDR report + tagged events" if self.has_edr_report else "analyst-tagged events only"
        current_app.logger.info(f"DFIR Report for case {self.case.id}: Using {data_source} ({len(self.tagged_events)} events)")
        
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
