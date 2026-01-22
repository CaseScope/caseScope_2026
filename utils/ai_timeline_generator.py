"""AI Timeline Report Generator for CaseScope

Generates detailed timeline reports using AI analysis of analyst-tagged events,
EDR reports, and IOCs with intelligent event grouping.

Event Grouping Rules:
- Only group "like" events if they precede unlike events
- Example: 4624 events across 10 systems from 9:10-9:16 can be grouped IF
  no other different event happened in that window
"""
import os
import requests
from datetime import datetime, timedelta
from typing import Dict, Optional, Callable, List, Tuple, Any
from collections import defaultdict

from docxtpl import DocxTemplate
from flask import current_app

from models.database import db
from models.case import Case
from models.ioc import IOC
from models.report_template import ReportTemplate
from utils.clickhouse import get_client
from utils.markdown_to_docx import markdown_to_subdoc
from config import Config


class TimelineEvent:
    """Represents a single timeline event for grouping analysis"""
    
    def __init__(self, row: Tuple):
        """Initialize from ClickHouse row"""
        (self.timestamp_utc, self.artifact_type, self.source_host, self.username,
         self.event_id, self.process_name, self.command_line, self.rule_title,
         self.mitre_tactics, self.mitre_tags, self.analyst_tags, self.analyst_notes,
         self.target_path, self.reg_key, self.src_ip, self.dst_ip, self.channel,
         self.level, self.parent_process) = row
        
        # Normalize for comparison
        self.mitre_tactics = list(self.mitre_tactics) if self.mitre_tactics else []
        self.mitre_tags = list(self.mitre_tags) if self.mitre_tags else []
        self.analyst_tags = list(self.analyst_tags) if self.analyst_tags else []
    
    def get_event_signature(self) -> str:
        """Generate a signature for event similarity comparison.
        
        Events with the same signature are candidates for grouping.
        Signature considers: artifact type, process name, rule title, and general action type.
        """
        # Normalize process name
        proc = (self.process_name or '').lower().split('\\')[-1].split('.')[0]
        
        # Normalize rule title
        rule = (self.rule_title or '').lower()[:50] if self.rule_title else ''
        
        # Categorize by general action
        action = self._categorize_action()
        
        return f"{self.artifact_type}|{proc}|{action}|{rule}"
    
    def _categorize_action(self) -> str:
        """Categorize the event into a general action type"""
        cmd = (self.command_line or '').lower()
        proc = (self.process_name or '').lower()
        
        # Discovery commands
        discovery_procs = ['whoami', 'ipconfig', 'netstat', 'arp', 'getmac', 
                          'systeminfo', 'net', 'nltest', 'dsquery', 'nslookup']
        if any(d in proc for d in discovery_procs):
            return 'discovery'
        
        # PowerShell discovery patterns
        if 'powershell' in proc:
            if any(p in cmd for p in ['get-computer', 'get-process', 'get-service', 
                                       'get-net', 'get-volume', 'whoami', 'get-psdrive']):
                return 'discovery'
            if 'iex' in cmd or 'invoke-expression' in cmd:
                return 'execution'
            return 'powershell'
        
        # Command execution
        if 'cmd.exe' in proc:
            return 'cmd_execution'
        
        # Default to artifact type
        return self.artifact_type or 'other'
    
    def get_brief_description(self) -> str:
        """Generate a brief one-line description of this event"""
        proc = self.process_name or 'Unknown process'
        user = self.username or 'Unknown user'
        host = self.source_host or 'Unknown host'
        
        # Extract meaningful action from command line
        if self.command_line:
            cmd = self.command_line[:100]
            # Simplify common patterns
            if 'powershell' in proc.lower():
                if 'Get-Process' in self.command_line:
                    return f"PowerShell enumerated running processes"
                if 'Get-Service' in self.command_line:
                    return f"PowerShell enumerated services"
                if 'Get-ComputerInfo' in self.command_line:
                    return f"PowerShell gathered computer information"
                if 'Get-Net' in self.command_line:
                    return f"PowerShell enumerated network configuration"
                if 'whoami' in self.command_line.lower():
                    return f"PowerShell executed whoami for user context"
                if 'iex' in self.command_line.lower():
                    return f"PowerShell executed obfuscated command"
            if 'cmd.exe' in proc.lower():
                if 'copy' in self.command_line.lower():
                    return f"Command prompt copied files"
                if 'finger.exe' in self.command_line.lower():
                    return f"Finger utility used for payload delivery"
        
        # Use rule title if available
        if self.rule_title:
            return self.rule_title
        
        # Default description
        return f"{user} executed {proc} on {host}"
    
    def get_mitre_string(self) -> str:
        """Get MITRE ATT&CK notation string"""
        parts = []
        if self.mitre_tactics:
            parts.extend(self.mitre_tactics)
        if self.mitre_tags:
            parts.extend(self.mitre_tags)
        return ', '.join(parts) if parts else ''


class EventGroup:
    """Represents a group of similar events that occurred together"""
    
    def __init__(self, first_event: TimelineEvent):
        self.events: List[TimelineEvent] = [first_event]
        self.signature = first_event.get_event_signature()
    
    @property
    def start_time(self) -> datetime:
        return self.events[0].timestamp_utc
    
    @property
    def end_time(self) -> datetime:
        return self.events[-1].timestamp_utc
    
    @property
    def count(self) -> int:
        return len(self.events)
    
    @property
    def is_grouped(self) -> bool:
        return len(self.events) > 1
    
    def add_event(self, event: TimelineEvent) -> bool:
        """Try to add an event to this group. Returns True if added."""
        if event.get_event_signature() == self.signature:
            self.events.append(event)
            return True
        return False
    
    def get_unique_hosts(self) -> List[str]:
        """Get list of unique hosts in this group"""
        return list(set(e.source_host for e in self.events if e.source_host))
    
    def get_unique_users(self) -> List[str]:
        """Get list of unique users in this group"""
        return list(set(e.username for e in self.events if e.username))
    
    def get_timeline_entry(self) -> Dict[str, Any]:
        """Generate timeline entry for this group"""
        first = self.events[0]
        
        if self.is_grouped:
            # Grouped event entry
            hosts = self.get_unique_hosts()
            users = self.get_unique_users()
            
            # Build summary description
            descriptions = [e.get_brief_description() for e in self.events]
            unique_descs = list(dict.fromkeys(descriptions))  # Preserve order, remove dupes
            summary = unique_descs[0] if len(unique_descs) == 1 else f"{len(self.events)} similar events"
            
            # Collect all MITRE tags
            all_tactics = set()
            all_tags = set()
            for e in self.events:
                all_tactics.update(e.mitre_tactics)
                all_tags.update(e.mitre_tags)
            
            return {
                'type': 'grouped',
                'start_time': self.start_time,
                'end_time': self.end_time,
                'count': self.count,
                'hosts': hosts,
                'users': users,
                'description': summary,
                'details': unique_descs,
                'mitre_tactics': list(all_tactics),
                'mitre_tags': list(all_tags),
                'processes': list(set(e.process_name for e in self.events if e.process_name))
            }
        else:
            # Single event entry
            return {
                'type': 'single',
                'timestamp': first.timestamp_utc,
                'host': first.source_host,
                'user': first.username,
                'description': first.get_brief_description(),
                'process': first.process_name,
                'command': first.command_line[:200] if first.command_line else None,
                'mitre_tactics': first.mitre_tactics,
                'mitre_tags': first.mitre_tags,
                'analyst_notes': first.analyst_notes
            }


class AITimelineGenerator:
    """Generates AI-powered timeline reports with intelligent event grouping"""
    
    # Maximum time gap (seconds) to consider events as part of same group
    GROUP_TIME_WINDOW = 120  # 2 minutes
    
    def __init__(self, case_id: int, template_id: Optional[int] = None,
                 progress_callback: Optional[Callable] = None):
        self.case = Case.query.get(case_id)
        if not self.case:
            raise ValueError(f"Case {case_id} not found")
        
        self.template_id = template_id
        self.progress_callback = progress_callback or (lambda step, total, msg: None)
        self.temp_folder = None
        self.sections = {}
        self.events: List[TimelineEvent] = []
        self.groups: List[EventGroup] = []
        self.iocs: List[IOC] = []
    
    def _update_progress(self, step: int, total: int, message: str):
        """Update progress callback"""
        self.progress_callback(step, total, message)
    
    def _generate_ai_content(self, prompt: str, timeout: int = 180) -> str:
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
        self.temp_folder = f"/opt/casescope/temp/{self.case.uuid}/timeline_report_{ts}"
        os.makedirs(self.temp_folder, exist_ok=True)
        return self.temp_folder
    
    def _save_section(self, name: str, content: str):
        """Save a section to temp folder and store in memory"""
        self.sections[name] = content
        if self.temp_folder:
            with open(f"{self.temp_folder}/{name}.txt", 'w') as f:
                f.write(content)
    
    def _fetch_tagged_events(self) -> List[TimelineEvent]:
        """Fetch all analyst-tagged events for the case"""
        client = get_client()
        query = """
            SELECT timestamp_utc, artifact_type, source_host, username,
                   event_id, process_name, command_line, rule_title,
                   mitre_tactics, mitre_tags, analyst_tags, analyst_notes,
                   target_path, reg_key, src_ip, dst_ip, channel,
                   level, parent_process
            FROM events
            WHERE case_id = {case_id:UInt32} AND analyst_tagged = true
            ORDER BY timestamp_utc ASC
        """
        result = client.query(query, parameters={'case_id': self.case.id})
        
        events = []
        for row in result.result_rows:
            events.append(TimelineEvent(row))
        
        self.events = events
        return events
    
    def _fetch_iocs(self) -> List[IOC]:
        """Fetch all IOCs for the case"""
        self.iocs = IOC.query.filter_by(case_id=self.case.id, hidden=False).all()
        return self.iocs
    
    def _group_events(self) -> List[EventGroup]:
        """Group events using the intelligent grouping algorithm.
        
        Rules:
        1. Only group "like" events (same signature) 
        2. Only group if they precede unlike events (no different event in between)
        3. Respect time window (default 2 minutes)
        """
        if not self.events:
            return []
        
        groups = []
        current_group = EventGroup(self.events[0])
        
        for i, event in enumerate(self.events[1:], 1):
            time_gap = (event.timestamp_utc - current_group.end_time).total_seconds()
            same_signature = event.get_event_signature() == current_group.signature
            
            if same_signature and time_gap <= self.GROUP_TIME_WINDOW:
                # Same type of event within time window - add to group
                current_group.add_event(event)
            else:
                # Different event or time gap too large - finalize current group
                groups.append(current_group)
                current_group = EventGroup(event)
        
        # Don't forget the last group
        groups.append(current_group)
        
        self.groups = groups
        return groups
    
    def _format_timestamp(self, ts: datetime) -> str:
        """Format timestamp for display"""
        if ts:
            return ts.strftime('%m/%d/%Y at %H:%M:%S')
        return 'Unknown time'
    
    def _format_time_range(self, start: datetime, end: datetime) -> str:
        """Format time range for display"""
        if start.date() == end.date():
            return f"{start.strftime('%m/%d/%Y')} at {start.strftime('%H:%M:%S')}-{end.strftime('%H:%M:%S')}"
        else:
            return f"{self._format_timestamp(start)} to {self._format_timestamp(end)}"
    
    def _build_raw_timeline(self) -> str:
        """Build the raw timeline text from grouped events"""
        lines = []
        
        for group in self.groups:
            entry = group.get_timeline_entry()
            
            if entry['type'] == 'grouped':
                # Grouped events
                time_str = self._format_time_range(entry['start_time'], entry['end_time'])
                hosts = ', '.join(entry['hosts'][:5])
                if len(entry['hosts']) > 5:
                    hosts += f" (+{len(entry['hosts'])-5} more)"
                users = ', '.join(entry['users'][:5])
                
                mitre = ''
                if entry['mitre_tactics'] or entry['mitre_tags']:
                    mitre_parts = entry['mitre_tactics'] + entry['mitre_tags']
                    mitre = f" - MITRE ({', '.join(mitre_parts[:3])})"
                
                lines.append(f"{time_str}: {entry['description']} ({entry['count']} events on {hosts} by {users}){mitre}")
                
                # Add details as bullet points
                for detail in entry['details'][:5]:
                    if detail != entry['description']:
                        lines.append(f"  * {detail}")
            else:
                # Single event
                time_str = self._format_timestamp(entry['timestamp'])
                mitre = ''
                if entry['mitre_tactics'] or entry['mitre_tags']:
                    mitre_parts = entry['mitre_tactics'] + entry['mitre_tags']
                    mitre = f" - MITRE ({', '.join(mitre_parts[:3])})"
                
                lines.append(f"{time_str}: {entry['description']}{mitre}")
                
                # Add command line snippet if meaningful
                if entry['command'] and len(entry['command']) > 10:
                    cmd_preview = entry['command'][:150]
                    if len(entry['command']) > 150:
                        cmd_preview += "..."
                    lines.append(f"  * Command: {cmd_preview}")
                
                # Add analyst notes if present
                if entry.get('analyst_notes'):
                    lines.append(f"  * Note: {entry['analyst_notes']}")
        
        return '\n'.join(lines)
    
    def _build_ioc_context(self) -> str:
        """Build IOC context for AI prompt"""
        if not self.iocs:
            return "No IOCs documented."
        
        ioc_lines = []
        for ioc in self.iocs[:30]:  # Limit to prevent prompt overflow
            ioc_lines.append(f"- {ioc.ioc_type}: {ioc.value}")
            if ioc.notes:
                ioc_lines.append(f"  Notes: {ioc.notes}")
        
        return '\n'.join(ioc_lines)
    
    def generate_ai_timeline(self) -> str:
        """Generate AI-enhanced detailed timeline"""
        raw_timeline = self._build_raw_timeline()
        ioc_context = self._build_ioc_context()
        
        if not raw_timeline:
            return "No analyst-tagged events found for timeline generation."
        
        prompt = f"""You are writing a detailed forensic timeline for an incident report.

TASK: Enhance and format this raw timeline into a professional incident timeline.
Add context, explanations of attacker techniques, and correlate with the IOCs.

FORMAT REQUIREMENTS:
1. Each entry: TIMESTAMP | Brief event description
2. For grouped events: TIMESTAMP_START to TIMESTAMP_END | Description (count events, hosts, users involved)
3. Below each entry, add a bullet point (*) explaining the significance
4. Reference IOCs when relevant (e.g., "connecting to malicious IP 149.248.78.114")
5. Note MITRE ATT&CK techniques where applicable

RAW TIMELINE DATA:
{raw_timeline}

EDR ANALYSIS CONTEXT:
{self.case.edr_report[:3000] if self.case.edr_report else 'Not available'}

IOCs IN THIS CASE:
{ioc_context}

Write the enhanced timeline (maintain chronological order, no headers):"""
        
        content = self._generate_ai_content(prompt, timeout=240)
        self._save_section('timeline_detailed', content)
        return content
    
    def generate_timeline_summary(self) -> str:
        """Generate a brief executive summary of the timeline"""
        if not self.groups:
            return "No events to summarize."
        
        # Calculate key stats
        total_events = sum(g.count for g in self.groups)
        unique_hosts = set()
        unique_users = set()
        for g in self.groups:
            for e in g.events:
                if e.source_host:
                    unique_hosts.add(e.source_host)
                if e.username:
                    unique_users.add(e.username)
        
        start_time = self.groups[0].start_time
        end_time = self.groups[-1].end_time
        duration = end_time - start_time
        
        prompt = f"""Write a 2-3 sentence executive summary of this incident timeline.

FACTS:
- Time span: {self._format_timestamp(start_time)} to {self._format_timestamp(end_time)} ({duration})
- Total events: {total_events}
- Affected hosts: {', '.join(unique_hosts)}
- Users involved: {', '.join(unique_users)}
- Number of activity phases: {len(self.groups)}

EDR SUMMARY: {self.case.edr_report[:1500] if self.case.edr_report else 'Not available'}

Write a brief professional summary (2-3 sentences, third person):"""
        
        content = self._generate_ai_content(prompt, timeout=60)
        self._save_section('timeline_summary', content)
        return content
    
    def generate_report(self) -> Dict:
        """Generate complete timeline report and return result info"""
        self._create_temp_folder()
        
        total_steps = 6
        
        # Step 1: Fetch tagged events
        self._update_progress(1, total_steps, "Fetching analyst-tagged events...")
        self._fetch_tagged_events()
        
        if not self.events:
            return {
                'success': False,
                'error': 'No analyst-tagged events found for timeline generation.'
            }
        
        # Step 2: Fetch IOCs
        self._update_progress(2, total_steps, "Fetching IOCs...")
        self._fetch_iocs()
        
        # Step 3: Group events
        self._update_progress(3, total_steps, "Analyzing and grouping events...")
        self._group_events()
        
        # Step 4: Generate AI timeline
        self._update_progress(4, total_steps, "Generating AI-enhanced timeline...")
        self.generate_ai_timeline()
        
        # Step 5: Generate summary
        self._update_progress(5, total_steps, "Generating timeline summary...")
        self.generate_timeline_summary()
        
        # Step 6: Generate Word Document
        self._update_progress(6, total_steps, "Generating Word document...")
        output_path = self._generate_word_document()
        
        return {
            'success': True,
            'output_path': output_path,
            'filename': os.path.basename(output_path),
            'temp_folder': self.temp_folder,
            'sections': list(self.sections.keys()),
            'stats': {
                'total_events': len(self.events),
                'event_groups': len(self.groups),
                'iocs': len(self.iocs)
            }
        }
    
    def _generate_word_document(self) -> str:
        """Generate Word document from template"""
        from models.report_template import ReportType
        
        # Find timeline template
        template = None
        if self.template_id:
            template = ReportTemplate.query.get(self.template_id)
        
        if not template:
            # Look for timeline template by report type
            template = ReportTemplate.get_default_template_for_type(ReportType.TIMELINE)
        
        if not template:
            # Fall back to any available template
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
        
        # Build template context - variable names must match template placeholders
        # Convert markdown sections to Word-formatted subdocuments
        # This converts ## to Heading 3, * to bullets, **bold**, etc.
        template_context = {
            'client_name': self.case.company,
            'case_name': self.case.name,
            'today_date': datetime.now().strftime('%B %d, %Y'),
            'timeline_summary': markdown_to_subdoc(doc, self.sections.get('timeline_summary', '')),
            'detailed_timeline': markdown_to_subdoc(doc, self.sections.get('timeline_detailed', '')),
            'timeline': markdown_to_subdoc(doc, self.sections.get('timeline_detailed', '')),
            'total_events': len(self.events),
            'event_groups': len(self.groups),
            'ioc_count': len(self.iocs),
        }
        
        doc.render(template_context)
        
        # Save to reports folder
        reports_folder = f'/opt/casescope/storage/{self.case.uuid}/reports'
        os.makedirs(reports_folder, exist_ok=True)
        
        filename = f"Timeline_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"
        output_path = os.path.join(reports_folder, filename)
        
        doc.save(output_path)
        
        return output_path


def generate_timeline_report(case_id: int, template_id: Optional[int] = None) -> Dict:
    """Convenience function to generate a timeline report"""
    generator = AITimelineGenerator(case_id, template_id)
    return generator.generate_report()
