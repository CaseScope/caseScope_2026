"""AI Timeline Report Generator for CaseScope

Generates detailed timeline reports using AI analysis of analyst-tagged events,
EDR reports, and IOCs with intelligent event grouping.

Event Grouping Rules:
- Only group "like" events if they precede unlike events
- Example: 4624 events across 10 systems from 9:10-9:16 can be grouped IF
  no other different event happened in that window
"""
import os
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
from utils.markdown_to_docx import clean_markdown


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
    
    # Limits for large datasets
    MAX_EVENTS_FOR_FULL_PROCESSING = 500  # Above this, use smart sampling
    MAX_GROUPS_FOR_AI = 150  # Maximum groups to send to AI
    MAX_RAW_TIMELINE_CHARS = 15000  # Maximum characters for raw timeline
    
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
        self._model_name = self._resolve_model_name()
    
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
    
    def _generate_ai_content(self, prompt: str, timeout: int = 180) -> str:
        """Send prompt to AI and get response via configured provider"""
        try:
            from utils.ai_providers import get_llm_provider
            provider = get_llm_provider()
            result = provider.generate(prompt=prompt, temperature=0.7, max_tokens=4000)
            if result.get('success'):
                return result.get('response', '')
            current_app.logger.error(f"AI generation error: {result.get('error')}")
            return f"[Error generating content: {result.get('error', 'Unknown')}]"
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
    
    def _pre_aggregate_events(self, events: List[TimelineEvent], time_window_minutes: int = 5) -> List[TimelineEvent]:
        """Pre-aggregate events by activity type within time windows.
        
        For very large datasets, aggregates events with same signature
        within 5-minute windows before the main grouping pass.
        """
        if len(events) <= self.MAX_EVENTS_FOR_FULL_PROCESSING:
            return events
        
        current_app.logger.info(f"Pre-aggregating {len(events)} events for timeline")
        
        # Group by signature + time bucket
        buckets = defaultdict(list)
        for event in events:
            bucket_time = event.timestamp_utc.replace(second=0, microsecond=0)
            bucket_time = bucket_time.replace(minute=(bucket_time.minute // time_window_minutes) * time_window_minutes)
            sig = event.get_event_signature()
            key = (sig, str(bucket_time))
            buckets[key].append(event)
        
        # Create representative events for each bucket
        aggregated = []
        for (sig, bucket), bucket_events in buckets.items():
            if len(bucket_events) == 1:
                aggregated.append(bucket_events[0])
            else:
                # Take first event as representative, but mark it with aggregate info
                rep = bucket_events[0]
                rep._aggregate_count = len(bucket_events)
                rep._aggregate_end_time = bucket_events[-1].timestamp_utc
                rep._aggregate_hosts = list(set(e.source_host for e in bucket_events if e.source_host))
                rep._aggregate_users = list(set(e.username for e in bucket_events if e.username))
                # Collect any analyst notes
                notes = [e.analyst_notes for e in bucket_events if e.analyst_notes]
                if notes:
                    rep.analyst_notes = notes[0]  # Keep first note
                aggregated.append(rep)
        
        # Sort by timestamp
        aggregated.sort(key=lambda e: e.timestamp_utc)
        current_app.logger.info(f"Pre-aggregated to {len(aggregated)} representative events")
        return aggregated
    
    def _group_events(self) -> List[EventGroup]:
        """Group events using the intelligent grouping algorithm.
        
        Rules:
        1. Only group "like" events (same signature) 
        2. Only group if they precede unlike events (no different event in between)
        3. Respect time window (default 2 minutes)
        4. For large datasets, pre-aggregate first
        """
        if not self.events:
            return []
        
        # Pre-aggregate if too many events
        events_to_process = self._pre_aggregate_events(self.events)
        
        groups = []
        current_group = EventGroup(events_to_process[0])
        
        for i, event in enumerate(events_to_process[1:], 1):
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
        self._original_event_count = len(self.events)
        return groups
    
    def _smart_sample_groups(self, groups: List[EventGroup]) -> List[EventGroup]:
        """Smart sample groups if there are too many for AI processing.
        
        Strategy:
        1. Always include groups with analyst notes
        2. Ensure rule/activity type diversity
        3. Sample evenly across timespan
        """
        if len(groups) <= self.MAX_GROUPS_FOR_AI:
            return groups
        
        current_app.logger.info(f"Smart sampling {len(groups)} groups down to {self.MAX_GROUPS_FOR_AI}")
        
        # Separate priority groups (with analyst notes)
        priority = []
        regular = []
        for g in groups:
            has_notes = any(e.analyst_notes for e in g.events)
            if has_notes:
                priority.append(g)
            else:
                regular.append(g)
        
        # Reserve 40% for priority, 60% for sampled
        priority_budget = min(len(priority), int(self.MAX_GROUPS_FOR_AI * 0.4))
        remaining_budget = self.MAX_GROUPS_FOR_AI - priority_budget
        
        sampled = priority[:priority_budget]
        sampled_ids = set(id(g) for g in sampled)
        
        # Ensure signature diversity - take one from each unique signature
        sig_groups = defaultdict(list)
        for g in regular:
            sig_groups[g.signature].append(g)
        
        diversity_budget = min(len(sig_groups), remaining_budget // 3)
        for sig, sig_group_list in list(sig_groups.items())[:diversity_budget]:
            if sig_group_list and id(sig_group_list[0]) not in sampled_ids:
                sampled.append(sig_group_list[0])
                sampled_ids.add(id(sig_group_list[0]))
                remaining_budget -= 1
        
        # Fill remaining with evenly distributed samples
        unsampled = [g for g in regular if id(g) not in sampled_ids]
        if unsampled and remaining_budget > 0:
            step = max(1, len(unsampled) // remaining_budget)
            for i in range(0, len(unsampled), step):
                if len(sampled) >= self.MAX_GROUPS_FOR_AI:
                    break
                sampled.append(unsampled[i])
        
        # Sort by time
        sampled.sort(key=lambda g: g.start_time)
        return sampled
    
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
        """Build the raw timeline text from grouped events.
        
        Uses smart sampling if there are too many groups.
        """
        # Apply smart sampling if needed
        groups_to_process = self._smart_sample_groups(self.groups)
        
        lines = []
        total_char_count = 0
        
        for group in groups_to_process:
            entry = group.get_timeline_entry()
            
            # Check for pre-aggregated events (from _pre_aggregate_events)
            first_event = group.events[0]
            pre_agg_count = getattr(first_event, '_aggregate_count', 1)
            pre_agg_hosts = getattr(first_event, '_aggregate_hosts', None)
            pre_agg_users = getattr(first_event, '_aggregate_users', None)
            
            if entry['type'] == 'grouped' or pre_agg_count > 1:
                # Grouped events
                time_str = self._format_time_range(entry.get('start_time', entry.get('timestamp')), 
                                                    entry.get('end_time', entry.get('timestamp')))
                
                # Use pre-aggregated info if available
                if pre_agg_hosts:
                    hosts = ', '.join(pre_agg_hosts[:5])
                    if len(pre_agg_hosts) > 5:
                        hosts += f" (+{len(pre_agg_hosts)-5} more)"
                else:
                    hosts = ', '.join(entry.get('hosts', [entry.get('host', 'Unknown')])[:5])
                
                if pre_agg_users:
                    users = ', '.join(pre_agg_users[:3])
                else:
                    users = ', '.join(entry.get('users', [entry.get('user', 'Unknown')])[:3])
                
                mitre = ''
                mitre_parts = entry.get('mitre_tactics', []) + entry.get('mitre_tags', [])
                if mitre_parts:
                    mitre = f" - MITRE ({', '.join(mitre_parts[:3])})"
                
                # Total count includes pre-aggregation
                total_count = entry.get('count', 1) * pre_agg_count
                
                line = f"{time_str}: {entry.get('description', 'Activity')} ({total_count} events on {hosts} by {users}){mitre}"
                lines.append(line)
                total_char_count += len(line)
                
                # Add details as bullet points (limit to 3)
                for detail in entry.get('details', [])[:3]:
                    if detail != entry.get('description'):
                        detail_line = f"  * {detail}"
                        lines.append(detail_line)
                        total_char_count += len(detail_line)
            else:
                # Single event
                time_str = self._format_timestamp(entry['timestamp'])
                mitre = ''
                mitre_parts = entry.get('mitre_tactics', []) + entry.get('mitre_tags', [])
                if mitre_parts:
                    mitre = f" - MITRE ({', '.join(mitre_parts[:3])})"
                
                line = f"{time_str}: {entry['description']}{mitre}"
                lines.append(line)
                total_char_count += len(line)
                
                # Add command line snippet if meaningful
                if entry.get('command') and len(entry['command']) > 10:
                    cmd_preview = entry['command'][:120]
                    if len(entry['command']) > 120:
                        cmd_preview += "..."
                    cmd_line = f"  * Command: {cmd_preview}"
                    lines.append(cmd_line)
                    total_char_count += len(cmd_line)
                
                # Add analyst notes if present
                if entry.get('analyst_notes'):
                    note_line = f"  * [ANALYST NOTE] {entry['analyst_notes']}"
                    lines.append(note_line)
                    total_char_count += len(note_line)
            
            # Stop if we're approaching character limit
            if total_char_count > self.MAX_RAW_TIMELINE_CHARS:
                remaining = len(groups_to_process) - groups_to_process.index(group) - 1
                if remaining > 0:
                    lines.append(f"\n... and {remaining} more activity groups (timeline truncated for processing)")
                break
        
        # Add sampling note if we sampled
        if len(groups_to_process) < len(self.groups):
            header = f"[Timeline: {len(groups_to_process)} key activities from {len(self.groups)} total groups, {getattr(self, '_original_event_count', len(self.events))} events]\n"
            return header + '\n'.join(lines)
        
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
        
        # Build incident context - prioritize attack description
        incident_context = ""
        if self.case.attack_description and self.case.attack_description.strip():
            incident_context = f"ANALYST ATTACK NARRATIVE:\n{self.case.attack_description[:2000]}\n\n"
        
        if self.case.edr_report and self.case.edr_report.strip():
            edr_limit = 2000 if incident_context else 3000
            incident_context += f"EDR ANALYSIS:\n{self.case.edr_report[:edr_limit]}"
        
        if not incident_context:
            incident_context = "No incident narrative or EDR analysis available."
        
        prompt = f"""You are a DFIR analyst writing a detailed forensic timeline for an incident report.

TASK: Convert this raw timeline into a professional, narrative incident timeline.
Explain what the attacker did at each phase, correlate with IOCs, and note attack techniques.

FORMAT - each entry should be:
MM/DD/YYYY at HH:MM:SS: Clear description of what happened
* Explanation of significance and attack technique used

For grouped/aggregated events:
MM/DD/YYYY at HH:MM-HH:MM: Description (X events across Y hosts)
* What this activity indicates about the attack

IMPORTANT:
- Entries marked [ANALYST NOTE] are especially significant - emphasize these
- Reference IOCs when relevant (IPs, hashes, domains)
- Note MITRE ATT&CK techniques where applicable
- Write for a technical but readable audience

INCIDENT CONTEXT:
{incident_context}

IOCs IN THIS CASE:
{ioc_context}

RAW TIMELINE DATA:
{raw_timeline}

Write the enhanced narrative timeline (chronological order, no section headers):"""
        
        content = self._generate_ai_content(prompt, timeout=240)
        self._save_section('timeline_detailed', content)
        return content
    
    def generate_timeline_summary(self) -> str:
        """Generate a brief executive summary of the timeline"""
        if not self.groups:
            return "No events to summarize."
        
        # Calculate key stats - use original event count if available
        total_events = getattr(self, '_original_event_count', sum(g.count for g in self.groups))
        unique_hosts = set()
        unique_users = set()
        for g in self.groups:
            for e in g.events:
                if e.source_host:
                    unique_hosts.add(e.source_host)
                if e.username:
                    unique_users.add(e.username)
                # Also check pre-aggregated hosts/users
                if hasattr(e, '_aggregate_hosts'):
                    unique_hosts.update(e._aggregate_hosts)
                if hasattr(e, '_aggregate_users'):
                    unique_users.update(e._aggregate_users)
        
        start_time = self.groups[0].start_time
        end_time = self.groups[-1].end_time
        duration = end_time - start_time
        
        # Build incident context
        incident_context = ""
        if self.case.attack_description and self.case.attack_description.strip():
            incident_context = f"ATTACK NARRATIVE: {self.case.attack_description[:1000]}\n\n"
        if self.case.edr_report and self.case.edr_report.strip():
            incident_context += f"EDR SUMMARY: {self.case.edr_report[:1000]}"
        if not incident_context:
            incident_context = "No incident narrative available."
        
        hosts_str = ', '.join(list(unique_hosts)[:10])
        if len(unique_hosts) > 10:
            hosts_str += f" (+{len(unique_hosts)-10} more)"
        
        users_str = ', '.join(list(unique_users)[:10])
        if len(unique_users) > 10:
            users_str += f" (+{len(unique_users)-10} more)"
        
        prompt = f"""Write a 2-3 sentence executive summary of this incident timeline.

FACTS:
- Time span: {self._format_timestamp(start_time)} to {self._format_timestamp(end_time)} ({duration})
- Total events analyzed: {total_events}
- Affected hosts ({len(unique_hosts)}): {hosts_str}
- Users involved ({len(unique_users)}): {users_str}
- Number of activity phases: {len(self.groups)}

{incident_context}

Write a brief professional summary (2-3 sentences, third person, focus on what happened):"""
        
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
            'ai_model': self._model_name,
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
        # Clean markdown formatting for Word insertion
        template_context = {
            'client_name': self.case.client.name if self.case.client else self.case.company,
            'case_name': self.case.name,
            'today_date': datetime.now().strftime('%B %d, %Y'),
            'timeline_summary': clean_markdown(self.sections.get('timeline_summary', '')),
            'detailed_timeline': clean_markdown(self.sections.get('timeline_detailed', '')),
            'timeline': clean_markdown(self.sections.get('timeline_detailed', '')),
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
