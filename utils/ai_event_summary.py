"""AI Event Summary Generator for CaseScope

Generates a detailed summary of an incident based on analyst-tagged events
from ClickHouse, without relying on EDR reports.

The summary is technical but worded for non-technical readers with examples.
"""
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

from flask import current_app

from models.case import Case
from utils.clickhouse import get_client
from config import Config


class AIEventSummaryGenerator:
    """Generates AI-powered incident summaries from analyst-tagged events"""
    
    def __init__(self, case_id: int):
        self.case = Case.query.get(case_id)
        if not self.case:
            raise ValueError(f"Case {case_id} not found")
        
        self.events: List[Dict] = []
        self.summary: str = ""
    
    def _fetch_tagged_events(self) -> List[Dict]:
        """Fetch all analyst-tagged events for the case from ClickHouse"""
        client = get_client()
        query = """
            SELECT timestamp_utc, artifact_type, source_host, username,
                   event_id, process_name, command_line, rule_title,
                   mitre_tactics, mitre_tags, analyst_tags, analyst_notes,
                   target_path, reg_key, src_ip, dst_ip, channel, level,
                   parent_process
            FROM events
            WHERE case_id = {case_id:UInt32} AND analyst_tagged = true
            ORDER BY timestamp_utc ASC
        """
        result = client.query(query, parameters={'case_id': self.case.id})
        
        events = []
        for row in result.result_rows:
            (ts_utc, artifact, host, user, eid, proc, cmd, rule,
             mitre_tac, mitre_tag, tags, notes, target, reg, srcip, dstip,
             channel, level, parent) = row
            
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
        
        self.events = events
        return events
    
    def _build_event_context(self) -> str:
        """Build a structured context string from events for AI analysis"""
        if not self.events:
            return "No analyst-tagged events found."
        
        lines = []
        lines.append(f"INCIDENT TIMELINE - {len(self.events)} Analyst-Tagged Events")
        lines.append(f"Timespan: {self.events[0]['timestamp']} to {self.events[-1]['timestamp']}")
        lines.append("")
        
        # Group events by host
        hosts = set(e['host'] for e in self.events if e['host'])
        users = set(e['user'] for e in self.events if e['user'])
        lines.append(f"Affected Systems: {', '.join(hosts)}")
        lines.append(f"Users Involved: {', '.join(users)}")
        lines.append("")
        lines.append("DETAILED EVENT SEQUENCE:")
        lines.append("-" * 60)
        
        for i, event in enumerate(self.events, 1):
            ts = event['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if event['timestamp'] else 'Unknown'
            lines.append(f"\n[{i}] {ts}")
            lines.append(f"    Host: {event['host'] or 'Unknown'}")
            lines.append(f"    User: {event['user'] or 'Unknown'}")
            lines.append(f"    Process: {event['process'] or 'Unknown'}")
            
            if event['command_line']:
                # Truncate very long commands for context
                cmd = event['command_line']
                if len(cmd) > 300:
                    cmd = cmd[:300] + "..."
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
                lines.append(f"    Analyst Note: {event['analyst_notes']}")
        
        return '\n'.join(lines)
    
    def _extract_key_indicators(self) -> Dict:
        """Extract key indicators from events for context"""
        indicators = {
            'external_ips': set(),
            'suspicious_processes': set(),
            'file_paths': set(),
            'commands_of_interest': []
        }
        
        for event in self.events:
            # External IPs (non-private)
            if event['dst_ip'] and not event['dst_ip'].startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '172.30.', '172.31.')):
                indicators['external_ips'].add(event['dst_ip'])
            
            # Suspicious processes
            proc = (event['process'] or '').lower()
            if proc in ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'regsvr32.exe']:
                indicators['suspicious_processes'].add(event['process'])
            
            # File paths
            if event['target_path']:
                indicators['file_paths'].add(event['target_path'])
            
            # Commands with interesting content
            cmd = event['command_line'] or ''
            if any(keyword in cmd.lower() for keyword in ['iex', 'invoke-', 'bypass', '-enc', 'hidden', 'copy', 'finger']):
                indicators['commands_of_interest'].append(cmd[:200])
        
        return indicators
    
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
            if current_app:
                current_app.logger.error(f"AI generation error: {e}")
            return f"[Error generating content: {str(e)}]"
    
    def generate_summary(self) -> str:
        """Generate a 3-5 paragraph technical but accessible summary"""
        # Fetch events if not already fetched
        if not self.events:
            self._fetch_tagged_events()
        
        if not self.events:
            return "No analyst-tagged events were found for this case."
        
        event_context = self._build_event_context()
        indicators = self._extract_key_indicators()
        
        # Build indicator context
        indicator_text = ""
        if indicators['external_ips']:
            indicator_text += f"\nExternal IPs observed: {', '.join(indicators['external_ips'])}"
        if indicators['suspicious_processes']:
            indicator_text += f"\nSuspicious processes used: {', '.join(indicators['suspicious_processes'])}"
        
        prompt = f"""You are a digital forensics expert writing an incident summary for a client.

TASK: Analyze the following analyst-tagged events and write a detailed 3-5 paragraph summary explaining what happened during this security incident.

REQUIREMENTS:
1. The summary should be TECHNICAL but written so a non-technical business executive can understand it
2. Use concrete EXAMPLES from the events (specific commands, file paths, times)
3. Explain WHAT happened, in what ORDER, and what the IMPACT was
4. Explain any technical terms in plain language (e.g., "PowerShell - a scripting language built into Windows")
5. Write in third person (e.g., "the attacker" or "the threat actor")
6. Be detailed and specific - reference actual data from the events
7. Structure the summary as:
   - Paragraph 1: Overview of what happened and when
   - Paragraph 2: How the attack began (initial access)
   - Paragraph 3: What the attacker did after gaining access (actions and tools)
   - Paragraph 4: What information or systems were affected
   - Paragraph 5 (optional): Key indicators that show this was malicious

CASE: {self.case.name} - {self.case.company}

KEY INDICATORS IDENTIFIED:
{indicator_text}

{event_context}

Write the incident summary (3-5 detailed paragraphs, approximately 500-700 words):"""

        self.summary = self._generate_ai_content(prompt, timeout=240)
        return self.summary
    
    def get_result(self) -> Dict:
        """Get complete result with metadata"""
        if not self.summary:
            self.generate_summary()
        
        return {
            'success': True,
            'case_name': self.case.name,
            'case_company': self.case.company,
            'event_count': len(self.events),
            'time_range': {
                'start': self.events[0]['timestamp'].isoformat() if self.events else None,
                'end': self.events[-1]['timestamp'].isoformat() if self.events else None
            },
            'affected_hosts': list(set(e['host'] for e in self.events if e['host'])),
            'affected_users': list(set(e['user'] for e in self.events if e['user'])),
            'summary': self.summary
        }


def generate_event_summary(case_id: int) -> Dict:
    """Convenience function to generate an event-based summary"""
    generator = AIEventSummaryGenerator(case_id)
    return generator.get_result()
