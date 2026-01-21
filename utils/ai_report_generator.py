"""AI Report Generator for CaseScope

Generates DFIR reports using AI analysis of case data.
"""
import os
import requests
from datetime import datetime
from typing import Dict, Optional, Callable

from docxtpl import DocxTemplate
from flask import current_app

from models.database import db
from models.case import Case
from models.ioc import IOC
from models.report_template import ReportTemplate
from utils.clickhouse import get_client
from config import Config


class AIReportGenerator:
    """Generates AI-powered DFIR reports"""
    
    def __init__(self, case_id: int, template_id: Optional[int] = None, 
                 progress_callback: Optional[Callable] = None):
        self.case = Case.query.get(case_id)
        if not self.case:
            raise ValueError(f"Case {case_id} not found")
        
        self.template_id = template_id
        self.progress_callback = progress_callback or (lambda step, msg: None)
        self.temp_folder = None
        self.sections = {}
    
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
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary from case data"""
        prompt = f"""You are a digital forensics consultant writing a final incident report for a CLIENT.
Write a professional 4-5 paragraph executive summary.

REQUIREMENTS:
- Technical but understandable by non-technical executives
- Written in third person (say "the organization" not "our")
- Focus on: what happened, what was affected, what remediation was performed, recommendations

CASE: {self.case.name} - {self.case.company}

EDR FINDINGS:
{self.case.edr_report or 'No EDR report available'}

CONTAINMENT ACTIONS:
{self.case.containment_actions or 'Not documented'}

ERADICATION ACTIONS:
{self.case.eradication_actions or 'Not documented'}

RECOVERY ACTIONS:
{self.case.recovery_actions or 'Not documented'}

LESSONS LEARNED:
{self.case.lessons_learned or 'Not documented'}

Write the executive summary:"""
        
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
        """Generate 'What Happened' summary"""
        prompt = f"""Write ONE paragraph (4-5 sentences) explaining what happened in this security incident.

REQUIREMENTS:
- Formal, professional tone for business audience
- Accessible to non-technical executives
- Third person (say "the organization" not "our")
- Focus on: when, who was affected, what the attacker achieved, what was done

INCIDENT: {self.case.edr_report[:2000] if self.case.edr_report else 'Security incident detected'}

Write the paragraph:"""
        
        content = self._generate_ai_content(prompt)
        self._save_section('summary_what', content)
        return content
    
    def generate_summary_why(self) -> str:
        """Generate 'Why It Happened' summary"""
        prompt = f"""Write ONE paragraph (4-5 sentences) explaining WHY this security incident happened.

REQUIREMENTS:
- Formal, professional tone
- Accessible to non-technical executives
- Third person
- Focus on root causes and gaps exploited
- Be constructive, not blaming

INCIDENT: {self.case.edr_report[:2000] if self.case.edr_report else 'Security incident detected'}

Write the "Why It Happened" paragraph:"""
        
        content = self._generate_ai_content(prompt)
        self._save_section('summary_why', content)
        return content
    
    def generate_summary_how(self) -> str:
        """Generate 'How To Prevent' summary"""
        prompt = f"""Write ONE paragraph (4-5 sentences) explaining what could have PREVENTED this incident.

REQUIREMENTS:
- Formal, professional tone
- Accessible to non-technical executives
- Third person
- Focus on actionable preventive measures
- Be constructive and forward-looking

INCIDENT: {self.case.edr_report[:2000] if self.case.edr_report else 'Security incident detected'}
LESSONS LEARNED: {self.case.lessons_learned or 'Not documented'}

Write the "How To Prevent" paragraph:"""
        
        content = self._generate_ai_content(prompt)
        self._save_section('summary_how', content)
        return content
    
    def generate_report(self) -> Dict:
        """Generate complete report and return result info"""
        self._create_temp_folder()
        
        total_steps = 7
        
        # Step 1: Executive Summary
        self._update_progress(1, total_steps, "Generating Executive Summary...")
        self.generate_executive_summary()
        
        # Step 2: Timeline
        self._update_progress(2, total_steps, "Generating Timeline...")
        self.generate_timeline()
        
        # Step 3: IOC List
        self._update_progress(3, total_steps, "Generating IOC List...")
        self.generate_ioc_list()
        
        # Step 4: What Happened
        self._update_progress(4, total_steps, "Generating 'What Happened'...")
        self.generate_summary_what()
        
        # Step 5: Why It Happened
        self._update_progress(5, total_steps, "Generating 'Why It Happened'...")
        self.generate_summary_why()
        
        # Step 6: How To Prevent
        self._update_progress(6, total_steps, "Generating 'How To Prevent'...")
        self.generate_summary_how()
        
        # Step 7: Generate Word Document
        self._update_progress(7, total_steps, "Generating Word document...")
        output_path = self._generate_word_document()
        
        return {
            'success': True,
            'output_path': output_path,
            'filename': os.path.basename(output_path),
            'temp_folder': self.temp_folder,
            'sections': list(self.sections.keys())
        }
    
    def _generate_word_document(self) -> str:
        """Generate Word document from template"""
        # Find template
        if self.template_id:
            template = ReportTemplate.query.get(self.template_id)
        else:
            template = ReportTemplate.get_default_template()
        
        if not template:
            # Fallback to first available template
            templates = ReportTemplate.get_active_templates()
            if templates:
                template = templates[0]
        
        if not template:
            raise ValueError("No report template available")
        
        template_path = template.get_template_path()
        if not os.path.exists(template_path):
            raise ValueError(f"Template file not found: {template_path}")
        
        doc = DocxTemplate(template_path)
        
        # Build context from generated sections
        template_context = {
            'client_name': self.case.company,
            'today_date': datetime.now().strftime('%B %d, %Y'),
            'executive_summary': self.sections.get('executive_summary', ''),
            'timeline': self.sections.get('timeline', ''),
            'ioc_list': self.sections.get('ioc_list', ''),
            'summary_what': self.sections.get('summary_what', ''),
            'summary_why': self.sections.get('summary_why', ''),
            'summary_how': self.sections.get('summary_how', ''),
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
