"""Analysis Results Formatter for CaseScope

Formats analysis results for display and export.

Supports multiple views:
- Timeline (chronological)
- By Pattern (grouped by attack type)
- By Entity (grouped by user/system)

Adapts output based on analysis mode (A/B/C/D).
"""

import logging
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import defaultdict

from models.database import db
from models.behavioral_profiles import (
    CaseAnalysisRun, AnalysisMode, AnalysisStatus,
    UserBehaviorProfile, SystemBehaviorProfile,
    PeerGroup, GapDetectionFinding, SuggestedAction
)

logger = logging.getLogger(__name__)


class AnalysisResultsFormatter:
    """
    Formats analysis results for display and export.
    
    Supports multiple views:
    - Timeline (chronological)
    - By Pattern (grouped by attack type)
    - By Entity (grouped by user/system)
    
    Adapts output based on analysis mode (A/B/C/D).
    """
    
    def __init__(self, analysis_id: str):
        """
        Args:
            analysis_id: UUID of the analysis run
        """
        self.analysis_id = analysis_id
        self._analysis_run: Optional[CaseAnalysisRun] = None
        self._gap_findings: Optional[List[GapDetectionFinding]] = None
        self._pattern_results: Optional[List] = None
        self._suggested_actions: Optional[List[SuggestedAction]] = None
    
    def _load_analysis_run(self) -> Optional[CaseAnalysisRun]:
        """Load analysis run record"""
        if self._analysis_run is None:
            self._analysis_run = CaseAnalysisRun.query.filter_by(
                analysis_id=self.analysis_id
            ).first()
        return self._analysis_run
    
    def _load_gap_findings(self) -> List[GapDetectionFinding]:
        """Load gap detection findings"""
        if self._gap_findings is None:
            run = self._load_analysis_run()
            if run:
                self._gap_findings = GapDetectionFinding.query.filter_by(
                    case_id=run.case_id,
                    analysis_id=self.analysis_id
                ).order_by(GapDetectionFinding.confidence.desc()).all()
            else:
                self._gap_findings = []
        return self._gap_findings
    
    def _load_pattern_results(self) -> List:
        """Load pattern analysis results"""
        if self._pattern_results is None:
            from models.rag import AIAnalysisResult
            run = self._load_analysis_run()
            if run:
                self._pattern_results = AIAnalysisResult.query.filter_by(
                    case_id=run.case_id,
                    analysis_id=self.analysis_id
                ).order_by(AIAnalysisResult.final_confidence.desc()).all()
            else:
                self._pattern_results = []
        return self._pattern_results
    
    def _load_suggested_actions(self) -> List[SuggestedAction]:
        """Load suggested actions"""
        if self._suggested_actions is None:
            run = self._load_analysis_run()
            if run:
                self._suggested_actions = SuggestedAction.query.filter_by(
                    case_id=run.case_id,
                    analysis_id=self.analysis_id
                ).order_by(SuggestedAction.confidence.desc()).all()
            else:
                self._suggested_actions = []
        return self._suggested_actions
    
    def get_summary(self) -> Dict[str, Any]:
        """
        High-level summary of analysis run.
        
        Returns:
            dict: Summary with statistics, severity breakdown, and top findings
        """
        run = self._load_analysis_run()
        if not run:
            return {'error': f'Analysis {self.analysis_id} not found'}
        
        gap_findings = self._load_gap_findings()
        pattern_results = self._load_pattern_results()
        actions = self._load_suggested_actions()
        
        # Calculate duration
        duration = 0
        if run.started_at and run.completed_at:
            duration = (run.completed_at - run.started_at).total_seconds()
        
        # Severity breakdown
        severity_breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for f in gap_findings:
            sev = f.severity or 'low'
            if sev in severity_breakdown:
                severity_breakdown[sev] += 1
        
        # High confidence findings
        high_confidence = sum(1 for f in gap_findings if f.confidence >= 75)
        high_confidence += sum(1 for r in pattern_results if r.final_confidence and r.final_confidence >= 75)
        
        # Top findings
        top_findings = []
        for f in gap_findings[:5]:
            top_findings.append({
                'type': 'gap',
                'id': f.id,
                'name': f.finding_type,
                'summary': f.summary,
                'severity': f.severity,
                'confidence': f.confidence,
                'entity': f.entity_value
            })
        
        # Pending actions
        pending_actions = sum(1 for a in actions if a.status == 'pending')
        
        # Mode description
        mode_descriptions = {
            'A': 'Rule-based analysis with behavioral profiling',
            'B': 'AI-enhanced analysis with behavioral profiling',
            'C': 'Rule-based analysis with threat intelligence',
            'D': 'Full analysis with AI and threat intelligence'
        }
        
        return {
            'analysis_id': self.analysis_id,
            'case_id': run.case_id,
            'mode': run.mode,
            'mode_description': mode_descriptions.get(run.mode, 'Unknown'),
            'status': run.status,
            'started_at': run.started_at.isoformat() if run.started_at else None,
            'completed_at': run.completed_at.isoformat() if run.completed_at else None,
            'duration_seconds': duration,
            'capabilities_used': {
                'behavioral_profiling': True,
                'peer_comparison': True,
                'gap_detection': True,
                'pattern_detection': True,
                'deterministic_engine': True,
                'ai_reasoning': run.mode in ['B', 'D'],
                'threat_intel': run.mode in ['C', 'D']
            },
            'statistics': {
                'users_profiled': run.users_profiled or 0,
                'systems_profiled': run.systems_profiled or 0,
                'peer_groups_created': run.peer_groups_created or 0,
                'patterns_evaluated': run.patterns_analyzed or 0,
                'total_findings': len(gap_findings) + len(pattern_results),
                'high_confidence_findings': high_confidence,
                'gap_findings': len(gap_findings),
                'pattern_findings': len(pattern_results),
                'attack_chains': run.attack_chains_found or 0
            },
            'severity_breakdown': severity_breakdown,
            'top_findings': top_findings,
            'suggested_actions_pending': pending_actions
        }
    
    def get_timeline_view(self) -> List[Dict[str, Any]]:
        """
        All findings sorted chronologically.
        
        Returns:
            list[dict]: Findings in chronological order
        """
        run = self._load_analysis_run()
        if not run:
            return []
        
        gap_findings = self._load_gap_findings()
        pattern_results = self._load_pattern_results()
        
        timeline = []
        
        # Add gap findings
        for f in gap_findings:
            timeline.append({
                'timestamp': f.time_window_start.isoformat() if f.time_window_start else None,
                'timestamp_end': f.time_window_end.isoformat() if f.time_window_end else None,
                'finding_type': 'gap',
                'finding_id': f.id,
                'name': f.finding_type,
                'summary': f.summary,
                'severity': f.severity,
                'confidence': f.confidence,
                'entities_involved': self._extract_entities_from_finding(f),
                'has_ai_reasoning': bool(f.ai_reasoning),
                'has_threat_intel': bool(f.opencti_context)
            })
        
        # Add pattern results
        for r in pattern_results:
            timeline.append({
                'timestamp': r.window_start.isoformat() if r.window_start else None,
                'timestamp_end': r.window_end.isoformat() if r.window_end else None,
                'finding_type': 'pattern',
                'finding_id': r.id,
                'name': r.pattern_name,
                'summary': f"Pattern match: {r.pattern_name} (correlation key: {r.correlation_key})",
                'severity': self._confidence_to_severity(r.final_confidence),
                'confidence': r.final_confidence,
                'entities_involved': self._extract_entities_from_correlation_key(r.correlation_key),
                'has_ai_reasoning': bool(r.ai_reasoning),
                'has_threat_intel': False
            })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x.get('timestamp') or '', reverse=True)
        
        return timeline
    
    def _extract_entities_from_finding(self, finding: GapDetectionFinding) -> List[Dict]:
        """Extract entities from a gap finding"""
        entities = []
        
        if finding.entity_type and finding.entity_value:
            entities.append({
                'type': finding.entity_type,
                'value': finding.entity_value
            })
        
        if finding.affected_entities:
            for key, value in finding.affected_entities.items():
                if isinstance(value, list):
                    for v in value[:5]:
                        entities.append({'type': key, 'value': str(v)})
                else:
                    entities.append({'type': key, 'value': str(value)})
        
        return entities[:10]  # Limit
    
    def _extract_entities_from_correlation_key(self, key: str) -> List[Dict]:
        """Extract entities from a correlation key"""
        entities = []
        if not key:
            return entities
        
        parts = key.split('|')
        for part in parts:
            if ':' in part:
                entity_type, value = part.split(':', 1)
                entities.append({'type': entity_type, 'value': value})
            else:
                entities.append({'type': 'unknown', 'value': part})
        
        return entities
    
    def _confidence_to_severity(self, confidence: float) -> str:
        """Convert confidence to severity level"""
        if not confidence:
            return 'low'
        if confidence >= 85:
            return 'critical'
        if confidence >= 70:
            return 'high'
        if confidence >= 50:
            return 'medium'
        return 'low'
    
    def get_pattern_grouped_view(self) -> Dict[str, Any]:
        """
        Findings grouped by pattern/finding type.
        
        Returns:
            dict: Findings grouped by category
        """
        run = self._load_analysis_run()
        if not run:
            return {}
        
        gap_findings = self._load_gap_findings()
        pattern_results = self._load_pattern_results()
        
        grouped = {
            'gap_detection': {
                'password_spraying': {'findings': [], 'count': 0, 'high_confidence_count': 0},
                'brute_force': {'findings': [], 'count': 0, 'high_confidence_count': 0},
                'distributed_brute_force': {'findings': [], 'count': 0, 'high_confidence_count': 0},
                'behavioral_anomaly': {'findings': [], 'count': 0, 'high_confidence_count': 0}
            },
            'pattern_detection': {}
        }
        
        # Group gap findings
        for f in gap_findings:
            finding_dict = self._format_gap_finding(f)
            
            # Determine category
            finding_type = f.finding_type or 'unknown'
            if finding_type in grouped['gap_detection']:
                grouped['gap_detection'][finding_type]['findings'].append(finding_dict)
                grouped['gap_detection'][finding_type]['count'] += 1
                if f.confidence >= 75:
                    grouped['gap_detection'][finding_type]['high_confidence_count'] += 1
            else:
                # Behavioral anomalies
                if 'anomal' in finding_type.lower():
                    grouped['gap_detection']['behavioral_anomaly']['findings'].append(finding_dict)
                    grouped['gap_detection']['behavioral_anomaly']['count'] += 1
                    if f.confidence >= 75:
                        grouped['gap_detection']['behavioral_anomaly']['high_confidence_count'] += 1
        
        # Group pattern results
        for r in pattern_results:
            pattern_id = r.pattern_id or 'unknown'
            
            if pattern_id not in grouped['pattern_detection']:
                grouped['pattern_detection'][pattern_id] = {
                    'name': r.pattern_name,
                    'findings': [],
                    'count': 0,
                    'high_confidence_count': 0
                }
            
            finding_dict = self._format_pattern_result(r)
            grouped['pattern_detection'][pattern_id]['findings'].append(finding_dict)
            grouped['pattern_detection'][pattern_id]['count'] += 1
            if r.final_confidence and r.final_confidence >= 75:
                grouped['pattern_detection'][pattern_id]['high_confidence_count'] += 1
        
        return grouped
    
    def _format_gap_finding(self, finding: GapDetectionFinding) -> Dict:
        """Format a gap finding for output"""
        return {
            'id': finding.id,
            'type': finding.finding_type,
            'severity': finding.severity,
            'confidence': finding.confidence,
            'entity_type': finding.entity_type,
            'entity_value': finding.entity_value,
            'summary': finding.summary,
            'time_window_start': finding.time_window_start.isoformat() if finding.time_window_start else None,
            'time_window_end': finding.time_window_end.isoformat() if finding.time_window_end else None,
            'event_count': finding.event_count,
            'has_ai_reasoning': bool(finding.ai_reasoning),
            'has_threat_intel': bool(finding.opencti_context),
            'analyst_reviewed': finding.analyst_reviewed,
            'analyst_verdict': finding.analyst_verdict
        }
    
    def _format_pattern_result(self, result) -> Dict:
        """Format a pattern result for output"""
        formatted = {
            'id': result.id,
            'pattern_id': result.pattern_id,
            'pattern_name': result.pattern_name,
            'correlation_key': result.correlation_key,
            'rule_based_confidence': result.rule_based_confidence,
            'ai_confidence': result.ai_confidence,
            'final_confidence': result.final_confidence,
            'deterministic_score': result.deterministic_score,
            'ai_adjustment': result.ai_adjustment,
            'coverage_quality': result.coverage_quality,
            'has_evidence_package': bool(result.evidence_package),
            'window_start': result.window_start.isoformat() if result.window_start else None,
            'window_end': result.window_end.isoformat() if result.window_end else None,
            'events_analyzed': result.events_analyzed,
            'has_ai_reasoning': bool(result.ai_reasoning)
        }
        if result.evidence_package and isinstance(result.evidence_package, dict):
            formatted['ai_escalated'] = result.evidence_package.get('ai_escalated', False)
        return formatted
    
    def get_entity_grouped_view(self) -> Dict[str, Any]:
        """
        Findings grouped by affected entity.
        
        Returns:
            dict: Findings grouped by users, systems, and source IPs
        """
        run = self._load_analysis_run()
        if not run:
            return {}
        
        gap_findings = self._load_gap_findings()
        
        grouped = {
            'users': {},
            'systems': {},
            'source_ips': {}
        }
        
        for f in gap_findings:
            # Group by primary entity
            if f.entity_type == 'user' and f.entity_value:
                self._add_to_entity_group(grouped['users'], f.entity_value, f, run.case_id)
            elif f.entity_type == 'system' and f.entity_value:
                self._add_to_entity_group(grouped['systems'], f.entity_value, f, run.case_id)
            elif f.entity_type == 'source_ip' and f.entity_value:
                self._add_to_entity_group(grouped['source_ips'], f.entity_value, f, run.case_id)
            
            # Also add affected entities
            if f.affected_entities:
                for key, values in f.affected_entities.items():
                    if key in ['usernames', 'users'] and isinstance(values, list):
                        for v in values[:5]:
                            self._add_to_entity_group(grouped['users'], str(v), f, run.case_id)
                    elif key in ['hostnames', 'systems', 'source_hosts'] and isinstance(values, list):
                        for v in values[:5]:
                            self._add_to_entity_group(grouped['systems'], str(v), f, run.case_id)
                    elif key in ['source_ips', 'ips'] and isinstance(values, list):
                        for v in values[:5]:
                            self._add_to_entity_group(grouped['source_ips'], str(v), f, run.case_id)
        
        # Add behavioral summaries for users and systems
        self._enrich_entity_groups(grouped, run.case_id)
        
        return grouped
    
    def _add_to_entity_group(self, group: Dict, entity_value: str, finding: GapDetectionFinding, case_id: int):
        """Add a finding to an entity group"""
        if not entity_value:
            return
        
        if entity_value not in group:
            group[entity_value] = {
                'findings': [],
                'finding_count': 0,
                'max_severity': 'low',
                'max_confidence': 0
            }
        
        # Avoid duplicates
        finding_ids = [f['id'] for f in group[entity_value]['findings']]
        if finding.id not in finding_ids:
            group[entity_value]['findings'].append(self._format_gap_finding(finding))
            group[entity_value]['finding_count'] += 1
            
            # Update max severity
            severity_order = ['low', 'medium', 'high', 'critical']
            current_idx = severity_order.index(group[entity_value]['max_severity'])
            new_idx = severity_order.index(finding.severity) if finding.severity in severity_order else 0
            if new_idx > current_idx:
                group[entity_value]['max_severity'] = finding.severity
            
            # Update max confidence
            if finding.confidence > group[entity_value]['max_confidence']:
                group[entity_value]['max_confidence'] = finding.confidence
    
    def _enrich_entity_groups(self, grouped: Dict, case_id: int):
        """Add behavioral summaries to entity groups"""
        from models.known_user import KnownUser
        from models.known_system import KnownSystem
        
        # Enrich users
        for username, data in grouped['users'].items():
            user = KnownUser.query.filter_by(case_id=case_id).filter(
                KnownUser.username.ilike(username)
            ).first()
            
            if user:
                data['user_id'] = user.id
                data['is_compromised'] = user.compromised
                
                # Get behavioral profile
                profile = UserBehaviorProfile.query.filter_by(
                    case_id=case_id,
                    user_id=user.id
                ).first()
                
                if profile:
                    data['behavioral_summary'] = {
                        'avg_daily_logons': profile.avg_daily_logons,
                        'failure_rate': profile.failure_rate,
                        'off_hours_percentage': profile.off_hours_percentage,
                        'peer_group_id': profile.peer_group_id
                    }
        
        # Enrich systems
        for hostname, data in grouped['systems'].items():
            system = KnownSystem.query.filter_by(case_id=case_id).filter(
                KnownSystem.hostname.ilike(hostname)
            ).first()
            
            if system:
                data['system_id'] = system.id
                data['is_compromised'] = system.compromised
                
                profile = SystemBehaviorProfile.query.filter_by(
                    case_id=case_id,
                    system_id=system.id
                ).first()
                
                if profile:
                    data['behavioral_summary'] = {
                        'system_role': profile.system_role,
                        'unique_users': profile.unique_users,
                        'peer_group_id': profile.peer_group_id
                    }
        
        # Enrich IPs
        for ip, data in grouped['source_ips'].items():
            # Check if internal
            data['is_internal'] = self._is_internal_ip(ip)
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if an IP is internal (RFC 1918)"""
        if not ip:
            return False
        
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first = int(parts[0])
            second = int(parts[1])
            
            # 10.x.x.x
            if first == 10:
                return True
            # 172.16.x.x - 172.31.x.x
            if first == 172 and 16 <= second <= 31:
                return True
            # 192.168.x.x
            if first == 192 and second == 168:
                return True
            
            return False
        except Exception:
            return False
    
    def get_finding_detail(self, finding_id: int, finding_type: str) -> Dict[str, Any]:
        """
        Full detail for a single finding.
        
        Args:
            finding_id: ID of the finding
            finding_type: 'pattern' or 'gap'
            
        Returns:
            dict: Complete finding with all context
        """
        run = self._load_analysis_run()
        if not run:
            return {'error': 'Analysis not found'}
        
        if finding_type == 'gap':
            finding = GapDetectionFinding.query.get(finding_id)
            if not finding or finding.analysis_id != self.analysis_id:
                return {'error': 'Finding not found'}
            
            return {
                'id': finding.id,
                'type': 'gap',
                'finding_type': finding.finding_type,
                'severity': finding.severity,
                'confidence': finding.confidence,
                'entity_type': finding.entity_type,
                'entity_value': finding.entity_value,
                'entity_id': finding.entity_id,
                'summary': finding.summary,
                'details': finding.details,
                'evidence': finding.evidence,
                'behavioral_context': finding.behavioral_context,
                'peer_comparison': finding.peer_comparison,
                'ai_reasoning': finding.ai_reasoning,
                'opencti_context': finding.opencti_context,
                'suggested_iocs': finding.suggested_iocs,
                'affected_entities': finding.affected_entities,
                'time_window_start': finding.time_window_start.isoformat() if finding.time_window_start else None,
                'time_window_end': finding.time_window_end.isoformat() if finding.time_window_end else None,
                'event_count': finding.event_count,
                'analyst_reviewed': finding.analyst_reviewed,
                'analyst_verdict': finding.analyst_verdict,
                'analyst_notes': finding.analyst_notes,
                'created_at': finding.created_at.isoformat() if finding.created_at else None,
                'suggested_actions': self._get_actions_for_finding(finding_id, 'gap_finding')
            }
        
        elif finding_type == 'pattern':
            from models.rag import AIAnalysisResult
            result = AIAnalysisResult.query.get(finding_id)
            if not result or result.analysis_id != self.analysis_id:
                return {'error': 'Finding not found'}
            
            detail = {
                'id': result.id,
                'type': 'pattern',
                'pattern_id': result.pattern_id,
                'pattern_name': result.pattern_name,
                'correlation_key': result.correlation_key,
                'rule_based_confidence': result.rule_based_confidence,
                'ai_confidence': result.ai_confidence,
                'final_confidence': result.final_confidence,
                'deterministic_score': result.deterministic_score,
                'ai_adjustment': result.ai_adjustment,
                'coverage_quality': result.coverage_quality,
                'evidence_package': result.evidence_package,
                'ai_reasoning': result.ai_reasoning,
                'indicators_found': result.ai_indicators_found,
                'iocs': result.ai_iocs,
                'false_positive_assessment': result.ai_false_positive_assessment,
                'window_start': result.window_start.isoformat() if result.window_start else None,
                'window_end': result.window_end.isoformat() if result.window_end else None,
                'events_analyzed': result.events_analyzed,
                'model_used': result.model_used,
                'analysis_duration_ms': result.analysis_duration_ms
            }
            return detail
        
        return {'error': f'Unknown finding type: {finding_type}'}
    
    def _get_actions_for_finding(self, source_id: int, source_type: str) -> List[Dict]:
        """Get suggested actions for a specific finding"""
        actions = SuggestedAction.query.filter_by(
            analysis_id=self.analysis_id,
            source_type=source_type,
            source_id=source_id
        ).all()
        
        return [{
            'id': a.id,
            'action_type': a.action_type,
            'target_entity': a.target_entity,
            'reason': a.reason,
            'confidence': a.confidence,
            'status': a.status
        } for a in actions]
    
    def get_suggested_actions(self) -> List[Dict[str, Any]]:
        """
        All pending suggested actions.
        
        Returns:
            list[dict]: Suggested actions with source finding info
        """
        actions = self._load_suggested_actions()
        
        result = []
        for a in actions:
            result.append({
                'id': a.id,
                'action_type': a.action_type,
                'target': a.target_entity,
                'reason': a.reason,
                'confidence': a.confidence,
                'source_finding': {
                    'type': a.source_type,
                    'id': a.source_id
                },
                'status': a.status,
                'created_at': a.created_at.isoformat() if a.created_at else None
            })
        
        return result
    
    def export_report(self, format: str = 'json') -> str:
        """
        Export full results.
        
        Args:
            format: 'json', 'csv', or 'markdown'
            
        Returns:
            str: Formatted report content
        """
        if format == 'json':
            return self._export_json()
        elif format == 'markdown':
            return self._export_markdown()
        elif format == 'csv':
            return self._export_csv()
        else:
            return self._export_json()
    
    def _export_json(self) -> str:
        """Export as JSON"""
        report = {
            'summary': self.get_summary(),
            'timeline': self.get_timeline_view(),
            'by_pattern': self.get_pattern_grouped_view(),
            'by_entity': self.get_entity_grouped_view(),
            'suggested_actions': self.get_suggested_actions(),
            'exported_at': datetime.utcnow().isoformat()
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def _export_markdown(self) -> str:
        """Export as Markdown"""
        summary = self.get_summary()
        
        lines = [
            f"# Analysis Report: {self.analysis_id}",
            "",
            f"**Case ID:** {summary.get('case_id')}",
            f"**Mode:** {summary.get('mode')} - {summary.get('mode_description')}",
            f"**Status:** {summary.get('status')}",
            f"**Duration:** {summary.get('duration_seconds', 0):.1f} seconds",
            "",
            "## Summary Statistics",
            "",
            f"- Users Profiled: {summary['statistics'].get('users_profiled', 0)}",
            f"- Systems Profiled: {summary['statistics'].get('systems_profiled', 0)}",
            f"- Total Findings: {summary['statistics'].get('total_findings', 0)}",
            f"- High Confidence Findings: {summary['statistics'].get('high_confidence_findings', 0)}",
            f"- Attack Chains: {summary['statistics'].get('attack_chains', 0)}",
            "",
            "## Severity Breakdown",
            "",
            f"- Critical: {summary['severity_breakdown'].get('critical', 0)}",
            f"- High: {summary['severity_breakdown'].get('high', 0)}",
            f"- Medium: {summary['severity_breakdown'].get('medium', 0)}",
            f"- Low: {summary['severity_breakdown'].get('low', 0)}",
            "",
            "## Top Findings",
            ""
        ]
        
        for i, finding in enumerate(summary.get('top_findings', []), 1):
            lines.append(f"{i}. **{finding.get('name')}** ({finding.get('severity')}, {finding.get('confidence')}%)")
            lines.append(f"   - {finding.get('summary')}")
            lines.append("")
        
        lines.extend([
            "## Pending Actions",
            "",
            f"**{summary.get('suggested_actions_pending', 0)}** suggested actions pending review.",
            "",
            f"*Report generated: {datetime.utcnow().isoformat()}*"
        ])
        
        return "\n".join(lines)
    
    def _export_csv(self) -> str:
        """Export findings as CSV"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            'Finding ID', 'Type', 'Name', 'Severity', 'Confidence',
            'Entity Type', 'Entity Value', 'Summary', 'Time Start', 'Time End',
            'Has AI Reasoning', 'Has Threat Intel', 'Analyst Verdict'
        ])
        
        # Gap findings
        for f in self._load_gap_findings():
            writer.writerow([
                f.id, 'gap', f.finding_type, f.severity, f.confidence,
                f.entity_type, f.entity_value, f.summary,
                f.time_window_start.isoformat() if f.time_window_start else '',
                f.time_window_end.isoformat() if f.time_window_end else '',
                bool(f.ai_reasoning), bool(f.opencti_context), f.analyst_verdict or ''
            ])
        
        # Pattern results
        for r in self._load_pattern_results():
            writer.writerow([
                r.id, 'pattern', r.pattern_name,
                self._confidence_to_severity(r.final_confidence), r.final_confidence,
                '', r.correlation_key, f'Pattern match: {r.pattern_name}',
                r.window_start.isoformat() if r.window_start else '',
                r.window_end.isoformat() if r.window_end else '',
                bool(r.ai_reasoning), False, ''
            ])
        
        return output.getvalue()
