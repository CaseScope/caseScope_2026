"""Gap Detection Module for CaseScope

Detects attacks that per-event Sigma/Hayabusa rules may miss through
aggregate statistical analysis and behavioral comparison.

Gap detectors include:
- Password Spraying: Single source attempting many usernames
- Brute Force: Many attempts against single account
- Behavioral Anomaly: Deviations from baseline and peer behavior
"""

import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable

from models.database import db
from models.behavioral_profiles import GapDetectionFinding, GapFindingType

logger = logging.getLogger(__name__)

DETECTOR_STAGES = (
    {
        'progress_percent': 20,
        'progress_message': 'Running password spraying detection...',
        'module_path': 'utils.gap_detectors.password_spraying',
        'class_name': 'PasswordSprayingDetector',
        'log_name': 'Password spraying',
    },
    {
        'progress_percent': 25,
        'progress_message': 'Running brute force detection...',
        'module_path': 'utils.gap_detectors.brute_force',
        'class_name': 'BruteForceDetector',
        'log_name': 'Brute force',
    },
    {
        'progress_percent': 30,
        'progress_message': 'Running behavioral anomaly detection...',
        'module_path': 'utils.gap_detectors.behavioral_anomaly',
        'class_name': 'BehavioralAnomalyDetector',
        'log_name': 'Behavioral anomaly',
    },
)


def get_gap_finding_severity_rank(severity: str) -> int:
    """Return canonical severity rank for gap-finding merge decisions."""
    ranks = {
        'low': 1,
        'medium': 2,
        'high': 3,
        'critical': 4,
    }
    return ranks.get(severity, 0)


def deduplicate_gap_detection_findings(
    findings: List[GapDetectionFinding],
) -> List[GapDetectionFinding]:
    """Remove or merge overlapping gap findings by canonical entity key."""
    if not findings:
        return []

    entity_findings: Dict[str, List[GapDetectionFinding]] = {}
    for finding in findings:
        key = f"{finding.entity_type}:{finding.entity_value}"
        entity_findings.setdefault(key, []).append(finding)

    deduplicated = []

    for entity_group in entity_findings.values():
        if len(entity_group) == 1:
            deduplicated.append(entity_group[0])
            continue

        sorted_group = sorted(entity_group, key=lambda f: f.confidence, reverse=True)
        primary = sorted_group[0]

        merged_details = primary.details or {}
        merged_evidence = primary.evidence or {}

        for other in sorted_group[1:]:
            if other.details:
                merged_details[f'also_{other.finding_type}'] = other.details
            if other.evidence:
                merged_evidence[f'also_{other.finding_type}'] = other.evidence

            if get_gap_finding_severity_rank(other.severity) > get_gap_finding_severity_rank(primary.severity):
                primary.severity = other.severity

        primary.details = merged_details
        primary.evidence = merged_evidence

        other_types = [f.finding_type for f in sorted_group[1:]]
        if other_types:
            primary.summary += f" (also detected as: {', '.join(other_types)})"

        deduplicated.append(primary)

    return deduplicated


def build_gap_detection_finding_payload(
    *,
    case_id: int,
    analysis_id: str,
    finding_type: str,
    severity: str,
    confidence: float,
    entity_type: str,
    entity_value: str,
    summary: str,
    **kwargs,
) -> Dict[str, Any]:
    """Build canonical payload fields for a gap-detection finding model."""
    return {
        'case_id': case_id,
        'analysis_id': analysis_id,
        'finding_type': finding_type,
        'severity': severity,
        'confidence': confidence,
        'entity_type': entity_type,
        'entity_value': entity_value,
        'summary': summary,
        **kwargs,
    }


class GapDetectionManager:
    """
    Orchestrates all gap detection modules.
    
    Runs enabled detectors and combines/deduplicates results.
    """
    
    def __init__(self, case_id: int, analysis_id: str, progress_callback: Callable = None):
        """
        Args:
            case_id: The case to analyze
            analysis_id: UUID for this analysis run
            progress_callback: Optional callable(phase, percent, message) for progress updates
        """
        self.case_id = case_id
        self.analysis_id = analysis_id
        self.progress_callback = progress_callback
    
    def _update_progress(self, phase: str, percent: int, message: str):
        """Update progress if callback is set"""
        if self.progress_callback:
            self.progress_callback(phase, percent, message)

    def _iter_detector_stages(self) -> tuple[dict[str, str | int], ...]:
        """Return canonical detector stage definitions."""
        return tuple(dict(stage) for stage in DETECTOR_STAGES)

    def _run_detector_stage(self, stage: Dict[str, Any]) -> List[GapDetectionFinding]:
        """Execute one detector stage and return any findings."""
        try:
            module = __import__(stage['module_path'], fromlist=[stage['class_name']])
            detector_class = getattr(module, stage['class_name'])
            detector = detector_class(self.case_id, self.analysis_id)
            findings = detector.detect()
            logger.info(f"{stage['log_name']} detection found {len(findings)} findings")
            return findings
        except Exception as e:
            logger.error(f"{stage['log_name']} detection failed: {e}")
            return []
    
    def run_all_detectors(self) -> List[GapDetectionFinding]:
        """
        Run all enabled gap detectors.
        
        Order:
        1. Password spraying
        2. Brute force
        3. Behavioral anomalies
        
        Deduplicates overlapping findings.
        
        Returns:
            list[GapDetectionFinding]: Combined findings
        """
        all_findings = []

        for stage in self._iter_detector_stages():
            self._update_progress(
                'gap_detection',
                int(stage['progress_percent']),
                str(stage['progress_message']),
            )
            all_findings.extend(self._run_detector_stage(stage))
        
        self._update_progress('gap_detection', 33, 'Deduplicating findings...')
        
        # Deduplicate overlapping findings
        deduplicated = self._deduplicate_findings(all_findings)
        
        # Save all findings to database
        for finding in deduplicated:
            db.session.add(finding)
        
        db.session.commit()
        
        self._update_progress('gap_detection', 35, f'Gap detection complete: {len(deduplicated)} findings')
        
        return deduplicated
    
    def _deduplicate_findings(self, findings: List[GapDetectionFinding]) -> List[GapDetectionFinding]:
        """
        Remove or merge overlapping findings.
        
        Example: If spray and brute force flag same source IP for
        different reasons, merge into single finding with both contexts.
        """
        return deduplicate_gap_detection_findings(findings)
    
    def _severity_rank(self, severity: str) -> int:
        """Convert severity to numeric rank for comparison"""
        return get_gap_finding_severity_rank(severity)


# Base class for detectors
class BaseGapDetector:
    """Base class for gap detection modules"""
    
    def __init__(self, case_id: int, analysis_id: str):
        self.case_id = case_id
        self.analysis_id = analysis_id
        self.ch_client = None
    
    def _get_clickhouse_client(self):
        """Get or create ClickHouse client"""
        if self.ch_client is None:
            from utils.clickhouse import get_fresh_client
            self.ch_client = get_fresh_client()
        return self.ch_client
    
    def detect(self) -> List[GapDetectionFinding]:
        """Override in subclass to implement detection logic"""
        raise NotImplementedError
    
    def _escape_sql(self, value: str) -> str:
        """Escape single quotes for SQL"""
        if value is None:
            return ''
        return str(value).replace("'", "''")
    
    def _create_finding(self, finding_type: str, severity: str, confidence: float,
                       entity_type: str, entity_value: str, summary: str,
                       **kwargs) -> GapDetectionFinding:
        """Helper to create a GapDetectionFinding with common fields"""
        return GapDetectionFinding(
            **build_gap_detection_finding_payload(
                case_id=self.case_id,
                analysis_id=self.analysis_id,
                finding_type=finding_type,
                severity=severity,
                confidence=confidence,
                entity_type=entity_type,
                entity_value=entity_value,
                summary=summary,
                **kwargs,
            )
        )
