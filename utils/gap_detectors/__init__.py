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
        
        self._update_progress('gap_detection', 20, 'Running password spraying detection...')
        
        # 1. Password spraying detection
        try:
            from utils.gap_detectors.password_spraying import PasswordSprayingDetector
            spray_detector = PasswordSprayingDetector(self.case_id, self.analysis_id)
            spray_findings = spray_detector.detect()
            all_findings.extend(spray_findings)
            logger.info(f"Password spraying detection found {len(spray_findings)} findings")
        except Exception as e:
            logger.error(f"Password spraying detection failed: {e}")
        
        self._update_progress('gap_detection', 25, 'Running brute force detection...')
        
        # 2. Brute force detection
        try:
            from utils.gap_detectors.brute_force import BruteForceDetector
            brute_detector = BruteForceDetector(self.case_id, self.analysis_id)
            brute_findings = brute_detector.detect()
            all_findings.extend(brute_findings)
            logger.info(f"Brute force detection found {len(brute_findings)} findings")
        except Exception as e:
            logger.error(f"Brute force detection failed: {e}")
        
        self._update_progress('gap_detection', 30, 'Running behavioral anomaly detection...')
        
        # 3. Behavioral anomaly detection
        try:
            from utils.gap_detectors.behavioral_anomaly import BehavioralAnomalyDetector
            anomaly_detector = BehavioralAnomalyDetector(self.case_id, self.analysis_id)
            anomaly_findings = anomaly_detector.detect()
            all_findings.extend(anomaly_findings)
            logger.info(f"Behavioral anomaly detection found {len(anomaly_findings)} findings")
        except Exception as e:
            logger.error(f"Behavioral anomaly detection failed: {e}")
        
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
        if not findings:
            return []
        
        # Group findings by entity
        entity_findings = {}
        for finding in findings:
            key = f"{finding.entity_type}:{finding.entity_value}"
            if key not in entity_findings:
                entity_findings[key] = []
            entity_findings[key].append(finding)
        
        deduplicated = []
        
        for key, entity_group in entity_findings.items():
            if len(entity_group) == 1:
                deduplicated.append(entity_group[0])
            else:
                # Multiple findings for same entity - keep highest confidence
                # and merge context from others
                sorted_group = sorted(entity_group, key=lambda f: f.confidence, reverse=True)
                primary = sorted_group[0]
                
                # Merge details from other findings
                merged_details = primary.details or {}
                merged_evidence = primary.evidence or {}
                
                for other in sorted_group[1:]:
                    if other.details:
                        merged_details[f'also_{other.finding_type}'] = other.details
                    if other.evidence:
                        merged_evidence[f'also_{other.finding_type}'] = other.evidence
                    
                    # Upgrade severity if other finding is more severe
                    if self._severity_rank(other.severity) > self._severity_rank(primary.severity):
                        primary.severity = other.severity
                
                primary.details = merged_details
                primary.evidence = merged_evidence
                
                # Note the merge in summary
                other_types = [f.finding_type for f in sorted_group[1:]]
                if other_types:
                    primary.summary += f" (also detected as: {', '.join(other_types)})"
                
                deduplicated.append(primary)
        
        return deduplicated
    
    def _severity_rank(self, severity: str) -> int:
        """Convert severity to numeric rank for comparison"""
        ranks = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        return ranks.get(severity, 0)


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
            case_id=self.case_id,
            analysis_id=self.analysis_id,
            finding_type=finding_type,
            severity=severity,
            confidence=confidence,
            entity_type=entity_type,
            entity_value=entity_value,
            summary=summary,
            **kwargs
        )
