"""Case Analyzer - Main Analysis Orchestrator for CaseScope

Coordinates all analysis phases:
1. Behavioral profiling
2. Peer group clustering  
3. Gap detection
4. Hayabusa correlation
5. Pattern analysis
6. OpenCTI enrichment (if available)
7. Suggested action generation

Adapts behavior based on available features (Mode A/B/C/D).
"""

import logging
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from uuid import uuid4

from models.database import db
from models.behavioral_profiles import (
    CaseAnalysisRun, AnalysisMode, AnalysisStatus,
    UserBehaviorProfile, SystemBehaviorProfile,
    PeerGroup, GapDetectionFinding, SuggestedAction
)
from config import Config

logger = logging.getLogger(__name__)


class AnalysisError(Exception):
    """Raised when analysis fails"""
    pass


class CaseAnalyzer:
    """
    Main orchestrator for case analysis.
    
    Coordinates all analysis phases:
    1. Behavioral profiling
    2. Peer group clustering
    3. Gap detection
    4. Hayabusa correlation
    5. Pattern analysis
    6. OpenCTI enrichment (if available)
    7. Suggested action generation
    
    Adapts behavior based on available features (Mode A/B/C/D).
    """
    
    def __init__(self, case_id: int, progress_callback: Callable = None):
        """
        Args:
            case_id: The case to analyze
            progress_callback: Optional callback(phase, percent, message) for progress updates
        """
        self.case_id = case_id
        self.analysis_id: Optional[str] = None
        self.mode: Optional[str] = None
        self.progress_callback = progress_callback
        
        # Runtime state
        self._analysis_run: Optional[CaseAnalysisRun] = None
        self._start_time: Optional[datetime] = None
        
        # Results storage
        self._profiling_stats: Dict = {}
        self._gap_findings: List = []
        self._attack_chains: List = []
        self._pattern_results: List = []
        self._all_findings: List = []
        self._census: Dict[str, int] = {}  # event_id -> count from census query
    
    def run_full_analysis(self) -> str:
        """
        Main entry point.
        
        Returns:
            str: analysis_id for this run
            
        Raises:
            AnalysisError: If analysis fails
        """
        try:
            # Phase 0: Initialize
            self._initialize_analysis_run()
            logger.info(f"[CaseAnalyzer] Starting analysis {self.analysis_id} for case {self.case_id} (Mode {self.mode})")
            
            # Phase 1: Behavioral Profiling (0-15%)
            self._update_progress('profiling', 0, 'Starting behavioral profiling...')
            self._profiling_stats = self._run_behavioral_profiling()
            
            # Phase 2: Peer Clustering (15-20%)
            self._update_progress('clustering', 15, 'Building peer groups...')
            clustering_stats = self._run_peer_clustering()
            self._profiling_stats.update(clustering_stats)
            
            # Phase 3: Gap Detection (20-35%)
            self._update_progress('gap_detection', 20, 'Running gap detection...')
            self._gap_findings = self._run_gap_detection()
            self._all_findings.extend(self._gap_findings)
            
            # Phase 4: Hayabusa Correlation (35-50%)
            self._update_progress('hayabusa_correlation', 35, 'Correlating Hayabusa detections...')
            self._attack_chains = self._run_hayabusa_correlation()
            
            # Phase 5: Pattern Analysis (50-85%)
            self._update_progress('pattern_analysis', 50, 'Analyzing attack patterns...')
            self._pattern_results = self._run_pattern_analysis(self._attack_chains)
            
            # Phase 6: OpenCTI Enrichment (85-90%) - Mode C/D only
            if self.mode in ['C', 'D']:
                self._update_progress('opencti_enrichment', 85, 'Enriching with threat intelligence...')
                self._enrich_with_opencti(self._all_findings)
            else:
                self._update_progress('opencti_enrichment', 85, 'Skipping OpenCTI (not available)')
            
            # Phase 7: Generate Suggested Actions (90-95%)
            self._update_progress('suggested_actions', 90, 'Generating suggested actions...')
            self._generate_suggested_actions(self._all_findings)
            
            # Phase 8: Finalize (95-100%)
            self._update_progress('finalizing', 95, 'Finalizing analysis...')
            self._finalize_analysis(self._all_findings)
            
            self._update_progress('complete', 100, 'Analysis complete')
            
            logger.info(f"[CaseAnalyzer] Analysis {self.analysis_id} completed successfully")
            return self.analysis_id
            
        except Exception as e:
            logger.error(f"[CaseAnalyzer] Analysis failed: {e}", exc_info=True)
            self._mark_failed(str(e))
            raise AnalysisError(f"Analysis failed: {e}")
    
    def _initialize_analysis_run(self) -> str:
        """
        Create case_analysis_runs record.
        Determine mode based on feature availability.
        
        Returns:
            str: analysis_id (UUID)
        """
        from utils.feature_availability import FeatureAvailability
        
        self.analysis_id = str(uuid4())
        self.mode = FeatureAvailability.get_analysis_mode()
        self._start_time = datetime.utcnow()
        
        # Create analysis run record
        capabilities = FeatureAvailability.get_available_capabilities()
        
        self._analysis_run = CaseAnalysisRun(
            case_id=self.case_id,
            analysis_id=self.analysis_id,
            mode=self.mode,
            status=AnalysisStatus.PENDING,
            ai_enabled=capabilities.get('ai_reasoning', False),
            opencti_enabled=capabilities.get('threat_intel_enrichment', False),
            started_at=self._start_time
        )
        
        db.session.add(self._analysis_run)
        db.session.commit()
        
        # Clear any stale data from previous runs
        self._clear_previous_analysis_data()
        
        return self.analysis_id
    
    def _clear_previous_analysis_data(self):
        """Clear data from previous analysis runs for this case"""
        try:
            # Clear previous behavioral profiles
            UserBehaviorProfile.query.filter_by(case_id=self.case_id).delete()
            SystemBehaviorProfile.query.filter_by(case_id=self.case_id).delete()
            
            # Clear previous peer groups
            PeerGroup.query.filter_by(case_id=self.case_id).delete()
            
            # Clear previous gap findings (keep for history? or clear?)
            # For now, we keep previous findings
            
            # Clear OpenCTI cache for fresh data
            from models.behavioral_profiles import OpenCTICache
            OpenCTICache.query.filter_by(case_id=self.case_id).delete()
            
            db.session.commit()
        except Exception as e:
            logger.warning(f"[CaseAnalyzer] Failed to clear previous data: {e}")
            db.session.rollback()
    
    def _update_progress(self, phase: str, percent: int, message: str):
        """
        Update progress in database and call progress callback.
        
        Args:
            phase: Current phase name
            percent: Progress percentage (0-100)
            message: Human-readable status message
        """
        # Update database record
        if self._analysis_run:
            self._analysis_run.progress_percent = percent
            self._analysis_run.current_phase = message or phase
            
            # Update phase timestamps and status based on phase
            if phase == 'profiling' and not self._analysis_run.profiling_started_at:
                self._analysis_run.profiling_started_at = datetime.utcnow()
                self._analysis_run.status = AnalysisStatus.PROFILING
            elif phase == 'hayabusa_correlation' and not self._analysis_run.correlation_started_at:
                self._analysis_run.correlation_started_at = datetime.utcnow()
                self._analysis_run.status = AnalysisStatus.CORRELATING
            elif phase == 'pattern_analysis' and not self._analysis_run.ai_analysis_started_at:
                self._analysis_run.ai_analysis_started_at = datetime.utcnow()
                self._analysis_run.status = AnalysisStatus.ANALYZING
            
            db.session.commit()
        
        # Call progress callback if provided
        if self.progress_callback:
            try:
                self.progress_callback(phase, percent, message)
            except Exception as e:
                logger.warning(f"[CaseAnalyzer] Progress callback error: {e}")
        
        logger.info(f"[CaseAnalyzer] [{percent}%] {phase}: {message}")
    
    def _run_behavioral_profiling(self) -> Dict[str, Any]:
        """
        Phase 1: Build behavioral profiles.
        
        Progress: 0-15%
        
        Returns:
            dict: {
                'users_profiled': int,
                'systems_profiled': int,
                'duration_seconds': float
            }
        """
        from utils.behavioral_profiler import BehavioralProfiler
        
        start = time.time()
        
        profiler = BehavioralProfiler(
            case_id=self.case_id,
            analysis_id=self.analysis_id,
            progress_callback=self._profiling_progress_callback
        )
        
        result = profiler.profile_all()
        
        duration = time.time() - start
        
        return {
            'users_profiled': result.get('users_profiled', 0),
            'systems_profiled': result.get('systems_profiled', 0),
            'duration_seconds': duration
        }
    
    def _profiling_progress_callback(self, phase: str, percent: int, message: str):
        """Translate profiler progress to overall progress (0-15%)"""
        # Scale 0-100 to 0-15
        overall_percent = int(percent * 0.15)
        self._update_progress(phase, overall_percent, message)
    
    def _run_peer_clustering(self) -> Dict[str, Any]:
        """
        Phase 2: Build peer groups.
        
        Progress: 15-20%
        
        Returns:
            dict: {
                'user_groups': int,
                'system_groups': int
            }
        """
        from utils.peer_clustering import PeerGroupBuilder
        
        builder = PeerGroupBuilder(self.case_id, self.analysis_id)
        result = builder.build_all_peer_groups()
        
        self._update_progress('clustering', 20, f"Created {result.get('total_groups', 0)} peer groups")
        
        return {
            'user_groups': result.get('user_groups', 0),
            'system_groups': result.get('system_groups', 0)
        }
    
    def _run_gap_detection(self) -> List[GapDetectionFinding]:
        """
        Phase 3: Run gap detectors.
        
        Progress: 20-35%
        
        Returns:
            list[GapDetectionFinding]
        """
        from utils.gap_detectors import GapDetectionManager
        
        manager = GapDetectionManager(
            case_id=self.case_id,
            analysis_id=self.analysis_id,
            progress_callback=self._gap_progress_callback
        )
        
        findings = manager.run_all_detectors()
        
        self._update_progress('gap_detection', 35, f"Found {len(findings)} gap detection findings")
        
        return findings
    
    def _gap_progress_callback(self, phase: str, percent: int, message: str):
        """Translate gap detection progress to overall progress (20-35%)"""
        # Scale 0-100 to 20-35
        overall_percent = 20 + int(percent * 0.15)
        self._update_progress(phase, overall_percent, message)
    
    def _run_hayabusa_correlation(self) -> List:
        """
        Phase 4: Correlate Hayabusa detections.
        
        Progress: 35-50%
        
        Returns:
            list[CorrelatedDetectionGroup]
        """
        from utils.hayabusa_correlator import HayabusaCorrelator
        from utils.attack_chain_builder import AttackChainBuilder
        
        # Correlate detections
        correlator = HayabusaCorrelator(
            case_id=self.case_id,
            analysis_id=self.analysis_id,
            progress_callback=self._hayabusa_progress_callback
        )
        
        detection_groups = correlator.correlate()
        
        # Build attack chains
        if detection_groups:
            self._update_progress('hayabusa_correlation', 48, 'Building attack chains...')
            builder = AttackChainBuilder(self.case_id, self.analysis_id)
            attack_chains = builder.build_chains(detection_groups)
            
            self._update_progress('hayabusa_correlation', 50, 
                                 f"Identified {len(attack_chains)} attack chains")
            return attack_chains
        
        self._update_progress('hayabusa_correlation', 50, 'No Hayabusa detections to correlate')
        return []
    
    def _hayabusa_progress_callback(self, phase: str, percent: int, message: str):
        """Translate Hayabusa progress to overall progress (35-50%)"""
        # Scale 35-50 range based on correlator's 35-50 output
        self._update_progress(phase, percent, message)
    
    def _run_census(self) -> Dict[str, int]:
        """Get event_id distribution for the case.
        
        Used to skip patterns whose required anchor event IDs don't exist
        in this case, avoiding unnecessary ClickHouse queries.
        
        Returns:
            dict: {event_id: count} mapping
        """
        from utils.clickhouse import get_fresh_client
        
        try:
            client = get_fresh_client()
            result = client.query(
                "SELECT event_id, count() as cnt FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND (noise_matched = false OR noise_matched IS NULL) "
                "GROUP BY event_id",
                parameters={'case_id': self.case_id}
            )
            census = {str(row[0]): row[1] for row in result.result_rows}
            logger.info(f"[CaseAnalyzer] Census: {len(census)} distinct event IDs in case {self.case_id}")
            return census
        except Exception as e:
            logger.warning(f"[CaseAnalyzer] Census query failed, running all patterns: {e}")
            return {}  # Empty census = skip no patterns (fail-open)
    
    def _should_run_pattern(self, pattern_config: Dict, census: Dict[str, int]) -> bool:
        """Check if a pattern's required anchor events exist in this case.
        
        If the census is empty (query failed), returns True (fail-open).
        If a pattern has no anchor_events defined, returns True.
        
        Args:
            pattern_config: Pattern definition with anchor_events list
            census: {event_id: count} from _run_census()
            
        Returns:
            bool: True if at least one anchor event ID exists in the case
        """
        if not census:
            return True  # No census data, run everything (fail-open)
        
        anchor_events = pattern_config.get('anchor_events', [])
        if not anchor_events:
            return True  # No anchors specified, always run
        
        return any(str(eid) in census for eid in anchor_events)
    
    def _run_pattern_analysis(self, attack_chains: List) -> List[Dict]:
        """
        Phase 5: Run pattern analysis.
        
        Progress: 50-85%
        
        Uses census-based pre-filtering to skip patterns whose anchor
        event IDs don't exist in the case, then runs extraction + analysis.
        
        Mode A/C: Uses rule-based analysis
        Mode B/D: Uses AI-enhanced analysis
        
        Returns:
            list: Pattern analysis results
        """
        from utils.candidate_extractor import CandidateExtractor
        from utils.ai_correlation_analyzer import AICorrelationAnalyzer, RuleBasedAnalyzer
        
        results = []
        
        # Get available patterns
        try:
            from utils.pattern_event_mappings import PATTERN_EVENT_MAPPINGS
            patterns = PATTERN_EVENT_MAPPINGS
        except ImportError:
            patterns = {}
            logger.warning("[CaseAnalyzer] No patterns configured for analysis")
        
        if not patterns:
            self._update_progress('pattern_analysis', 85, 'No patterns to analyze')
            return results
        
        # Census pre-filter: get event_id distribution for this case
        self._update_progress('pattern_analysis', 51, 'Running event census...')
        census = self._run_census()
        self._census = census  # Store for summary stats
        
        # Determine which patterns can run based on census
        runnable_patterns = {
            pid: cfg for pid, cfg in patterns.items()
            if self._should_run_pattern(cfg, census)
        }
        skipped_count = len(patterns) - len(runnable_patterns)
        
        if skipped_count > 0:
            logger.info(f"[CaseAnalyzer] Census filter: {len(runnable_patterns)}/{len(patterns)} "
                       f"patterns eligible ({skipped_count} skipped — anchor events not in case)")
        
        if not runnable_patterns:
            self._update_progress('pattern_analysis', 85, 
                                 f'No matching patterns (0/{len(patterns)} eligible after census)')
            return results
        
        pattern_count = len(runnable_patterns)
        self._update_progress('pattern_analysis', 52, 
                             f'Analyzing {pattern_count} patterns ({skipped_count} skipped by census)...')
        
        # Initialize analyzers
        extractor = CandidateExtractor(self.case_id, self.analysis_id)
        
        if self.mode in ['B', 'D']:
            # AI-enhanced analysis
            ai_analyzer = AICorrelationAnalyzer(
                case_id=self.case_id,
                analysis_id=self.analysis_id
            )
        else:
            # Rule-based analysis
            rule_analyzer = RuleBasedAnalyzer(
                case_id=self.case_id,
                analysis_id=self.analysis_id
            )
        
        # Process each eligible pattern
        for i, (pattern_id, pattern_config) in enumerate(runnable_patterns.items()):
            progress = 52 + int((i / pattern_count) * 33)  # 52-85%
            
            pattern_name = pattern_config.get('name', pattern_id)
            self._update_progress('pattern_analysis', progress, f'Analyzing {pattern_name}...')
            
            try:
                # Extract candidates
                pattern_config['id'] = pattern_id
                extraction_result = extractor.extract_pattern_candidates(pattern_config)
                
                if extraction_result.get('anchor_count', 0) == 0:
                    continue  # No candidates for this pattern
                
                # Attach behavioral context
                candidates = extractor.get_candidates_for_key(
                    pattern_id,
                    extraction_result.get('correlation_key', '')
                )
                candidates = extractor.attach_behavioral_context(candidates)
                
                # Run analysis based on mode
                if self.mode in ['B', 'D']:
                    # AI analysis
                    pattern_results = ai_analyzer.analyze_pattern(
                        pattern_config=pattern_config,
                        rule_based_confidence=extraction_result.get('base_confidence', 50)
                    )
                else:
                    # Rule-based analysis for each correlation key
                    pattern_results = []
                    for key in extractor.get_correlation_keys(pattern_id):
                        key_candidates = extractor.get_candidates_for_key(pattern_id, key)
                        behavioral_ctx = key_candidates[0].get('behavioral_context') if key_candidates else None
                        
                        result = rule_analyzer.analyze_without_ai(
                            candidates=key_candidates,
                            pattern_config=pattern_config,
                            behavioral_context=behavioral_ctx
                        )
                        result['correlation_key'] = key
                        result['pattern_id'] = pattern_id
                        pattern_results.append(result)
                
                results.extend(pattern_results)
                
            except Exception as e:
                logger.warning(f"[CaseAnalyzer] Pattern analysis failed for {pattern_id}: {e}")
        
        # Cleanup extracted candidates
        extractor.cleanup()
        
        self._update_progress('pattern_analysis', 85, f'Completed {len(results)} pattern analyses')
        
        return results
    
    def _enrich_with_opencti(self, all_findings: List):
        """
        Phase 6: Add OpenCTI context (Mode C/D only).
        
        Progress: 85-90%
        
        Updates findings in-place with threat intel.
        """
        from utils.opencti_context import OpenCTIContextProvider
        
        provider = OpenCTIContextProvider(self.case_id, self.analysis_id)
        
        if not provider.is_available():
            self._update_progress('opencti_enrichment', 90, 'OpenCTI not available')
            return
        
        # Clear cache for fresh data
        provider.clear_cache()
        
        self._update_progress('opencti_enrichment', 86, 'Fetching threat intelligence context...')
        
        # Get aggregated context
        context = provider.get_context_for_findings(all_findings)
        
        # Update findings with context
        for finding in all_findings:
            if hasattr(finding, 'opencti_context'):
                finding.opencti_context = context
            elif isinstance(finding, dict):
                finding['opencti_context'] = context
        
        # Also enrich attack chains
        for chain in self._attack_chains:
            if hasattr(chain, 'to_dict'):
                chain_dict = chain.to_dict()
            else:
                chain_dict = chain
            
            techniques = chain_dict.get('tactics_observed', [])
            if techniques:
                chain_context = {}
                for tech in techniques[:5]:
                    tech_ctx = provider.get_attack_pattern_context(tech)
                    if tech_ctx.get('technique_name'):
                        chain_context[tech] = tech_ctx
                
                if hasattr(chain, 'opencti_context'):
                    chain.opencti_context = chain_context
        
        self._update_progress('opencti_enrichment', 90, 'Threat intelligence enrichment complete')
    
    def _generate_suggested_actions(self, all_findings: List) -> List[SuggestedAction]:
        """
        Phase 7: Create suggested actions.
        
        Progress: 90-95%
        
        Rules:
        - Confidence >= 75 AND entity identified → suggest mark compromised
        - IOCs discovered → suggest add to case IOCs
        - High severity finding → suggest investigate
        
        Returns:
            list[SuggestedAction]
        """
        actions = []
        
        self._update_progress('suggested_actions', 91, 'Generating investigation suggestions...')
        
        for finding in all_findings:
            finding_actions = self._generate_actions_for_finding(finding)
            actions.extend(finding_actions)
        
        # Also generate actions for attack chains
        for chain in self._attack_chains:
            chain_actions = self._generate_actions_for_chain(chain)
            actions.extend(chain_actions)
        
        self._update_progress('suggested_actions', 95, f'Generated {len(actions)} suggested actions')
        
        return actions
    
    def _generate_actions_for_finding(self, finding) -> List[SuggestedAction]:
        """Generate suggested actions for a single finding"""
        actions = []
        
        # Get finding attributes
        if hasattr(finding, 'confidence'):
            confidence = finding.confidence
            severity = finding.severity
            entity_type = finding.entity_type
            entity_value = finding.entity_value
            suggested_iocs = finding.suggested_iocs or []
            finding_id = finding.id
        elif isinstance(finding, dict):
            confidence = finding.get('confidence', 0)
            severity = finding.get('severity', 'low')
            entity_type = finding.get('entity_type', '')
            entity_value = finding.get('entity_value', '')
            suggested_iocs = finding.get('suggested_iocs', [])
            finding_id = finding.get('id', 0)
        else:
            return actions
        
        # Rule 1: High confidence + entity → suggest mark compromised
        if confidence >= 75 and entity_value:
            if entity_type == 'user':
                actions.append(SuggestedAction(
                    case_id=self.case_id,
                    analysis_id=self.analysis_id,
                    source_type='gap_finding',
                    source_id=finding_id,
                    action_type='mark_user_compromised',
                    target_entity=entity_value,
                    reason=f'High confidence finding ({confidence}%) suggests user compromise',
                    confidence=confidence,
                    status='pending'
                ))
            elif entity_type == 'system':
                actions.append(SuggestedAction(
                    case_id=self.case_id,
                    analysis_id=self.analysis_id,
                    source_type='gap_finding',
                    source_id=finding_id,
                    action_type='mark_system_compromised',
                    target_entity=entity_value,
                    reason=f'High confidence finding ({confidence}%) suggests system compromise',
                    confidence=confidence,
                    status='pending'
                ))
        
        # Rule 2: IOCs discovered → suggest add to case
        for ioc in suggested_iocs[:5]:  # Limit to 5
            ioc_value = ioc.get('value') if isinstance(ioc, dict) else str(ioc)
            ioc_type = ioc.get('type', 'Unknown') if isinstance(ioc, dict) else 'Unknown'
            ioc_reason = ioc.get('reason', 'Discovered during analysis') if isinstance(ioc, dict) else 'Discovered during analysis'
            
            actions.append(SuggestedAction(
                case_id=self.case_id,
                analysis_id=self.analysis_id,
                source_type='gap_finding',
                source_id=finding_id,
                action_type='add_ioc',
                target_entity=ioc_value,
                reason=ioc_reason,
                confidence=confidence,
                status='pending'
            ))
        
        # Rule 3: High severity → suggest investigate
        if severity in ['high', 'critical']:
            actions.append(SuggestedAction(
                case_id=self.case_id,
                analysis_id=self.analysis_id,
                source_type='gap_finding',
                source_id=finding_id,
                action_type='investigate',
                target_entity=entity_value or 'Finding',
                reason=f'{severity.title()} severity finding requires investigation',
                confidence=confidence,
                status='pending'
            ))
        
        # Save actions
        for action in actions:
            db.session.add(action)
        
        return actions
    
    def _generate_actions_for_chain(self, chain) -> List[SuggestedAction]:
        """Generate suggested actions for an attack chain"""
        # Attack chains already generate their own suggested actions
        # in AttackChainBuilder, so we just return empty here
        return []
    
    def _finalize_analysis(self, all_findings: List):
        """
        Phase 8: Finalize.
        
        Progress: 95-100%
        
        - Update case_analysis_runs with final stats
        - Mark analysis complete
        - Calculate summary metrics
        """
        db.session.commit()  # Commit any pending actions
        
        # Calculate statistics
        total_findings = len(all_findings)
        critical_count = sum(1 for f in all_findings 
                           if (hasattr(f, 'severity') and f.severity == 'critical') or
                           (isinstance(f, dict) and f.get('severity') == 'critical'))
        high_count = sum(1 for f in all_findings 
                        if (hasattr(f, 'severity') and f.severity == 'high') or
                        (isinstance(f, dict) and f.get('severity') == 'high'))
        
        # Update analysis run record
        if self._analysis_run:
            self._analysis_run.status = AnalysisStatus.COMPLETE
            self._analysis_run.completed_at = datetime.utcnow()
            self._analysis_run.progress_percent = 100
            self._analysis_run.current_phase = 'complete'
            
            # Store statistics
            self._analysis_run.total_findings = total_findings
            self._analysis_run.users_profiled = self._profiling_stats.get('users_profiled', 0)
            self._analysis_run.systems_profiled = self._profiling_stats.get('systems_profiled', 0)
            self._analysis_run.user_peer_groups = self._profiling_stats.get('user_groups', 0)
            self._analysis_run.system_peer_groups = self._profiling_stats.get('system_groups', 0)
            self._analysis_run.gap_findings = len(self._gap_findings)
            self._analysis_run.attack_chains_found = len(self._attack_chains)
            self._analysis_run.patterns_analyzed = len(self._pattern_results)
            
            # Store summary
            self._analysis_run.summary = {
                'total_findings': total_findings,
                'critical_findings': critical_count,
                'high_findings': high_count,
                'gap_findings': len(self._gap_findings),
                'attack_chains': len(self._attack_chains),
                'patterns_analyzed': len(self._pattern_results),
                'users_profiled': self._profiling_stats.get('users_profiled', 0),
                'systems_profiled': self._profiling_stats.get('systems_profiled', 0),
                'mode': self.mode,
                'duration_seconds': (datetime.utcnow() - self._start_time).total_seconds()
                    if self._start_time else 0,
                'census_distinct_event_ids': len(self._census),
                'census_total_events': sum(self._census.values()) if self._census else 0
            }
            
            db.session.commit()
    
    def _mark_failed(self, error_message: str):
        """Mark the analysis as failed"""
        if self._analysis_run:
            self._analysis_run.status = AnalysisStatus.FAILED
            self._analysis_run.error_message = error_message[:500]  # Truncate
            self._analysis_run.completed_at = datetime.utcnow()
            db.session.commit()
    
    def get_results(self) -> Dict[str, Any]:
        """
        Get analysis results summary.
        
        Returns:
            dict: Analysis results and statistics
        """
        if not self._analysis_run:
            return {}
        
        return {
            'analysis_id': self.analysis_id,
            'case_id': self.case_id,
            'mode': self.mode,
            'status': self._analysis_run.status,
            'summary': self._analysis_run.summary,
            'gap_findings': len(self._gap_findings),
            'attack_chains': len(self._attack_chains),
            'pattern_results': len(self._pattern_results),
            'total_findings': len(self._all_findings)
        }


def run_case_analysis(case_id: int, progress_callback: Callable = None) -> str:
    """
    Convenience function to run case analysis.
    
    Args:
        case_id: The case to analyze
        progress_callback: Optional callback for progress updates
        
    Returns:
        str: analysis_id
    """
    analyzer = CaseAnalyzer(case_id, progress_callback)
    return analyzer.run_full_analysis()
