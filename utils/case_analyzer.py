"""Case Analyzer - Main Analysis Orchestrator for CaseScope

Coordinates all analysis phases:
1-4. Behavioral profiling, peer clustering, gap detection, Hayabusa correlation
     (parallel via Celery group, or sequential fallback)
5.   Pattern analysis (with census pre-filter)
6.   IOC-anchored timeline
7.   AI Checkpoint 1: Triage & prioritize (Mode B/D only)
8.   OpenCTI enrichment (Mode C/D only)
9.   AI Checkpoint 2: Synthesis narrative (Mode B/D only)
10.  Suggested action generation
11.  Finalize

Adapts behavior based on available features (Mode A/B/C/D).
"""

import logging
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from uuid import uuid4
from celery.exceptions import SoftTimeLimitExceeded

from models.database import db
from models.behavioral_profiles import (
    CaseAnalysisRun, AnalysisMode, AnalysisStatus,
    UserBehaviorProfile, SystemBehaviorProfile,
    PeerGroup, GapDetectionFinding, SuggestedAction
)
from config import Config
from utils.analysis_summary import summarize_findings
from utils.pattern_suppression import (
    build_confirmed_pattern_entry,
    should_track_pattern_for_suppression,
)

logger = logging.getLogger(__name__)


class AnalysisError(Exception):
    """Raised when analysis fails"""
    pass


class CaseAnalyzer:
    """
    Main orchestrator for case analysis.
    
    Coordinates all analysis phases:
    1-4. Profiling, clustering, gap detection, Hayabusa (parallel or sequential)
    5.   Pattern analysis (with census pre-filter)
    6.   IOC-anchored timeline
    7.   AI Checkpoint 1: Triage (Mode B/D)
    8.   OpenCTI enrichment (Mode C/D)
    9.   AI Checkpoint 2: Synthesis (Mode B/D)
    10.  Suggested action generation
    11.  Finalize
    
    Adapts behavior based on available features (Mode A/B/C/D).
    """
    
    def __init__(self, case_id: int, progress_callback: Callable = None, 
                 parallel: bool = True):
        """
        Args:
            case_id: The case to analyze
            progress_callback: Optional callback(phase, percent, message) for progress updates
            parallel: If True, run phases 1-4 in parallel via Celery chord
        """
        self.case_id = case_id
        self.analysis_id: Optional[str] = None
        self.mode: Optional[str] = None
        self.progress_callback = progress_callback
        self.parallel = parallel
        
        # Runtime state
        self._analysis_run: Optional[CaseAnalysisRun] = None
        self._start_time: Optional[datetime] = None
        self._finalized = False
        
        # Results storage
        self._profiling_stats: Dict = {}
        self._gap_findings: List = []
        self._hayabusa_findings: List = []
        self._attack_chains: List = []
        self._pattern_results: List = []
        self._all_findings: List = []
        self._census: Dict[str, int] = {}  # event_id -> count from census query
        self._ioc_timeline: Dict = {}  # IOC-anchored timeline result
        self._storyline_results: Dict = {}  # Download/execution/containment storylines
        self._triage_result: Dict = {}  # AI Checkpoint 1 output
        self._synthesis_result: Dict = {}  # AI Checkpoint 2 output
        self._opencti_context: Dict = {}  # Aggregated OpenCTI threat intel context
        self._phase_outcomes: Dict[str, Dict[str, Any]] = {}

    def _record_phase_outcome(self, phase: str, success: bool,
                              details: Optional[Dict[str, Any]] = None,
                              duration_seconds: Optional[float] = None,
                              message: Optional[str] = None):
        """Persist lightweight phase outcome metadata for debugging and UI."""
        outcome = {
            'success': success,
            'message': message or ('completed' if success else 'failed'),
        }
        if details:
            outcome['details'] = details
        if duration_seconds is not None:
            outcome['duration_seconds'] = round(duration_seconds, 3)
        self._phase_outcomes[phase] = outcome
    
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
            
            # Phases 1-4: Profiling, Clustering, Gap Detection, Hayabusa Correlation
            # These can run in parallel since gap detection and Hayabusa correlation
            # are independent of behavioral profiling.
            if self.parallel:
                self._run_phases_parallel()
            else:
                self._run_phases_sequential()

            self._all_findings.extend(self._hayabusa_findings)
            
            # Phase 5: Pattern Analysis (50-78%)
            self._update_progress('pattern_analysis', 50, 'Analyzing attack patterns...')
            self._pattern_results = self._run_pattern_analysis(self._attack_chains)
            self._all_findings.extend(self._pattern_results)
            
            # Phase 6: IOC Timeline (78-84%)
            self._update_progress('ioc_timeline', 78, 'Building IOC-anchored timeline...')
            self._ioc_timeline = self._run_ioc_timeline()

            # Phase 6b: Generic incident storylines (83-84%)
            self._update_progress('incident_storylines', 83, 'Linking download, execution, and containment signals...')
            self._storyline_results = self._run_incident_storylines()
            self._all_findings.extend(self._storyline_results.get('storylines', []))
            
            # Phase 7: AI Checkpoint 1 - Triage (84-88%) - Mode B/D only
            if self.mode in ['B', 'D']:
                self._update_progress('ai_triage', 84, 'AI triage: prioritizing findings...')
                self._triage_result = self._run_ai_triage()
            else:
                self._update_progress('ai_triage', 84, 'Skipping AI triage (not available)')
                self._triage_result = {}
            
            # Phase 8: OpenCTI Enrichment (88-91%) - Mode C/D only
            if self.mode in ['C', 'D']:
                self._update_progress('opencti_enrichment', 88, 'Enriching with threat intelligence...')
                self._enrich_with_opencti(self._gap_findings + self._hayabusa_findings + self._pattern_results)
            else:
                self._update_progress('opencti_enrichment', 88, 'Skipping OpenCTI (not available)')
            
            # Phase 9: AI Checkpoint 2 - Synthesis (91-95%) - Mode B/D only
            if self.mode in ['B', 'D']:
                self._update_progress('ai_synthesis', 91, 'AI synthesis: generating narrative...')
                self._synthesis_result = self._run_ai_synthesis()
            else:
                self._update_progress('ai_synthesis', 91, 'Skipping AI synthesis (not available)')
                self._synthesis_result = {}
            
            # Phase 10: Generate Suggested Actions (95-97%)
            self._update_progress('suggested_actions', 95, 'Generating suggested actions...')
            self._generate_suggested_actions(self._all_findings)
            
            # Phase 11: Finalize (97-100%)
            self._update_progress('finalizing', 97, 'Finalizing analysis...')
            degraded_reasons = self._analysis_degraded_reasons()
            final_status = AnalysisStatus.PARTIAL if degraded_reasons else AnalysisStatus.COMPLETE
            self._finalize_analysis(
                self._all_findings,
                final_status=final_status,
                phase_message='Analysis complete' if not degraded_reasons else 'Analysis completed with degraded phases',
                progress_percent=100,
                error_message='; '.join(degraded_reasons) if degraded_reasons else None,
                partial_results_available=bool(degraded_reasons),
            )
            
            self._update_progress(
                'complete',
                100,
                'Analysis complete' if not degraded_reasons else 'Analysis completed with degraded phases',
            )
            
            logger.info(f"[CaseAnalyzer] Analysis {self.analysis_id} completed successfully")
            return self.analysis_id
            
        except SoftTimeLimitExceeded:
            logger.warning(f"[CaseAnalyzer] Analysis {self.analysis_id} hit soft time limit — saving partial results")
            try:
                all_findings = getattr(self, '_all_findings', [])
                saved_partial = self._finalize_analysis(
                    all_findings,
                    final_status=AnalysisStatus.PARTIAL,
                    phase_message='Partial results saved after analysis timeout',
                    progress_percent=100,
                    error_message='Partial completion: hit Celery soft time limit. Results saved up to last completed phase.',
                    partial_results_available=self._has_partial_results()
                )
                if not saved_partial:
                    self._mark_failed('Hit time limit before any partial results could be saved.')
            except Exception as save_err:
                logger.error(f"[CaseAnalyzer] Failed to save partial results: {save_err}")
                self._mark_failed(f'Hit time limit, partial save failed: {save_err}')
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
        feature_snapshot = FeatureAvailability.get_feature_snapshot()
        self.mode = feature_snapshot.mode
        self._start_time = datetime.utcnow()
        
        # Create analysis run record
        capabilities = feature_snapshot.capabilities
        
        self._analysis_run = CaseAnalysisRun(
            case_id=self.case_id,
            analysis_id=self.analysis_id,
            mode=self.mode,
            status=AnalysisStatus.PENDING,
            ai_enabled=feature_snapshot.ai_enabled,
            opencti_enabled=feature_snapshot.threat_intel_enabled,
            started_at=self._start_time,
            last_progress_at=self._start_time,
            current_phase='Queued for analysis'
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
            self._analysis_run.last_progress_at = datetime.utcnow()
            
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
    
    def _run_phases_sequential(self):
        """Run phases 1-4 sequentially (fallback mode)."""
        # Phase 1: Behavioral Profiling (0-15%)
        self._update_progress('profiling', 0, 'Starting behavioral profiling...')
        profiling_started = time.time()
        self._profiling_stats = self._run_behavioral_profiling()
        self._record_phase_outcome(
            'profile_cluster',
            True,
            details={
                'users_profiled': self._profiling_stats.get('users_profiled', 0),
                'systems_profiled': self._profiling_stats.get('systems_profiled', 0),
            },
            duration_seconds=time.time() - profiling_started,
            message='Behavioral profiling completed',
        )
        
        # Phase 2: Peer Clustering (15-20%)
        self._update_progress('clustering', 15, 'Building peer groups...')
        clustering_started = time.time()
        clustering_stats = self._run_peer_clustering()
        self._profiling_stats.update(clustering_stats)
        self._record_phase_outcome(
            'peer_clustering',
            True,
            details=clustering_stats,
            duration_seconds=time.time() - clustering_started,
            message='Peer clustering completed',
        )
        
        # Phase 3: Gap Detection (20-35%)
        self._update_progress('gap_detection', 20, 'Running gap detection...')
        gap_started = time.time()
        self._gap_findings = self._run_gap_detection()
        self._all_findings.extend(self._gap_findings)
        self._record_phase_outcome(
            'gap_detection',
            True,
            details={'findings_count': len(self._gap_findings)},
            duration_seconds=time.time() - gap_started,
            message=f'Gap detection completed with {len(self._gap_findings)} findings',
        )
        
        # Phase 4: Hayabusa Correlation (35-50%)
        self._update_progress('hayabusa_correlation', 35, 'Correlating Hayabusa detections...')
        hayabusa_started = time.time()
        self._attack_chains = self._run_hayabusa_correlation()
        self._record_phase_outcome(
            'hayabusa_correlation',
            True,
            details={
                'findings_count': len(self._hayabusa_findings),
                'attack_chains': len(self._attack_chains),
            },
            duration_seconds=time.time() - hayabusa_started,
            message=f'Hayabusa correlation completed with {len(self._attack_chains)} attack chains',
        )
    
    def _run_phases_parallel(self):
        """Run phases 1-4 in parallel via Celery group.
        
        Three parallel subtasks:
        - Profiling + Clustering (sequential within)
        - Gap Detection
        - Hayabusa Correlation + Attack Chain Building
        
        Falls back to sequential if Celery dispatch fails.
        """
        from celery import group
        from celery.result import allow_join_result
        
        self._update_progress('parallel_init', 0, 
                             'Starting parallel analysis (profiling + gaps + Hayabusa)...')
        
        try:
            from tasks.rag_tasks import (
                analyze_phase_profile, 
                analyze_phase_gaps, 
                analyze_phase_hayabusa
            )
            
            # Dispatch three parallel subtasks via group
            job = group([
                analyze_phase_profile.s(self.case_id, self.analysis_id),
                analyze_phase_gaps.s(self.case_id, self.analysis_id),
                analyze_phase_hayabusa.s(self.case_id, self.analysis_id)
            ]).apply_async()
            
            self._update_progress('parallel_running', 5, 
                                 'Parallel phases running (profiling, gaps, Hayabusa)...')
            
            # Wait for all subtasks to complete (timeout: 1 hour)
            # propagate=False ensures we get partial results even if one fails
            try:
                with allow_join_result():
                    phase_results = job.get(timeout=3600, propagate=False)
            except Exception as e:
                logger.warning(f"[CaseAnalyzer] Parallel group timed out or failed: {e}")
                logger.info("[CaseAnalyzer] Falling back to sequential execution")
                self._run_phases_sequential()
                return
            
            # Process results from all three subtasks
            if not isinstance(phase_results, list):
                phase_results = [phase_results]
            
            for sub_result in phase_results:
                if not isinstance(sub_result, dict):
                    continue
                    
                phase = sub_result.get('phase', '')
                success = sub_result.get('success', False)
                
                if phase == 'profile_cluster':
                    if success:
                        self._profiling_stats = {
                            'users_profiled': sub_result.get('users_profiled', 0),
                            'systems_profiled': sub_result.get('systems_profiled', 0),
                            'user_groups': sub_result.get('user_groups', 0),
                            'system_groups': sub_result.get('system_groups', 0)
                        }
                        self._record_phase_outcome(
                            'profile_cluster',
                            True,
                            details=self._profiling_stats,
                            duration_seconds=sub_result.get('duration_seconds'),
                            message='Profiling and clustering completed',
                        )
                    else:
                        logger.warning(f"[CaseAnalyzer] Profiling subtask failed: "
                                      f"{sub_result.get('error')}")
                        self._record_phase_outcome(
                            'profile_cluster',
                            False,
                            details={'error': sub_result.get('error')},
                            duration_seconds=sub_result.get('duration_seconds'),
                            message='Profiling and clustering subtask failed',
                        )
                
                elif phase == 'gap_detection':
                    if success:
                        # Gap findings are stored in DB by the subtask,
                        # reload them for the findings list
                        from models.behavioral_profiles import GapDetectionFinding
                        self._gap_findings = GapDetectionFinding.query.filter_by(
                            case_id=self.case_id,
                            analysis_id=self.analysis_id
                        ).all()
                        self._all_findings.extend(self._gap_findings)
                        self._record_phase_outcome(
                            'gap_detection',
                            True,
                            details={'findings_count': len(self._gap_findings)},
                            duration_seconds=sub_result.get('duration_seconds'),
                            message=f'Gap detection completed with {len(self._gap_findings)} findings',
                        )
                    else:
                        logger.warning(f"[CaseAnalyzer] Gap detection subtask failed: "
                                      f"{sub_result.get('error')}")
                        self._record_phase_outcome(
                            'gap_detection',
                            False,
                            details={'error': sub_result.get('error')},
                            duration_seconds=sub_result.get('duration_seconds'),
                            message='Gap detection subtask failed',
                        )
                
                elif phase == 'hayabusa_correlation':
                    if success:
                        self._hayabusa_findings = sub_result.get('finding_summaries', []) or []
                        self._attack_chains = sub_result.get('attack_chain_summaries', []) or []
                        logger.info(f"[CaseAnalyzer] Hayabusa: {len(self._attack_chains)} "
                                   f"attack chains built")
                        self._record_phase_outcome(
                            'hayabusa_correlation',
                            True,
                            details={
                                'findings_count': len(self._hayabusa_findings),
                                'attack_chains': len(self._attack_chains),
                                'detection_groups': sub_result.get('detection_groups', 0),
                            },
                            duration_seconds=sub_result.get('duration_seconds'),
                            message=f'Hayabusa correlation completed with {len(self._attack_chains)} attack chains',
                        )
                    else:
                        logger.warning(f"[CaseAnalyzer] Hayabusa subtask failed: "
                                      f"{sub_result.get('error')}")
                        self._record_phase_outcome(
                            'hayabusa_correlation',
                            False,
                            details={'error': sub_result.get('error')},
                            duration_seconds=sub_result.get('duration_seconds'),
                            message='Hayabusa subtask failed',
                        )
            
            # Count successes
            success_count = sum(1 for r in phase_results 
                               if isinstance(r, dict) and r.get('success'))
            total_count = len(phase_results)
            
            self._update_progress('parallel_complete', 50, 
                                 f'Parallel phases complete ({success_count}/{total_count} succeeded)')
            
            logger.info(f"[CaseAnalyzer] Parallel execution: "
                       f"{success_count}/{total_count} phases succeeded")
            
        except ImportError as e:
            logger.warning(f"[CaseAnalyzer] Celery tasks not available, "
                          f"falling back to sequential: {e}")
            self._run_phases_sequential()
        except Exception as e:
            logger.warning(f"[CaseAnalyzer] Parallel dispatch failed, "
                          f"falling back to sequential: {e}")
            self._run_phases_sequential()
    
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
        from pipeline.baselines import run_behavioral_profiling

        return run_behavioral_profiling(
            case_id=self.case_id,
            analysis_id=self.analysis_id,
            progress_callback=self._profiling_progress_callback,
        )
    
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
        from pipeline.baselines import run_peer_clustering

        result = run_peer_clustering(self.case_id, self.analysis_id)
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
        from pipeline.detect_anomalies import run_detect_anomalies

        findings = run_detect_anomalies(
            case_id=self.case_id,
            analysis_id=self.analysis_id,
            progress_callback=self._gap_progress_callback,
        )

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
            list[AttackChain]
        """
        from pipeline.detect import run_hayabusa_correlation

        result = run_hayabusa_correlation(
            case_id=self.case_id,
            analysis_id=self.analysis_id,
            progress_callback=self._hayabusa_progress_callback,
        )
        detection_groups = result.get('detection_groups', [])
        self._hayabusa_findings = detection_groups
        attack_chains = result.get('attack_chains', [])
        if attack_chains:
            self._update_progress('hayabusa_correlation', 50, 
                                 f"Identified {len(attack_chains)} attack chains")
            return attack_chains

        self._update_progress('hayabusa_correlation', 50, 'No Hayabusa detections to correlate')
        return []
    
    def _hayabusa_progress_callback(self, phase: str, percent: int, message: str):
        """Translate Hayabusa progress to overall progress (35-50%)"""
        # Scale 35-50 range based on correlator's 35-50 output
        self._update_progress(phase, percent, message)
    
    def _run_pattern_analysis(self, attack_chains: List) -> List[Dict]:
        """
        Phase 5: Run pattern analysis with Deterministic Evidence Engine.
        
        Progress: 50-85%
        
        Uses census-based pre-filtering to skip patterns whose anchor
        event IDs don't exist in the case, then runs extraction +
        deterministic evidence scoring + optional AI judgment.
        
        Mode A/C: Uses rule-based analysis
        Mode B/D: Uses deterministic engine + AI judgment layer
        
        Returns:
            list: Pattern analysis results
        """
        from utils.ai_correlation_analyzer import AICorrelationAnalyzer, RuleBasedAnalyzer
        from pipeline.pattern_analysis import (
            apply_pattern_suppression,
            create_candidate_extractor,
            create_evidence_engine,
            materialize_pattern_package,
            prepare_pattern_analysis,
            select_highest_scoring_packages,
        )
        
        results = []

        prep = prepare_pattern_analysis(self.case_id)
        patterns = prep['patterns']
        
        if not patterns:
            self._update_progress('pattern_analysis', 85, 'No patterns to analyze')
            return results
        
        self._update_progress('pattern_analysis', 51, 'Running event census...')
        census = prep['census']
        self._census = census
        ordered_patterns = prep['ordered_patterns']
        skipped_count = prep['skipped_count']
        
        if skipped_count > 0:
            logger.info(f"[CaseAnalyzer] Census filter: {len(ordered_patterns)}/{len(patterns)} "
                       f"patterns eligible ({skipped_count} skipped — anchor events not in case)")
        
        if not ordered_patterns:
            self._update_progress('pattern_analysis', 85, 
                                 f'No matching patterns (0/{len(patterns)} eligible after census)')
            return results

        pattern_count = len(ordered_patterns)
        self._update_progress('pattern_analysis', 52, 
                             f'Analyzing {pattern_count} patterns ({skipped_count} skipped by census)...')
        
        extractor = create_candidate_extractor(self.case_id, self.analysis_id)
        
        gap_findings = getattr(self, '_gap_findings', None) or []
        evidence_engine = create_evidence_engine(
            self.case_id,
            self.analysis_id,
            census=census,
            gap_findings=gap_findings,
        )
        if self.mode in ['B', 'D']:
            ai_analyzer = AICorrelationAnalyzer(
                case_id=self.case_id,
                analysis_id=self.analysis_id
            )
        else:
            rule_analyzer = RuleBasedAnalyzer(
                case_id=self.case_id,
                analysis_id=self.analysis_id
            )
        
        confirmed_patterns = {}
        
        for i, (pattern_id, pattern_config) in enumerate(ordered_patterns):
            progress = 52 + int((i / pattern_count) * 33)
            
            pattern_name = pattern_config.get('name', pattern_id)
            self._update_progress('pattern_analysis', progress, f'Analyzing {pattern_name}...')
            
            try:
                pattern_config['id'] = pattern_id
                extraction_result = extractor.extract_pattern_candidates(pattern_config)
                
                if extraction_result.get('anchor_count', 0) == 0:
                    continue
                
                candidates = extractor.get_candidates_for_key(
                    pattern_id,
                    extraction_result.get('correlation_key', '')
                )
                candidates = extractor.attach_behavioral_context(candidates)
                
                if self.mode in ['B', 'D']:
                    anchor_events = extraction_result.get('anchors', candidates)
                    time_window = pattern_config.get('time_window_minutes', 60)
                    
                    evidence_packages = evidence_engine.evaluate_pattern(
                        pattern_id, pattern_config, anchor_events, time_window
                    )
                    
                    ai_full_threshold = pattern_config.get('ai_full_threshold', 40)
                    ai_gray_threshold = pattern_config.get('ai_gray_threshold', 30)
                    pattern_confirmed = []
                    evidence_packages = select_highest_scoring_packages(evidence_packages)
                    
                    for pkg in evidence_packages:
                        suppression_result = apply_pattern_suppression(
                            pattern_id,
                            pkg,
                            confirmed_patterns,
                        )
                        if suppression_result['suppressed']:
                            logger.info(
                                f"[CaseAnalyzer] Suppressing {pattern_id}:{pkg.correlation_key} — "
                                f"superseded by {suppression_result['suppressor']}"
                            )
                            continue

                        soft_adjustment = suppression_result['soft_adjustment']
                        if soft_adjustment:
                            logger.info(
                                f"[CaseAnalyzer] Down-ranking {pattern_id}:{pkg.correlation_key} by "
                                f"{soft_adjustment} due to overlapping higher-specificity pattern(s)"
                            )

                        materialized = materialize_pattern_package(
                            case_id=self.case_id,
                            analysis_id=self.analysis_id,
                            pattern_id=pattern_id,
                            pattern_name=pattern_name,
                            pattern_config=pattern_config,
                            package=pkg,
                            extraction_result=extraction_result,
                            ai_full_threshold=ai_full_threshold,
                            ai_gray_threshold=ai_gray_threshold,
                            run_full_analysis=lambda: ai_analyzer.analyze_with_evidence(pkg, pattern_config),
                            run_light_analysis=lambda: ai_analyzer.analyze_with_evidence_lightweight(
                                pkg, pattern_config
                            ),
                            model_name=ai_analyzer.model,
                            extra_finding_fields={
                                'overlay_score_adjustment': pkg.overlay_score_adjustment,
                                'intel_overlay': pkg.intel_overlay,
                            },
                        )
                        db.session.add(materialized['result_record'])
                        
                        if materialized['should_emit_finding']:
                            results.append(materialized['finding'])
                        pattern_confirmed.append(materialized['confirmed_pattern_entry'])
                    
                    db.session.commit()
                    
                    if should_track_pattern_for_suppression(pattern_id):
                        confirmed_patterns[pattern_id] = pattern_confirmed
                else:
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
                    
                    if should_track_pattern_for_suppression(pattern_id) and pattern_results:
                        confirmed_patterns[pattern_id] = [
                            build_confirmed_pattern_entry(
                                correlation_key=r['correlation_key'],
                                score=r.get('final_confidence', 0),
                            )
                            for r in pattern_results
                        ]
                
            except Exception as e:
                logger.warning(f"[CaseAnalyzer] Pattern analysis failed for {pattern_id}: {e}")
        
        extractor.cleanup()
        
        self._update_progress('pattern_analysis', 85, f'Completed {len(results)} pattern analyses')
        
        return results
    
    def _run_ioc_timeline(self) -> Dict:
        """
        Phase 6: Build IOC-anchored timeline.
        
        Progress: 78-88%
        
        For each IOC in the case, finds matching events, gets
        surrounding context, builds causal chains, and detects
        cross-host IOC movement. Deterministic (no AI).
        
        Returns:
            dict: IOC timeline result with entries, cross-host links, summaries
        """
        try:
            from utils.ioc_timeline_builder import IOCTimelineBuilder
            
            builder = IOCTimelineBuilder(
                case_id=self.case_id,
                analysis_id=self.analysis_id,
                progress_callback=self._ioc_timeline_progress_callback
            )
            
            result = builder.build()
            
            entries_count = len(result.get('entries', []))
            links_count = len(result.get('cross_host_links', []))
            
            self._update_progress('ioc_timeline', 88, 
                                 f'IOC timeline: {entries_count} entries, {links_count} cross-host links')
            
            return result
            
        except Exception as e:
            logger.warning(f"[CaseAnalyzer] IOC timeline build failed: {e}", exc_info=True)
            self._update_progress('ioc_timeline', 88, 'IOC timeline skipped (no IOCs or error)')
            return {}
    
    def _ioc_timeline_progress_callback(self, phase: str, percent: int, message: str):
        """Translate IOC timeline progress to overall progress (78-84%)"""
        overall_percent = 78 + int(percent * 0.06)
        self._update_progress(phase, overall_percent, message)
    
    def _run_ai_triage(self) -> Dict:
        """
        Phase 7: AI Checkpoint 1 — Triage and prioritize findings.
        
        Progress: 84-88%
        
        Runs a single LLM call to rank findings by importance,
        group them into investigation threads, and assess risk.
        Only runs in Mode B/D (AI enabled).
        
        Returns:
            dict: Triage result with priority_findings, investigation_threads, etc.
        """
        try:
            from utils.ai_checkpoints import TriageCheckpoint
            
            checkpoint = TriageCheckpoint(
                case_id=self.case_id,
                analysis_id=self.analysis_id
            )
            
            context = {
                'census': self._census,
                'gap_findings': self._gap_findings,
                'pattern_results': self._pattern_results,
                'attack_chains': self._attack_chains,
                'ioc_timeline': self._ioc_timeline,
                'incident_storylines': self._storyline_results.get('storylines', []),
                'profiling_stats': self._profiling_stats
            }
            
            result = checkpoint.run(context)
            
            priority_count = len(result.get('priority_findings', []))
            thread_count = len(result.get('investigation_threads', []))
            duration = result.get('triage_duration_ms', 0)
            
            self._update_progress('ai_triage', 88, 
                                 f'AI triage: {priority_count} priority findings, '
                                 f'{thread_count} threads ({duration}ms)')
            self._record_phase_outcome(
                'ai_triage',
                not result.get('fallback', False),
                details={
                    'priority_findings': priority_count,
                    'investigation_threads': thread_count,
                    'fallback': result.get('fallback', False),
                },
                duration_seconds=duration / 1000 if duration else None,
                message='AI triage complete' if not result.get('fallback') else 'AI triage fallback',
            )
            
            return result
            
        except Exception as e:
            logger.warning(f"[CaseAnalyzer] AI triage failed: {e}", exc_info=True)
            self._update_progress('ai_triage', 88, 'AI triage skipped (error)')
            self._record_phase_outcome(
                'ai_triage',
                False,
                details={'error': str(e)},
                message='AI triage failed',
            )
            return {}
    
    def _run_ai_synthesis(self) -> Dict:
        """
        Phase 9: AI Checkpoint 2 — Synthesize executive narrative.
        
        Progress: 91-95%
        
        Runs a single LLM call to produce an executive summary,
        key findings, affected assets, and recommended actions.
        Only runs in Mode B/D (AI enabled).
        
        Returns:
            dict: Synthesis result with executive_summary, key_findings, etc.
        """
        try:
            from utils.ai_checkpoints import SynthesisCheckpoint
            
            checkpoint = SynthesisCheckpoint(
                case_id=self.case_id,
                analysis_id=self.analysis_id
            )
            
            context = {
                'triage': self._triage_result,
                'gap_findings': self._gap_findings,
                'pattern_results': self._pattern_results,
                'attack_chains': self._attack_chains,
                'ioc_timeline': self._ioc_timeline,
                'incident_storylines': self._storyline_results.get('storylines', []),
                'profiling_stats': self._profiling_stats,
                'opencti_context': self._opencti_context,
            }
            
            result = checkpoint.run(context)
            
            findings_count = len(result.get('key_findings', []))
            actions_count = len(result.get('recommended_actions', []))
            duration = result.get('synthesis_duration_ms', 0)
            
            self._update_progress('ai_synthesis', 95, 
                                 f'AI synthesis: {findings_count} findings, '
                                 f'{actions_count} actions ({duration}ms)')
            self._record_phase_outcome(
                'ai_synthesis',
                not result.get('fallback', False),
                details={
                    'key_findings': findings_count,
                    'recommended_actions': actions_count,
                    'fallback': result.get('fallback', False),
                },
                duration_seconds=duration / 1000 if duration else None,
                message='AI synthesis complete' if not result.get('fallback') else 'AI synthesis fallback',
            )
            
            return result
            
        except Exception as e:
            logger.warning(f"[CaseAnalyzer] AI synthesis failed: {e}", exc_info=True)
            self._update_progress('ai_synthesis', 95, 'AI synthesis skipped (error)')
            self._record_phase_outcome(
                'ai_synthesis',
                False,
                details={'error': str(e)},
                message='AI synthesis failed',
            )
            return {}

    def _run_incident_storylines(self) -> Dict[str, Any]:
        """Build generic download/execution/containment storylines."""
        try:
            from utils.incident_storyline_detector import IncidentStorylineDetector

            detector = IncidentStorylineDetector(self.case_id)
            result = detector.build()
            storylines = result.get('storylines', [])
            self._record_phase_outcome(
                'incident_storylines',
                True,
                details={
                    'storyline_count': len(storylines),
                    'download_count': result.get('download_count', 0),
                    'containment_count': result.get('containment_count', 0),
                },
                message='Incident storyline correlation complete',
            )
            self._update_progress(
                'incident_storylines',
                84,
                f"Correlated {len(storylines)} incident storylines",
            )
            return result
        except Exception as e:
            logger.warning(f"[CaseAnalyzer] Incident storyline detection failed: {e}", exc_info=True)
            self._record_phase_outcome(
                'incident_storylines',
                False,
                details={'error': str(e)},
                message='Incident storyline correlation failed',
            )
            return {}
    
    def _enrich_with_opencti(self, all_findings: List):
        """
        Phase 8: Add OpenCTI context (Mode C/D only).
        
        Progress: 88-91%
        
        Stores aggregated threat intel as self._opencti_context for use
        by Phase 9 (synthesis) and Phase 10 (suggested actions).
        Also enriches attack chains with per-technique context.
        """
        from utils.opencti_context import OpenCTIContextProvider
        from utils.ti.enrichment import apply_ti_overlay_to_finding, is_ti_overlay_enabled
        
        provider = OpenCTIContextProvider(self.case_id, self.analysis_id)
        
        if not provider.is_available():
            self._update_progress('opencti_enrichment', 90, 'OpenCTI not available')
            self._record_phase_outcome(
                'opencti_enrichment',
                False,
                details={'error': 'OpenCTI context provider unavailable'},
                message='OpenCTI not available',
            )
            return
        
        provider.clear_cache()
        
        self._update_progress('opencti_enrichment', 86, 'Fetching threat intelligence context...')
        
        context = provider.get_context_for_findings(all_findings)
        self._opencti_context = context

        overlay_updates = 0
        if is_ti_overlay_enabled():
            for finding in all_findings:
                overlay_context = apply_ti_overlay_to_finding(finding)
                if overlay_context and overlay_context.get('applied_boost', 0) > 0:
                    overlay_updates += 1
                    logger.info(
                        "[CaseAnalyzer] Attached TI overlay to %s:%s (+%s metadata-only)",
                        finding.get('pattern_id', ''),
                        finding.get('correlation_key', ''),
                        overlay_context['applied_boost'],
                    )
        
        # Enrich attack chains with per-technique lookups
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
                
                if isinstance(chain, dict):
                    chain['opencti_context'] = chain_context
                elif hasattr(chain, 'opencti_context'):
                    chain.opencti_context = chain_context
        
        self._update_progress('opencti_enrichment', 90, 'Threat intelligence enrichment complete')
        self._record_phase_outcome(
            'opencti_enrichment',
            True,
            details={
                'threat_actors': len(context.get('threat_actors', [])),
                'campaigns': len(context.get('campaigns', [])),
                'ioc_enrichment': len(context.get('ioc_enrichment', {})),
                'overlay_updates': overlay_updates,
            },
            message='Threat intelligence enrichment complete',
        )
    
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
        
        # OpenCTI-driven hunt suggestions: find co-occurring techniques
        # from the same threat actors that we haven't detected yet
        if self._opencti_context and self._opencti_context.get('available'):
            try:
                detected_techniques = set()
                for finding in all_findings:
                    if hasattr(finding, 'mitre_techniques') and finding.mitre_techniques:
                        detected_techniques.update(finding.mitre_techniques)
                    elif isinstance(finding, dict) and finding.get('mitre_techniques'):
                        detected_techniques.update(finding['mitre_techniques'])
                
                for chain in self._attack_chains:
                    cd = chain.to_dict() if hasattr(chain, 'to_dict') else chain
                    if isinstance(cd, dict):
                        detected_techniques.update(cd.get('tactics_observed', []))
                
                for actor in self._opencti_context.get('threat_actors', [])[:5]:
                    actor_techniques = {t['mitre_id'] for t in actor.get('attack_patterns', [])
                                        if t.get('mitre_id')}
                    missing = actor_techniques - detected_techniques
                    for tech_id in list(missing)[:3]:
                        actions.append(SuggestedAction(
                            case_id=self.case_id,
                            analysis_id=self.analysis_id,
                            source_type='opencti',
                            source_id=0,
                            action_type='hunt',
                            target_type='technique',
                            target_value=tech_id,
                            reason=(
                                f"Hunt for {tech_id} — used by {actor['name']} "
                                f"alongside detected techniques"
                            ),
                            confidence=60,
                            status='pending'
                        ))
            except Exception as e:
                logger.debug(f"[CaseAnalyzer] OpenCTI hunt suggestions skipped: {e}")

        actions = self._deduplicate_actions(actions)

        for action in actions:
            db.session.add(action)
        
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
            source_type = 'gap_finding'
        elif isinstance(finding, dict):
            confidence = finding.get('confidence', 0)
            severity = finding.get('severity', 'low')
            entity_type = finding.get('entity_type', '')
            entity_value = finding.get('entity_value', '')
            suggested_iocs = finding.get('suggested_iocs', [])
            finding_id = finding.get('id', 0)
            source_type = finding.get('type', 'finding')
        else:
            return actions
        
        # Rule 1: High confidence + entity → suggest mark compromised
        if confidence >= 75 and entity_value:
            if entity_type == 'user':
                actions.append(SuggestedAction(
                    case_id=self.case_id,
                    analysis_id=self.analysis_id,
                    source_type=source_type,
                    source_id=finding_id,
                    action_type='mark_user_compromised',
                    target_type='user',
                    target_value=entity_value,
                    reason=f'High confidence finding ({confidence}%) suggests user compromise',
                    confidence=confidence,
                    status='pending'
                ))
            elif entity_type == 'system':
                actions.append(SuggestedAction(
                    case_id=self.case_id,
                    analysis_id=self.analysis_id,
                    source_type=source_type,
                    source_id=finding_id,
                    action_type='mark_system_compromised',
                    target_type='system',
                    target_value=entity_value,
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
                source_type=source_type,
                source_id=finding_id,
                action_type='add_ioc',
                target_type='ioc',
                target_value=ioc_value,
                reason=ioc_reason,
                confidence=confidence,
                status='pending'
            ))
        
        # Rule 3: High severity → suggest investigate
        if severity in ['high', 'critical']:
            actions.append(SuggestedAction(
                case_id=self.case_id,
                analysis_id=self.analysis_id,
                source_type=source_type,
                source_id=finding_id,
                action_type='investigate',
                target_type=entity_type or 'finding',
                target_value=entity_value or 'Finding',
                reason=f'{severity.title()} severity finding requires investigation',
                confidence=confidence,
                status='pending'
            ))
        
        return actions
    
    def _generate_actions_for_chain(self, chain) -> List[SuggestedAction]:
        """Generate suggested actions for an attack chain"""
        # Attack chains already generate their own suggested actions
        # in AttackChainBuilder, so we just return empty here
        return []
    
    def _has_partial_results(self) -> bool:
        return bool(
            self._profiling_stats or
            self._gap_findings or
            self._hayabusa_findings or
            self._attack_chains or
            self._pattern_results or
            self._ioc_timeline or
            self._storyline_results or
            self._triage_result or
            self._synthesis_result
        )

    @staticmethod
    def _deduplicate_actions(actions: List[SuggestedAction]) -> List[SuggestedAction]:
        """Collapse duplicate actions generated by overlapping findings."""
        deduped: Dict[Any, SuggestedAction] = {}
        for action in actions:
            key = (
                action.action_type,
                action.target_type,
                str(action.target_value or '').lower(),
            )
            existing = deduped.get(key)
            if existing is None or (action.confidence or 0) > (existing.confidence or 0):
                deduped[key] = action
        return list(deduped.values())

    def _analysis_degraded_reasons(self) -> List[str]:
        """Summarize failed or fallback phases that warrant partial status."""
        reasons = []
        for phase, outcome in self._phase_outcomes.items():
            if outcome.get('success') is False:
                reasons.append(f"{phase} degraded")
        return reasons

    @staticmethod
    def _make_json_safe(value: Any) -> Any:
        """Recursively convert datetimes and complex values for JSON storage."""
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, str):
            return value.replace('\x00', '')
        if isinstance(value, dict):
            return {
                CaseAnalyzer._make_json_safe(str(key)): CaseAnalyzer._make_json_safe(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [CaseAnalyzer._make_json_safe(item) for item in value]
        if isinstance(value, tuple):
            return [CaseAnalyzer._make_json_safe(item) for item in value]
        return value

    def _finalize_analysis(self, all_findings: List,
                           final_status: str = AnalysisStatus.COMPLETE,
                           phase_message: Optional[str] = None,
                           progress_percent: int = 100,
                           error_message: Optional[str] = None,
                           partial_results_available: bool = False) -> bool:
        """Persist terminal analysis state and summary metrics."""
        if not self._analysis_run:
            return False

        if self._finalized and self._analysis_run.status in AnalysisStatus.terminal_statuses():
            return True

        db.session.commit()  # Commit any pending actions

        finding_summary = summarize_findings(all_findings)
        total_findings = finding_summary['total_findings']
        critical_count = finding_summary['critical_findings']
        high_count = finding_summary['high_findings']

        now = datetime.utcnow()
        self._analysis_run.status = final_status
        self._analysis_run.completed_at = now
        self._analysis_run.last_progress_at = now
        self._analysis_run.progress_percent = min(100, max(0, progress_percent))
        self._analysis_run.current_phase = phase_message or (
            'Analysis complete' if final_status == AnalysisStatus.COMPLETE
            else 'Partial results saved' if final_status == AnalysisStatus.PARTIAL
            else 'Analysis failed'
        )
        self._analysis_run.partial_results_available = partial_results_available
        self._analysis_run.error_message = error_message[:500] if error_message else None

        self._analysis_run.findings_generated = total_findings
        self._analysis_run.high_confidence_findings = finding_summary['high_confidence_findings']
        self._analysis_run.users_profiled = self._profiling_stats.get('users_profiled', 0)
        self._analysis_run.systems_profiled = self._profiling_stats.get('systems_profiled', 0)
        self._analysis_run.peer_groups_created = (
            self._profiling_stats.get('user_groups', 0) +
            self._profiling_stats.get('system_groups', 0)
        )
        self._analysis_run.patterns_evaluated = len(self._pattern_results)
        self._analysis_run.gap_findings = len(self._gap_findings)
        self._analysis_run.attack_chains_found = len(self._attack_chains)
        self._analysis_run.patterns_analyzed = len(self._pattern_results)

        summary = {
            'total_findings': total_findings,
            'critical_findings': critical_count,
            'high_findings': high_count,
            'medium_findings': finding_summary['medium_findings'],
            'low_findings': finding_summary['low_findings'],
            'gap_findings': len(self._gap_findings),
            'hayabusa_findings': len(self._hayabusa_findings),
            'attack_chains': len(self._attack_chains),
            'patterns_analyzed': len(self._pattern_results),
            'storyline_findings': len(self._storyline_results.get('storylines', [])),
            'users_profiled': self._profiling_stats.get('users_profiled', 0),
            'systems_profiled': self._profiling_stats.get('systems_profiled', 0),
            'high_confidence_findings': finding_summary['high_confidence_findings'],
            'severity_breakdown': finding_summary['severity_breakdown'],
            'top_findings': finding_summary['top_findings'],
            'mode': self.mode,
            'duration_seconds': (now - self._start_time).total_seconds()
                if self._start_time else 0,
            'census_distinct_event_ids': len(self._census),
            'census_total_events': sum(self._census.values()) if self._census else 0,
            'ioc_timeline_entries': len(self._ioc_timeline.get('entries', [])) if self._ioc_timeline else 0,
            'ioc_timeline_cross_host_links': len(self._ioc_timeline.get('cross_host_links', [])) if self._ioc_timeline else 0,
            'incident_storylines': self._storyline_results.get('storylines', []),
            'ai_triage': self._triage_result if self._triage_result else None,
            'ai_synthesis': self._synthesis_result if self._synthesis_result else None,
            'phase_outcomes': self._phase_outcomes,
            'degraded_reasons': self._analysis_degraded_reasons(),
            'partial_results_available': partial_results_available,
            'final_status': final_status,
        }
        self._analysis_run.summary = self._make_json_safe(summary)

        db.session.commit()

        try:
            from utils.unified_findings_store import sync_case_findings

            mirrored_count = sync_case_findings(
                self.case_id,
                self.analysis_id,
                all_findings,
            )
            self._record_phase_outcome(
                "finding_storage_sync",
                True,
                details={"mirrored_findings": mirrored_count},
                message="Unified findings mirrored to ClickHouse",
            )
        except Exception as exc:
            logger.warning("[CaseAnalyzer] Unified findings mirror failed: %s", exc)
            self._record_phase_outcome(
                "finding_storage_sync",
                False,
                details={"error": str(exc)},
                message="Unified findings mirror unavailable",
            )

        summary["phase_outcomes"] = self._phase_outcomes
        self._analysis_run.summary = self._make_json_safe(summary)
        db.session.commit()
        self._finalized = True
        return True
    
    def _mark_failed(self, error_message: str):
        """Mark the analysis as failed"""
        if self._analysis_run:
            db.session.rollback()
            self._analysis_run.status = AnalysisStatus.FAILED
            self._analysis_run.error_message = error_message[:500]  # Truncate
            self._analysis_run.completed_at = datetime.utcnow()
            self._analysis_run.last_progress_at = self._analysis_run.completed_at
            self._analysis_run.partial_results_available = False
            self._analysis_run.current_phase = 'Analysis failed'
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
            'hayabusa_findings': len(self._hayabusa_findings),
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
