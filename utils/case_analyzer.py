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
from typing import Dict, List, Any, Optional, Callable, Tuple
from uuid import uuid4
from celery.exceptions import SoftTimeLimitExceeded

from models.database import db
from models.behavioral_profiles import (
    CaseAnalysisRun, AnalysisMode, AnalysisStatus,
    UserBehaviorProfile, SystemBehaviorProfile,
    PeerGroup, GapDetectionFinding, SuggestedAction
)
from config import Config
from pipeline.case_finalize import finalize_case_analysis_run
from utils.analysis_phases import is_optional, phase_progress
from utils.analysis_progress import record_analysis_progress
from utils.pattern_ai_budget import budget_from_config
from utils.async_cancellation import clear_cancellation, is_cancellation_requested
logger = logging.getLogger(__name__)


class AnalysisError(Exception):
    """Raised when analysis fails"""
    pass


class AnalysisCancelled(Exception):
    """Raised when an active analysis run is cooperatively cancelled."""
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
            parallel: Retained for callers that construct an analyzer directly.
                How the phases are distributed is now decided by the dispatching
                task, not here; `run_full_analysis` always runs in process.
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

    @classmethod
    def attach_to_run(cls, case_id: int, analysis_id: str,
                      progress_callback: Callable = None) -> 'CaseAnalyzer':
        """Rebuild an analyzer around a run that another task already started.

        The dispatching task creates the run record and the phases execute in
        tasks of their own, so the task that continues the run has to pick the
        record back up rather than create a second one.
        """
        analyzer = cls(case_id, progress_callback)
        analyzer.analysis_id = analysis_id
        analyzer._analysis_run = CaseAnalysisRun.query.filter_by(
            analysis_id=analysis_id
        ).first()

        if not analyzer._analysis_run:
            raise AnalysisError(f'Analysis run {analysis_id} not found for case {case_id}')

        analyzer.mode = analyzer._analysis_run.mode
        analyzer._start_time = analyzer._analysis_run.started_at
        analyzer._phase_outcomes = dict(
            (analyzer._analysis_run.summary or {}).get('phase_outcomes') or {}
        )
        return analyzer

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
    
    def begin_analysis(self) -> str:
        """Create the run record and clear stale data, without running any phase.

        Split out so the dispatching task can establish the run and hand the
        phases to Celery without holding a worker slot for the duration. The
        orchestrator used to block in a polling loop waiting on three children
        that needed worker slots of their own on the same queue, which could
        deadlock outright and was the reason gap detection observed profiles that
        were still being written.
        """
        self._initialize_analysis_run()
        self._ensure_not_cancelled()
        logger.info(
            "[CaseAnalyzer] Starting analysis %s for case %s (Mode %s)",
            self.analysis_id, self.case_id, self.mode,
        )
        return self.analysis_id

    def run_full_analysis(self) -> str:
        """
        Run every phase in this process, start to finish.

        Used when Celery is unavailable and by the tests. The dispatched path
        runs the same phases across several tasks; see `resume_from_baselines`.
        
        Returns:
            str: analysis_id for this run
            
        Raises:
            AnalysisError: If analysis fails
        """
        try:
            self.begin_analysis()
            self._run_phases_sequential()
            self._run_tail_phases()
            return self.analysis_id
        except AnalysisCancelled:
            self._handle_cancelled()
            raise
        except SoftTimeLimitExceeded:
            self._handle_soft_time_limit()
            return self.analysis_id
        except Exception as e:
            logger.error(f"[CaseAnalyzer] Analysis failed: {e}", exc_info=True)
            self._mark_failed(str(e))
            raise AnalysisError(f"Analysis failed: {e}")
        finally:
            clear_cancellation('analysis', self.case_id)

    def resume_from_baselines(self, wave_results: List[Any]) -> str:
        """Continue a dispatched run once profiling and correlation have finished.

        This is the chord callback's entry point. Gap detection runs here rather
        than alongside profiling because every one of its detectors reads the
        profiles and peer groups that profiling writes; running the two
        concurrently meant the behavioural anomaly detector queried a table that
        initialisation had just emptied and profiling had not yet refilled.
        """
        try:
            self._absorb_wave_results(wave_results)
            self._ensure_not_cancelled()
            self._run_gap_detection_phase()
            self._run_tail_phases()
            return self.analysis_id
        except AnalysisCancelled:
            self._handle_cancelled()
            raise
        except SoftTimeLimitExceeded:
            self._handle_soft_time_limit()
            return self.analysis_id
        except Exception as e:
            logger.error(f"[CaseAnalyzer] Analysis failed: {e}", exc_info=True)
            self._mark_failed(str(e))
            raise AnalysisError(f"Analysis failed: {e}")
        finally:
            clear_cancellation('analysis', self.case_id)

    def _run_tail_phases(self) -> str:
        """Phases 5 to 11, which run identically however the earlier ones ran."""
        self._ensure_not_cancelled()
        self._all_findings.extend(self._hayabusa_findings)

        # Phase 5: Pattern Analysis (50-78%)
        self._ensure_not_cancelled()
        self._update_progress('pattern_analysis', 50, 'Analyzing attack patterns...')
        self._pattern_results = self._run_pattern_analysis(self._attack_chains)
        self._all_findings.extend(self._pattern_results)

        # Phase 6: IOC Timeline (78-84%)
        self._ensure_not_cancelled()
        self._update_progress('ioc_timeline', 78, 'Building IOC-anchored timeline...')
        self._ioc_timeline = self._run_ioc_timeline()

        # Phase 6b: Generic incident storylines (83-84%)
        self._ensure_not_cancelled()
        self._update_progress('incident_storylines', 83, 'Linking download, execution, and containment signals...')
        self._storyline_results = self._run_incident_storylines()
        self._all_findings.extend(self._storyline_results.get('storylines', []))

        # Phase 7: AI Checkpoint 1 - Triage (84-88%) - Mode B/D only
        self._ensure_not_cancelled()
        if self.mode in ['B', 'D']:
            self._update_progress('ai_triage', 84, 'AI triage: prioritizing findings...')
            self._triage_result = self._run_ai_triage()
        else:
            self._update_progress('ai_triage', 84, 'Skipping AI triage (not available)')
            self._triage_result = {}

        # Phase 8: OpenCTI Enrichment (88-91%) - Mode C/D only
        self._ensure_not_cancelled()
        if self.mode in ['C', 'D']:
            self._update_progress('opencti_enrichment', 88, 'Enriching with threat intelligence...')
            self._enrich_with_opencti(self._gap_findings + self._hayabusa_findings + self._pattern_results)
        else:
            self._update_progress('opencti_enrichment', 88, 'Skipping OpenCTI (not available)')

        # Phase 9: AI Checkpoint 2 - Synthesis (91-95%) - Mode B/D only
        self._ensure_not_cancelled()
        if self.mode in ['B', 'D']:
            self._update_progress('ai_synthesis', 91, 'AI synthesis: generating narrative...')
            self._synthesis_result = self._run_ai_synthesis()
        else:
            self._update_progress('ai_synthesis', 91, 'Skipping AI synthesis (not available)')
            self._synthesis_result = {}

        # Phase 10: Generate Suggested Actions (95-97%)
        self._ensure_not_cancelled()
        self._update_progress('suggested_actions', 95, 'Generating suggested actions...')
        self._generate_suggested_actions(self._all_findings)

        # Phase 11: Finalize (97-100%)
        self._ensure_not_cancelled()
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

    def _handle_cancelled(self):
        """Persist the cancelled state, preserving whatever was already found."""
        logger.info(f"[CaseAnalyzer] Analysis {self.analysis_id} cancelled cooperatively")
        try:
            saved_cancelled = self._finalize_analysis(
                getattr(self, '_all_findings', []),
                final_status=AnalysisStatus.CANCELLED,
                phase_message='Analysis cancelled',
                progress_percent=self._analysis_run.progress_percent if self._analysis_run else 0,
                error_message='Analysis cancellation requested',
                partial_results_available=self._has_partial_results(),
            )
            if not saved_cancelled:
                self._mark_cancelled('Analysis cancellation requested')
        except Exception as cancel_err:
            logger.error(f"[CaseAnalyzer] Failed to persist cancelled analysis state: {cancel_err}")
            self._mark_cancelled(
                f'Analysis cancellation requested; cancel finalization failed: {cancel_err}'
            )

    def _handle_soft_time_limit(self):
        """Persist partial results when the worker's soft time limit fires."""
        logger.warning(
            f"[CaseAnalyzer] Analysis {self.analysis_id} hit soft time limit - saving partial results"
        )
        try:
            saved_partial = self._finalize_analysis(
                getattr(self, '_all_findings', []),
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

            # Untouched suggestions from earlier runs describe findings this run is
            # about to regenerate, so leaving them made the queue the sum of every
            # run rather than the current picture. Anything the analyst has already
            # acted on is a record of their decision and stays.
            SuggestedAction.query.filter_by(
                case_id=self.case_id, status='pending'
            ).delete()

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
        if self._analysis_run:
            record_analysis_progress(
                self._analysis_run, phase=phase, percent=percent, message=message
            )
        
        # Call progress callback if provided
        if self.progress_callback:
            try:
                self.progress_callback(phase, percent, message)
            except Exception as e:
                logger.warning(f"[CaseAnalyzer] Progress callback error: {e}")
        
        logger.info(f"[CaseAnalyzer] [{percent}%] {phase}: {message}")

    def _cleanup_pattern_extractor(self, extractor):
        """Delete this run's staged candidate events, whatever went wrong.

        Cleanup must not be able to mask the failure that prompted it, so its own
        errors are logged rather than raised.
        """
        try:
            extractor.cleanup()
        except Exception as cleanup_error:
            logger.warning(
                "[CaseAnalyzer] Could not clean up staged candidate events for %s: %s",
                self.analysis_id, cleanup_error,
            )

    def _update_phase_fraction(self, phase: str, percent: int, message: str):
        """Report progress as a position within `phase` rather than within the run.

        Each phase used to scale its own 0-100 onto a hardcoded slice of the run,
        and those slices had drifted apart from one another - correlation reported
        into the range pattern analysis owns, and gap detection used two different
        ranges depending on which path invoked it. Phases now say only how far
        through themselves they are.
        """
        if self._analysis_run:
            record_analysis_progress(
                self._analysis_run,
                phase=phase,
                fraction=(percent or 0) / 100.0,
                message=message,
            )

        if self.progress_callback:
            try:
                absolute = phase_progress(phase, (percent or 0) / 100.0)
                self.progress_callback(phase, absolute if absolute is not None else percent, message)
            except Exception as e:
                logger.warning(f"[CaseAnalyzer] Progress callback error: {e}")

    def _ensure_not_cancelled(self):
        """Stop between analysis phases once a cancellation request is present."""
        if self._analysis_run:
            try:
                db.session.refresh(self._analysis_run)
            except Exception:
                db.session.rollback()
        if is_cancellation_requested('analysis', self.case_id):
            raise AnalysisCancelled(f"Analysis {self.analysis_id or self.case_id} cancelled")
    
    def _run_phases_sequential(self):
        """Run phases 1-4 sequentially (fallback mode)."""
        # Phase 1: Behavioral Profiling (0-15%)
        self._ensure_not_cancelled()
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
        self._ensure_not_cancelled()
        self._update_progress('clustering', 25, 'Building peer groups...')
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
        self._run_gap_detection_phase()
        
        # Phase 4: Hayabusa Correlation (35-50%)
        self._ensure_not_cancelled()
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
    
    def _run_gap_detection_phase(self):
        """Phase 3: gap detection, always after profiling has finished.

        Every gap detector reads the behavioural profiles and peer groups that
        phases 1 and 2 write, so this cannot run alongside them.
        """
        self._ensure_not_cancelled()
        self._update_progress('gap_detection', 35, 'Running gap detection...')
        gap_started = time.time()
        self._gap_findings, gap_failure = self._run_gap_detection()
        self._all_findings.extend(self._gap_findings)
        self._record_phase_outcome(
            'gap_detection',
            gap_failure is None,
            details={
                'findings_count': len(self._gap_findings),
                **({'failed_detectors': gap_failure} if gap_failure else {}),
            },
            duration_seconds=time.time() - gap_started,
            message=(
                f'Gap detection completed with {len(self._gap_findings)} findings'
                if gap_failure is None
                else f"Gap detection incomplete: {', '.join(gap_failure)} failed"
            ),
        )

    def _absorb_wave_results(self, wave_results: List[Any]):
        """Record the outcome of the phases that ran as separate tasks.

        The wave tasks report their own failures as a result rather than raising,
        so a failure of one is recorded and the run continues degraded. Nothing
        is re-run here: the previous implementation caught every exception from
        its polling loop, including cancellation and the worker's soft time
        limit, and responded by running all of phases 1 to 4 again in process -
        so asking to cancel a run started it over, and hitting the soft limit
        guaranteed hitting the hard one.
        """
        if not isinstance(wave_results, list):
            wave_results = [wave_results]

        for sub_result in wave_results:
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
                    logger.warning(
                        f"[CaseAnalyzer] Profiling task failed: {sub_result.get('error')}"
                    )
                    self._record_phase_outcome(
                        'profile_cluster',
                        False,
                        details={'error': sub_result.get('error')},
                        duration_seconds=sub_result.get('duration_seconds'),
                        message='Profiling and clustering task failed',
                    )

            elif phase == 'hayabusa_correlation':
                if success:
                    self._hayabusa_findings = sub_result.get('finding_summaries', []) or []
                    self._attack_chains = sub_result.get('attack_chain_summaries', []) or []
                    logger.info(
                        f"[CaseAnalyzer] Hayabusa: {len(self._attack_chains)} attack chains built"
                    )
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
                    logger.warning(
                        f"[CaseAnalyzer] Hayabusa task failed: {sub_result.get('error')}"
                    )
                    self._record_phase_outcome(
                        'hayabusa_correlation',
                        False,
                        details={'error': sub_result.get('error')},
                        duration_seconds=sub_result.get('duration_seconds'),
                        message='Hayabusa correlation task failed',
                    )

        succeeded = sum(
            1 for result in wave_results
            if isinstance(result, dict) and result.get('success')
        )
        logger.info(
            "[CaseAnalyzer] Baseline phases for %s: %s of %s succeeded",
            self.analysis_id, succeeded, len(wave_results),
        )

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
        """Place profiler progress (0-100) inside the profiling phase's span."""
        self._update_phase_fraction('profiling', percent, message)
    
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
        self._update_progress('clustering', 35, f"Created {result.get('total_groups', 0)} peer groups")

        return {
            'user_groups': result.get('user_groups', 0),
            'system_groups': result.get('system_groups', 0)
        }
    
    def _run_gap_detection(self) -> Tuple[List[GapDetectionFinding], Optional[List[str]]]:
        """
        Phase 3: Run gap detectors.
        
        Progress: 20-35%
        
        Returns:
            tuple: (findings, names of detectors that failed or None)

        A detector that crashes marks this phase as degraded rather than
        aborting the run, and the findings from the detectors that did complete
        are kept. Previously the detectors swallowed their own exceptions, so a
        crash was reported as a successful phase that happened to find nothing.
        """
        from pipeline.detect_anomalies import run_detect_anomalies
        from utils.stateful_detectors import GapDetectionError

        failed_detectors = None
        try:
            findings = run_detect_anomalies(
                case_id=self.case_id,
                analysis_id=self.analysis_id,
                progress_callback=self._gap_progress_callback,
            )
        except GapDetectionError as gap_error:
            findings = gap_error.findings
            failed_detectors = gap_error.failed_detectors
            logger.error(
                "[CaseAnalyzer] Gap detection incomplete for case %s: %s failed",
                self.case_id,
                ', '.join(failed_detectors),
            )

        self._update_progress('gap_detection', 50, f"Found {len(findings)} gap detection findings")

        return findings, failed_detectors
    
    def _gap_progress_callback(self, phase: str, percent: int, message: str):
        """Place gap detection progress inside the gap detection phase's span."""
        self._update_phase_fraction('gap_detection', percent, message)
    
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

        self._update_progress('hayabusa_correlation', 35, 'No Hayabusa detections to correlate')
        return []
    
    def _hayabusa_progress_callback(self, phase: str, percent: int, message: str):
        """Place correlator progress inside the correlation phase's span.

        The correlator reports on its own 35-50 scale, a leftover from when that
        was the phase's place in the run. Its position within its own phase is
        what matters, so it is normalised here rather than trusted.
        """
        self._update_phase_fraction('hayabusa_correlation', percent, message)
    
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
        from pipeline.pattern_analysis import (
            complete_case_pattern_run,
            prepare_case_pattern_head,
            prepare_case_pattern_runtime,
            run_case_pattern_loop,
        )
        
        results = []

        head = prepare_case_pattern_head(
            case_id=self.case_id,
            progress_callback=self._update_progress,
            info_callback=logger.info,
        )
        if head['should_return']:
            self._record_phase_outcome(
                'pattern_analysis',
                True,
                details={
                    'patterns_requested': head['pattern_total'],
                    'patterns_eligible': head['pattern_count'],
                    'patterns_skipped_by_census': head['skipped_count'],
                    'findings_generated': 0,
                },
                message='Pattern analysis skipped',
            )
            return results

        census = head['census']
        self._census = census
        ordered_patterns = head['ordered_patterns']

        from utils.case_timezone import get_case_timezone

        case_tz = get_case_timezone(self.case_id)
        
        gap_findings = getattr(self, '_gap_findings', None) or []
        runtime = prepare_case_pattern_runtime(
            case_id=self.case_id,
            analysis_id=self.analysis_id,
            mode=self.mode,
            census=census,
            gap_findings=gap_findings,
            case_tz=case_tz,
        )
        extractor = runtime['extractor']
        evidence_engine = runtime['evidence_engine']
        ai_analyzer = runtime['ai_analyzer']
        rule_analyzer = runtime['rule_analyzer']
        confirmed_patterns = runtime['confirmed_patterns']

        pattern_errors = []

        def _handle_pattern_warning(pattern_id: str, error: str):
            pattern_errors.append({
                'pattern_id': pattern_id,
                'error': error,
            })
            logger.warning(
                f"[CaseAnalyzer] Pattern analysis failed for {pattern_id}: {error}"
            )
        
        ai_budget = budget_from_config(Config)

        # Cleanup deletes this run's staged candidate events, and it used to sit
        # after the loop, so any exception from the loop - a cancellation, or the
        # oversized-identifier failure that aborted the phase - left them behind
        # for good. There are 775,968 such rows in the database from three runs
        # that failed this way, the oldest untouched since June.
        try:
            run_case_pattern_loop(
                ordered_patterns=ordered_patterns,
                case_id=self.case_id,
                analysis_id=self.analysis_id,
                mode=self.mode,
                extractor=extractor,
                evidence_engine=evidence_engine,
                ai_analyzer=ai_analyzer,
                rule_analyzer=rule_analyzer,
                confirmed_patterns=confirmed_patterns,
                findings_output=results,
                progress_callback=self._update_progress,
                warning_callback=_handle_pattern_warning,
                cancellation_check=self._ensure_not_cancelled,
                ai_budget=ai_budget,
            )
        except BaseException:
            self._cleanup_pattern_extractor(extractor)
            raise

        completed_results = complete_case_pattern_run(
            extractor=extractor,
            results=results,
            progress_callback=self._update_progress,
        )

        self._record_phase_outcome(
            'pattern_analysis',
            not pattern_errors,
            details={
                'patterns_requested': head['pattern_total'],
                'patterns_eligible': len(ordered_patterns),
                'patterns_skipped_by_census': head['skipped_count'],
                'patterns_failed': len(pattern_errors),
                'failed_patterns': [error['pattern_id'] for error in pattern_errors[:10]],
                'findings_generated': len(completed_results),
                # So a phase constrained by a slow model is distinguishable from
                # one where the model simply had little to say.
                **ai_budget.summary(),
            },
            message='Pattern analysis complete' if not pattern_errors else 'Pattern analysis completed with per-pattern failures',
        )
        return completed_results
    
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
            from pipeline.case_timeline import run_ioc_timeline

            result = run_ioc_timeline(
                case_id=self.case_id,
                analysis_id=self.analysis_id,
                progress_callback=self._update_progress,
            )
            self._record_phase_outcome(
                'ioc_timeline',
                True,
                details={
                    'entries': len(result.get('entries', [])),
                    'cross_host_links': len(result.get('cross_host_links', [])),
                },
                message='IOC timeline build complete',
            )
            return result
        except Exception as e:
            logger.warning(f"[CaseAnalyzer] IOC timeline build failed: {e}", exc_info=True)
            self._update_progress('ioc_timeline', 83, 'IOC timeline skipped (no IOCs or error)')
            self._record_phase_outcome(
                'ioc_timeline',
                False,
                details={'error': str(e)},
                message='IOC timeline build failed',
            )
            return {}
    
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
            from pipeline.case_narrative import run_ai_triage

            context = {
                'census': self._census,
                'gap_findings': self._gap_findings,
                'pattern_results': self._pattern_results,
                'attack_chains': self._attack_chains,
                'ioc_timeline': self._ioc_timeline,
                'incident_storylines': self._storyline_results.get('storylines', []),
                'profiling_stats': self._profiling_stats,
            }
            return run_ai_triage(
                case_id=self.case_id,
                analysis_id=self.analysis_id,
                context=context,
                progress_callback=self._update_progress,
                record_phase_outcome=self._record_phase_outcome,
            )
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
            from pipeline.case_narrative import run_ai_synthesis

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
            return run_ai_synthesis(
                case_id=self.case_id,
                analysis_id=self.analysis_id,
                context=context,
                progress_callback=self._update_progress,
                record_phase_outcome=self._record_phase_outcome,
            )
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
            from pipeline.case_timeline import run_incident_storylines

            return run_incident_storylines(
                case_id=self.case_id,
                record_phase_outcome=self._record_phase_outcome,
                progress_callback=self._update_progress,
            )
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
        from pipeline.case_enrichment import run_opencti_enrichment

        self._opencti_context, _overlay_updates = run_opencti_enrichment(
            case_id=self.case_id,
            analysis_id=self.analysis_id,
            findings=all_findings,
            attack_chains=self._attack_chains,
            progress_callback=self._update_progress,
            record_phase_outcome=self._record_phase_outcome,
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
        from pipeline.case_actions import generate_suggested_actions

        return generate_suggested_actions(
            case_id=self.case_id,
            analysis_id=self.analysis_id,
            all_findings=all_findings,
            attack_chains=self._attack_chains,
            opencti_context=self._opencti_context,
            progress_callback=self._update_progress,
        )
    
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

    def _analysis_degraded_reasons(self) -> List[str]:
        """Failed phases that make the analysis itself incomplete.

        Only the phases the analysis depends on count. The AI checkpoints and
        threat-intel enrichment are capabilities a deployment may not have, and
        their absence used to mark the run `partial` - so an otherwise complete
        analysis was reported as missing results because a model was briefly
        unreachable or OpenCTI was down, while the identical analysis on a
        deployment without AI configured at all completed cleanly. Those are
        reported separately by `_unavailable_capabilities`.
        """
        reasons = []
        for phase, outcome in self._phase_outcomes.items():
            if outcome.get('success') is False and not is_optional(phase):
                reasons.append(f"{phase} degraded")
        return reasons

    def _unavailable_capabilities(self) -> List[str]:
        """Optional phases that could not run, so the analyst knows what is missing."""
        unavailable = []
        for phase, outcome in self._phase_outcomes.items():
            if outcome.get('success') is False and is_optional(phase):
                unavailable.append(phase)
        return sorted(unavailable)

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

        finalized = finalize_case_analysis_run(
            self._analysis_run,
            case_id=self.case_id,
            analysis_id=self.analysis_id,
            all_findings=all_findings,
            profiling_stats=self._profiling_stats,
            pattern_results=self._pattern_results,
            gap_findings=self._gap_findings,
            hayabusa_findings=self._hayabusa_findings,
            attack_chains=self._attack_chains,
            census=self._census,
            ioc_timeline=self._ioc_timeline,
            storyline_results=self._storyline_results,
            triage_result=self._triage_result,
            synthesis_result=self._synthesis_result,
            phase_outcomes=self._phase_outcomes,
            degraded_reasons=self._analysis_degraded_reasons(),
            unavailable_capabilities=self._unavailable_capabilities(),
            final_status=final_status,
            phase_message=phase_message,
            progress_percent=progress_percent,
            error_message=error_message,
            partial_results_available=partial_results_available,
            start_time=self._start_time,
            make_json_safe=self._make_json_safe,
            record_phase_outcome=self._record_phase_outcome,
        )
        self._finalized = True
        return finalized
    
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

    def _mark_cancelled(self, error_message: str):
        """Mark the analysis as cancelled when cooperative finalization fails."""
        if self._analysis_run:
            db.session.rollback()
            self._analysis_run.status = AnalysisStatus.CANCELLED
            self._analysis_run.error_message = error_message[:500]
            self._analysis_run.completed_at = datetime.utcnow()
            self._analysis_run.last_progress_at = self._analysis_run.completed_at
            self._analysis_run.current_phase = 'Analysis cancelled'
            self._analysis_run.partial_results_available = self._has_partial_results()
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
