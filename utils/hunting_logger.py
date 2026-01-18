"""AI Hunting Logger for CaseScope

Provides detailed logging for AI/pattern hunting operations.
Logs are stored per-case at: /opt/casescope/logs/{case_id}/ai_hunting/

This helps track:
- Pattern detection operations
- Query execution times
- Match results
- Confidence calculations
- Errors and warnings

Usage:
    from utils.hunting_logger import HuntingLogger
    
    logger = HuntingLogger(case_id=123, case_uuid='abc-123')
    logger.log_start('detect_attack_patterns', categories=['Credential Access'])
    logger.log_pattern_check('pass_the_ticket', query_time_ms=150, rows_returned=3)
    logger.log_match('pass_the_ticket', host='WORKSTATION1', confidence=85)
    logger.log_complete(patterns_checked=45, matches_found=12)
"""

import os
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path


class HuntingLogger:
    """Case-specific logger for AI hunting operations"""
    
    BASE_LOG_DIR = '/opt/casescope/logs'
    
    def __init__(self, case_id: int, case_uuid: str = None):
        """
        Initialize hunting logger for a specific case.
        
        Args:
            case_id: The PostgreSQL case ID
            case_uuid: Optional case UUID for reference
        """
        self.case_id = case_id
        self.case_uuid = case_uuid
        self.session_id = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        self.log_dir = Path(self.BASE_LOG_DIR) / str(case_id) / 'ai_hunting'
        self.log_file = self.log_dir / f'hunting_{self.session_id}.log'
        self.start_time = None
        self.operation = None
        
        # Ensure directory exists
        self._ensure_log_dir()
        
        # Set up file logger
        self._setup_logger()
    
    def _ensure_log_dir(self):
        """Create log directory if it doesn't exist"""
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            # Set permissions for casescope user
            os.chmod(self.log_dir, 0o775)
            if self.log_dir.parent.exists():
                os.chmod(self.log_dir.parent, 0o775)
        except Exception as e:
            # Fall back to /tmp if we can't create the directory
            self.log_dir = Path('/tmp/casescope_hunting') / str(self.case_id)
            self.log_dir.mkdir(parents=True, exist_ok=True)
            self.log_file = self.log_dir / f'hunting_{self.session_id}.log'
    
    def _setup_logger(self):
        """Set up the file logger"""
        self.logger = logging.getLogger(f'hunting_{self.case_id}_{self.session_id}')
        self.logger.setLevel(logging.DEBUG)
        
        # Clear any existing handlers
        self.logger.handlers = []
        
        # File handler with detailed format
        try:
            fh = logging.FileHandler(self.log_file, encoding='utf-8')
            fh.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                '%(asctime)s.%(msecs)03d | %(levelname)-8s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)
        except Exception as e:
            # If file logging fails, just use console
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            self.logger.addHandler(ch)
    
    def _format_entry(self, event_type: str, data: Dict[str, Any] = None) -> str:
        """Format a log entry with structured data"""
        entry = {
            'event': event_type,
            'case_id': self.case_id,
            'session': self.session_id
        }
        if data:
            entry.update(data)
        return json.dumps(entry, default=str)
    
    # ========================================
    # Operation Lifecycle
    # ========================================
    
    def log_start(self, operation: str, **kwargs):
        """
        Log the start of a hunting operation.
        
        Args:
            operation: Name of the operation (e.g., 'detect_attack_patterns')
            **kwargs: Additional context (categories, filters, etc.)
        """
        self.start_time = datetime.utcnow()
        self.operation = operation
        
        data = {
            'operation': operation,
            'case_uuid': self.case_uuid,
            **kwargs
        }
        
        self.logger.info(f"=== HUNTING SESSION START ===")
        self.logger.info(f"Operation: {operation}")
        self.logger.info(f"Case ID: {self.case_id} | UUID: {self.case_uuid}")
        if kwargs:
            self.logger.info(f"Parameters: {json.dumps(kwargs, default=str)}")
        self.logger.info(f"{'=' * 50}")
    
    def log_complete(self, patterns_checked: int = 0, matches_found: int = 0, 
                     errors: int = 0, **kwargs):
        """
        Log the completion of a hunting operation.
        
        Args:
            patterns_checked: Number of patterns checked
            matches_found: Number of matches found
            errors: Number of errors encountered
            **kwargs: Additional stats
        """
        elapsed = None
        if self.start_time:
            elapsed = (datetime.utcnow() - self.start_time).total_seconds()
        
        self.logger.info(f"{'=' * 50}")
        self.logger.info(f"=== HUNTING SESSION COMPLETE ===")
        self.logger.info(f"Duration: {elapsed:.2f}s" if elapsed else "Duration: unknown")
        self.logger.info(f"Patterns Checked: {patterns_checked}")
        self.logger.info(f"Matches Found: {matches_found}")
        self.logger.info(f"Errors: {errors}")
        if kwargs:
            for key, value in kwargs.items():
                self.logger.info(f"{key}: {value}")
        self.logger.info(f"Log file: {self.log_file}")
    
    # ========================================
    # Pattern Detection
    # ========================================
    
    def log_pattern_start(self, pattern_id: str, pattern_name: str, 
                          category: str = None, temporal: bool = False):
        """Log the start of checking a specific pattern"""
        self.logger.debug(
            f"PATTERN_START | {pattern_id} | {pattern_name} | "
            f"category={category} | temporal={temporal}"
        )
    
    def log_pattern_query(self, pattern_id: str, query_time_ms: float, 
                          rows_returned: int, query_preview: str = None):
        """
        Log pattern query execution.
        
        Args:
            pattern_id: Pattern identifier
            query_time_ms: Query execution time in milliseconds
            rows_returned: Number of rows returned
            query_preview: First 200 chars of query (optional)
        """
        self.logger.debug(
            f"QUERY_EXEC | {pattern_id} | {query_time_ms:.1f}ms | "
            f"rows={rows_returned}"
        )
        if query_preview:
            preview = query_preview[:200].replace('\n', ' ')
            self.logger.debug(f"  Query: {preview}...")
    
    def log_pattern_complete(self, pattern_id: str, matches: int, 
                             query_time_ms: float = None):
        """Log completion of pattern check"""
        time_str = f" | {query_time_ms:.1f}ms" if query_time_ms else ""
        self.logger.debug(
            f"PATTERN_DONE | {pattern_id} | matches={matches}{time_str}"
        )
    
    def log_pattern_error(self, pattern_id: str, error: str):
        """Log an error during pattern checking"""
        self.logger.error(f"PATTERN_ERROR | {pattern_id} | {error[:500]}")
    
    def log_pattern_skip(self, pattern_id: str, reason: str):
        """Log when a pattern is skipped"""
        self.logger.debug(f"PATTERN_SKIP | {pattern_id} | {reason}")
    
    # ========================================
    # Match Logging
    # ========================================
    
    def log_match(self, pattern_id: str, pattern_name: str = None,
                  source_host: str = None, username: str = None,
                  confidence: int = None, event_count: int = None,
                  first_seen: datetime = None, last_seen: datetime = None,
                  duration_minutes: float = None, **kwargs):
        """
        Log a pattern match.
        
        Args:
            pattern_id: Pattern identifier
            pattern_name: Human-readable pattern name
            source_host: Host where match occurred
            username: Affected username
            confidence: Confidence score (0-100)
            event_count: Number of matching events
            first_seen: First event timestamp
            last_seen: Last event timestamp
            duration_minutes: Attack window duration
            **kwargs: Additional match data
        """
        match_data = {
            'host': source_host,
            'user': username,
            'confidence': confidence,
            'events': event_count,
            'duration_min': duration_minutes
        }
        # Remove None values
        match_data = {k: v for k, v in match_data.items() if v is not None}
        
        self.logger.info(
            f"MATCH | {pattern_id} | {pattern_name or 'unknown'} | "
            f"{json.dumps(match_data, default=str)}"
        )
        
        if first_seen and last_seen:
            self.logger.info(
                f"  Timeframe: {first_seen} to {last_seen}"
            )
    
    def log_match_saved(self, pattern_id: str, match_id: int):
        """Log when a match is saved to database"""
        self.logger.debug(f"MATCH_SAVED | {pattern_id} | db_id={match_id}")
    
    # ========================================
    # Confidence Calculation
    # ========================================
    
    def log_confidence_calc(self, pattern_id: str, confidence: int,
                            factors: Dict[str, Any] = None):
        """
        Log confidence score calculation details.
        
        Args:
            pattern_id: Pattern identifier
            confidence: Final confidence score
            factors: Breakdown of confidence factors
        """
        self.logger.debug(
            f"CONFIDENCE | {pattern_id} | score={confidence}"
        )
        if factors:
            for factor_name, factor_data in factors.items():
                score = factor_data.get('score', 0)
                detail = factor_data.get('detail', '')
                self.logger.debug(
                    f"  {factor_name}: {score} pts | {detail}"
                )
    
    # ========================================
    # Campaign Detection
    # ========================================
    
    def log_campaign_start(self, template_name: str):
        """Log start of campaign detection"""
        self.logger.debug(f"CAMPAIGN_CHECK | {template_name}")
    
    def log_campaign_found(self, campaign_type: str, campaign_name: str,
                           hosts_affected: int, users_affected: int,
                           confidence: float, severity: str):
        """Log a detected campaign"""
        self.logger.info(
            f"CAMPAIGN | {campaign_type} | {campaign_name} | "
            f"hosts={hosts_affected} | users={users_affected} | "
            f"confidence={confidence:.0%} | severity={severity}"
        )
    
    # ========================================
    # General Logging
    # ========================================
    
    def info(self, message: str):
        """Log an info message"""
        self.logger.info(message)
    
    def debug(self, message: str):
        """Log a debug message"""
        self.logger.debug(message)
    
    def warning(self, message: str):
        """Log a warning message"""
        self.logger.warning(message)
    
    def error(self, message: str):
        """Log an error message"""
        self.logger.error(message)
    
    def log_event_count(self, total_events: int, filtered_events: int = None):
        """Log event counts for the case"""
        msg = f"EVENT_COUNT | total={total_events:,}"
        if filtered_events is not None:
            msg += f" | after_noise_filter={filtered_events:,}"
        self.logger.info(msg)
    
    def log_category_summary(self, category_counts: Dict[str, int]):
        """Log summary of matches by category"""
        self.logger.info("CATEGORY_SUMMARY |")
        for category, count in sorted(category_counts.items()):
            self.logger.info(f"  {category}: {count} matches")
    
    def get_log_path(self) -> str:
        """Return the path to the current log file"""
        return str(self.log_file)


def get_hunting_logger(case_id: int, case_uuid: str = None) -> HuntingLogger:
    """
    Factory function to get a hunting logger for a case.
    
    Args:
        case_id: The PostgreSQL case ID
        case_uuid: Optional case UUID
        
    Returns:
        HuntingLogger instance
    """
    return HuntingLogger(case_id=case_id, case_uuid=case_uuid)


def list_hunting_logs(case_id: int) -> List[Dict[str, Any]]:
    """
    List all hunting logs for a case.
    
    Args:
        case_id: The PostgreSQL case ID
        
    Returns:
        List of log file info dicts
    """
    log_dir = Path(HuntingLogger.BASE_LOG_DIR) / str(case_id) / 'ai_hunting'
    
    if not log_dir.exists():
        return []
    
    logs = []
    for log_file in sorted(log_dir.glob('hunting_*.log'), reverse=True):
        stat = log_file.stat()
        logs.append({
            'filename': log_file.name,
            'path': str(log_file),
            'size_bytes': stat.st_size,
            'size_kb': round(stat.st_size / 1024, 1),
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
        })
    
    return logs


def read_hunting_log(case_id: int, filename: str, tail_lines: int = 100) -> str:
    """
    Read contents of a hunting log file.
    
    Args:
        case_id: The PostgreSQL case ID
        filename: Log filename
        tail_lines: Number of lines from end (0 for all)
        
    Returns:
        Log file contents
    """
    log_path = Path(HuntingLogger.BASE_LOG_DIR) / str(case_id) / 'ai_hunting' / filename
    
    if not log_path.exists():
        return f"Log file not found: {log_path}"
    
    if tail_lines <= 0:
        return log_path.read_text()
    
    # Read last N lines
    with open(log_path, 'r') as f:
        lines = f.readlines()
        return ''.join(lines[-tail_lines:])
