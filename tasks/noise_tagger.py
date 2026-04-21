"""Noise Tagging Task for CaseScope

Tags events in ClickHouse as noise based on active noise filter rules.
Uses keyword-based token matching with hasTokenCaseInsensitive() on raw_json.
Keywords containing separators (like huntress.io) use positionCaseInsensitive() instead.

This ensures whole-word matching:
- 'ltsvc' matches 'c:\\windows\\ltsvc\\agent.exe' 
- 'ltsvc' does NOT match 'altsvc'
- 'huntress.io' works correctly for exclusion patterns

"""
import logging
from datetime import datetime

from tasks.celery_tasks import celery_app, get_flask_app
from utils.event_noise_state import (
    count_effective_noise_events,
    insert_noise_scan_matches,
    start_noise_scan,
)
from utils.noise_keywords import build_keyword_clause, build_keyword_not_clause

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name='tasks.noise_tagger.tag_noise_events')
def tag_noise_events(self, case_id: int, username: str = 'system'):
    """Tag events matching noise filter rules using keyword token matching
    
    Uses hasTokenCaseInsensitive() on raw_json for whole-word matching.
    This ensures 'ltsvc' matches paths like 'c:\\ltsvc\\' but NOT 'altsvc'.
    
    Args:
        case_id: The case ID to process
        username: User who initiated the task
        
    Returns:
        Dict with results including total_events, total_tagged, rule_matches
    """
    app = get_flask_app()
    
    with app.app_context():
        from utils.clickhouse import get_fresh_client
        from models.noise import NoiseRule
        
        logger.info(f"Starting noise tagging for case {case_id}")
        
        self.update_state(state='PROGRESS', meta={
            'progress': 0,
            'status': 'Loading noise rules...'
        })
        
        # Get active rules
        active_rules = NoiseRule.get_active_rules()
        
        if not active_rules:
            logger.info("No active noise rules found")
            return {
                'success': True,
                'total_events': 0,
                'total_tagged': 0,
                'noise_percentage': 0,
                'rule_matches': [],
                'message': 'No active noise rules'
            }
        
        logger.info(f"Found {len(active_rules)} active noise rules")
        
        client = get_fresh_client()
        
        # Get total event count for this case
        total_result = client.query(
            "SELECT count() FROM events WHERE case_id = {case_id:UInt32}",
            parameters={'case_id': case_id}
        )
        total_events = total_result.result_rows[0][0] if total_result.result_rows else 0
        
        if total_events == 0:
            return {
                'success': True,
                'total_events': 0,
                'total_tagged': 0,
                'noise_percentage': 0,
                'rule_matches': [],
                'message': 'No events in case'
            }
        
        self.update_state(state='PROGRESS', meta={
            'progress': 5,
            'status': f'Processing {total_events:,} events against {len(active_rules)} rules...'
        })
        
        # Start a new overlay scan generation for this case. Reads project only
        # the latest scan generation, so older scan rows fall out automatically.
        self.update_state(state='PROGRESS', meta={
            'progress': 10,
            'status': 'Preparing noise overlay scan...'
        })
        scan_version = start_noise_scan(case_id, updated_by=username, client=client)
        
        rule_matches = []
        total_tagged = 0
        rules_processed = 0
        
        for rule in active_rules:
            rules_processed += 1
            progress = 10 + int((rules_processed / len(active_rules)) * 85)
            
            self.update_state(state='PROGRESS', meta={
                'progress': progress,
                'status': f'Processing rule: {rule.name} ({rules_processed}/{len(active_rules)})'
            })
            
            # Get keywords from rule
            or_keywords, and_keywords, not_keywords = rule.get_keywords()
            
            if not or_keywords:
                continue
            
            # Build WHERE clause using hasTokenCaseInsensitive on raw_json
            # Logic: (OR keywords) AND (AND keywords) AND NOT (NOT keywords)
            where_parts = ["case_id = {case_id:UInt32}"]
            
            # OR keywords: match if ANY keyword found as token
            or_clause = build_keyword_clause(or_keywords, 'raw_json')
            where_parts.append(or_clause)
            
            # AND keywords: must ALSO find at least one of these
            if and_keywords:
                and_clause = build_keyword_clause(and_keywords, 'raw_json')
                where_parts.append(and_clause)
            
            # NOT keywords: exclude if ANY of these found
            if not_keywords:
                not_clause = build_keyword_not_clause(not_keywords, 'raw_json')
                where_parts.append(f"({not_clause})")
            
            where_clause = " AND ".join(where_parts)
            
            # Count matches for this rule
            try:
                match_count = insert_noise_scan_matches(
                    case_id,
                    scan_version,
                    rule.name,
                    where_clause=where_clause,
                    parameters={'case_id': case_id},
                    updated_by=username,
                    client=client,
                )

                if match_count > 0:
                    rule_matches.append({
                        'id': rule.id,
                        'name': rule.name,
                        'category': rule.category.name if rule.category else None,
                        'count': match_count
                    })
                    total_tagged += match_count
                    
                    logger.info(f"Rule '{rule.name}' matched {match_count} events")
                    
            except Exception as e:
                logger.error(f"Error processing rule '{rule.name}': {e}")
                continue
        
        # Count projected noise state after the overlay scan completes.
        actual_tagged = count_effective_noise_events(case_id, client=client)
        
        self.update_state(state='PROGRESS', meta={
            'progress': 100,
            'status': 'Completed'
        })
        
        # Update case with last scan timestamp
        from models.case import Case
        from models.database import db
        case = Case.query.get(case_id)
        if case:
            case.noise_last_scan = datetime.utcnow()
            db.session.commit()
        
        result = {
            'success': True,
            'total_events': total_events,
            'total_tagged': actual_tagged,
            'noise_percentage': round((actual_tagged / total_events * 100), 2) if total_events > 0 else 0,
            'rule_matches': sorted(rule_matches, key=lambda x: x['count'], reverse=True)
        }
        
        logger.info(f"Noise tagging complete for case {case_id}: {actual_tagged} events tagged ({result['noise_percentage']}%)")
        
        return result
