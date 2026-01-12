"""Noise Tagging Task for CaseScope

Tags events in ClickHouse as noise based on active noise filter rules.
Similar to IOC tagging but for known-good software.
"""
import logging
from datetime import datetime

from tasks.celery_tasks import celery_app, get_flask_app

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name='tasks.noise_tagger.tag_noise_events')
def tag_noise_events(self, case_id: int, username: str = 'system'):
    """Tag events matching noise filter rules
    
    Args:
        case_id: The case ID to process
        username: User who initiated the task
        
    Returns:
        Dict with results including total_events, total_tagged, rule_matches
    """
    app = get_flask_app()
    
    with app.app_context():
        from utils.clickhouse import get_fresh_client
        from models.noise import NoiseRule, NoiseFilterType
        
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
        
        # Map filter types to ClickHouse columns
        filter_type_columns = {
            'process_name': 'process_name',
            'file_path': 'process_path',
            'command_line': 'command_line',
            'hash': 'file_hash_sha256',
            'service_name': 'process_name',
            'network': 'search_blob',
            'registry': 'reg_key'
        }
        
        # First, reset noise flags for this case
        self.update_state(state='PROGRESS', meta={
            'progress': 10,
            'status': 'Resetting previous noise tags...'
        })
        
        client.command(
            f"ALTER TABLE events UPDATE noise_matched = false, noise_rules = [] "
            f"WHERE case_id = {case_id}"
        )
        
        # Wait for mutations to complete (simplified - in production use mutations system table)
        import time
        time.sleep(2)
        
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
            
            column = filter_type_columns.get(rule.filter_type, 'search_blob')
            or_patterns, and_conditions = rule.parse_pattern()
            
            if not or_patterns:
                continue
            
            # Build LIKE conditions for OR patterns
            or_clauses = []
            for pattern in or_patterns:
                escaped = pattern.replace("'", "''").replace("\\", "\\\\")
                if rule.is_case_sensitive:
                    or_clauses.append(f"{column} LIKE '%{escaped}%'")
                else:
                    or_clauses.append(f"lower({column}) LIKE '%{escaped.lower()}%'")
            
            # Build AND conditions
            and_clauses = []
            for condition in and_conditions:
                escaped = condition.replace("'", "''").replace("\\", "\\\\")
                if rule.is_case_sensitive:
                    and_clauses.append(f"search_blob LIKE '%{escaped}%'")
                else:
                    and_clauses.append(f"lower(search_blob) LIKE '%{escaped.lower()}%'")
            
            # Build WHERE clause
            where_parts = [f"case_id = {case_id}"]
            where_parts.append(f"({' OR '.join(or_clauses)})")
            
            if and_clauses:
                where_parts.extend(and_clauses)
            
            where_clause = " AND ".join(where_parts)
            
            # Count matches for this rule
            try:
                count_result = client.query(f"SELECT count() FROM events WHERE {where_clause}")
                match_count = count_result.result_rows[0][0] if count_result.result_rows else 0
                
                if match_count > 0:
                    rule_matches.append({
                        'id': rule.id,
                        'name': rule.name,
                        'category': rule.category.name if rule.category else None,
                        'count': match_count
                    })
                    
                    # Update events with noise flag
                    # Use arrayPushBack to append to existing rules array
                    update_query = f"""
                        ALTER TABLE events UPDATE 
                            noise_matched = true,
                            noise_rules = arrayPushBack(noise_rules, '{rule.name.replace("'", "''")}')
                        WHERE {where_clause}
                    """
                    
                    client.command(update_query)
                    total_tagged += match_count
                    
                    logger.info(f"Rule '{rule.name}' matched {match_count} events")
                    
            except Exception as e:
                logger.error(f"Error processing rule '{rule.name}': {e}")
                continue
        
        # Wait for mutations to complete
        time.sleep(2)
        
        # Get actual tagged count (some events may match multiple rules)
        final_result = client.query(
            "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND noise_matched = true",
            parameters={'case_id': case_id}
        )
        actual_tagged = final_result.result_rows[0][0] if final_result.result_rows else 0
        
        self.update_state(state='PROGRESS', meta={
            'progress': 100,
            'status': 'Completed'
        })
        
        result = {
            'success': True,
            'total_events': total_events,
            'total_tagged': actual_tagged,
            'noise_percentage': round((actual_tagged / total_events * 100), 2) if total_events > 0 else 0,
            'rule_matches': sorted(rule_matches, key=lambda x: x['count'], reverse=True)
        }
        
        logger.info(f"Noise tagging complete for case {case_id}: {actual_tagged} events tagged ({result['noise_percentage']}%)")
        
        return result
