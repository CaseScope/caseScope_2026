"""
Celery Task: Automated Threat Detection
Runs all detection patterns against case data and generates LLM report
"""

import os
import sys
import logging

# Add app directory to Python path
app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

logger = logging.getLogger(__name__)

from celery_app import celery


@celery.task(bind=True)
def run_automated_detection(self, case_id, user_id, tier=0, clear_previous=False):
    """
    Run automated detection patterns against full case dataset
    
    Args:
        case_id: Case ID to analyze
        user_id: User who initiated detection
        tier: Which tier to run (0=all, 1=tier1, 2=tier2, 3=tier3)
        clear_previous: Not used (for API consistency)
    
    Returns:
        Detection results and LLM-generated report
    """
    
    # Import dependencies inside function to avoid circular imports
    from detection.patterns import DETECTION_PATTERNS, get_patterns_by_tier
    from detection.detector import PatternDetector
    from opensearchpy import OpenSearch
    from config import OPENSEARCH_HOST, OPENSEARCH_PORT, OPENSEARCH_USE_SSL, LLM_MODEL_CHAT
    from audit_logger import log_action
    import ollama
    import json
    
    try:
        # Get case name without database query (avoid circular imports)
        # We'll get it from OpenSearch if needed
        case_name = f"Case {case_id}"
        
        # Initialize OpenSearch client
        client = OpenSearch(
            hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
            use_ssl=OPENSEARCH_USE_SSL,
            verify_certs=False,
            ssl_show_warn=False
        )
        
        # Initialize detector
        detector = PatternDetector(client)
        
        # Select patterns based on tier
        if tier == 0:
            patterns = DETECTION_PATTERNS  # All 30 patterns
        else:
            patterns = get_patterns_by_tier(tier)
        
        total_patterns = len(patterns)
        findings = []
        errors = []
        
        logger.info(f"Running {total_patterns} patterns against case {case_id}")
        
        # Execute each pattern
        for i, pattern in enumerate(patterns):
            # Update progress
            progress = int((i / total_patterns) * 95)  # Reserve 5% for report generation
            
            self.update_state(
                state='PROGRESS',
                meta={
                    'status': f"Checking pattern {i+1} of {total_patterns}",
                    'progress': progress,
                    'current_pattern': pattern['name'],
                    'pattern_number': i + 1,
                    'total_patterns': total_patterns,
                    'findings_count': len(findings),
                    'errors_count': len(errors)
                }
            )
            
            logger.info(f"[{i+1}/{total_patterns}] Checking: {pattern['name']}")
            
            # Execute pattern
            try:
                result = detector.execute_pattern(pattern, case_id)
                
                if result:
                    if result.get('status') == 'error':
                        errors.append(result)
                        logger.warning(f"Pattern {pattern['id']} errored: {result.get('error')}")
                    else:
                        findings.append(result)
                        logger.info(f"  ✓ FINDING: {result['pattern_name']} - {result['total_events']} events, {len(result['entities'])} entities")
                else:
                    logger.debug(f"  - No findings for {pattern['name']}")
                    
            except Exception as e:
                logger.error(f"Pattern {pattern['id']} execution failed: {e}", exc_info=True)
                errors.append({
                    'pattern_id': pattern['id'],
                    'pattern_name': pattern['name'],
                    'error': str(e)
                })
        
        # Update progress: Starting LLM report generation
        self.update_state(
            state='PROGRESS',
            meta={
                'status': 'Generating threat intelligence report...',
                'progress': 96,
                'findings_count': len(findings),
                'errors_count': len(errors)
            }
        )
        
        # Generate LLM report (pass case_name instead of case object)
        report = generate_threat_report(findings, case_name, patterns_checked=total_patterns)
        
        # Log action
        log_action(
            action='automated_detection_complete',
            resource_type='case',
            resource_id=case_id,
            resource_name=case_name,
            details={
                'patterns_checked': total_patterns,
                'findings_count': len(findings),
                'errors_count': len(errors),
                'tier': tier if tier > 0 else 'all'
            }
        )
        
        # Return results
        return {
            'success': True,
            'case_id': case_id,
            'case_name': case_name,
            'patterns_checked': total_patterns,
            'findings_count': len(findings),
            'errors_count': len(errors),
            'findings': findings,
            'errors': errors,
            'report': report
        }
        
    except Exception as e:
        logger.error(f"Automated detection failed: {e}", exc_info=True)
        return {
            'success': False,
            'error': str(e)
        }


def generate_threat_report(findings, case_name, patterns_checked):
    """
    Generate LLM-based threat intelligence report from findings
    
    Args:
        findings: List of finding dictionaries
        case_name: Case name string
        patterns_checked: Number of patterns executed
    
    Returns:
        Formatted threat report
    """
    
    from datetime import datetime
    
    if not findings:
        return f"""
# Automated Threat Detection Report

**Case**: {case_name}  
**Date**: {datetime.utcnow().strftime('%Y-%m-%d')}  
**Patterns Checked**: {patterns_checked}

## Executive Summary

**Threat Level**: LOW (No Patterns Detected)

All {patterns_checked} detection patterns were executed against the full case dataset. No suspicious patterns were identified.

**Assessment**: Case appears clean based on automated detection. This does not rule out sophisticated attacks that evade detection patterns. Manual analysis may still reveal threats.

**Recommendation**: Proceed with standard forensic analysis procedures.
"""
    
    # Build findings summary for LLM
    findings_text = []
    
    for finding in findings[:20]:  # Limit to top 20 findings for token management
        entities_summary = ', '.join([
            f"{e['type']}: {e['value']} ({e['count']} events)"
            for e in finding['entities'][:5]
        ])
        
        findings_text.append(f"""
Pattern: {finding['pattern_name']}
- MITRE: {finding['mitre_technique']} - {finding['mitre_tactic']}
- Severity: {finding['severity'].upper()}
- Total Events: {finding['total_events']:,}
- Key Entities: {entities_summary}
- Description: {finding['description']}
""")
    
    # Generate LLM report
    try:
        prompt = f"""You are a DFIR analyst generating a threat detection report.

CASE: {case_name}
PATTERNS ANALYZED: {patterns_checked} detection patterns covering MITRE ATT&CK tactics
FINDINGS: {len(findings)} suspicious patterns detected

DETAILED FINDINGS:
{chr(10).join(findings_text)}

Generate a concise threat intelligence report with:

1. **Executive Summary** (2-3 sentences)
   - Overall threat level (CRITICAL/HIGH/MEDIUM/LOW)
   - Number of patterns detected
   - Top 2-3 most concerning findings

2. **Critical Findings** (list top 5 by severity)
   For each:
   - Pattern name and MITRE technique
   - What was detected (entities, counts)
   - Why it matters
   - Recommended action

3. **Attack Chain Analysis**
   - Do findings indicate multi-stage attack?
   - Map to kill chain if applicable

4. **Priority Recommendations**
   - Top 3 immediate actions
   - Investigation steps

Keep it concise and actionable. Focus on critical/high severity findings."""

        response = ollama.chat(
            model=LLM_MODEL_CHAT,
            messages=[
                {
                    "role": "system",
                    "content": "You are a DFIR analyst. Generate clear, concise threat reports. Focus on actionable findings."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            options={
                "temperature": 0.3,
                "top_p": 0.9
            }
        )
        
        report = response['message']['content']
        
    except Exception as e:
        logger.error(f"LLM report generation failed: {e}")
        
        # Fallback: Generate basic report without LLM
        report = f"""
# Automated Threat Detection Report

**Case**: {case_name}
**Patterns Checked**: {patterns_checked}
**Findings**: {len(findings)}

## Critical Findings

"""
        for finding in findings[:10]:
            report += f"""
### {finding['pattern_name']}
- **Severity**: {finding['severity'].upper()}
- **MITRE**: {finding['mitre_technique']} - {finding['mitre_tactic']}
- **Events**: {finding['total_events']:,}
- **Description**: {finding['description']}

**Key Entities**:
"""
            for entity in finding['entities'][:5]:
                report += f"- {entity['type']}: {entity['value']} ({entity['count']} occurrences)\n"
            
            report += "\n"
    
    return report

