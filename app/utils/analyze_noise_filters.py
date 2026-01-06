#!/usr/bin/env python3
"""
Noise Filter Analysis Tool
Analyzes how many events would be filtered vs not filtered based on enabled rules
"""

import sys
import os

# Set up path before imports
sys.path.insert(0, '/opt/casescope/app')
os.chdir('/opt/casescope/app')

from opensearchpy import OpenSearch
import json
from utils.opensearch_client import get_opensearch_client
from datetime import datetime
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Initialize minimal Flask app
app = Flask(__name__)
app.config.from_pyfile('config.py', silent=True)

# Initialize database
db = SQLAlchemy()
db.init_app(app)

# Import models after app/db setup
with app.app_context():
    from models import NoiseFilterCategory, NoiseFilterRule, Case

def get_opensearch_client():
    """Get OpenSearch client from app config"""
    with app.app_context():
        opensearch_hosts = app.config.get('OPENSEARCH_HOSTS', ['https://localhost:9200'])
        opensearch_user = app.config.get('OPENSEARCH_USER', 'admin')
        opensearch_password = app.config.get('OPENSEARCH_PASSWORD', 'admin')
        
        client = OpenSearch(
            opensearch_hosts,
            http_auth=(opensearch_user, opensearch_password),
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False
        )
        return client

def analyze_noise_filters(case_id=None, index_pattern='events-*', sample_size=10000):
    """
    Analyze how many events would be filtered
    
    Args:
        case_id: Optional case ID to analyze specific case
        index_pattern: OpenSearch index pattern
        sample_size: Maximum events to analyze (for performance)
    
    Returns:
        dict: Analysis results
    """
    with app.app_context():
        # Get enabled rules
        enabled_categories = NoiseFilterCategory.query.filter_by(is_enabled=True).all()
        category_ids = [cat.id for cat in enabled_categories]
        
        if not category_ids:
            return {
                'error': 'No enabled categories found',
                'enabled_categories': 0,
                'enabled_rules': 0
            }
        
        enabled_rules = NoiseFilterRule.query.filter(
            NoiseFilterRule.category_id.in_(category_ids),
            NoiseFilterRule.is_enabled == True
        ).all()
        
        if not enabled_rules:
            return {
                'error': 'No enabled rules found',
                'enabled_categories': len(enabled_categories),
                'enabled_rules': 0
            }
        
        # Build noise filter query
        noise_filter = build_noise_filter_query(case_id)
        
        # Get OpenSearch client
        client = get_opensearch_client()
        
        # Base query
        base_query = {
            "query": {
                "bool": {
                    "must": [
                        {"match_all": {}}
                    ]
                }
            }
        }
        
        # Add case filter if specified
        if case_id:
            case = Case.query.get(case_id)
            if case:
                base_query["query"]["bool"]["filter"] = [
                    {"range": {"@timestamp": {"gte": case.start_date, "lte": case.end_date}}}
                ]
                # Could also add case-specific filters here
        
        # Query 1: Count all events (without noise filter)
        try:
            result_all = client.count(index=index_pattern, body=base_query)
            total_events = result_all['count']
        except Exception as e:
            return {
                'error': f'OpenSearch query failed: {str(e)}',
                'enabled_categories': len(enabled_categories),
                'enabled_rules': len(enabled_rules)
            }
        
        # Query 2: Count events WITH noise filter applied
        filtered_query = json.loads(json.dumps(base_query))  # Deep copy
        if noise_filter and 'bool' in noise_filter and 'must_not' in noise_filter['bool']:
            if 'must_not' not in filtered_query['query']['bool']:
                filtered_query['query']['bool']['must_not'] = []
            filtered_query['query']['bool']['must_not'].extend(noise_filter['bool']['must_not'])
        
        try:
            result_filtered = client.count(index=index_pattern, body=filtered_query)
            remaining_events = result_filtered['count']
        except Exception as e:
            return {
                'error': f'OpenSearch filtered query failed: {str(e)}',
                'enabled_categories': len(enabled_categories),
                'enabled_rules': len(enabled_rules),
                'total_events': total_events
            }
        
        # Calculate statistics
        filtered_count = total_events - remaining_events
        filter_percentage = (filtered_count / total_events * 100) if total_events > 0 else 0
        
        # Get breakdown by rule (sample-based analysis)
        rule_breakdown = {}
        for rule in enabled_rules:
            # Build query for just this rule
            single_rule_filter = build_noise_filter_query(case_id, rules=[rule])
            single_query = json.loads(json.dumps(base_query))
            
            if single_rule_filter and 'bool' in single_rule_filter and 'must_not' in single_rule_filter['bool']:
                if 'must_not' not in single_query['query']['bool']:
                    single_query['query']['bool']['must_not'] = []
                single_query['query']['bool']['must_not'].extend(single_rule_filter['bool']['must_not'])
                
                try:
                    result_single = client.count(index=index_pattern, body=single_query)
                    remaining = result_single['count']
                    matched = total_events - remaining
                    rule_breakdown[rule.name] = {
                        'category': rule.category.name,
                        'pattern': rule.pattern,
                        'filter_type': rule.filter_type,
                        'matched_events': matched,
                        'percentage': (matched / total_events * 100) if total_events > 0 else 0
                    }
                except Exception as e:
                    rule_breakdown[rule.name] = {'error': str(e)}
        
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'case_id': case_id,
            'index_pattern': index_pattern,
            'enabled_categories': len(enabled_categories),
            'enabled_rules': len(enabled_rules),
            'total_events': total_events,
            'filtered_events': filtered_count,
            'remaining_events': remaining_events,
            'filter_percentage': round(filter_percentage, 2),
            'categories': [cat.name for cat in enabled_categories],
            'rule_breakdown': rule_breakdown
        }

def print_analysis(results):
    """Pretty print analysis results"""
    print("\n" + "="*80)
    print("NOISE FILTER ANALYSIS REPORT")
    print("="*80)
    print(f"Generated: {results.get('timestamp', 'N/A')}")
    
    if 'error' in results:
        print(f"\n❌ ERROR: {results['error']}")
        print(f"Enabled Categories: {results.get('enabled_categories', 0)}")
        print(f"Enabled Rules: {results.get('enabled_rules', 0)}")
        return
    
    print(f"\nIndex Pattern: {results['index_pattern']}")
    if results['case_id']:
        print(f"Case ID: {results['case_id']}")
    
    print(f"\n📊 FILTER STATUS")
    print(f"  Enabled Categories: {results['enabled_categories']}")
    print(f"  Enabled Rules: {results['enabled_rules']}")
    print(f"  Categories: {', '.join(results['categories'])}")
    
    print(f"\n📈 EVENT STATISTICS")
    print(f"  Total Events: {results['total_events']:,}")
    print(f"  Filtered (Hidden): {results['filtered_events']:,} ({results['filter_percentage']}%)")
    print(f"  Remaining (Visible): {results['remaining_events']:,}")
    
    if results['rule_breakdown']:
        print(f"\n🔍 BREAKDOWN BY RULE")
        print(f"{'Rule Name':<40} {'Category':<20} {'Matches':>10} {'%':>7}")
        print("-" * 80)
        
        # Sort by matched events descending
        sorted_rules = sorted(
            results['rule_breakdown'].items(),
            key=lambda x: x[1].get('matched_events', 0),
            reverse=True
        )
        
        for rule_name, stats in sorted_rules:
            if 'error' in stats:
                print(f"{rule_name:<40} {'ERROR':<20} {stats['error']}")
            elif stats['matched_events'] > 0:
                print(f"{rule_name:<40} {stats['category']:<20} {stats['matched_events']:>10,} {stats['percentage']:>6.2f}%")
                print(f"  └─ Pattern: {stats['pattern']}")
    
    print("\n" + "="*80)
    
    # Provide recommendations
    print("\n💡 RECOMMENDATIONS")
    if results['filter_percentage'] < 5:
        print("  ⚠️  Very few events are being filtered (<5%). Consider enabling more rules.")
    elif results['filter_percentage'] > 50:
        print("  ⚠️  Over 50% of events are being filtered. Review rules to ensure legitimate events aren't hidden.")
    else:
        print("  ✅ Filter percentage looks reasonable (5-50% of events).")
    
    print("\n")

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze noise filter impact on event data')
    parser.add_argument('--case-id', type=int, help='Analyze specific case ID')
    parser.add_argument('--index', default='events-*', help='OpenSearch index pattern (default: events-*)')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    
    results = analyze_noise_filters(case_id=args.case_id, index_pattern=args.index)
    
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_analysis(results)

