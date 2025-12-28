#!/bin/bash
# Quick script to check noise filter impact

cd /opt/casescope/app
sudo -u casescope /opt/casescope/venv/bin/python << 'PYEOF'
import sys
sys.path.insert(0, '/opt/casescope/app')

from opensearchpy import OpenSearch
from main import app
from models import NoiseFilterCategory, NoiseFilterRule
import urllib3
urllib3.disable_warnings()

with app.app_context():
    # Get enabled rules
    enabled_cats = NoiseFilterCategory.query.filter_by(is_enabled=True).all()
    cat_ids = [c.id for c in enabled_cats]
    
    enabled_rules = NoiseFilterRule.query.filter(
        NoiseFilterRule.category_id.in_(cat_ids),
        NoiseFilterRule.is_enabled == True
    ).all()
    
    print("\n" + "="*80)
    print("NOISE FILTER STATUS")
    print("="*80)
    print(f"\nEnabled Categories: {len(enabled_cats)}")
    for cat in enabled_cats:
        rule_count = len([r for r in enabled_rules if r.category_id == cat.id])
        print(f"  ✓ {cat.name} ({rule_count} rules)")
    
    print(f"\nEnabled Rules: {len(enabled_rules)}")
    for rule in enabled_rules:
        print(f"  • {rule.name}")
        print(f"    └─ Pattern: {rule.pattern}")
    
    # Try to connect to OpenSearch
    try:
        client = OpenSearch(
            [f"http://{app.config.get('OPENSEARCH_HOST', 'localhost')}:{app.config.get('OPENSEARCH_PORT', 9200)}"],
            http_auth=(
                app.config.get('OPENSEARCH_USER', 'admin'),
                app.config.get('OPENSEARCH_PASSWORD', 'admin')
            ),
            use_ssl=False,
            verify_certs=False,
            ssl_show_warn=False,
            timeout=10
        )
        
        # Count total events
        total = client.count(index='events-*', body={"query": {"match_all": {}}})['count']
        
        print(f"\n{'='*80}")
        print(f"EVENT ANALYSIS")
        print(f"{'='*80}")
        print(f"\nTotal Events in OpenSearch: {total:,}")
        
        if total == 0:
            print("\n⚠️  No events found yet. Upload EVTX files to see filtering impact.")
            sys.exit(0)
        
        # Analyze each rule
        print(f"\nFilter Impact (per rule):")
        print(f"{'-'*80}")
        
        total_matches = 0
        for rule in enabled_rules:
            patterns = [p.strip() for p in rule.pattern.split(',')]
            
            # Build query
            should_clauses = []
            for pattern in patterns:
                if rule.filter_type == 'process_name':
                    should_clauses.extend([
                        {"wildcard": {"event_data.Image": {"value": f"*{pattern}*", "case_insensitive": True}}},
                        {"wildcard": {"event_data.ProcessName": {"value": f"*{pattern}*", "case_insensitive": True}}},
                        {"wildcard": {"process.name": {"value": f"*{pattern}*", "case_insensitive": True}}}
                    ])
            
            if should_clauses:
                query = {"query": {"bool": {"should": should_clauses, "minimum_should_match": 1}}}
                
                try:
                    matched = client.count(index='events-*', body=query)['count']
                    if matched > 0:
                        pct = (matched / total * 100)
                        total_matches += matched
                        print(f"{rule.name:<40} {matched:>10,} ({pct:>5.2f}%)")
                except Exception as e:
                    print(f"{rule.name:<40} ERROR")
        
        print(f"{'-'*80}")
        print(f"{'ESTIMATED TOTAL':<40} {total_matches:>10,} ({(total_matches/total*100):>5.2f}%)")
        print(f"{'WOULD REMAIN VISIBLE':<40} {total-total_matches:>10,} ({((total-total_matches)/total*100):>5.2f}%)")
        print(f"\n💡 Note: Events may match multiple rules, so total is approximate\n")
        
    except Exception as e:
        print(f"\n❌ OpenSearch Error: {e}")
        print("Unable to analyze event counts. Ensure OpenSearch is running.\n")

PYEOF
