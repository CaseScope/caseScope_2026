#!/usr/bin/env python3
"""Migration: invalidate legacy 4.16.0 Zeek DNS graph support.

4.16.0 enabled DOMAIN RESOLVED_TO IP_ADDRESS from Zeek DNS rows using
pcap_id + uid + query + answer. 4.16.1 disabled creation because uid is a
connection identifier, not an exact DNS transaction identity. This one-time
reconciliation keeps historical graph rows but removes their current authority.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from utils.graph_support_lifecycle import GraphSupportLifecycleService


LEGACY_DNS_EXTRACTOR = 'zeek_dns_resolved_to_ip'


def migrate():
    app = create_app()
    with app.app_context():
        service = GraphSupportLifecycleService(session=db.session)
        summary = service.invalidate_support_by_extractor(
            extractor_name=LEGACY_DNS_EXTRACTOR,
            reason='4.16.2 disabled DNS RESOLVED_TO: missing exact Zeek DNS transaction identity',
        )
        db.session.commit()
        print('Phase 0E 4.16.3 restart-safe DNS reconciliation applied:')
        print(f"  - extractor: {LEGACY_DNS_EXTRACTOR}")
        print(f"  - support_updated: {summary.get('support_updated', 0)}")
        print(f"  - relationships_touched: {summary.get('relationships_touched', 0)}")


if __name__ == '__main__':
    migrate()
