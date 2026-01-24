#!/usr/bin/env python3
"""
Clear all case data except for specified case (PANEL).
Clears: PostgreSQL, ClickHouse, and file storage.
"""

import os
import sys
import shutil

# Add parent directory to path
sys.path.insert(0, '/opt/casescope')

from flask import Flask
from models.database import db
from models.case import Case
from models.case_file import CaseFile
from models.case_report import CaseReport
from models.ioc import IOC, IOCCase, IOCSystemSighting, IOCAudit
from models.known_user import KnownUser, KnownUserCase, KnownUserAlias, KnownUserEmail, KnownUserAudit
from models.known_system import KnownSystem, KnownSystemCase, KnownSystemIP, KnownSystemMAC, KnownSystemAlias, KnownSystemShare, KnownSystemAudit
from models.memory_data import (
    MemoryProcess, MemoryNetwork, MemoryService, MemoryMalfind,
    MemoryModule, MemoryCredential, MemorySID, MemoryInfo
)
from models.memory_job import MemoryJob
from models.pcap_file import PcapFile
from models.audit_log import AuditLog
from models.file_audit_log import FileAuditLog
from models.rag import AskAIHistory, RAGQueryLog, PatternMatch, AttackCampaign, PatternRuleMatch
from config import Config
from utils.clickhouse import get_client as get_clickhouse_client

# Configuration
KEEP_CASE_NAME = "PANEL"
STORAGE_PATH = "/opt/casescope/storage"
UPLOADS_PATH = "/opt/casescope/uploads/sftp"
EVIDENCE_PATH = "/opt/casescope/evidence"

def clear_clickhouse(case_ids_to_delete):
    """Clear ClickHouse data for specified case IDs."""
    ch = get_clickhouse_client()
    
    print("\n=== Clearing ClickHouse Data ===")
    
    # First, flush buffer tables
    print("Flushing buffer tables...")
    try:
        ch.command("OPTIMIZE TABLE events_buffer")
        print("  - events_buffer flushed")
    except Exception as e:
        print(f"  - events_buffer flush error (may not exist): {e}")
    
    try:
        ch.command("OPTIMIZE TABLE network_logs_buffer")
        print("  - network_logs_buffer flushed")
    except Exception as e:
        print(f"  - network_logs_buffer flush error (may not exist): {e}")
    
    # Count records before deletion
    for case_id in case_ids_to_delete:
        try:
            result = ch.query(f"SELECT count() FROM events WHERE case_id = {case_id}")
            events_count = result.result_rows[0][0] if result.result_rows else 0
        except:
            events_count = 0
        try:
            result = ch.query(f"SELECT count() FROM network_logs WHERE case_id = {case_id}")
            network_count = result.result_rows[0][0] if result.result_rows else 0
        except:
            network_count = 0
        print(f"  Case {case_id}: {events_count} events, {network_count} network_logs")
    
    # Delete from events table
    for case_id in case_ids_to_delete:
        print(f"Deleting events for case_id={case_id}...")
        try:
            ch.command(f"ALTER TABLE events DELETE WHERE case_id = {case_id}")
        except Exception as e:
            print(f"  Error: {e}")
    
    # Delete from network_logs table
    for case_id in case_ids_to_delete:
        print(f"Deleting network_logs for case_id={case_id}...")
        try:
            ch.command(f"ALTER TABLE network_logs DELETE WHERE case_id = {case_id}")
        except Exception as e:
            print(f"  Error: {e}")
    
    print("ClickHouse deletion mutations scheduled (async)")

def clear_postgresql(case_ids_to_delete, case_uuids_to_delete):
    """Clear PostgreSQL data for specified cases."""
    print("\n=== Clearing PostgreSQL Data ===")
    
    # Tables with case_id FK (integer)
    for case_id in case_ids_to_delete:
        print(f"\nClearing data for case_id={case_id}...")
        
        # Memory tables (have CASCADE but let's be explicit)
        count = MemoryProcess.query.filter_by(case_id=case_id).delete()
        print(f"  - MemoryProcess: {count} deleted")
        count = MemoryNetwork.query.filter_by(case_id=case_id).delete()
        print(f"  - MemoryNetwork: {count} deleted")
        count = MemoryService.query.filter_by(case_id=case_id).delete()
        print(f"  - MemoryService: {count} deleted")
        count = MemoryMalfind.query.filter_by(case_id=case_id).delete()
        print(f"  - MemoryMalfind: {count} deleted")
        count = MemoryModule.query.filter_by(case_id=case_id).delete()
        print(f"  - MemoryModule: {count} deleted")
        count = MemoryCredential.query.filter_by(case_id=case_id).delete()
        print(f"  - MemoryCredential: {count} deleted")
        count = MemorySID.query.filter_by(case_id=case_id).delete()
        print(f"  - MemorySID: {count} deleted")
        count = MemoryInfo.query.filter_by(case_id=case_id).delete()
        print(f"  - MemoryInfo: {count} deleted")
        count = MemoryJob.query.filter_by(case_id=case_id).delete()
        print(f"  - MemoryJob: {count} deleted")
        
        # RAG/Pattern tables
        count = PatternMatch.query.filter_by(case_id=case_id).delete()
        print(f"  - PatternMatch: {count} deleted")
        count = AttackCampaign.query.filter_by(case_id=case_id).delete()
        print(f"  - AttackCampaign: {count} deleted")
        count = PatternRuleMatch.query.filter_by(case_id=case_id).delete()
        print(f"  - PatternRuleMatch: {count} deleted")
        count = AskAIHistory.query.filter_by(case_id=case_id).delete()
        print(f"  - AskAIHistory: {count} deleted")
        count = RAGQueryLog.query.filter_by(case_id=case_id).delete()
        print(f"  - RAGQueryLog: {count} deleted")
        
        # Case reports
        count = CaseReport.query.filter_by(case_id=case_id).delete()
        print(f"  - CaseReport: {count} deleted")
        
        # IOC and related tables - need to get IOCs first for foreign key cleanup
        iocs = IOC.query.filter_by(case_id=case_id).all()
        sighting_count = 0
        audit_count = 0
        case_link_count = 0
        for ioc in iocs:
            sighting_count += IOCSystemSighting.query.filter_by(ioc_id=ioc.id).delete()
            audit_count += IOCAudit.query.filter_by(ioc_id=ioc.id).delete()
            case_link_count += IOCCase.query.filter_by(ioc_id=ioc.id).delete()
        print(f"  - IOCSystemSighting: {sighting_count} deleted")
        print(f"  - IOCAudit: {audit_count} deleted")
        print(f"  - IOCCase (by ioc_id): {case_link_count} deleted")
        # Also delete by case_id in case there are orphaned records
        IOCSystemSighting.query.filter_by(case_id=case_id).delete()
        IOCCase.query.filter_by(case_id=case_id).delete()
        count = IOC.query.filter_by(case_id=case_id).delete()
        print(f"  - IOC: {count} deleted")
        
        # Known users and their related tables (users are case-specific)
        users = KnownUser.query.filter_by(case_id=case_id).all()
        user_related_count = 0
        for user in users:
            KnownUserAlias.query.filter_by(user_id=user.id).delete()
            KnownUserEmail.query.filter_by(user_id=user.id).delete()
            KnownUserAudit.query.filter_by(user_id=user.id).delete()
            user_related_count += KnownUserCase.query.filter_by(user_id=user.id).delete()
        # Also delete by case_id
        KnownUserCase.query.filter_by(case_id=case_id).delete()
        print(f"  - KnownUserCase (related): {user_related_count} deleted")
        count = KnownUser.query.filter_by(case_id=case_id).delete()
        print(f"  - KnownUser (+ aliases/emails/audit): {count} deleted")
        
        # Known systems and their related tables
        systems = KnownSystem.query.filter_by(case_id=case_id).all()
        system_related_count = 0
        for system in systems:
            KnownSystemIP.query.filter_by(system_id=system.id).delete()
            KnownSystemMAC.query.filter_by(system_id=system.id).delete()
            KnownSystemAlias.query.filter_by(system_id=system.id).delete()
            KnownSystemShare.query.filter_by(system_id=system.id).delete()
            KnownSystemAudit.query.filter_by(system_id=system.id).delete()
            system_related_count += KnownSystemCase.query.filter_by(system_id=system.id).delete()
        # Also delete by case_id
        KnownSystemCase.query.filter_by(case_id=case_id).delete()
        print(f"  - KnownSystemCase (related): {system_related_count} deleted")
        count = KnownSystem.query.filter_by(case_id=case_id).delete()
        print(f"  - KnownSystem (+ IPs/MACs/aliases/shares/audit): {count} deleted")
    
    # Tables with case_uuid FK (string)
    for case_uuid in case_uuids_to_delete:
        print(f"\nClearing data for case_uuid={case_uuid}...")
        
        # Case files
        count = CaseFile.query.filter_by(case_uuid=case_uuid).delete()
        print(f"  - CaseFile: {count} deleted")
        
        # PCAP files
        count = PcapFile.query.filter_by(case_uuid=case_uuid).delete()
        print(f"  - PcapFile: {count} deleted")
        
        # Audit logs
        count = AuditLog.query.filter_by(case_uuid=case_uuid).delete()
        print(f"  - AuditLog: {count} deleted")
        count = FileAuditLog.query.filter_by(case_uuid=case_uuid).delete()
        print(f"  - FileAuditLog: {count} deleted")
    
    # Delete the cases themselves
    for case_id in case_ids_to_delete:
        case = Case.query.get(case_id)
        if case:
            print(f"Deleting case: {case.name}")
            db.session.delete(case)
    
    db.session.commit()
    print("\nPostgreSQL data cleared and committed")

def clear_file_storage(case_uuids_to_delete):
    """Clear file storage for specified case UUIDs."""
    print("\n=== Clearing File Storage ===")
    
    for case_uuid in case_uuids_to_delete:
        # Storage folder
        storage_dir = os.path.join(STORAGE_PATH, case_uuid)
        if os.path.exists(storage_dir):
            print(f"Removing: {storage_dir}")
            shutil.rmtree(storage_dir)
        else:
            print(f"Not found (skip): {storage_dir}")
        
        # Uploads/SFTP folder
        uploads_dir = os.path.join(UPLOADS_PATH, case_uuid)
        if os.path.exists(uploads_dir):
            print(f"Removing: {uploads_dir}")
            shutil.rmtree(uploads_dir)
        else:
            print(f"Not found (skip): {uploads_dir}")
        
        # Evidence folder
        evidence_dir = os.path.join(EVIDENCE_PATH, case_uuid)
        if os.path.exists(evidence_dir):
            print(f"Removing: {evidence_dir}")
            shutil.rmtree(evidence_dir)
        else:
            print(f"Not found (skip): {evidence_dir}")
    
    print("File storage cleared")

def main():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    
    with app.app_context():
        # Find the case to keep
        keep_case = Case.query.filter(Case.name.ilike(f'%{KEEP_CASE_NAME}%')).first()
        if not keep_case:
            print(f"ERROR: Case '{KEEP_CASE_NAME}' not found!")
            sys.exit(1)
        
        print(f"Keeping case: id={keep_case.id}, uuid={keep_case.uuid}, name={keep_case.name}")
        
        # Find all cases to delete
        cases_to_delete = Case.query.filter(Case.id != keep_case.id).all()
        
        if not cases_to_delete:
            print("No cases to delete.")
            sys.exit(0)
        
        print("\nCases to DELETE:")
        case_ids_to_delete = []
        case_uuids_to_delete = []
        for c in cases_to_delete:
            print(f"  - id={c.id}, uuid={c.uuid}, name={c.name}")
            case_ids_to_delete.append(c.id)
            case_uuids_to_delete.append(c.uuid)
        
        # Confirmation
        print("\n" + "="*50)
        print("WARNING: This will permanently delete all data for the above cases!")
        print("="*50)
        confirm = input("Type 'YES' to confirm: ")
        if confirm != 'YES':
            print("Aborted.")
            sys.exit(0)
        
        # Clear data
        clear_clickhouse(case_ids_to_delete)
        clear_postgresql(case_ids_to_delete, case_uuids_to_delete)
        clear_file_storage(case_uuids_to_delete)
        
        print("\n" + "="*50)
        print("COMPLETE: All case data cleared except PANEL")
        print("="*50)

if __name__ == "__main__":
    main()
