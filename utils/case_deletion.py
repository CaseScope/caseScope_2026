"""Helpers for permanently deleting a case across all storage layers."""
import logging
import os
import shutil
from typing import Dict, Iterable, List

from config import Config
from models.agent import Agent
from models.archive_job import ArchiveJob
from models.audit_log import AuditAction, AuditEntityType, AuditLog
from models.behavioral_profiles import (
    CaseAnalysisRun,
    GapDetectionFinding,
    OpenCTICache,
    PeerGroup,
    PeerGroupMember,
    SuggestedAction,
    SystemBehaviorProfile,
    UserBehaviorProfile,
)
from models.case import Case
from models.case_file import CaseFile
from models.case_report import CaseReport
from models.client import Client
from models.database import db
from models.evidence_file import EvidenceFile
from models.file_audit_log import FileAuditLog
from models.ioc import IOC, IOCAudit, IOCCase, IOCSystemSighting
from models.graph import (
    GraphEntity,
    GraphEntityObservation,
    GraphRelationship,
    GraphRelationshipEvidence,
)
from models.graph_saved_view import GraphSavedView
from models.investigation_thread import (
    InvestigationThread,
    InvestigationThreadEntity,
    InvestigationThreadEvidence,
    InvestigationThreadFinding,
    InvestigationThreadIOC,
    InvestigationThreadNote,
    InvestigationThreadRelationship,
)
from models.known_system import (
    KnownSystem,
    KnownSystemAlias,
    KnownSystemAudit,
    KnownSystemCase,
    KnownSystemIP,
    KnownSystemMAC,
    KnownSystemShare,
)
from models.known_user import (
    KnownUser,
    KnownUserAlias,
    KnownUserAudit,
    KnownUserCase,
    KnownUserEmail,
)
from models.memory_data import (
    MemoryCredential,
    MemoryInfo,
    MemoryMalfind,
    MemoryModule,
    MemoryNetwork,
    MemoryProcess,
    MemoryService,
    MemorySID,
)
from models.memory_job import MemoryJob
from models.network_log import delete_case_logs
from models.pcap_file import PcapFile
from models.rag import (
    AIAnalysisResult,
    AnalystVerdict,
    AskAIHistory,
    AttackCampaign,
    ChatConversationSession,
    CandidateEventSet,
    PatternMatch,
    PatternRuleMatch,
    RAGQueryLog,
    SemanticMatchFeedback,
)
from models.system_settings import SettingKeys, SystemSettings
from utils.clickhouse import delete_case_events, get_client as get_clickhouse_client
from utils.event_overlay_repair import purge_case_legacy_overlay_rows
from utils.artifact_paths import get_case_originals_root

logger = logging.getLogger(__name__)

DEFAULT_ARCHIVE_PATH = "/archive"


def _delete_many(model, **filters) -> int:
    """Bulk delete helper with session sync disabled for speed."""
    return model.query.filter_by(**filters).delete(synchronize_session=False)


def _delete_by_ids(model, column, ids: Iterable[int]) -> int:
    """Bulk delete helper for IN filters."""
    id_list = [item for item in ids if item is not None]
    if not id_list:
        return 0
    return model.query.filter(column.in_(id_list)).delete(synchronize_session=False)


def _collect_ids(model, column, **filters) -> List[int]:
    """Collect primary/foreign key IDs for dependent cleanup."""
    rows = db.session.query(column).filter_by(**filters).all()
    return [row[0] for row in rows]


def _flush_clickhouse_buffers() -> None:
    """Push buffered records into MergeTree tables before deletion."""
    client = get_clickhouse_client()

    try:
        client.command("OPTIMIZE TABLE events_buffer")
    except Exception as exc:  # pragma: no cover - depends on deployment mode
        logger.debug("events_buffer optimize skipped: %s", exc)

    try:
        client.command("OPTIMIZE TABLE network_logs_buffer")
    except Exception as exc:  # pragma: no cover - depends on deployment mode
        logger.debug("network_logs_buffer optimize skipped: %s", exc)


def _remove_tree(path: str) -> bool:
    """Delete a directory tree if it exists."""
    if not path or not os.path.exists(path):
        return False
    shutil.rmtree(path)
    return True


def _drop_case_event_vectors(case_id: int) -> bool:
    """Remove the case's Qdrant event vectors during permanent deletion.

    Deletion cleaned ClickHouse, PostgreSQL and disk but left the vector
    collection behind, so evidence-derived text survived the case it belonged
    to. Qdrant being unreachable must not strand the rest of the deletion, so
    the failure is logged rather than raised.
    """
    try:
        from utils.rag_vectorstore import delete_case_event_collection

        return delete_case_event_collection(case_id)
    except Exception as exc:
        logger.warning("Could not drop Qdrant event vectors for case %s: %s", case_id, exc)
        return False


def delete_case_permanently(case: Case) -> Dict[str, int]:
    """Delete a case from ClickHouse, PostgreSQL, and disk storage."""
    if not case:
        raise ValueError("Case is required for permanent deletion")

    case_id = case.id
    case_uuid = case.uuid
    # Captured before deletion so the audit entry can still name what was removed
    case_name = case.name
    case_client_id = case.client_id

    archive_folders = {
        path for path in _collect_archive_paths(case_id, case_uuid) if path
    }

    summary: Dict[str, int] = {
        "filesystem_paths_removed": 0,
        "clickhouse_commands_issued": 0,
        "clickhouse_mutations_completed": 0,
    }

    try:
        _flush_clickhouse_buffers()
        delete_case_events(case_id, wait=True)
        summary["clickhouse_commands_issued"] += 1
        summary["clickhouse_mutations_completed"] += 1
        legacy_overlay_purge = purge_case_legacy_overlay_rows(case_id, wait=True)
        summary["clickhouse_commands_issued"] += legacy_overlay_purge["commands_issued"]
        summary["clickhouse_mutations_completed"] += legacy_overlay_purge["mutations_completed"]
        for table_name, deleted_rows in legacy_overlay_purge["tables"].items():
            summary[f"{table_name}_rows_deleted"] = deleted_rows
        delete_case_logs(case_id, wait=True)
        summary["clickhouse_commands_issued"] += 1
        summary["clickhouse_mutations_completed"] += 1

        summary["qdrant_collection_dropped"] = int(_drop_case_event_vectors(case_id))

        ioc_ids = _collect_ids(IOC, IOC.id, case_id=case_id)
        user_ids = _collect_ids(KnownUser, KnownUser.id, case_id=case_id)
        system_ids = _collect_ids(KnownSystem, KnownSystem.id, case_id=case_id)
        analysis_result_ids = _collect_ids(AIAnalysisResult, AIAnalysisResult.id, case_id=case_id)
        peer_group_ids = _collect_ids(PeerGroup, PeerGroup.id, case_id=case_id)

        summary["AnalystVerdict"] = _delete_by_ids(
            AnalystVerdict,
            AnalystVerdict.analysis_result_id,
            analysis_result_ids,
        )
        summary["PeerGroupMember"] = _delete_by_ids(
            PeerGroupMember,
            PeerGroupMember.peer_group_id,
            peer_group_ids,
        )

        summary["IOCSystemSightingByIoc"] = _delete_by_ids(
            IOCSystemSighting,
            IOCSystemSighting.ioc_id,
            ioc_ids,
        )
        summary["IOCAudit"] = _delete_by_ids(IOCAudit, IOCAudit.ioc_id, ioc_ids)
        summary["IOCCaseByIoc"] = _delete_by_ids(IOCCase, IOCCase.ioc_id, ioc_ids)

        summary["KnownUserAlias"] = _delete_by_ids(KnownUserAlias, KnownUserAlias.user_id, user_ids)
        summary["KnownUserEmail"] = _delete_by_ids(KnownUserEmail, KnownUserEmail.user_id, user_ids)
        summary["KnownUserAudit"] = _delete_by_ids(KnownUserAudit, KnownUserAudit.user_id, user_ids)
        summary["KnownUserCaseByUser"] = _delete_by_ids(
            KnownUserCase,
            KnownUserCase.user_id,
            user_ids,
        )

        summary["KnownSystemIP"] = _delete_by_ids(KnownSystemIP, KnownSystemIP.system_id, system_ids)
        summary["KnownSystemMAC"] = _delete_by_ids(KnownSystemMAC, KnownSystemMAC.system_id, system_ids)
        summary["KnownSystemAlias"] = _delete_by_ids(
            KnownSystemAlias,
            KnownSystemAlias.system_id,
            system_ids,
        )
        summary["KnownSystemShare"] = _delete_by_ids(
            KnownSystemShare,
            KnownSystemShare.system_id,
            system_ids,
        )
        summary["KnownSystemAudit"] = _delete_by_ids(
            KnownSystemAudit,
            KnownSystemAudit.system_id,
            system_ids,
        )
        summary["KnownSystemCaseBySystem"] = _delete_by_ids(
            KnownSystemCase,
            KnownSystemCase.system_id,
            system_ids,
        )

        case_id_models = [
            InvestigationThreadNote,
            InvestigationThreadFinding,
            InvestigationThreadIOC,
            InvestigationThreadEvidence,
            InvestigationThreadRelationship,
            InvestigationThreadEntity,
            InvestigationThread,
            GraphSavedView,
            GraphRelationshipEvidence,
            GraphEntityObservation,
            GraphRelationship,
            GraphEntity,
            MemoryProcess,
            MemoryNetwork,
            MemoryService,
            MemoryMalfind,
            MemoryModule,
            MemoryCredential,
            MemorySID,
            MemoryInfo,
            MemoryJob,
            PatternMatch,
            AttackCampaign,
            PatternRuleMatch,
            CandidateEventSet,
            AIAnalysisResult,
            AskAIHistory,
            ChatConversationSession,
            RAGQueryLog,
            SemanticMatchFeedback,
            CaseAnalysisRun,
            UserBehaviorProfile,
            SystemBehaviorProfile,
            PeerGroup,
            GapDetectionFinding,
            SuggestedAction,
            OpenCTICache,
            CaseReport,
            IOC,
            KnownUser,
            KnownSystem,
            ArchiveJob,
        ]
        # Clear Thread -> Saved View pointers before deleting either side.
        db.session.query(InvestigationThread).filter_by(case_id=case_id).update(
            {InvestigationThread.current_saved_view_id: None},
            synchronize_session=False,
        )
        for model in case_id_models:
            summary[model.__name__] = _delete_many(model, case_id=case_id)

        summary["IOCSystemSightingByCase"] = _delete_many(IOCSystemSighting, case_id=case_id)
        summary["IOCCaseByCase"] = _delete_many(IOCCase, case_id=case_id)
        summary["KnownUserCaseByCase"] = _delete_many(KnownUserCase, case_id=case_id)
        summary["KnownSystemCaseByCase"] = _delete_many(KnownSystemCase, case_id=case_id)

        # AuditLog and FileAuditLog are deliberately absent: the audit trail
        # must outlive the evidence it describes, otherwise deleting a case
        # destroys the record of who touched it.
        case_uuid_models = [CaseFile, PcapFile, EvidenceFile]
        for model in case_uuid_models:
            summary[model.__name__] = _delete_many(model, case_uuid=case_uuid)

        case_row = Case.query.filter_by(id=case_id).first()
        if case_row:
            db.session.delete(case_row)
            summary["Case"] = 1
        else:
            summary["Case"] = 0

        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    storage_paths = [
        os.path.join(Config.STORAGE_FOLDER, case_uuid),
        os.path.join(Config.UPLOAD_FOLDER_WEB, case_uuid),
        os.path.join(Config.UPLOAD_FOLDER_SFTP, case_uuid),
        os.path.join(Config.STAGING_FOLDER, case_uuid),
        os.path.join(Config.EVIDENCE_FOLDER, case_uuid),
        get_case_originals_root(case_uuid),
        *sorted(archive_folders),
    ]

    for path in storage_paths:
        if _remove_tree(path):
            summary["filesystem_paths_removed"] += 1

    AuditLog.log(
        entity_type=AuditEntityType.CASE,
        entity_id=case_uuid,
        entity_name=case_name,
        action=AuditAction.DELETED,
        case_uuid=case_uuid,
        client_id=case_client_id,
        details=summary,
    )

    return summary


def delete_client_permanently(client: Client) -> Dict[str, int]:
    """Delete a client and all related cases, agents, and client audit data."""
    if not client:
        raise ValueError("Client is required for permanent deletion")

    client_id = client.id
    client_uuid = client.uuid
    # Captured before deletion so the audit entry can still name what was removed
    client_name = client.name
    client_cases = (
        Case.query.filter_by(client_id=client_id)
        .order_by(Case.created_at.desc())
        .all()
    )

    summary: Dict[str, int] = {
        "cases_deleted": 0,
        "agents_deleted": 0,
        "client_audit_entries_deleted": 0,
        "case_filesystem_paths_removed": 0,
        "case_clickhouse_commands_issued": 0,
        "case_clickhouse_mutations_completed": 0,
    }

    for case in client_cases:
        case_summary = delete_case_permanently(case)
        summary["cases_deleted"] += case_summary.get("Case", 0)
        summary["case_filesystem_paths_removed"] += case_summary.get(
            "filesystem_paths_removed", 0
        )
        summary["case_clickhouse_commands_issued"] += case_summary.get(
            "clickhouse_commands_issued", 0
        )
        summary["case_clickhouse_mutations_completed"] += case_summary.get(
            "clickhouse_mutations_completed", 0
        )

    try:
        summary["agents_deleted"] = _delete_many(Agent, client_id=client_id)
        # Client audit entries are retained; see the note in
        # delete_case_permanently on why the trail outlives its subject.
        summary["client_audit_entries_deleted"] = 0

        client_row = Client.query.filter_by(id=client_id).first()
        if client_row:
            db.session.delete(client_row)
            summary["Client"] = 1
        else:
            summary["Client"] = 0

        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    AuditLog.log(
        entity_type=AuditEntityType.CLIENT,
        entity_id=client_uuid,
        entity_name=client_name,
        action=AuditAction.DELETED,
        client_id=client_id,
        client_name=client_name,
        details=summary,
    )

    return summary


def _collect_archive_paths(case_id: int, case_uuid: str) -> List[str]:
    """Collect possible archive paths for a case."""
    archive_path = SystemSettings.get(SettingKeys.ARCHIVE_PATH, DEFAULT_ARCHIVE_PATH)
    paths = []

    if archive_path:
        paths.append(os.path.join(archive_path, case_uuid))

    job_paths = db.session.query(ArchiveJob.archive_folder).filter_by(case_id=case_id).all()
    paths.extend(path for (path,) in job_paths if path)

    return paths
