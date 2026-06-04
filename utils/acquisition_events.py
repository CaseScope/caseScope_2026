"""Helpers for acquisition provenance events."""
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, Optional

from parsers.base import ParsedEvent
from parsers.catalog import CYLR_UPLOAD_LABEL
from parsers.registry import BatchProcessor

logger = logging.getLogger(__name__)


def emit_cylr_acquisition_event(
    *,
    case_id: int,
    case_file_id: int,
    archive_name: str,
    source_path: str,
    source_host: str,
    file_type: str,
    upload_source: str,
    extraction_status: str,
    extracted_file_count: int,
    extraction_details: Optional[Dict[str, Any]] = None,
    clickhouse_client=None,
) -> bool:
    """Emit one acquisition summary row for a CyLR archive."""
    if (file_type or '').strip() != CYLR_UPLOAD_LABEL:
        return False

    details = dict(extraction_details or {})
    raw_data = {
        'archive_name': archive_name,
        'source_path': source_path,
        'upload_source': upload_source,
        'file_type': file_type,
        'extraction_status': extraction_status,
        'extracted_file_count': int(extracted_file_count or 0),
        'extraction_method': details.get('extraction_method'),
        'methods': details.get('methods'),
        'member_count': details.get('member_count'),
    }
    search_blob = ' '.join(
        str(part)
        for part in (
            archive_name,
            source_host,
            file_type,
            upload_source,
            extraction_status,
            details.get('extraction_method'),
            source_path,
        )
        if part
    )

    event = ParsedEvent(
        case_id=case_id,
        artifact_type='cylr_acquisition',
        timestamp=datetime.utcnow(),
        timestamp_source_tz='UTC',
        source_file=os.path.basename(archive_name or source_path or ''),
        source_path=source_path or '',
        source_host=source_host or '',
        case_file_id=case_file_id,
        event_id='archive_extracted',
        provider='CyLR',
        record_id=int(extracted_file_count or 0),
        target_path=archive_name or source_path or '',
        raw_json=json.dumps(raw_data, default=str),
        search_blob=search_blob,
        extra_fields=json.dumps(raw_data, default=str),
        parser_version='1.0.0',
    )

    try:
        if clickhouse_client is None:
            from utils.clickhouse import get_fresh_client

            clickhouse_client = get_fresh_client()
        processor = BatchProcessor(clickhouse_client, use_buffer=False)
        processor.add_event(event)
        processor.flush()
        return True
    except Exception as exc:
        logger.warning("Failed to emit CyLR acquisition event for %s: %s", archive_name, exc)
        return False
