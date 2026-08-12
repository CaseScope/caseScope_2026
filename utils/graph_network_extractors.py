"""Deterministic investigative graph extractors for Zeek/PCAP network logs.

Network logs live in ClickHouse (``network_logs``) and carry NO Evidence
Identity v2 key. Candidates are anchored with a typed native ``zeek_dns``
support locator (``utils.graph_support_locator.build_zeek_dns_locator``) and are
bound to their owning PCAP via ``source_ref_type=PCAP_FILE`` /
``source_ref_id=pcap_id``.

NOT ENABLED — INSUFFICIENT SOURCE CONTRACT: DNS RESOLVED_TO
-----------------------------------------------------------
CaseScope stores ``query``, ``answers``, ``pcap_id`` and Zeek ``uid`` today, but
does not retain Zeek ``trans_id`` or another exact DNS transaction/source-record
identity. Zeek ``uid`` identifies the connection carrying DNS messages, not a
single DNS exchange. Repeated identical query/answer activity on one connection
could therefore collapse to one support locator.

Until the parser/storage contract retains exact DNS transaction identity
(preferably PCAP + uid + trans_id + source-record context), authoritative
DOMAIN -RESOLVED_TO-> IP_ADDRESS extraction remains disabled.

Hardening rules:

* Rows with no answers (e.g. NXDOMAIN) simply produce no edges.
* ``answers`` mixes IPs with CNAME/other rdata; only entries that parse as a
  routable IP become edges. Non-IP answers are ignored.
* ``source_host`` (the capture sensor / pcap owner) is NEVER treated as the
  traffic source or the resolver. Only ``query`` and the answer IP form the edge.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, Iterable, List, Optional

from models.database import db
from utils.graph_extractors import GraphRelationshipCandidate
from utils.graph_identity import (
    EntitySpec,
    GraphDerivationType,
    GraphEntityType,
    GraphRelationshipType,
    GraphSourceRefType,
    build_domain_entity,
)
from utils.graph_support_locator import build_zeek_dns_locator, support_key_for_locator

logger = logging.getLogger(__name__)

NETWORK_EXTRACTOR_VERSION = '1'


def _clean(value: Any) -> str:
    return str(value or '').strip()


def _valid_ip(value: Any) -> Optional[str]:
    text = _clean(value)
    if not text:
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if addr.is_unspecified:
        return None
    return str(addr)


def _valid_query_domain(value: Any) -> Optional[str]:
    """Return canonical domain if the DNS query name is a real domain, else None."""
    try:
        return build_domain_entity(value).canonical_value
    except ValueError:
        return None


class DomainResolvedToIpExtractor:
    """DOMAIN -RESOLVED_TO-> IP_ADDRESS from Zeek DNS responses.

    Disabled for 4.16.1 corrective hardening because current network_logs do not
    retain Zeek trans_id / exact DNS exchange identity.
    """

    name = 'zeek_dns_resolved_to_ip'
    version = NETWORK_EXTRACTOR_VERSION

    def extract_row(
        self,
        *,
        case_id: int,
        pcap_id: int,
        uid: str,
        query: str,
        answers: Iterable[Any],
        observed_at: Any = None,
    ) -> Iterable[GraphRelationshipCandidate]:
        return
        yield  # pragma: no cover - keeps this an empty generator
        domain = _valid_query_domain(query)
        if not domain:
            return
        uid_clean = _clean(uid)
        if not uid_clean:
            return
        seen_ips = set()
        for answer in answers or []:
            answer_ip = _valid_ip(answer)
            if answer_ip is None or answer_ip in seen_ips:
                continue
            seen_ips.add(answer_ip)
            locator = build_zeek_dns_locator(
                case_id=int(case_id),
                pcap_id=int(pcap_id),
                uid=uid_clean,
                query=_clean(query),
                answer=answer_ip,
            )
            evidence_record_key = support_key_for_locator(locator)
            yield GraphRelationshipCandidate(
                case_id=int(case_id),
                source=EntitySpec(GraphEntityType.DOMAIN, _clean(query)),
                relationship_type=GraphRelationshipType.RESOLVED_TO,
                target=EntitySpec(GraphEntityType.IP_ADDRESS, answer_ip),
                derivation_type=GraphDerivationType.OBSERVED,
                evidence_record_key=evidence_record_key,
                observed_at=observed_at,
                source_table='network_logs',
                evidence_role='supporting_record',
                extractor_name=self.name,
                extractor_version=self.version,
                metadata={
                    'rule': 'Zeek DNS response co-locates query name and answer IP',
                    'zeek_uid': uid_clean,
                    'query': _clean(query),
                },
                source_ref_type=GraphSourceRefType.PCAP_FILE,
                source_ref_id=int(pcap_id),
                support_locator=locator,
            )


DEFAULT_NETWORK_EXTRACTORS: tuple = ()


def _iter_dns_rows(case_id: int, *, client=None, batch_size: int = 5000):
    """Stream Zeek DNS rows for a case in LIMIT/OFFSET batches (never one list)."""
    if client is None:
        from utils.clickhouse import get_client

        client = get_client()

    offset = 0
    batch_size = max(1, int(batch_size))
    while True:
        result = client.query(
            """
            SELECT pcap_id, uid, query, answers, timestamp
            FROM network_logs
            WHERE case_id = {case_id:UInt32}
              AND log_type = 'dns'
              AND notEmpty(answers)
            ORDER BY pcap_id, uid, timestamp
            LIMIT {limit:UInt32} OFFSET {offset:UInt32}
            """,
            parameters={
                'case_id': int(case_id),
                'limit': batch_size,
                'offset': offset,
            },
        )
        rows = result.result_rows or []
        if not rows:
            break
        for row in rows:
            yield row
        if len(rows) < batch_size:
            break
        offset += batch_size


def materialize_network_for_case(
    case_id: int,
    *,
    client=None,
    session=None,
    extractors: Iterable = DEFAULT_NETWORK_EXTRACTORS,
    batch_size: int = 5000,
) -> Dict[str, int]:
    """Materialize deterministic network facts.

    DNS RESOLVED_TO is intentionally disabled until exact DNS transaction
    provenance is retained. Return a bounded no-op summary.
    """
    from utils.graph_materializer import GraphMaterializer

    session = session or db.session
    materializer = GraphMaterializer(session=session)

    if not tuple(extractors or ()):
        return {
            'dns_rows_seen': 0,
            'candidates_seen': 0,
            'relationships_materialized': 0,
            'errors': 0,
            'disabled': True,
            'reason': 'NOT ENABLED — INSUFFICIENT SOURCE CONTRACT: missing Zeek trans_id/exact DNS exchange identity',
        }

    rows_seen = 0
    candidates_seen = 0
    relationships_materialized = 0
    errors = 0

    for row in _iter_dns_rows(case_id, client=client, batch_size=batch_size):
        rows_seen += 1
        pcap_id, uid, query, answers, timestamp = (
            row[0], row[1], row[2], row[3], row[4]
        )
        if pcap_id in (None, ''):
            continue
        answer_list: List[Any]
        if isinstance(answers, (list, tuple)):
            answer_list = list(answers)
        elif answers:
            answer_list = [answers]
        else:
            answer_list = []
        for extractor in extractors:
            for candidate in extractor.extract_row(
                case_id=int(case_id),
                pcap_id=int(pcap_id),
                uid=uid,
                query=query,
                answers=answer_list,
                observed_at=timestamp,
            ):
                candidates_seen += 1
                try:
                    with session.begin_nested():
                        materializer.materialize_candidate(int(case_id), candidate)
                    relationships_materialized += 1
                    if candidates_seen % 1000 == 0:
                        session.commit()
                except Exception as exc:
                    errors += 1
                    logger.warning(
                        'Network graph extraction skipped %s record %s for case %s: %s',
                        extractor.name,
                        candidate.evidence_record_key,
                        case_id,
                        exc,
                    )
    session.commit()
    return {
        'dns_rows_seen': rows_seen,
        'candidates_seen': candidates_seen,
        'relationships_materialized': relationships_materialized,
        'errors': errors,
    }
