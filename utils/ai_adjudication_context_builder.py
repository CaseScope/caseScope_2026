"""Build standardized AI adjudication context from deterministic evidence.

The builder is intentionally read-only. It converts already-computed
EvidencePackage data plus optional caller-provided metadata into typed contract
objects without changing scoring, finding eligibility, prompts, or reports.
"""

from __future__ import annotations

import re
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, Iterable, List, Optional, Set

from utils.ai_adjudication_contract import (
    KNOWN_STATUS,
    UNKNOWN_STATUS,
    AdjudicationContext,
    AdjudicationContextCheck,
    AdjudicationContextEntity,
    AdjudicationContextEvidenceItem,
    AdjudicationContextFact,
    ScoringPolicy,
)


UNKNOWN_CONTEXT_FACTS = {
    "context:known_good": "known_good",
    "context:noise": "noise",
    "context:source_host_role": "source_host_role",
    "context:user_role": "user_role",
    "context:business_hours": "business_hours",
    "context:baseline": "baseline",
    "context:asset_criticality": "asset_criticality",
    "context:threat_intel": "threat_intel",
}


ENTITY_FIELDS = {
    "username": "user",
    "source_host": "host",
    "target_host": "host",
    "src_ip": "ip",
    "dest_ip": "ip",
    "dst_ip": "ip",
    "process_name": "process",
    "file_path": "file",
}


DETAIL_ENTITY_PATTERNS = {
    "username": re.compile(r"\busername=([^,\s\)]+)", re.IGNORECASE),
    "source_host": re.compile(r"\bsource_host=([^,\s\)]+)", re.IGNORECASE),
    "target_host": re.compile(r"\btarget_host=([^,\s\)]+)", re.IGNORECASE),
    "src_ip": re.compile(r"\bsrc_ip=([^,\s\)]+)", re.IGNORECASE),
    "dest_ip": re.compile(r"\b(?:dest_ip|dst_ip)=([^,\s\)]+)", re.IGNORECASE),
    "process_name": re.compile(r"\bprocess_name=([^,\s\)]+)", re.IGNORECASE),
    "file_path": re.compile(r"\bfile_path=([^,\s\)]+)", re.IGNORECASE),
}


class AdjudicationContextBuilder:
    """Create an AdjudicationContext from deterministic package data."""

    def __init__(
        self,
        evidence_package: Any,
        *,
        case_id: Optional[int] = None,
        context_metadata: Optional[Dict[str, Any]] = None,
        scoring_policy: Optional[ScoringPolicy] = None,
    ) -> None:
        self.evidence_package = evidence_package
        self.case_id = case_id
        self.context_metadata = context_metadata or {}
        self.scoring_policy = scoring_policy or ScoringPolicy()
        self._used_evidence_ids: Set[str] = set()
        self._used_check_ids: Set[str] = set()
        self._used_context_ids: Set[str] = set()

    def build(self) -> AdjudicationContext:
        """Return a JSON-serializable adjudication context."""
        coverage = getattr(self.evidence_package, "coverage", None)
        coverage_limitations, coverage_facts = self._build_coverage_context(coverage)
        evidence_items = self._build_evidence_items()
        context_facts = [
            *coverage_facts,
            *self._metadata_context_facts(),
            *self._noise_context_facts(evidence_items),
        ]
        context_facts = self._append_required_unknowns(context_facts)

        return AdjudicationContext(
            case_id=self.case_id,
            pattern_id=str(getattr(self.evidence_package, "pattern_id", "") or ""),
            pattern_name=str(getattr(self.evidence_package, "pattern_name", "") or ""),
            mitre_technique=self._mitre_technique(),
            deterministic_score=float(getattr(self.evidence_package, "deterministic_score", 0) or 0),
            max_possible_score=float(getattr(self.evidence_package, "max_possible_score", 0) or 0),
            coverage_status=self._coverage_status(coverage),
            coverage_limitations=coverage_limitations,
            checks=self._build_checks(),
            evidence_items=evidence_items,
            entities=self._build_entities(),
            context_facts=context_facts,
            scoring_policy=self.scoring_policy,
        )

    def _mitre_technique(self) -> Optional[str]:
        techniques = getattr(self.evidence_package, "mitre_techniques", None) or []
        if isinstance(techniques, (list, tuple)) and techniques:
            return str(techniques[0])
        technique = self.context_metadata.get("mitre_technique")
        return str(technique) if technique else None

    @staticmethod
    def _coverage_status(coverage: Any) -> str:
        if coverage is None:
            return UNKNOWN_STATUS
        return str(getattr(coverage, "coverage_status", "") or UNKNOWN_STATUS).lower()

    def _build_checks(self) -> List[AdjudicationContextCheck]:
        checks: List[AdjudicationContextCheck] = []
        for index, check in enumerate(getattr(self.evidence_package, "checks", []) or []):
            raw_id = str(getattr(check, "check_id", "") or f"check_{index}")
            check_id = self._stable_check_id(raw_id, index)
            checks.append(
                AdjudicationContextCheck(
                    check_id=check_id,
                    status=str(getattr(check, "status", "") or "INCONCLUSIVE"),
                    name=str(getattr(check, "name", "") or raw_id),
                    detail=str(getattr(check, "detail", "") or "No deterministic detail provided"),
                    weight=float(getattr(check, "weight", 0) or 0),
                    contribution=float(getattr(check, "contribution", 0) or 0),
                    source=str(getattr(check, "source", "") or "deterministic_engine"),
                )
            )
        return checks

    def _build_evidence_items(self) -> List[AdjudicationContextEvidenceItem]:
        items = [self._anchor_evidence_item()]
        items.extend(self._burst_evidence_items())
        items.extend(self._sequence_evidence_items())
        spread_item = self._spread_evidence_item()
        if spread_item is not None:
            items.append(spread_item)
        items.extend(self._producer_input_evidence_items())
        return [item for item in items if item is not None]

    def _anchor_evidence_item(self) -> AdjudicationContextEvidenceItem:
        anchor = self._object_dict(getattr(self.evidence_package, "anchor", {}) or {})
        summary_parts = [
            str(anchor.get("event_id") or "").strip(),
            str(anchor.get("source_host") or "").strip(),
            str(anchor.get("username") or "").strip(),
        ]
        summary = "Anchor evidence"
        visible_parts = [part for part in summary_parts if part]
        if visible_parts:
            summary = "Anchor evidence: " + " / ".join(visible_parts)
        return AdjudicationContextEvidenceItem(
            evidence_id=self._stable_evidence_id("evidence:anchor"),
            evidence_type="anchor",
            summary=summary,
            source="evidence_package.anchor",
            detail=anchor,
        )

    def _burst_evidence_items(self) -> List[AdjudicationContextEvidenceItem]:
        items = []
        for index, burst in enumerate(getattr(self.evidence_package, "bursts", []) or []):
            detail = self._object_dict(burst)
            summary = (
                f"Burst evidence: {detail.get('events_in_bucket', '?')} events "
                f"in {detail.get('span_seconds', '?')} seconds"
            )
            items.append(
                AdjudicationContextEvidenceItem(
                    evidence_id=self._stable_evidence_id(f"evidence:burst:{index}"),
                    evidence_type="burst",
                    summary=summary,
                    source="evidence_package.bursts",
                    detail=detail,
                )
            )
        return items

    def _sequence_evidence_items(self) -> List[AdjudicationContextEvidenceItem]:
        items = []
        for index, sequence in enumerate(getattr(self.evidence_package, "sequences", []) or []):
            detail = self._object_dict(sequence)
            summary = (
                f"Sequence evidence: {detail.get('chain', 'unknown chain')} "
                f"status={detail.get('status', UNKNOWN_STATUS)}"
            )
            items.append(
                AdjudicationContextEvidenceItem(
                    evidence_id=self._stable_evidence_id(f"evidence:sequence:{index}"),
                    evidence_type="sequence",
                    summary=summary,
                    source="evidence_package.sequences",
                    detail=detail,
                )
            )
        return items

    def _spread_evidence_item(self) -> Optional[AdjudicationContextEvidenceItem]:
        spread = getattr(self.evidence_package, "spread", None)
        if spread is None:
            return None
        detail = self._object_dict(spread)
        summary = (
            f"Spread evidence: {detail.get('pivot_field', 'pivot')} "
            f"touched {detail.get('total_targets', 0)} targets"
        )
        return AdjudicationContextEvidenceItem(
            evidence_id=self._stable_evidence_id("evidence:spread"),
            evidence_type="spread",
            summary=summary,
            source="evidence_package.spread",
            detail=detail,
        )

    def _producer_input_evidence_items(self) -> List[AdjudicationContextEvidenceItem]:
        items = []
        for index, producer_input in enumerate(getattr(self.evidence_package, "producer_inputs", []) or []):
            detail = self._object_dict(producer_input)
            producer = self._id_token(detail.get("producer") or "unknown")
            producer_type = str(detail.get("producer_type") or "producer input")
            items.append(
                AdjudicationContextEvidenceItem(
                    evidence_id=self._stable_evidence_id(f"evidence:producer:{producer}:{index}"),
                    evidence_type="producer_input",
                    summary=f"Producer input: {producer_type}",
                    source="evidence_package.producer_inputs",
                    detail=detail,
                )
            )
        return items

    def _build_coverage_context(self, coverage: Any) -> tuple[List[str], List[AdjudicationContextFact]]:
        if coverage is None:
            return (
                ["Coverage unavailable"],
                [self._unknown_fact("context:coverage", "coverage", "evidence_package.coverage")],
            )

        limitations: List[str] = []
        facts: List[AdjudicationContextFact] = []
        missing_sources = self._string_values(getattr(coverage, "missing_sources", []) or [])
        present_sources = self._string_values(getattr(coverage, "present_sources", []) or [])
        sysmon_warning = str(getattr(coverage, "sysmon_fp_warning", "") or "").strip()

        for index, source in enumerate(missing_sources):
            limitations.append(f"Missing source: {source}")
            context_id = f"context:coverage:{self._id_token(source) or index}"
            facts.append(
                self._known_fact(
                    context_id=context_id,
                    category="coverage",
                    statement=f"Missing coverage source: {source}",
                    source="evidence_package.coverage.missing_sources",
                    value={"source": source, "availability": "missing"},
                )
            )

        if sysmon_warning:
            limitations.append(sysmon_warning)
            facts.append(
                self._known_fact(
                    context_id="context:coverage:sysmon_fp_warning",
                    category="coverage",
                    statement=sysmon_warning,
                    source="evidence_package.coverage.sysmon_fp_warning",
                    value={"warning": sysmon_warning},
                )
            )

        if present_sources:
            facts.append(
                self._known_fact(
                    context_id="context:coverage:present_sources",
                    category="coverage",
                    statement="Coverage sources present: " + ", ".join(present_sources),
                    source="evidence_package.coverage.present_sources",
                    value={"sources": present_sources},
                )
            )

        if not facts:
            facts.append(
                self._known_fact(
                    context_id="context:coverage",
                    category="coverage",
                    statement=(
                        "Coverage status: "
                        f"{str(getattr(coverage, 'coverage_status', UNKNOWN_STATUS) or UNKNOWN_STATUS)}"
                    ),
                    source="evidence_package.coverage",
                    value=self._object_dict(coverage),
                )
            )

        return limitations, facts

    def _metadata_context_facts(self) -> List[AdjudicationContextFact]:
        facts: List[AdjudicationContextFact] = []
        explicit_facts = self.context_metadata.get("context_facts")
        if isinstance(explicit_facts, list):
            for fact in explicit_facts:
                coerced = self._coerce_metadata_fact(fact)
                if coerced is not None:
                    facts.append(coerced)

        for context_id, category in UNKNOWN_CONTEXT_FACTS.items():
            if category not in self.context_metadata:
                continue
            fact = self._metadata_value_to_fact(
                context_id=context_id,
                category=category,
                value=self.context_metadata.get(category),
            )
            if fact is not None:
                facts.append(fact)

        return facts

    def _noise_context_facts(
        self,
        evidence_items: List[AdjudicationContextEvidenceItem],
    ) -> List[AdjudicationContextFact]:
        facts: List[AdjudicationContextFact] = []
        for item in evidence_items:
            detail = self._object_dict(item.detail)
            noise_rules = self._string_values(detail.get("noise_rules") or [])
            noise_matched = bool(detail.get("noise_matched"))
            if not noise_matched and not noise_rules:
                continue

            context_id = "context:noise"
            if item.evidence_id != "evidence:anchor":
                context_id = f"context:noise:{self._id_token(item.evidence_id)}"
            facts.append(
                self._known_fact(
                    context_id=context_id,
                    category="noise",
                    statement=(
                        "Event matched explicit noise/known-good rule(s); "
                        "this may indicate a benign explanation but is not proof the activity is benign."
                    ),
                    source=f"{item.source}.noise",
                    value={
                        "evidence_id": item.evidence_id,
                        "noise_matched": noise_matched,
                        "noise_rules": noise_rules,
                    },
                )
            )
        return facts

    def _append_required_unknowns(
        self,
        facts: List[AdjudicationContextFact],
    ) -> List[AdjudicationContextFact]:
        by_id = {fact.context_id: fact for fact in facts}
        for context_id, category in UNKNOWN_CONTEXT_FACTS.items():
            if context_id not in by_id:
                by_id[context_id] = self._unknown_fact(
                    context_id,
                    category,
                    "adjudication_context_builder",
                )
        return list(by_id.values())

    def _metadata_value_to_fact(
        self,
        *,
        context_id: str,
        category: str,
        value: Any,
    ) -> Optional[AdjudicationContextFact]:
        if value in (None, "", [], {}):
            return self._unknown_fact(context_id, category, "context_metadata")
        if isinstance(value, AdjudicationContextFact):
            return value
        if isinstance(value, dict):
            status = str(value.get("status") or KNOWN_STATUS).lower()
            if status == UNKNOWN_STATUS:
                return self._unknown_fact(context_id, category, str(value.get("source") or "context_metadata"))
            statement = str(
                value.get("statement")
                or value.get("summary")
                or value.get("detail")
                or f"{category} context provided"
            )
            return self._known_fact(
                context_id=str(value.get("context_id") or context_id),
                category=str(value.get("category") or category),
                statement=statement,
                source=str(value.get("source") or "context_metadata"),
                value=value.get("value", value),
            )
        return self._known_fact(
            context_id=context_id,
            category=category,
            statement=f"{category} context provided",
            source="context_metadata",
            value=value,
        )

    def _coerce_metadata_fact(self, value: Any) -> Optional[AdjudicationContextFact]:
        if isinstance(value, AdjudicationContextFact):
            return value
        if not isinstance(value, dict):
            return None
        context_id = str(value.get("context_id") or "").strip()
        category = str(value.get("category") or "").strip()
        if not context_id or not category:
            return None
        if str(value.get("status") or "").lower() == UNKNOWN_STATUS:
            return self._unknown_fact(context_id, category, str(value.get("source") or "context_metadata"))
        return self._metadata_value_to_fact(
            context_id=context_id,
            category=category,
            value=value,
        )

    def _known_fact(
        self,
        *,
        context_id: str,
        category: str,
        statement: str,
        source: str,
        value: Any,
    ) -> AdjudicationContextFact:
        return AdjudicationContextFact(
            context_id=self._stable_context_id(context_id),
            category=category,
            status=KNOWN_STATUS,
            statement=statement,
            source=source,
            value=value,
        )

    def _unknown_fact(
        self,
        context_id: str,
        category: str,
        source: str,
    ) -> AdjudicationContextFact:
        return AdjudicationContextFact.unknown(
            context_id=self._stable_context_id(context_id),
            category=category,
            source=source,
        )

    def _build_entities(self) -> List[AdjudicationContextEntity]:
        entity_values: Dict[str, Dict[str, str]] = {}
        anchor = self._object_dict(getattr(self.evidence_package, "anchor", {}) or {})
        self._collect_entities_from_dict(anchor, entity_values)
        for check in getattr(self.evidence_package, "checks", []) or []:
            self._collect_entities_from_detail(str(getattr(check, "detail", "") or ""), entity_values)

        entity_overrides = self.context_metadata.get("entities")
        if isinstance(entity_overrides, list):
            for item in entity_overrides:
                if isinstance(item, dict):
                    field_name = str(item.get("field") or item.get("entity_type") or "")
                    value = str(item.get("value") or "").strip()
                    if value:
                        self._add_entity(
                            entity_values,
                            field_name=field_name,
                            entity_type=str(item.get("entity_type") or ENTITY_FIELDS.get(field_name, "entity")),
                            value=value,
                            role=str(item.get("role") or UNKNOWN_STATUS),
                            status=str(item.get("status") or UNKNOWN_STATUS),
                        )

        return [
            AdjudicationContextEntity(
                entity_id=entity["entity_id"],
                entity_type=entity["entity_type"],
                value=entity["value"],
                role=entity.get("role", UNKNOWN_STATUS),
                status=entity.get("status", UNKNOWN_STATUS),
                facts=entity.get("facts", []),
            )
            for entity in entity_values.values()
        ]

    def _collect_entities_from_dict(
        self,
        source: Dict[str, Any],
        entity_values: Dict[str, Dict[str, str]],
    ) -> None:
        for field_name, entity_type in ENTITY_FIELDS.items():
            value = str(source.get(field_name) or "").strip()
            if value:
                self._add_entity(entity_values, field_name, entity_type, value)

    def _collect_entities_from_detail(
        self,
        detail: str,
        entity_values: Dict[str, Dict[str, str]],
    ) -> None:
        if not detail:
            return
        for field_name, pattern in DETAIL_ENTITY_PATTERNS.items():
            match = pattern.search(detail)
            if not match:
                continue
            value = match.group(1).strip()
            if value:
                self._add_entity(entity_values, field_name, ENTITY_FIELDS[field_name], value)

    def _add_entity(
        self,
        entity_values: Dict[str, Dict[str, str]],
        field_name: str,
        entity_type: str,
        value: str,
        role: str = UNKNOWN_STATUS,
        status: str = UNKNOWN_STATUS,
    ) -> None:
        entity_type = entity_type or ENTITY_FIELDS.get(field_name, "entity")
        key = f"{entity_type}:{value}".lower()
        if key in entity_values:
            return
        entity_values[key] = {
            "entity_id": f"entity:{self._id_token(entity_type)}:{self._id_token(value)}",
            "entity_type": entity_type,
            "value": value,
            "role": role or UNKNOWN_STATUS,
            "status": status or UNKNOWN_STATUS,
            "facts": [],
        }

    def _stable_check_id(self, raw_id: str, index: int) -> str:
        base = raw_id if raw_id.startswith("check:") else f"check:{raw_id}"
        return self._dedupe_id(base, self._used_check_ids, index)

    def _stable_evidence_id(self, evidence_id: str) -> str:
        return self._dedupe_id(evidence_id, self._used_evidence_ids)

    def _stable_context_id(self, context_id: str) -> str:
        return self._dedupe_id(context_id, self._used_context_ids)

    @staticmethod
    def _dedupe_id(identifier: str, used: Set[str], index: Optional[int] = None) -> str:
        base = str(identifier or "").strip()
        if not base:
            base = f"item:{index or 0}"
        candidate = base
        suffix = index if index is not None else 1
        while candidate in used:
            candidate = f"{base}:{suffix}"
            suffix += 1
        used.add(candidate)
        return candidate

    @staticmethod
    def _id_token(value: Any) -> str:
        token = re.sub(r"[^a-zA-Z0-9_.$-]+", "_", str(value or "").strip()).strip("_")
        return token.lower()

    @staticmethod
    def _string_values(values: Iterable[Any]) -> List[str]:
        return [str(value).strip() for value in values if str(value or "").strip()]

    @staticmethod
    def _object_dict(value: Any) -> Dict[str, Any]:
        if value is None:
            return {}
        if isinstance(value, dict):
            return dict(value)
        if hasattr(value, "to_dict") and callable(value.to_dict):
            converted = value.to_dict()
            return dict(converted) if isinstance(converted, dict) else {"value": converted}
        if is_dataclass(value):
            return asdict(value)
        if hasattr(value, "__dict__"):
            return {
                str(key): field_value
                for key, field_value in vars(value).items()
                if not key.startswith("_")
            }
        return {"value": value}

