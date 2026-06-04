"""Typed contracts for future AI adjudication validation.

These objects intentionally do not execute scoring policy or alter finding
eligibility. They define the JSON-safe boundary that future AI adjudication
guardrails can validate against.
"""

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


UNKNOWN_STATUS = "unknown"
KNOWN_STATUS = "known"
MISSING_STATUS = "missing"
ALLOWED_FACT_STATUSES = {KNOWN_STATUS, UNKNOWN_STATUS, MISSING_STATUS}


def _require_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} is required")
    return value.strip()


def _string_list(values: Optional[List[str]], field_name: str) -> List[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError(f"{field_name} must be a list")
    normalized: List[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} entries must be non-empty strings")
        normalized.append(value.strip())
    return normalized


def _json_ready(value: Any) -> Any:
    """Return a JSON-compatible value without inventing domain semantics."""
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


class JsonSerializableContract:
    """Mixin for simple dataclass contracts that need JSON serialization."""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass
class AdjudicationContextEvidenceItem(JsonSerializableContract):
    """A stable evidence item the AI may cite."""

    evidence_id: str
    evidence_type: str
    summary: str
    source: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.evidence_id = _require_text(self.evidence_id, "evidence_id")
        self.evidence_type = _require_text(self.evidence_type, "evidence_type")
        self.summary = _require_text(self.summary, "summary")
        self.source = str(self.source or "")
        if not isinstance(self.detail, dict):
            raise ValueError("detail must be a dict")
        self.detail = {str(key): _json_ready(value) for key, value in self.detail.items()}


@dataclass
class AdjudicationContextCheck(JsonSerializableContract):
    """A deterministic check exposed to the AI adjudication layer."""

    check_id: str
    status: str
    name: str
    detail: str
    weight: float = 0.0
    contribution: float = 0.0
    source: str = ""

    def __post_init__(self) -> None:
        self.check_id = _require_text(self.check_id, "check_id")
        self.status = _require_text(self.status, "status").upper()
        if self.status not in {"PASS", "FAIL", "INCONCLUSIVE"}:
            raise ValueError("status must be PASS, FAIL, or INCONCLUSIVE")
        self.name = _require_text(self.name, "name")
        self.detail = _require_text(self.detail, "detail")
        self.weight = float(self.weight or 0.0)
        self.contribution = float(self.contribution or 0.0)
        self.source = str(self.source or "")


@dataclass
class AdjudicationContextEntity(JsonSerializableContract):
    """A host, user, source, or other entity visible to adjudication."""

    entity_id: str
    entity_type: str
    value: str
    role: str = UNKNOWN_STATUS
    status: str = UNKNOWN_STATUS
    facts: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.entity_id = _require_text(self.entity_id, "entity_id")
        self.entity_type = _require_text(self.entity_type, "entity_type")
        self.value = _require_text(self.value, "value")
        self.role = str(self.role or UNKNOWN_STATUS)
        self.status = str(self.status or UNKNOWN_STATUS).lower()
        if self.status not in ALLOWED_FACT_STATUSES:
            raise ValueError("status must be known, unknown, or missing")
        self.facts = _string_list(self.facts, "facts")


@dataclass
class AdjudicationContextFact(JsonSerializableContract):
    """A context fact, including explicit unknown or missing state."""

    context_id: str
    category: str
    status: str = UNKNOWN_STATUS
    statement: str = ""
    source: str = ""
    value: Any = None

    def __post_init__(self) -> None:
        self.context_id = _require_text(self.context_id, "context_id")
        self.category = _require_text(self.category, "category")
        self.status = str(self.status or UNKNOWN_STATUS).lower()
        if self.status not in ALLOWED_FACT_STATUSES:
            raise ValueError("status must be known, unknown, or missing")
        self.statement = str(self.statement or "")
        self.source = str(self.source or "")
        self.value = _json_ready(self.value)
        if self.status == KNOWN_STATUS and not self.statement.strip():
            raise ValueError("known facts require a statement")

    @classmethod
    def unknown(cls, context_id: str, category: str, source: str = ""):
        return cls(
            context_id=context_id,
            category=category,
            status=UNKNOWN_STATUS,
            statement="Unknown; no verified context available.",
            source=source,
            value=None,
        )


@dataclass
class ScoringPolicy(JsonSerializableContract):
    """Declarative scoring policy values matching current behavior.

    This class is descriptive only in Phase 1. It does not apply adjustments.
    """

    min_adjustment: float = -20.0
    max_adjustment: float = 10.0
    final_score_min: float = 0.0
    final_score_max: float = 100.0
    strong_detection_no_benign_min_score: float = 85.0
    strong_detection_no_benign_min_adjustment: float = 0.0
    score_floor_adjustments: Dict[str, float] = field(default_factory=lambda: {
        "80": -2.0,
        "70": -4.0,
        "60": -6.0,
        "50": -8.0,
    })
    protected_remote_exec_patterns: List[str] = field(default_factory=lambda: [
        "psexec_execution",
        "wmi_lateral",
        "winrm_lateral",
        "rdp_lateral",
    ])
    protected_remote_exec_min_score: float = 50.0
    protected_remote_exec_min_adjustment: float = -4.0
    strong_user_signal_min_score: float = 70.0
    strong_user_signal_min_adjustment: float = -4.0
    confirmed_detection_score_floor_min_score: float = 50.0
    confirmed_detection_final_score_floor: float = 50.0

    def __post_init__(self) -> None:
        self.min_adjustment = float(self.min_adjustment)
        self.max_adjustment = float(self.max_adjustment)
        self.final_score_min = float(self.final_score_min)
        self.final_score_max = float(self.final_score_max)
        if self.min_adjustment > self.max_adjustment:
            raise ValueError("min_adjustment cannot exceed max_adjustment")
        if self.final_score_min > self.final_score_max:
            raise ValueError("final_score_min cannot exceed final_score_max")
        if not isinstance(self.score_floor_adjustments, dict):
            raise ValueError("score_floor_adjustments must be a dict")
        self.score_floor_adjustments = {
            str(key): float(value)
            for key, value in self.score_floor_adjustments.items()
        }
        self.protected_remote_exec_patterns = _string_list(
            self.protected_remote_exec_patterns,
            "protected_remote_exec_patterns",
        )


@dataclass
class AdjudicationContext(JsonSerializableContract):
    """The standardized context object future AI adjudication will consume."""

    pattern_id: str
    pattern_name: str
    deterministic_score: float
    max_possible_score: float
    case_id: Optional[int] = None
    mitre_technique: Optional[str] = None
    coverage_status: str = UNKNOWN_STATUS
    coverage_limitations: List[str] = field(default_factory=list)
    checks: List[AdjudicationContextCheck] = field(default_factory=list)
    evidence_items: List[AdjudicationContextEvidenceItem] = field(default_factory=list)
    entities: List[AdjudicationContextEntity] = field(default_factory=list)
    context_facts: List[AdjudicationContextFact] = field(default_factory=list)
    scoring_policy: ScoringPolicy = field(default_factory=ScoringPolicy)

    def __post_init__(self) -> None:
        self.pattern_id = _require_text(self.pattern_id, "pattern_id")
        self.pattern_name = _require_text(self.pattern_name, "pattern_name")
        self.deterministic_score = float(self.deterministic_score)
        self.max_possible_score = float(self.max_possible_score)
        self.case_id = int(self.case_id) if self.case_id is not None else None
        self.mitre_technique = str(self.mitre_technique) if self.mitre_technique else None
        self.coverage_status = str(self.coverage_status or UNKNOWN_STATUS).lower()
        self.coverage_limitations = _string_list(
            self.coverage_limitations,
            "coverage_limitations",
        )
        self.checks = self._coerce_list(
            self.checks,
            AdjudicationContextCheck,
            "checks",
        )
        self.evidence_items = self._coerce_list(
            self.evidence_items,
            AdjudicationContextEvidenceItem,
            "evidence_items",
        )
        self.entities = self._coerce_list(
            self.entities,
            AdjudicationContextEntity,
            "entities",
        )
        self.context_facts = self._coerce_list(
            self.context_facts,
            AdjudicationContextFact,
            "context_facts",
        )
        if isinstance(self.scoring_policy, dict):
            self.scoring_policy = ScoringPolicy(**self.scoring_policy)
        if not isinstance(self.scoring_policy, ScoringPolicy):
            raise ValueError("scoring_policy must be a ScoringPolicy")

    @staticmethod
    def _coerce_list(values: Any, item_type: Any, field_name: str) -> List[Any]:
        if values is None:
            return []
        if not isinstance(values, list):
            raise ValueError(f"{field_name} must be a list")
        coerced = []
        for value in values:
            if isinstance(value, item_type):
                coerced.append(value)
            elif isinstance(value, dict):
                coerced.append(item_type(**value))
            else:
                raise ValueError(f"{field_name} entries must be {item_type.__name__}")
        return coerced

    def context_ids(self) -> List[str]:
        return [fact.context_id for fact in self.context_facts]

    def evidence_ids(self) -> List[str]:
        ids = [item.evidence_id for item in self.evidence_items]
        ids.extend(check.check_id for check in self.checks)
        return ids


@dataclass
class AIAdjudicationResult(JsonSerializableContract):
    """Validated AI adjudication output shape."""

    confidence_adjustment: float
    reasoning: str
    false_positive_assessment: str
    investigation_priority: str
    supporting_evidence_ids: List[str] = field(default_factory=list)
    mitigating_evidence_ids: List[str] = field(default_factory=list)
    referenced_context_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    recommended_next_steps: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.confidence_adjustment = float(self.confidence_adjustment)
        if self.confidence_adjustment < -20 or self.confidence_adjustment > 10:
            raise ValueError("confidence_adjustment must be between -20 and +10")
        self.reasoning = _require_text(self.reasoning, "reasoning")
        self.false_positive_assessment = _require_text(
            self.false_positive_assessment,
            "false_positive_assessment",
        )
        self.investigation_priority = _require_text(
            self.investigation_priority,
            "investigation_priority",
        )
        self.supporting_evidence_ids = _string_list(
            self.supporting_evidence_ids,
            "supporting_evidence_ids",
        )
        self.mitigating_evidence_ids = _string_list(
            self.mitigating_evidence_ids,
            "mitigating_evidence_ids",
        )
        self.referenced_context_ids = _string_list(
            self.referenced_context_ids,
            "referenced_context_ids",
        )
        self.limitations = _string_list(self.limitations, "limitations")
        self.recommended_next_steps = _string_list(
            self.recommended_next_steps,
            "recommended_next_steps",
        )


@dataclass
class AIAdjudicationValidationResult(JsonSerializableContract):
    """Validation outcome for future AI adjudication guardrails."""

    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    invalid_evidence_ids: List[str] = field(default_factory=list)
    invalid_context_ids: List[str] = field(default_factory=list)
    unsupported_fact_claims: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.is_valid = bool(self.is_valid)
        self.errors = _string_list(self.errors, "errors")
        self.warnings = _string_list(self.warnings, "warnings")
        self.invalid_evidence_ids = _string_list(
            self.invalid_evidence_ids,
            "invalid_evidence_ids",
        )
        self.invalid_context_ids = _string_list(
            self.invalid_context_ids,
            "invalid_context_ids",
        )
        self.unsupported_fact_claims = _string_list(
            self.unsupported_fact_claims,
            "unsupported_fact_claims",
        )

