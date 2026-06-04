"""Validation guardrails for AI adjudication results.

This module validates AI adjudication output against an AdjudicationContext.
It does not apply scores, mutate EvidencePackage objects, call an LLM, or
decide finding eligibility.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Set, Tuple

from utils.ai_adjudication_contract import (
    KNOWN_STATUS,
    AIAdjudicationResult,
    AIAdjudicationValidationResult,
    AdjudicationContext,
    AdjudicationContextFact,
)


NEUTRAL_REASONING = "AI adjudication invalid or unsupported; deterministic score retained."
NEUTRAL_FALSE_POSITIVE_ASSESSMENT = "No validated AI false-positive assessment."
NEUTRAL_INVESTIGATION_PRIORITY = "Unchanged"


CLAIM_SUPPORT_CATEGORIES: Dict[str, Set[str]] = {
    "known-good": {"known_good"},
    "known good": {"known_good"},
    "allowlisted": {"known_good"},
    "whitelisted": {"known_good"},
    "approved admin": {"known_good", "user_role"},
    "expected admin": {"known_good", "user_role"},
    "known administrative workflow": {"known_good"},
    "rmm": {"known_good"},
    "domain controller": {"source_host_role", "target_host_role", "host_role"},
    "workstation": {"source_host_role", "target_host_role", "host_role"},
    "server role": {"source_host_role", "target_host_role", "host_role"},
    "jump box": {"source_host_role", "target_host_role", "host_role"},
    "backup server": {"source_host_role", "target_host_role", "host_role"},
    "business hours": {"business_hours"},
    "off-hours": {"business_hours"},
    "baseline": {"baseline"},
    "normally": {"baseline"},
    "typical": {"baseline"},
    "asset criticality": {"asset_criticality"},
    "critical asset": {"asset_criticality"},
    "threat intel": {"threat_intel"},
    "malware family": {"threat_intel"},
    "known malicious infrastructure": {"threat_intel"},
}


class AIAdjudicationValidator:
    """Validate and sanitize AI adjudication output."""

    def __init__(self, context: AdjudicationContext):
        if not isinstance(context, AdjudicationContext):
            raise ValueError("context must be an AdjudicationContext")
        self.context = context
        self._valid_evidence_ids = set(context.evidence_ids())
        self._context_facts_by_id = {
            fact.context_id: fact
            for fact in context.context_facts
        }
        self._valid_context_ids = set(self._context_facts_by_id.keys())

    def validate(self, result: AIAdjudicationResult) -> AIAdjudicationValidationResult:
        """Validate citations and conservative no-new-facts constraints."""
        errors: List[str] = []
        invalid_evidence_ids: List[str] = []
        invalid_context_ids: List[str] = []
        unsupported_fact_claims: List[str] = []

        cited_supporting = self._dedupe(result.supporting_evidence_ids)
        cited_mitigating = self._dedupe(result.mitigating_evidence_ids)
        cited_context = self._dedupe(result.referenced_context_ids)

        invalid_evidence_ids.extend(
            evidence_id
            for evidence_id in [*cited_supporting, *cited_mitigating]
            if evidence_id not in self._valid_evidence_ids
        )
        invalid_context_ids.extend(
            context_id
            for context_id in cited_context
            if context_id not in self._valid_context_ids
        )

        if invalid_evidence_ids:
            errors.append("AI adjudication referenced unknown evidence IDs.")
        if invalid_context_ids:
            errors.append("AI adjudication referenced unknown context IDs.")

        valid_supporting = [
            evidence_id for evidence_id in cited_supporting
            if evidence_id in self._valid_evidence_ids
        ]
        valid_mitigating = [
            evidence_id for evidence_id in cited_mitigating
            if evidence_id in self._valid_evidence_ids
        ]
        valid_context = [
            context_id for context_id in cited_context
            if context_id in self._valid_context_ids
        ]

        if result.confidence_adjustment > 0 and not valid_supporting:
            errors.append(
                "Positive confidence adjustment requires at least one valid supporting evidence ID."
            )
        if result.confidence_adjustment < 0 and not (valid_mitigating or valid_context):
            errors.append(
                "Negative confidence adjustment requires at least one valid mitigating evidence "
                "or referenced context ID."
            )

        unsupported_fact_claims = self._unsupported_claims(result, valid_context)
        if unsupported_fact_claims:
            errors.append("AI adjudication made unsupported trusted-context claims.")

        return AIAdjudicationValidationResult(
            is_valid=not errors,
            errors=errors,
            invalid_evidence_ids=self._dedupe(invalid_evidence_ids),
            invalid_context_ids=self._dedupe(invalid_context_ids),
            unsupported_fact_claims=unsupported_fact_claims,
        )

    def safe_result(
        self,
        result_or_payload: Any,
    ) -> Tuple[AIAdjudicationResult, AIAdjudicationValidationResult]:
        """Return a validated result, or a neutral fallback with validation details."""
        try:
            result = self._coerce_result(result_or_payload)
        except Exception as exc:
            error = f"Invalid AI adjudication payload: {str(exc)}"
            validation = AIAdjudicationValidationResult(
                is_valid=False,
                errors=[error],
            )
            return self._neutral_result([error]), validation

        validation = self.validate(result)
        if validation.is_valid:
            return result, validation
        return self._neutral_result(validation.errors), validation

    @staticmethod
    def _coerce_result(result_or_payload: Any) -> AIAdjudicationResult:
        if isinstance(result_or_payload, AIAdjudicationResult):
            return result_or_payload
        if isinstance(result_or_payload, dict):
            return AIAdjudicationResult(**result_or_payload)
        raise ValueError("AI adjudication payload must be a dict or AIAdjudicationResult")

    @staticmethod
    def _neutral_result(errors: Iterable[str]) -> AIAdjudicationResult:
        limitations = [
            "; ".join(str(error) for error in errors if str(error).strip())
        ]
        limitations = [item for item in limitations if item]
        return AIAdjudicationResult(
            confidence_adjustment=0,
            reasoning=NEUTRAL_REASONING,
            false_positive_assessment=NEUTRAL_FALSE_POSITIVE_ASSESSMENT,
            investigation_priority=NEUTRAL_INVESTIGATION_PRIORITY,
            supporting_evidence_ids=[],
            mitigating_evidence_ids=[],
            referenced_context_ids=[],
            limitations=limitations,
            recommended_next_steps=[],
        )

    def _unsupported_claims(
        self,
        result: AIAdjudicationResult,
        valid_context_ids: List[str],
    ) -> List[str]:
        narrative = self._narrative_text(result)
        if not narrative:
            return []

        unsupported: List[str] = []
        for phrase, supported_categories in CLAIM_SUPPORT_CATEGORIES.items():
            if phrase not in narrative:
                continue
            if self._phrase_is_unknown_limitation(narrative, phrase):
                continue
            if not self._has_referenced_known_context(
                valid_context_ids,
                supported_categories,
            ):
                unsupported.append(phrase)
        return self._dedupe(unsupported)

    @staticmethod
    def _phrase_is_unknown_limitation(narrative: str, phrase: str) -> bool:
        """Allow trusted-context terms when explicitly described as unknown/absent.

        This does not allow a benign/trusted conclusion. It only prevents phrases
        like "known-good context is unknown" from being treated as unsupported
        claims.
        """
        phrase_index = narrative.find(phrase)
        if phrase_index < 0:
            return False
        start = max(0, phrase_index - 80)
        end = min(len(narrative), phrase_index + len(phrase) + 120)
        window = narrative[start:end]
        limitation_markers = (
            "unknown",
            "not provided",
            "not cited",
            "no cited",
            "not available",
            "unavailable",
            "cannot be changed without cited",
            "no validated",
            "not verified",
        )
        return any(marker in window for marker in limitation_markers)

    def _has_referenced_known_context(
        self,
        valid_context_ids: List[str],
        supported_categories: Set[str],
    ) -> bool:
        for context_id in valid_context_ids:
            fact = self._context_facts_by_id.get(context_id)
            if self._fact_supports_claim(fact, supported_categories):
                return True
        return False

    @staticmethod
    def _fact_supports_claim(
        fact: AdjudicationContextFact | None,
        supported_categories: Set[str],
    ) -> bool:
        if fact is None:
            return False
        if str(fact.status or "").lower() != KNOWN_STATUS:
            return False
        category = str(fact.category or "").lower()
        return category in supported_categories

    @staticmethod
    def _narrative_text(result: AIAdjudicationResult) -> str:
        parts: List[str] = [
            result.reasoning,
            result.false_positive_assessment,
            *result.limitations,
            *result.recommended_next_steps,
        ]
        return " ".join(str(part or "") for part in parts).lower()

    @staticmethod
    def _dedupe(values: Iterable[str]) -> List[str]:
        deduped: List[str] = []
        seen = set()
        for value in values or []:
            cleaned = str(value or "").strip()
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            deduped.append(cleaned)
        return deduped

