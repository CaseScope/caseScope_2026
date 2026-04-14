"""Pattern overlay helpers for additive OpenCTI enrichment.

Keeps built-in deterministic patterns authoritative while allowing external
intel to add bounded score boosts, freshness, aliases, and companion context.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from utils.pattern_event_mappings import PATTERN_EVENT_MAPPINGS


CURATED_PATTERN_ALIASES: Dict[str, List[str]] = {
    'pass_the_hash': ['pth', 'hash reuse', 'ntlm hash reuse'],
    'password_spraying': ['password spray', 'password spraying', 'spray attack'],
    'brute_force': ['bruteforce', 'brute force login', 'credential stuffing'],
    'psexec_execution': ['psexec', 'paexec', 'remcom', 'service exec'],
    'wmi_lateral': ['wmi lateral movement', 'wmic remote exec', 'win32_process create'],
    'rdp_lateral': ['rdp lateral movement', 'remote desktop lateral movement'],
    'winrm_lateral': ['powershell remoting', 'winrm lateral movement', 'wsman remoting'],
    'scheduled_task_persistence': ['scheduled task', 'task scheduler persistence'],
    'log_clearing': ['clear event log', 'log clearing', 'wevtutil clear'],
}


def _normalize_text(value: Any) -> str:
    text = str(value or '').strip().lower()
    text = re.sub(r'[^a-z0-9]+', ' ', text)
    return re.sub(r'\s+', ' ', text).strip()


def _normalize_techniques(values: Optional[Iterable[Any]]) -> List[str]:
    normalized = []
    for value in values or []:
        technique = str(value or '').strip().upper()
        if technique and technique not in normalized:
            normalized.append(technique)
    return normalized


def _tokenize_aliases(values: Iterable[Any]) -> List[str]:
    tokens = set()
    for value in values:
        normalized = _normalize_text(value)
        if not normalized:
            continue
        tokens.add(normalized)
        for token in normalized.split():
            if len(token) >= 4:
                tokens.add(token)
    return sorted(tokens)


def build_builtin_overlay_catalog(
    patterns: Optional[Dict[str, Dict[str, Any]]] = None
) -> Dict[str, Dict[str, Any]]:
    """Build normalized lookup data for built-in patterns."""
    catalog = {}
    for pattern_id, config in (patterns or PATTERN_EVENT_MAPPINGS).items():
        aliases = list(config.get('overlay_aliases', []))
        aliases.extend(CURATED_PATTERN_ALIASES.get(pattern_id, []))
        aliases.extend([
            config.get('name', ''),
            pattern_id.replace('_', ' '),
        ])
        aliases = [alias for alias in aliases if alias]
        catalog[pattern_id] = {
            'pattern_id': pattern_id,
            'name': config.get('name', pattern_id),
            'mitre_techniques': _normalize_techniques(config.get('mitre_techniques', [])),
            'aliases': sorted({_normalize_text(alias) for alias in aliases if _normalize_text(alias)}),
            'alias_tokens': _tokenize_aliases(aliases),
        }
    return catalog


def match_external_pattern_to_builtins(
    external_name: str,
    *,
    mitre_techniques: Optional[Iterable[Any]] = None,
    aliases: Optional[Iterable[Any]] = None,
    labels: Optional[Iterable[Any]] = None,
    patterns: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Match external OpenCTI content to built-in patterns.

    MITRE technique overlap is authoritative. Alias-based matching is used as
    a secondary fallback so overlays can still attach when the external record
    lacks clean ATT&CK metadata.
    """
    catalog = build_builtin_overlay_catalog(patterns)
    normalized_techniques = _normalize_techniques(mitre_techniques)
    normalized_external_name = _normalize_text(external_name)
    external_aliases = [
        _normalize_text(value)
        for value in ([external_name] + list(aliases or []) + list(labels or []))
        if _normalize_text(value)
    ]
    external_tokens = set(_tokenize_aliases(external_aliases))

    matches: Dict[str, Dict[str, Any]] = {}

    for pattern_id, built_in in catalog.items():
        match_reasons: List[str] = []
        matched_techniques = sorted(
            set(normalized_techniques).intersection(built_in['mitre_techniques'])
        )
        score = 0

        if matched_techniques:
            match_reasons.append('mitre_technique')
            score += 100 + (10 * len(matched_techniques))

        alias_hit = normalized_external_name in built_in['aliases']
        if not alias_hit:
            alias_hit = any(alias in built_in['aliases'] for alias in external_aliases)
        token_overlap = len(external_tokens.intersection(set(built_in['alias_tokens'])))

        if alias_hit:
            match_reasons.append('alias_exact')
            score += 40
        elif token_overlap >= 2:
            match_reasons.append('alias_token_overlap')
            score += min(30, token_overlap * 10)

        if score <= 0:
            continue

        matches[pattern_id] = {
            'pattern_id': pattern_id,
            'pattern_name': built_in['name'],
            'matched_mitre_techniques': matched_techniques,
            'match_reasons': match_reasons,
            'match_score': score,
        }

    return sorted(matches.values(), key=lambda item: (-item['match_score'], item['pattern_id']))


def parse_external_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse OpenCTI timestamps into timezone-aware UTC datetimes."""
    if not value:
        return None
    cleaned = str(value).strip()
    if cleaned.endswith('Z'):
        cleaned = cleaned[:-1] + '+00:00'
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def derive_overlay_freshness(
    *,
    valid_from: Optional[str] = None,
    valid_until: Optional[str] = None,
    has_detection_guidance: bool = False,
) -> float:
    """Estimate how fresh an external overlay should be treated."""
    now = datetime.now(timezone.utc)
    valid_from_dt = parse_external_datetime(valid_from)
    valid_until_dt = parse_external_datetime(valid_until)

    freshness = 55.0
    if valid_until_dt:
        if valid_until_dt >= now:
            freshness = 85.0
        else:
            age_days = max(0, (now - valid_until_dt).days)
            freshness = 50.0 if age_days <= 30 else 30.0
    elif valid_from_dt:
        age_days = max(0, (now - valid_from_dt).days)
        freshness = 80.0 if age_days <= 30 else 65.0 if age_days <= 180 else 50.0

    if has_detection_guidance:
        freshness = min(95.0, freshness + 5.0)

    return freshness


def recommend_overlay_boost(
    *,
    overlay_type: str,
    match_reasons: Sequence[str],
    has_detection_guidance: bool = False,
    has_companion_query: bool = False,
) -> float:
    """Translate overlay quality into a small, bounded additive boost."""
    base = 2.0 if overlay_type == 'mitre_context' else 3.0
    if 'mitre_technique' in match_reasons:
        base += 1.0
    if 'alias_exact' in match_reasons:
        base += 1.0
    if has_detection_guidance:
        base += 1.0
    if has_companion_query:
        base += 1.0
    return min(8.0, base)


def build_opencti_mitre_overlay_payload(
    pattern: Dict[str, Any],
    match: Dict[str, Any],
) -> Dict[str, Any]:
    """Build the upsert payload for an OpenCTI ATT&CK context overlay."""
    has_detection_guidance = bool(pattern.get('detection'))
    return {
        'source': 'opencti',
        'source_id': pattern['opencti_id'],
        'overlay_type': 'mitre_context',
        'source_pattern_name': pattern['name'],
        'matched_mitre_techniques': match['matched_mitre_techniques'],
        'source_mitre_techniques': [pattern.get('mitre_id')],
        'aliases': [pattern.get('name')],
        'confidence_boost': recommend_overlay_boost(
            overlay_type='mitre_context',
            match_reasons=match['match_reasons'],
            has_detection_guidance=has_detection_guidance,
        ),
        'freshness_score': derive_overlay_freshness(
            has_detection_guidance=has_detection_guidance,
        ),
        'overlay_data': {
            'description': pattern.get('description'),
            'detection_guidance': pattern.get('detection'),
            'kill_chain_phases': pattern.get('kill_chain_phases', []),
            'platforms': pattern.get('platforms', []),
            'match_reasons': match['match_reasons'],
        },
    }


def build_opencti_sigma_companion_queries(
    converted_sigma: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Build non-authoritative companion query metadata from a converted Sigma rule."""
    if not converted_sigma or not converted_sigma.get('clickhouse_query'):
        return []
    return [{
        'name': converted_sigma.get('name'),
        'query': converted_sigma.get('clickhouse_query'),
        'non_authoritative': True,
    }]


def build_opencti_sigma_overlay_payload(
    indicator: Dict[str, Any],
    match: Dict[str, Any],
    *,
    sigma_techniques: Optional[Iterable[Any]] = None,
    companion_queries: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build the upsert payload for an OpenCTI Sigma companion overlay."""
    companion_queries = companion_queries or []
    has_companion_query = bool(companion_queries)
    return {
        'source': 'opencti_sigma',
        'source_id': indicator['opencti_id'],
        'overlay_type': 'sigma_companion',
        'source_pattern_name': indicator['name'],
        'matched_mitre_techniques': match['matched_mitre_techniques'],
        'source_mitre_techniques': list(sigma_techniques or []),
        'aliases': [indicator.get('name')],
        'labels': indicator.get('labels', []),
        'confidence_boost': recommend_overlay_boost(
            overlay_type='sigma_companion',
            match_reasons=match['match_reasons'],
            has_companion_query=has_companion_query,
        ),
        'freshness_score': derive_overlay_freshness(
            valid_from=indicator.get('valid_from'),
            valid_until=indicator.get('valid_until'),
            has_detection_guidance=has_companion_query,
        ),
        'companion_queries': companion_queries,
        'overlay_data': {
            'indicator_score': indicator.get('score', 0),
            'valid_from': indicator.get('valid_from'),
            'valid_until': indicator.get('valid_until'),
            'labels': indicator.get('labels', []),
            'kill_chain_phases': indicator.get('kill_chain_phases', []),
            'match_reasons': match['match_reasons'],
        },
    }


def compute_overlay_score_adjustment(
    deterministic_score: float,
    overlays: Sequence[Dict[str, Any]],
) -> float:
    """Apply a bounded overlay boost without letting intel create a strong hit."""
    if deterministic_score < 25:
        return 0.0

    cap = 2.0
    if deterministic_score >= 70:
        cap = 8.0
    elif deterministic_score >= 55:
        cap = 6.0
    elif deterministic_score >= 40:
        cap = 4.0

    candidate = 0.0
    for overlay in overlays:
        boost = float(overlay.get('confidence_boost') or 0.0)
        freshness = float(overlay.get('freshness_score') or 0.0)
        if freshness < 40.0:
            boost = max(0.0, boost - 1.0)
        candidate = max(candidate, boost)

    return min(cap, candidate)


def is_opencti_overlay_enabled() -> bool:
    """Gate overlay use to the same license/settings path as OpenCTI sync."""
    try:
        from models.system_settings import SystemSettings, SettingKeys
        from utils.licensing.license_manager import LicenseManager

        return bool(
            LicenseManager.is_feature_activated('opencti')
            and SystemSettings.get(SettingKeys.OPENCTI_ENABLED, False)
            and SystemSettings.get(SettingKeys.OPENCTI_RAG_SYNC, False)
        )
    except Exception:
        return False


def upsert_pattern_overlay(
    *,
    pattern_id: str,
    source: str,
    source_id: str,
    overlay_type: str,
    source_pattern_name: str,
    matched_mitre_techniques: Optional[Iterable[Any]] = None,
    source_mitre_techniques: Optional[Iterable[Any]] = None,
    aliases: Optional[Iterable[Any]] = None,
    labels: Optional[Iterable[Any]] = None,
    confidence_boost: float = 0.0,
    freshness_score: float = 0.0,
    companion_queries: Optional[List[Dict[str, Any]]] = None,
    overlay_data: Optional[Dict[str, Any]] = None,
) -> bool:
    """Create or update a stored overlay record."""
    from models.database import db
    from models.rag import PatternIntelOverlay

    existing = PatternIntelOverlay.query.filter_by(
        pattern_id=pattern_id,
        source=source,
        source_id=source_id,
    ).first()

    payload = {
        'overlay_type': overlay_type,
        'source_pattern_name': source_pattern_name,
        'matched_mitre_techniques': _normalize_techniques(matched_mitre_techniques),
        'source_mitre_techniques': _normalize_techniques(source_mitre_techniques),
        'aliases': sorted({str(alias).strip() for alias in (aliases or []) if str(alias).strip()}),
        'labels': sorted({str(label).strip() for label in (labels or []) if str(label).strip()}),
        'confidence_boost': float(confidence_boost or 0.0),
        'freshness_score': float(freshness_score or 0.0),
        'companion_queries': companion_queries or [],
        'overlay_data': overlay_data or {},
        'enabled': True,
        'last_synced_at': datetime.utcnow(),
    }

    if existing:
        for key, value in payload.items():
            setattr(existing, key, value)
        created = False
    else:
        existing = PatternIntelOverlay(
            pattern_id=pattern_id,
            source=source,
            source_id=source_id,
            **payload,
        )
        db.session.add(existing)
        created = True

    return created


def sync_external_pattern_overlays(
    *,
    external_name: str,
    payload_builder: Callable[[Dict[str, Any]], Dict[str, Any]],
    mitre_techniques: Optional[Iterable[Any]] = None,
    aliases: Optional[Iterable[Any]] = None,
    labels: Optional[Iterable[Any]] = None,
    patterns: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[bool]:
    """Match an external pattern to built-ins and upsert the resulting overlays."""
    results: List[bool] = []
    matches = match_external_pattern_to_builtins(
        external_name,
        mitre_techniques=mitre_techniques,
        aliases=aliases,
        labels=labels,
        patterns=patterns,
    )
    for match in matches:
        payload = payload_builder(match)
        results.append(
            upsert_pattern_overlay(
                pattern_id=match['pattern_id'],
                **payload,
            )
        )
    return results


def summarize_overlay_sync_results(results: Sequence[bool]) -> Dict[str, int]:
    """Summarize created-versus-updated overlay upsert results."""
    total_count = len(results)
    created_count = sum(1 for created in results if created)
    return {
        'added': created_count,
        'updated': total_count - created_count,
    }


def apply_overlay_sync_summary(
    stats: Dict[str, int],
    summary: Dict[str, int],
    *,
    added_key: str = 'overlays_added',
    updated_key: str = 'overlays_updated',
) -> None:
    """Apply an overlay sync summary onto a mutable stats dict."""
    stats[added_key] = int(stats.get(added_key, 0)) + int(summary.get('added', 0))
    stats[updated_key] = int(stats.get(updated_key, 0)) + int(summary.get('updated', 0))


class PatternOverlayEnhancer:
    """Apply stored overlays to deterministic evidence packages."""

    def __init__(self, overlays_by_pattern: Optional[Dict[str, List[Dict[str, Any]]]] = None):
        self._overlays_by_pattern = overlays_by_pattern

    def _load_overlays(self, pattern_id: str) -> List[Dict[str, Any]]:
        if self._overlays_by_pattern is not None:
            return list(self._overlays_by_pattern.get(pattern_id, []))

        from models.rag import PatternIntelOverlay

        overlays = PatternIntelOverlay.query.filter_by(
            pattern_id=pattern_id,
            enabled=True,
        ).order_by(
            PatternIntelOverlay.confidence_boost.desc(),
            PatternIntelOverlay.freshness_score.desc(),
            PatternIntelOverlay.updated_at.desc(),
        ).all()
        return [overlay.to_public_dict() for overlay in overlays]

    def build_overlay_context(
        self,
        *,
        pattern_id: str,
        deterministic_score: float,
        mitre_techniques: Optional[Iterable[Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        overlays = self._load_overlays(pattern_id)
        if not overlays:
            return None

        normalized_mitre = set(_normalize_techniques(mitre_techniques))
        relevant = []
        for overlay in overlays:
            matched = set(_normalize_techniques(overlay.get('matched_mitre_techniques')))
            if matched and normalized_mitre and matched.isdisjoint(normalized_mitre):
                continue
            relevant.append(overlay)

        if not relevant:
            return None

        boost = compute_overlay_score_adjustment(deterministic_score, relevant)
        freshest = max(float(item.get('freshness_score') or 0.0) for item in relevant)

        return {
            'available': True,
            'authority': 'metadata_only',
            'overlay_count': len(relevant),
            'applied_boost': boost,
            'freshness_score': freshest,
            'sources': sorted({item.get('source', 'unknown') for item in relevant}),
            'matched_mitre_techniques': sorted({
                technique
                for item in relevant
                for technique in _normalize_techniques(item.get('matched_mitre_techniques'))
            }),
            'overlays': relevant[:3],
        }

    def apply_to_package(self, package) -> Optional[Dict[str, Any]]:
        context = self.build_overlay_context(
            pattern_id=package.pattern_id,
            deterministic_score=package.deterministic_score,
            mitre_techniques=package.mitre_techniques,
        )
        if not context:
            return None

        package.overlay_score_adjustment = context['applied_boost']
        package.intel_overlay = context
        return context

