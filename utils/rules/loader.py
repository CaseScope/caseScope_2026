"""Minimal dual-path rule loader for deterministic analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


@dataclass
class RuleCatalog:
    """Loaded declarative packs and Python verifier registrations."""

    declarative_packs: List[str] = field(default_factory=list)
    declarative_rules: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    python_verifiers: Dict[str, tuple[Any, ...]] = field(default_factory=dict)
    burst_configs: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    sequence_configs: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    spread_configs: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def get_checks_for_pattern(self, pattern_id: str) -> List[Any]:
        return list(self.python_verifiers.get(pattern_id, ()))

    def get_burst_config(self, pattern_id: str) -> Optional[Dict[str, Any]]:
        return self.burst_configs.get(pattern_id)

    def get_sequence_config(self, pattern_id: str) -> Optional[Dict[str, Any]]:
        return self.sequence_configs.get(pattern_id)

    def get_spread_config(self, pattern_id: str) -> Optional[Dict[str, Any]]:
        return self.spread_configs.get(pattern_id)


@dataclass
class RuleLoadReport:
    """Loader result with the live rule catalog and basic diagnostics."""

    catalog: RuleCatalog
    loaded: int
    skipped: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    licensed_skipped: List[str] = field(default_factory=list)


class RuleLoader:
    """Load declarative packs and Python verifiers behind one interface."""

    def __init__(
        self,
        engine: Any = None,
        *,
        builtin_root: Optional[Path] = None,
        extra_pack_paths: Optional[Sequence[str | Path]] = None,
    ):
        self.engine = engine
        self.builtin_root = builtin_root or Path(__file__).resolve().parent
        self.extra_pack_paths = [Path(path) for path in (extra_pack_paths or [])]

    def discover_packs(self) -> List[Path]:
        """Discover directories that may hold declarative rule packs."""
        candidates = [
            self.builtin_root / 'builtin',
            Path('/etc/casescope/rules.d'),
            Path('/var/lib/casescope/ti'),
            *self.extra_pack_paths,
        ]

        discovered: List[Path] = []
        seen = set()
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved in seen or not resolved.exists() or not resolved.is_dir():
                continue
            seen.add(resolved)
            discovered.append(resolved)
        return discovered

    def load_all(self) -> RuleLoadReport:
        """Load the current rule catalog."""
        from utils.pattern_check_definitions import (
            get_burst_config,
            get_sequence_config,
            get_spread_config,
            iter_pattern_checks,
        )
        from utils.pattern_event_mappings import get_all_patterns

        declarative_pack_dirs = self.discover_packs()
        declarative_rules: Dict[str, Dict[str, Any]] = {}
        skipped: List[str] = []

        for pack_dir in declarative_pack_dirs:
            for path in sorted(pack_dir.glob('*')):
                if path.is_dir():
                    continue
                if path.suffix.lower() not in {'.yml', '.yaml', '.rules'}:
                    skipped.append(str(path))
                    continue
                declarative_rules[path.stem] = {
                    'id': path.stem,
                    'path': str(path),
                    'format': path.suffix.lower().lstrip('.'),
                }

        python_verifiers = {
            pattern_id: tuple(checks)
            for pattern_id, checks in iter_pattern_checks()
        }

        burst_configs: Dict[str, Dict[str, Any]] = {}
        sequence_configs: Dict[str, Dict[str, Any]] = {}
        spread_configs: Dict[str, Dict[str, Any]] = {}
        for pattern_id in get_all_patterns():
            burst = get_burst_config(pattern_id)
            if burst:
                burst_configs[pattern_id] = burst
            sequence = get_sequence_config(pattern_id)
            if sequence:
                sequence_configs[pattern_id] = sequence
            spread = get_spread_config(pattern_id)
            if spread:
                spread_configs[pattern_id] = spread

        catalog = RuleCatalog(
            declarative_packs=[str(path) for path in declarative_pack_dirs],
            declarative_rules=declarative_rules,
            python_verifiers=python_verifiers,
            burst_configs=burst_configs,
            sequence_configs=sequence_configs,
            spread_configs=spread_configs,
        )
        return RuleLoadReport(
            catalog=catalog,
            loaded=len(declarative_rules) + len(python_verifiers),
            skipped=skipped,
            errors=[],
            licensed_skipped=[],
        )

    def register_with_engine(self) -> RuleCatalog:
        """Load the rule catalog and attach it to the target engine."""
        report = self.load_all()
        if self.engine is not None and hasattr(self.engine, 'register_rule_catalog'):
            self.engine.register_rule_catalog(report.catalog)
        return report.catalog
