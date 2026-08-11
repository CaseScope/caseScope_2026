"""Shared confirmed-host evidence helpers for IOC extraction."""

from __future__ import annotations

import re
from typing import Any, List, Optional


HOST_COMPROMISE_PATTERNS = (
    re.compile(
        r"\bhost\s+(?P<host>[A-Za-z0-9][A-Za-z0-9._-]{1,254})\s+(?:was\s+|is\s+)?(?:confirmed\s+)?compromised\b",
        re.I,
    ),
    re.compile(
        r"\b(?P<host>[A-Za-z0-9][A-Za-z0-9._-]{1,254})\s+(?:(?:was|is)\s+)?(?:confirmed\s+)?compromised\b",
        re.I,
    ),
    re.compile(r"\battacker\s+compromised\s+(?P<host>[A-Za-z0-9][A-Za-z0-9._-]{1,254})\b", re.I),
    re.compile(r"\battacker\s+gained\s+access\s+to\s+(?P<host>[A-Za-z0-9][A-Za-z0-9._-]{1,254})\b", re.I),
)

HOST_COMPROMISE_STOPWORDS = {
    "affected",
    "attacker",
    "compromised",
    "confirmed",
    "is",
    "the",
    "was",
    "we",
}

GENERIC_HOST_NOUNS = {
    "asset",
    "assets",
    "client",
    "clients",
    "computer",
    "computers",
    "device",
    "devices",
    "endpoint",
    "endpoints",
    "host",
    "hosts",
    "machine",
    "machines",
    "node",
    "nodes",
    "server",
    "servers",
    "system",
    "systems",
    "workstation",
    "workstations",
}


def _host_value(candidate: Any) -> str:
    if isinstance(candidate, dict):
        candidate = candidate.get("value")
    return str(candidate or "").strip()


def _is_valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
        except ValueError:
            return False
        if num < 0 or num > 255:
            return False
    return True


def is_plausible_confirmed_host(host: str, is_known_candidate: bool = False) -> bool:
    """Require explicit named host evidence without promoting generic prose nouns."""
    token = (host or "").strip().strip(".,;:")
    lowered = token.lower()
    if not token or lowered in HOST_COMPROMISE_STOPWORDS or lowered in GENERIC_HOST_NOUNS:
        return False
    if _is_valid_ipv4(token):
        return False
    if is_known_candidate:
        return True
    if any(char.isdigit() for char in token):
        return True
    if any(char in token for char in ".-_"):
        return True
    return token.isupper() and len(token) >= 3


def extract_confirmed_compromised_hosts(
    report_text: str,
    candidate_hosts: Optional[List[Any]] = None,
) -> List[str]:
    """Extract explicitly compromised hosts without treating mere affected hosts as compromised."""
    candidates = {
        value.lower(): value
        for value in (_host_value(host) for host in candidate_hosts or [])
        if value
    }
    confirmed: List[str] = []
    seen = set()
    for pattern in HOST_COMPROMISE_PATTERNS:
        for match in pattern.finditer(report_text or ""):
            host = (match.group("host") or "").strip().strip(".,;:")
            if not host:
                continue
            normalized = host.lower()
            if not is_plausible_confirmed_host(host, normalized in candidates):
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            confirmed.append(candidates.get(normalized, host))
    return confirmed
