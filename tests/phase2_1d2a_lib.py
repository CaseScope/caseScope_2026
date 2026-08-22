"""Phase 2.1D2A measurement helpers.

Predicate inventory, safe ILIKE prefilter derivation, and EXPLAIN parsing.
No production readers or index DDL live here.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple


SEARCH_BLOB_PRED_RE = re.compile(
    r"(?P<expr>lower\s*\(\s*search_blob\s*\)|search_blob)\s+"
    r"(?P<not>NOT\s+)?(?P<op>ILIKE|LIKE)\s+"
    r"'(?P<pat>(?:\\'|[^'])*)'",
    re.IGNORECASE,
)
HAS_TOKEN_RE = re.compile(
    r"(?P<fn>hasTokenCaseInsensitive|hasToken)\s*\(\s*(?P<expr>search_blob)(?:\s*,|\))",
    re.IGNORECASE,
)
POSITION_RE = re.compile(
    r"(?P<fn>positionCaseInsensitive|position)\s*\(\s*(?:e\.)?(?P<expr>search_blob)\s*,",
    re.IGNORECASE,
)
MATCH_RE = re.compile(
    r"\bmatch\s*\(\s*(?:lower\s*\(\s*)?(?:e\.)?search_blob",
    re.IGNORECASE,
)
ALNUM_RUN_RE = re.compile(r"[A-Za-z0-9]+")

# Measured on deployed ClickHouse 26.7.3.19: search_blob ILIKE '%TOK%'
# uses idx_search_blob_text (__text_index_*_ilike_*) only when TOK is a
# splitByNonAlpha token of length >= 4. Length 1-3 never selected the text index.
TEXT_INDEX_ILIKE_MIN_ALNUM = 4

CONFIG_ALL = "ALL"
CONFIG_NO_NGRAM = "NO_NGRAM"
CONFIG_NO_TOKEN = "NO_TOKEN"
CONFIG_NO_BLOOMS = "NO_BLOOMS"
IGNORE_SETTINGS = {
    CONFIG_ALL: {},
    CONFIG_NO_NGRAM: {"ignore_data_skipping_indices": "idx_search_ngram"},
    CONFIG_NO_TOKEN: {"ignore_data_skipping_indices": "idx_search_token"},
    CONFIG_NO_BLOOMS: {"ignore_data_skipping_indices": "idx_search_ngram,idx_search_token"},
}


def unescape_sql_string(pat: str) -> str:
    return pat.replace("''", "'")


def like_literal_segments(pattern: str) -> List[str]:
    """Split a ClickHouse LIKE pattern into guaranteed literal segments.

    Unescaped % and _ are wildcards. Backslash is treated as a literal character
    (ClickHouse default LIKE, no standard SQL ESCAPE in these production predicates).
    """
    segments = []
    buf = []
    for ch in pattern:
        if ch in "%_":
            if buf:
                segments.append("".join(buf))
                buf = []
        else:
            buf.append(ch)
    if buf:
        segments.append("".join(buf))
    return segments


def alnum_runs(text: str) -> List[str]:
    return ALNUM_RUN_RE.findall(text or "")


def longest_guaranteed_alnum(pattern: str) -> Optional[str]:
    runs: List[str] = []
    for segment in like_literal_segments(pattern):
        runs.extend(alnum_runs(segment))
    if not runs:
        return None
    return max(runs, key=lambda item: (len(item), item))


def extract_predicates_from_sql(sql: str) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    if not sql:
        return found
    for match in SEARCH_BLOB_PRED_RE.finditer(sql):
        expr = re.sub(r"\s+", "", match.group("expr")).lower()
        if expr.startswith("lower("):
            expr_class = "lower(search_blob)"
        else:
            expr_class = "search_blob"
        op = match.group("op").upper()
        negated = bool(match.group("not"))
        pat = unescape_sql_string(match.group("pat"))
        found.append(
            {
                "expr": expr_class,
                "negated": negated,
                "op": op,
                "pattern": pat,
                "sql": match.group(0),
            }
        )
    for match in HAS_TOKEN_RE.finditer(sql):
        found.append(
            {
                "expr": "search_blob",
                "negated": False,
                "op": match.group("fn"),
                "pattern": None,
                "sql": match.group(0),
            }
        )
    for match in POSITION_RE.finditer(sql):
        found.append(
            {
                "expr": "search_blob",
                "negated": False,
                "op": match.group("fn"),
                "pattern": None,
                "sql": match.group(0),
            }
        )
    for match in MATCH_RE.finditer(sql):
        found.append(
            {
                "expr": "search_blob",
                "negated": False,
                "op": "match",
                "pattern": None,
                "sql": match.group(0),
            }
        )
    return found


def predicate_shape(item: Dict[str, Any]) -> str:
    expr = item["expr"]
    op = item["op"]
    negated = "NOT " if item.get("negated") else ""
    if item.get("pattern") is None:
        return f"{expr} {negated}{op}(...)"
    return f"{expr} {negated}{op} '{item['pattern']}'"


def derive_prefilter(item: Dict[str, Any]) -> Dict[str, Any]:
    """Return a candidate redundant prefilter, or NO_SAFE_TEXT_PREFILTER.

    ORIGINAL always remains authoritative. The prefilter must be a logical
    superset: ORIGINAL_MATCH => PREFILTER_MATCH.
    """
    op = str(item.get("op") or "").upper()
    pattern = item.get("pattern")
    negated = bool(item.get("negated"))
    expr = item.get("expr")
    result = {
        "original": predicate_shape(item),
        "original_sql": item.get("sql"),
        "prefilter_sql": None,
        "candidate_sql": None,
        "alnum_run": None,
        "alnum_len": 0,
        "text_index_usable_length": False,
        "classification": "NO_SAFE_TEXT_PREFILTER",
        "reason": "",
    }
    if negated:
        result["reason"] = "NOT LIKE/ILIKE is not a positive match set; a narrower prefilter is unsafe"
        return result
    if op not in {"LIKE", "ILIKE"} or pattern is None:
        result["reason"] = f"{op} is not a LIKE/ILIKE substring predicate"
        return result
    if expr not in {"search_blob", "lower(search_blob)"}:
        result["reason"] = f"unsupported expression {expr}"
        return result

    run = longest_guaranteed_alnum(pattern)
    if not run:
        result["reason"] = "no guaranteed ASCII alphanumeric substring in the LIKE pattern"
        return result

    # ILIKE of a guaranteed literal alnum run is a superset of:
    # - search_blob LIKE '%...run...%' (exact-case match implies case-insensitive)
    # - search_blob ILIKE '%...run...%'
    # - lower(search_blob) LIKE '%...run...%'
    prefilter = f"search_blob ILIKE '%{run}%'"
    original_sql = item.get("sql") or predicate_shape(item)
    result.update(
        {
            "alnum_run": run,
            "alnum_len": len(run),
            "text_index_usable_length": len(run) >= TEXT_INDEX_ILIKE_MIN_ALNUM,
            "prefilter_sql": prefilter,
            "candidate_sql": f"({prefilter} AND {original_sql})",
            "classification": (
                "SAFE_TEXT_PREFILTER"
                if len(run) >= TEXT_INDEX_ILIKE_MIN_ALNUM
                else "SAFE_LOGICAL_PREFILTER_NO_TEXT_PRUNE"
            ),
            "reason": (
                f"every original match contains alphanumeric run {run!r}; "
                f"ILIKE of that run is a superset. Deployed 26.7.3.19 text-index "
                f"ILIKE utilization requires length >= {TEXT_INDEX_ILIKE_MIN_ALNUM}."
            ),
        }
    )
    return result


def wrap_like_sql(sql: str, *, require_text_usable: bool = False) -> str:
    """Rewrite LIKE/ILIKE search_blob predicates with redundant ILIKE prefilters."""

    def _sub(match: re.Match) -> str:
        item = {
            "expr": (
                "lower(search_blob)"
                if match.group("expr").lower().startswith("lower")
                else "search_blob"
            ),
            "negated": bool(match.group("not")),
            "op": match.group("op").upper(),
            "pattern": unescape_sql_string(match.group("pat")),
            "sql": match.group(0),
        }
        derived = derive_prefilter(item)
        candidate = derived.get("candidate_sql")
        if not candidate:
            return match.group(0)
        if require_text_usable and not derived.get("text_index_usable_length"):
            return match.group(0)
        return candidate

    return SEARCH_BLOB_PRED_RE.sub(_sub, sql)


def collect_pattern_rule_predicates(rules: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for rule in rules:
        rule_id = str(rule.get("id") or "")
        rule_name = str(rule.get("name") or rule_id)
        blobs: List[Tuple[str, str]] = []
        if rule.get("detection_query"):
            blobs.append(("detection_query", str(rule["detection_query"])))
        anchor = rule.get("anchor") or {}
        if anchor.get("conditions"):
            blobs.append(("anchor.conditions", str(anchor["conditions"])))
        for supporting in rule.get("supporting") or []:
            if supporting.get("conditions"):
                blobs.append(
                    (
                        f"supporting.{supporting.get('name')}.conditions",
                        str(supporting["conditions"]),
                    )
                )
        for location, sql in blobs:
            for pred in extract_predicates_from_sql(sql):
                shape = predicate_shape(pred)
                bucket = grouped.setdefault(
                    shape,
                    {
                        "shape": shape,
                        "expr": pred["expr"],
                        "op": pred["op"],
                        "negated": pred["negated"],
                        "pattern": pred["pattern"],
                        "sql": pred["sql"],
                        "rules": [],
                        "locations": [],
                    },
                )
                ref = {"id": rule_id, "name": rule_name, "location": location}
                if ref not in bucket["rules"]:
                    bucket["rules"].append(ref)
                if location not in bucket["locations"]:
                    bucket["locations"].append(location)
    out = []
    for item in grouped.values():
        item["prefilter"] = derive_prefilter(item)
        item["rule_ids"] = sorted({ref["id"] for ref in item["rules"] if ref["id"]})
        out.append(item)
    out.sort(key=lambda row: (row["expr"], row["op"], row.get("pattern") or "", row["shape"]))
    return out


def parse_explain_indexes(text: str) -> Dict[str, Any]:
    blocks = []
    current = None
    prewhere = None
    read_line = None
    direct_text = False
    for raw in (text or "").splitlines():
        line = raw.strip()
        if "__text_index_" in line:
            direct_text = True
            prewhere = line
        if "Prewhere filter column" in line:
            prewhere = line
        if line.startswith("Parts:") and "|" in line and "Granules:" in line:
            read_line = line
        if line.startswith("Name:"):
            current = {"name": line.split(":", 1)[1].strip()}
            blocks.append(current)
            continue
        if current is None:
            continue
        if line.startswith("Description:"):
            current["description"] = line.split(":", 1)[1].strip()
        elif line.startswith("Parts:") and "parts" not in current:
            current["parts"] = line.split(":", 1)[1].strip()
        elif line.startswith("Granules:") and "granules" not in current:
            current["granules"] = line.split(":", 1)[1].strip()
            before, after = _split_granules(current["granules"])
            current["granules_before"] = before
            current["granules_after"] = after
            current["pruned"] = (
                before is not None and after is not None and after < before
            )
    names = [block["name"] for block in blocks]
    by_name = {block["name"]: block for block in blocks}

    def _pruned(name: str) -> bool:
        block = by_name.get(name) or {}
        return bool(block.get("pruned"))

    return {
        "skip_names": names,
        "blocks": blocks,
        "prewhere": prewhere,
        "read": read_line,
        "direct_text_index": direct_text,
        "idx_search_blob_text": "idx_search_blob_text" in names,
        "idx_search_ngram": "idx_search_ngram" in names,
        "idx_search_token": "idx_search_token" in names,
        "text_pruned": _pruned("idx_search_blob_text"),
        "ngram_pruned": _pruned("idx_search_ngram"),
        "token_pruned": _pruned("idx_search_token"),
        "text_granules": (by_name.get("idx_search_blob_text") or {}).get("granules"),
        "ngram_granules": (by_name.get("idx_search_ngram") or {}).get("granules"),
        "token_granules": (by_name.get("idx_search_token") or {}).get("granules"),
    }


def _split_granules(text: Optional[str]) -> Tuple[Optional[int], Optional[int]]:
    if not text or "/" not in text:
        return None, None
    left, right = text.split("/", 1)
    try:
        after = int(left.strip())
        before = int(right.strip())
        return before, after
    except ValueError:
        return None, None


def percentile(values: Sequence[float], pct: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(float(v) for v in values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * (pct / 100.0)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    weight = rank - low
    return ordered[low] * (1.0 - weight) + ordered[high] * weight


def classify_consumer(path: str) -> str:
    lowered = path.replace("\\", "/").lower()
    if "/tests/" in lowered or lowered.startswith("tests/"):
        return "test-only"
    if lowered.startswith("docs/") or "/docs/" in lowered:
        return "historical-docs"
    if (
        lowered.startswith("bin/")
        or lowered.startswith("scripts/")
        or "/migrations/" in lowered
        or lowered.startswith("migrations/")
    ):
        return "offline-admin"
    production_required = (
        "routes/hunting",
        "models/pattern_rules.py",
        "models/network_log.py",
        "utils/chat_tools.py",
        "utils/forensic_chat_sources.py",
    )
    if any(token in lowered for token in production_required):
        return "production-required"
    background = (
        "utils/ioc_artifact_tagger.py",
        "utils/sigma_converter.py",
        "utils/noise_keywords.py",
        "utils/candidate_extractor.py",
        "utils/mitre_attack_sync.py",
        "models/rag.py",
        "utils/pattern_check_definitions.py",
        "utils/incident_storyline_detector.py",
        "utils/mitre_procedure_rules.py",
        "utils/graph_query.py",
    )
    if any(token in lowered for token in background):
        return "background-derivation"
    if "/parsers/" in lowered or lowered.startswith("parsers/"):
        return "ingest-write"
    return "other"


REPRESENTATIVE_PREDICATES: Tuple[Dict[str, Any], ...] = (
    {
        "id": "like_ntlm",
        "pred": "search_blob LIKE '%NTLM%'",
        "consumer": "models/pattern_rules.py pass_the_hash",
    },
    {
        "id": "like_ntlmssp",
        "pred": "search_blob LIKE '%NtLmSsp%'",
        "consumer": "models/pattern_rules.py pass_the_hash",
    },
    {
        "id": "like_kerberos",
        "pred": "search_blob LIKE '%Kerberos%'",
        "consumer": "models/pattern_rules.py pass_the_ticket",
    },
    {
        "id": "like_admin_share",
        "pred": "search_blob LIKE '%ADMIN$%'",
        "consumer": "models/pattern_rules.py psexec / smb",
    },
    {
        "id": "like_admin_unc",
        "pred": "search_blob LIKE '%\\\\ADMIN$%'",
        "consumer": "models/pattern_rules.py smb_admin_shares",
    },
    {
        "id": "like_ipc",
        "pred": "search_blob LIKE '%IPC$%'",
        "consumer": "models/pattern_rules.py psexec",
    },
    {
        "id": "like_c_share",
        "pred": "search_blob LIKE '%C$%'",
        "consumer": "models/pattern_rules.py smb / file copy",
    },
    {
        "id": "like_c_unc",
        "pred": "search_blob LIKE '%\\\\C$%'",
        "consumer": "models/pattern_rules.py smb_admin_shares",
    },
    {
        "id": "like_ipc_unc",
        "pred": "search_blob LIKE '%\\\\IPC$%'",
        "consumer": "models/pattern_rules.py smb_admin_shares",
    },
    {
        "id": "like_0x17",
        "pred": "search_blob LIKE '%0x17%'",
        "consumer": "models/pattern_rules.py kerberoasting RC4",
    },
    {
        "id": "like_rc4",
        "pred": "search_blob LIKE '%RC4%'",
        "consumer": "models/pattern_rules.py kerberoasting RC4",
    },
    {
        "id": "like_txt",
        "pred": "search_blob LIKE '%TXT%'",
        "consumer": "models/pattern_rules.py dns_exfiltration",
    },
    {
        "id": "like_0x1010",
        "pred": "search_blob LIKE '%0x1010%'",
        "consumer": "models/pattern_rules.py lsass access mask",
    },
    {
        "id": "like_sedebug",
        "pred": "search_blob LIKE '%SeDebugPrivilege%'",
        "consumer": "models/pattern_rules.py privilege",
    },
    {
        "id": "like_winrm",
        "pred": "search_blob LIKE '%WinRM%'",
        "consumer": "models/pattern_rules.py winrm",
    },
    {
        "id": "like_wsmprovhost",
        "pred": "search_blob LIKE '%wsmprovhost%'",
        "consumer": "models/pattern_rules.py winrm",
    },
    {
        "id": "like_dcom",
        "pred": "search_blob LIKE '%DCOM%'",
        "consumer": "models/pattern_rules.py dcom",
    },
    {
        "id": "like_powershell",
        "pred": "search_blob LIKE '%powershell%'",
        "consumer": "models/pattern_rules.py service image",
    },
    {
        "id": "like_cmd_c",
        "pred": "search_blob LIKE '%cmd /c%'",
        "consumer": "models/pattern_rules.py service image",
    },
    {
        "id": "like_temp",
        "pred": "search_blob LIKE '%\\\\Temp\\\\%'",
        "consumer": "models/pattern_rules.py temp path",
    },
    {
        "id": "like_preauth",
        "pred": "search_blob LIKE '%PreAuth%0%'",
        "consumer": "models/pattern_rules.py asrep roasting",
    },
    {
        "id": "like_cpassword",
        "pred": "search_blob LIKE '%cpassword%'",
        "consumer": "models/pattern_rules.py gpp",
    },
    {
        "id": "or_ntlm_ssp",
        "pred": "(search_blob LIKE '%NTLM%' OR search_blob LIKE '%NtLmSsp%')",
        "consumer": "models/pattern_rules.py pass_the_hash detection_query",
    },
    {
        "id": "or_admin_ipc",
        "pred": "(search_blob LIKE '%ADMIN$%' OR search_blob LIKE '%IPC$%')",
        "consumer": "models/pattern_rules.py psexec supporting",
    },
    {
        "id": "or_rc4",
        "pred": "(search_blob LIKE '%0x17%' OR search_blob LIKE '%RC4%')",
        "consumer": "models/pattern_rules.py kerberoasting",
    },
    {
        "id": "or_admin_shares",
        "pred": (
            "(search_blob LIKE '%\\\\C$%' OR search_blob LIKE '%\\\\ADMIN$%' "
            "OR search_blob LIKE '%\\\\IPC$%')"
        ),
        "consumer": "models/pattern_rules.py smb_admin_shares",
    },
    {
        "id": "lower_guid",
        "pred": "lower(search_blob) LIKE '%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%'",
        "consumer": "models/pattern_rules.py dcsync guid",
    },
    {
        "id": "lower_lsass",
        "pred": "lower(search_blob) LIKE '%lsass%'",
        "consumer": "models/pattern_rules.py lsass",
    },
    {
        "id": "lower_mimikatz",
        "pred": "lower(search_blob) LIKE '%mimikatz%'",
        "consumer": "models/pattern_rules.py credential dump",
    },
    {
        "id": "not_password_policy",
        "pred": "search_blob NOT LIKE '%PasswordPolicy%'",
        "consumer": "models/pattern_rules.py password search exclusion",
    },
)


CAPABILITY_PROBES: Tuple[str, ...] = (
    "search_blob LIKE '%NTLM%'",
    "search_blob ILIKE '%NTLM%'",
    "search_blob LIKE '%ADMIN%'",
    "search_blob ILIKE '%ADMIN%'",
    "search_blob LIKE '%Kerberos%'",
    "search_blob ILIKE '%Kerberos%'",
    "search_blob LIKE '%ADMIN$%'",
    "search_blob ILIKE '%ADMIN$%'",
)


FULL_DETECTION_RULE_IDS: Tuple[str, ...] = (
    "pass_the_hash",
    "pass_the_ticket",
    "smb_admin_shares",
    "psexec_remote_service",
    "kerberoasting",
    "dcsync_attack",
    "dns_exfiltration",
)
