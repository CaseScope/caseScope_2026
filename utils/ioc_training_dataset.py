#!/usr/bin/env python3
"""Build and validate the Huntress IOC extraction dataset."""

import hashlib
import importlib.util
import json
import os
import random
import re
from copy import deepcopy
from typing import Dict, Iterable, List, Tuple

_ioc_contract_spec = importlib.util.spec_from_file_location(
    "ioc_contract_shared",
    os.path.join(os.path.dirname(__file__), "ioc_contract.py"),
)
_ioc_contract = importlib.util.module_from_spec(_ioc_contract_spec)
_ioc_contract_spec.loader.exec_module(_ioc_contract)


SEED = 42
REPORTS_DIR = "/opt/casescope/example_reports/huntress"
TRAINING_DATA_DIR = "/opt/casescope/training_data"
REPORT_MANIFEST_FILE = os.path.join(TRAINING_DATA_DIR, "ioc_report_manifest.jsonl")
DRAFT_LABELS_FILE = os.path.join(TRAINING_DATA_DIR, "ioc_draft_labels.jsonl")
REVIEWED_LABELS_FILE = os.path.join(TRAINING_DATA_DIR, "ioc_reviewed_labels.jsonl")
TRAIN_FILE = os.path.join(TRAINING_DATA_DIR, "ioc_train.jsonl")
VALID_FILE = os.path.join(TRAINING_DATA_DIR, "ioc_valid.jsonl")
TEST_FILE = os.path.join(TRAINING_DATA_DIR, "ioc_test.jsonl")
RAW_SHAREGPT_FILE = os.path.join(TRAINING_DATA_DIR, "ioc_training_raw.jsonl")
DATASET_MANIFEST_FILE = os.path.join(TRAINING_DATA_DIR, "ioc_dataset_manifest.json")
IOC_CONTRACT_VERSION = _ioc_contract.IOC_CONTRACT_VERSION
IOC_SYSTEM_PROMPT = _ioc_contract.IOC_SYSTEM_PROMPT
IOC_TRAINING_USER_PROMPTS = _ioc_contract.IOC_TRAINING_USER_PROMPTS
build_empty_ioc_extraction = _ioc_contract.build_empty_ioc_extraction

WINDOWS_PATH_PATTERN = re.compile(
    r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]+"
)
HASH_PATTERN = {
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
}
SECTION_HEADER_PATTERN = re.compile(r"^[A-Za-z0-9 /()\[\]_-]+:?$")
BLOCK_LABEL_PATTERN = re.compile(
    r"^(Command|Executable|Process ID|Parent Process|User|Start Time):\s*(.*)$"
)
SID_PATTERN = re.compile(r"S-1-\d+(?:-\d+)+")
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}(?:\[\.\]|\.)?){3}\d{1,3}\b")
URL_PATTERN = re.compile(r"(?:hxxps?|https?)(?:\[://\]|://)[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(
    r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\[\.\]|\.)"
    r"(?:[a-zA-Z0-9-]{1,63}(?:\[\.\]|\.)?)+[a-zA-Z]{2,63}\b"
)
REPORT_USER_PATTERN = re.compile(
    r'user\s+"([^"]+)"\s*\((S-1-\d+(?:-\d+)+)\)', re.IGNORECASE
)
DOMAIN_USER_PATTERN = re.compile(r"Domain User:\s*([^\n]+)", re.IGNORECASE)
SCREENCONNECT_ID_PATTERN = re.compile(
    r"ScreenConnect Client \(([a-f0-9]{16})\)", re.IGNORECASE
)

CURATED_HOLDOUT_REPORTS = {
    "report2",
    "report20",
    "report36",
    "report42",
    "report46",
    "report50",
    "report63",
    "report72",
    "report75",
    "report64",
}

NEGATIVE_TEXTS = [
    "Weekly team update. Project status looks healthy. No security events were observed and there are no indicators to extract.",
    "Finance meeting notes for next quarter. Budget and hiring plans were discussed. No incident response content was included.",
    "Product release summary. Dashboard alignment and PDF export were improved. No security report data appears here.",
]

INVALID_HOSTS = {
    "details",
    "since",
    "that",
    "which",
    "none",
    "unknown",
    "system",
    "utc",
}
INVALID_DOMAIN_SUFFIXES = {
    ".exe",
    ".dll",
    ".hta",
    ".bat",
    ".cmd",
    ".ps1",
    ".js",
    ".vbs",
    ".msi",
    ".ini",
    ".log",
}
SKIP_DOMAINS = {
    "huntress.io",
    "tabinc.huntress.io",
    "windowsupdate.com",
    "microsoft.com",
    "google.com",
    "amazonaws.com",
}


def defang_text(text: str) -> str:
    clean = text.replace("hxxps://", "https://").replace("hxxp://", "http://")
    clean = clean.replace("hxxps[://]", "https://").replace("hxxp[://]", "http://")
    clean = re.sub(r"\[://\]", "://", clean)
    clean = re.sub(r"\[:\]", ":", clean)
    clean = re.sub(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)", ".", clean, flags=re.IGNORECASE)
    clean = re.sub(r"\[@\]|\[at\]|\(at\)", "@", clean, flags=re.IGNORECASE)
    return clean


def make_context(section_name: str, text: str = "") -> str:
    section_label = f"Source: {section_name}"
    if not text:
        return section_label
    snippet = " ".join(text.strip().split())
    snippet = snippet[:180]
    return f"{section_label} | {snippet}"


def normalize_section_name(name: str) -> str:
    """Normalize Huntress section headers to stable names."""
    clean = name.strip().rstrip(":").strip()
    clean = re.sub(r"\s*-\s*$", "", clean)
    return clean.strip()


def split_sections(report_text: str) -> Dict[str, str]:
    lines = report_text.splitlines()
    sections: Dict[str, List[str]] = {}
    current_name = "Full Report"
    current_body: List[str] = []
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        next_line = lines[i + 1].rstrip() if i + 1 < len(lines) else ""
        if (
            line
            and SECTION_HEADER_PATTERN.match(line)
            and next_line
            and set(next_line) <= {"-"}
            and len(next_line) >= 3
        ):
            sections[current_name] = current_body
            current_name = normalize_section_name(line)
            current_body = []
            i += 2
            continue
        current_body.append(lines[i])
        i += 1
    sections[current_name] = current_body
    return {
        name: "\n".join(body).strip()
        for name, body in sections.items()
        if "\n".join(body).strip()
    }


def read_reviewed_labels() -> Dict[str, Dict]:
    if not os.path.exists(REVIEWED_LABELS_FILE):
        return {}
    reviewed = {}
    with open(REVIEWED_LABELS_FILE, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            report_id = payload.get("report_id")
            extraction = payload.get("extraction")
            if report_id and extraction:
                reviewed[report_id] = extraction
    return reviewed


def ensure_reviewed_labels_file() -> None:
    if not os.path.exists(REVIEWED_LABELS_FILE):
        with open(REVIEWED_LABELS_FILE, "w", encoding="utf-8") as handle:
            handle.write("")


def normalize_path(path: str) -> str:
    cleaned = path.strip().strip('"').strip("'").rstrip(".,;)")
    cleaned = re.sub(
        r"\s+\+\s+(?:pid|sha256|name|parameters|value|remediation)(?::.*)?$",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = cleaned.replace("\\\\", "\\")
    return cleaned


def valid_windows_path(path: str) -> bool:
    if not path or not WINDOWS_PATH_PATTERN.fullmatch(path):
        return False
    lowered = path.lower()
    if lowered in {"c:\\program", "c:\\users", "c:\\windows"}:
        return False
    if len(path) > 3 and path[3] == " ":
        return False
    if path.count("(") != path.count(")"):
        return False
    return len(path) >= 8


def valid_host(hostname: str) -> bool:
    if not hostname:
        return False
    lowered = hostname.lower()
    if lowered in INVALID_HOSTS:
        return False
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}", hostname))


def valid_domain_candidate(domain: str) -> bool:
    """Filter executable-like or obviously non-domain tokens."""
    lowered = domain.lower()
    if any(lowered.endswith(suffix) for suffix in INVALID_DOMAIN_SUFFIXES):
        return False
    if "\\" in domain or "/" in domain:
        return False
    return True


def iter_windows_paths(text: str) -> Iterable[str]:
    clean = defang_text(text)
    for match in WINDOWS_PATH_PATTERN.finditer(clean):
        candidate = normalize_path(match.group(0))
        if valid_windows_path(candidate):
            yield candidate


def extract_affected_hosts(sections: Dict[str, str], full_text: str) -> List[str]:
    hosts = set()
    host_sections = [
        sections.get("Investigative Summary", ""),
        sections.get("Host Details", ""),
        sections.get("Lead Signal Information", ""),
    ]
    joined = "\n".join(host_sections) or full_text
    patterns = [
        re.compile(r'host\s+"([^"]+)"', re.IGNORECASE),
        re.compile(r'endpoint\s+"([^"]+)"', re.IGNORECASE),
        re.compile(r"Host Name:\s*([^\n]+)", re.IGNORECASE),
    ]
    for pattern in patterns:
        for match in pattern.finditer(joined):
            host = match.group(1).strip().strip('"')
            if valid_host(host):
                hosts.add(host)
    return sorted(hosts)


def extract_affected_users(sections: Dict[str, str], full_text: str) -> List[Dict[str, str]]:
    users = {}

    for match in REPORT_USER_PATTERN.finditer(full_text):
        username, sid = match.groups()
        users[(username.lower(), sid)] = {"username": username.strip(), "sid": sid}

    user_account = sections.get("User Account", "")
    user_match = re.search(r"User Account:\s*([^\n]+)", user_account, re.IGNORECASE)
    sid_match = SID_PATTERN.search(user_account)
    if user_match or sid_match:
        username = user_match.group(1).strip() if user_match else ""
        sid = sid_match.group(0) if sid_match else ""
        users[(username.lower(), sid)] = {"username": username, "sid": sid}

    for match in DOMAIN_USER_PATTERN.finditer(full_text):
        raw_user = match.group(1).strip()
        if raw_user and ":" not in raw_user:
            sid_match = SID_PATTERN.search(
                full_text[max(0, match.start() - 120): match.end() + 120]
            )
            sid = sid_match.group(0) if sid_match else ""
            username = raw_user.split("\\")[-1]
            users[(username.lower(), sid)] = {"username": username, "sid": sid}

    for match in re.finditer(r"^User:\s*(.+)$", full_text, re.MULTILINE):
        username = match.group(1).strip()
        if not username or ":" in username:
            continue
        sid_window = full_text[max(0, match.start() - 180): match.end() + 180]
        sid_match = SID_PATTERN.search(sid_window)
        sid = sid_match.group(0) if sid_match else ""
        users.setdefault((username.lower(), sid), {"username": username, "sid": sid})

    return sorted(
        [user for user in users.values() if user.get("username") or user.get("sid")],
        key=lambda item: (item.get("username", "").lower(), item.get("sid", "")),
    )


def extract_network_iocs(sections: Dict[str, str]) -> Dict[str, List[Dict[str, str]]]:
    domains = {}
    urls = {}
    ipv4 = {}

    for section_name, body in sections.items():
        clean = defang_text(body)
        body_lower = clean.lower()

        for match in URL_PATTERN.finditer(body):
            url = defang_text(match.group(0)).rstrip(".,;)")
            if any(skip in url for skip in SKIP_DOMAINS):
                continue
            urls[url.lower()] = {"value": url, "context": make_context(section_name, url)}
            host_match = re.search(r"https?://([^/:?#]+)", url, re.IGNORECASE)
            if host_match:
                host = host_match.group(1).strip().lower()
                if valid_domain_candidate(host) and not any(
                    host == skip or host.endswith(f".{skip}") for skip in SKIP_DOMAINS
                ):
                    domains[host] = {"value": host, "context": make_context(section_name, host)}

        explicit_patterns = [
            re.compile(
                r'(?:domain|website|communicat\w+\s+with|connect\w+\s+to|hosted\s+on|reaches?\s+out\s+to)\s+'
                r'(?:the\s+)?(?:following\s+)?(?:adversarial\s+)?(?:domain\s+)?["\']?([A-Za-z0-9.-]+\.[A-Za-z]{2,63})',
                re.IGNORECASE,
            ),
            re.compile(r"\bh=([A-Za-z0-9.-]+\.[A-Za-z]{2,63})", re.IGNORECASE),
        ]
        for pattern in explicit_patterns:
            for match in pattern.finditer(clean):
                domain = match.group(1).rstrip(".,;)")
                lowered = domain.lower()
                if any(lowered == skip or lowered.endswith(f".{skip}") for skip in SKIP_DOMAINS):
                    continue
                if not valid_domain_candidate(domain):
                    continue
                domains[lowered] = {"value": domain, "context": make_context(section_name, domain)}

        for match in IPV4_PATTERN.finditer(body):
            ip = defang_text(match.group(0))
            octets = ip.split(".")
            if len(octets) != 4 or not all(part.isdigit() for part in octets):
                continue
            nums = [int(part) for part in octets]
            if not all(0 <= num <= 255 for num in nums):
                continue
            is_private = (
                nums[0] == 10
                or (nums[0] == 172 and 16 <= nums[1] <= 31)
                or (nums[0] == 192 and nums[1] == 168)
            )
            explicit_indicator = (
                section_name in {"IOCs", "Lead Signal Information", "Investigative Summary"}
                and any(
                    token in body_lower
                    for token in ["adversarial", "communicat", "reaches out", "port", "ioc", "ip(s)"]
                )
            )
            if is_private and not explicit_indicator:
                continue
            ipv4[ip] = {"value": ip, "port": None, "context": make_context(section_name, ip)}

    cloudflare_tunnels = sorted(
        {url["value"] for url in urls.values() if "trycloudflare.com" in url["value"].lower()}
    )
    return {
        "ipv4": list(ipv4.values()),
        "ipv6": [],
        "domains": list(domains.values()),
        "urls": list(urls.values()),
        "cloudflare_tunnels": cloudflare_tunnels,
    }


def extract_hashes(full_text: str) -> List[Dict[str, str]]:
    hashes = []
    seen = set()
    clean = defang_text(full_text)
    for hash_type, pattern in HASH_PATTERN.items():
        for match in pattern.finditer(clean):
            value = match.group(0).lower()
            if value in seen:
                continue
            seen.add(value)
            window = clean[max(0, match.start() - 180): match.end() + 180]
            filename = ""
            name_match = re.search(
                r"([^\s\\/:*?\"<>|]+\.(?:exe|dll|js|ps1|msi|zip|hta|vbs|bat|cmd))",
                window,
                re.IGNORECASE,
            )
            if name_match:
                filename = name_match.group(1)
            hashes.append({"value": value, "type": hash_type, "filename": filename, "context": ""})
    return hashes


def extract_file_iocs(sections: Dict[str, str], full_text: str) -> Dict[str, List]:
    file_paths = []
    file_names = set()
    seen_paths = set()
    prioritized_sections = [
        "File System",
        "Footholds",
        "Processes",
        "Lead Signal Information",
        "Remediation Instructions",
        "Remediations",
        "Investigative Summary",
    ]
    ordered_sections = [
        (name, sections.get(name, "")) for name in prioritized_sections if sections.get(name)
    ]
    ordered_sections.extend(
        (name, body) for name, body in sections.items() if name not in prioritized_sections
    )

    for section_name, body in ordered_sections:
        for candidate in iter_windows_paths(body):
            key = candidate.lower()
            if key in seen_paths:
                continue
            seen_paths.add(key)
            file_paths.append({"value": candidate, "context": make_context(section_name, candidate)})
            basename = os.path.basename(candidate.replace("\\", "/"))
            if basename and "." in basename:
                file_names.add(basename)

    return {
        "hashes": extract_hashes(full_text),
        "file_paths": file_paths,
        "file_names": sorted(file_names, key=str.lower),
    }


def parse_process_blocks(section_name: str, body: str) -> List[Dict[str, str]]:
    commands = []
    current = {}
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = BLOCK_LABEL_PATTERN.match(line)
        if not match:
            continue
        label, value = match.groups()
        value = value.strip()
        if label == "Command" and current.get("full_command"):
            current["context"] = make_context(section_name, current.get("full_command", ""))
            commands.append(current)
            current = {}
        if label == "Command":
            current["full_command"] = value.strip('"')
        elif label == "Executable":
            current["executable"] = value
        elif label == "Parent Process" and ":" not in value:
            current["parent_process"] = value
        elif label == "User" and ":" not in value:
            current["user"] = value
        elif label == "Process ID":
            current["pid"] = value
    if current.get("full_command"):
        current["context"] = make_context(section_name, current.get("full_command", ""))
        commands.append(current)
    return commands


def extract_process_iocs(sections: Dict[str, str]) -> Dict[str, List[Dict[str, str]]]:
    commands = []
    seen_cmds = set()
    for section_name in ("Processes", "Lead Signal Information", "Investigative Summary"):
        body = sections.get(section_name, "")
        if not body:
            continue
        for item in parse_process_blocks(section_name, body):
            value = item["full_command"].lower()
            if value in seen_cmds:
                continue
            seen_cmds.add(value)
            commands.append(item)

    services = {}
    tasks = {}
    for body in sections.values():
        for match in re.finditer(r"Delete Service\s*-\s*name:\s*(.+?)(?:\n|$)", body, re.IGNORECASE):
            name = match.group(1).strip()
            services[name.lower()] = {"name": name, "path": "", "action": "delete"}
        for match in re.finditer(r"Service Name:\s*(.+?)(?:\n|$)", body, re.IGNORECASE):
            name = match.group(1).strip()
            services.setdefault(name.lower(), {"name": name, "path": "", "action": "create"})
        for match in re.finditer(r"Delete Scheduled Task\s*-\s*name:\s*(.+?)(?:\n|$)", body, re.IGNORECASE):
            name = match.group(1).strip()
            tasks[name.lower()] = {"name": name, "path": "", "command": ""}
    return {
        "commands": commands,
        "services": list(services.values()),
        "scheduled_tasks": list(tasks.values()),
    }


def extract_registry_iocs(sections: Dict[str, str]) -> List[Dict[str, str]]:
    entries = {}
    for section_name, body in sections.items():
        for match in re.finditer(
            r"Registry Key:\s*([^\n]+)(?:\nRegistry Value:\s*([^\n]+))?(?:\nRegistry Data:\s*([^\n]+))?",
            body,
            re.IGNORECASE,
        ):
            key, value_name, value_data = match.groups()
            key = key.strip()
            entries[(key.lower(), (value_name or "").lower())] = {
                "key": key,
                "value_name": (value_name or "").strip(),
                "value_data": (value_data or "").strip(),
                "action": "create",
                "context": make_context(section_name, key),
            }
        for match in re.finditer(
            r"Delete Registry (?:Key|Value)\s*-\s*key:\s*(.+?)(?:\s*\+\s*value:\s*(.+?))?(?:\n|$)",
            body,
            re.IGNORECASE,
        ):
            key, value_name = match.groups()
            key = key.strip()
            entries[(key.lower(), (value_name or "").lower())] = {
                "key": key,
                "value_name": (value_name or "").strip(),
                "value_data": "",
                "action": "delete",
                "context": make_context(section_name, key),
            }
    return list(entries.values())


def extract_raw_artifacts(full_text: str) -> Dict[str, List[str]]:
    clean = defang_text(full_text)
    encoded = sorted(set(re.findall(r"-(?:enc|EncodedCommand)\s+([A-Za-z0-9+/=]{20,})", clean)))
    screenconnect_ids = sorted({match.group(1) for match in SCREENCONNECT_ID_PATTERN.finditer(clean)})
    return {
        "encoded_powershell": encoded,
        "vnc_connection_ids": [],
        "screenconnect_ids": screenconnect_ids,
    }


def extract_cves(full_text: str) -> List[str]:
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", full_text, re.IGNORECASE)))


def build_draft_extraction(report_text: str) -> Dict:
    sections = split_sections(report_text)
    extraction = build_empty_ioc_extraction()
    extraction["affected_hosts"] = extract_affected_hosts(sections, report_text)
    extraction["affected_users"] = extract_affected_users(sections, report_text)
    extraction["network_iocs"] = extract_network_iocs(sections)
    extraction["file_iocs"] = extract_file_iocs(sections, report_text)
    extraction["process_iocs"] = extract_process_iocs(sections)
    extraction["persistence_iocs"]["registry"] = extract_registry_iocs(sections)
    extraction["authentication_iocs"]["compromised_users"] = deepcopy(extraction["affected_users"])
    extraction["vulnerability_iocs"]["cves"] = extract_cves(report_text)
    extraction["raw_artifacts"] = extract_raw_artifacts(report_text)
    return validate_extraction(extraction, report_text)


def validate_extraction(extraction: Dict, report_text: str) -> Dict:
    clean = deepcopy(extraction)
    clean["affected_hosts"] = [host for host in clean["affected_hosts"] if valid_host(host)]

    valid_paths = []
    for item in clean["file_iocs"]["file_paths"]:
        value = normalize_path(item.get("value", ""))
        if valid_windows_path(value):
            item["value"] = value
            valid_paths.append(item)
    clean["file_iocs"]["file_paths"] = valid_paths
    clean["file_iocs"]["file_names"] = sorted(
        {
            name
            for name in clean["file_iocs"]["file_names"]
            if name and "." in name and ":" not in name
        },
        key=str.lower,
    )

    valid_users = []
    for user in clean["affected_users"]:
        username = user.get("username", "").strip()
        sid = user.get("sid", "").strip()
        if username or sid:
            valid_users.append({"username": username, "sid": sid})
    clean["affected_users"] = valid_users
    clean["authentication_iocs"]["compromised_users"] = deepcopy(valid_users)

    validated_commands = []
    for cmd in clean["process_iocs"]["commands"]:
        parent = cmd.get("parent_process", "")
        user = cmd.get("user", "")
        if ":" in parent:
            parent = ""
        if ":" in user:
            user = ""
        validated_commands.append(
            {
                "full_command": cmd.get("full_command", ""),
                "executable": normalize_path(cmd.get("executable", "")) if cmd.get("executable") else "",
                "parent_process": normalize_path(parent) if parent else "",
                "user": user,
                "pid": cmd.get("pid", ""),
            }
        )
    clean["process_iocs"]["commands"] = [cmd for cmd in validated_commands if cmd.get("full_command")]

    if not clean["affected_users"]:
        fallback_users = []
        for match in re.finditer(r"^User:\s*(.+)$", report_text, re.MULTILINE):
            username = match.group(1).strip()
            if username and ":" not in username:
                sid_window = report_text[max(0, match.start() - 180): match.end() + 180]
                sid_match = SID_PATTERN.search(sid_window)
                fallback_users.append({"username": username, "sid": sid_match.group(0) if sid_match else ""})
        clean["affected_users"] = fallback_users[:1]
        clean["authentication_iocs"]["compromised_users"] = deepcopy(clean["affected_users"])

    return clean


def make_sample(report_text: str, extraction_json: Dict, prompt_idx: int) -> Dict:
    return {
        "conversations": [
            {"from": "system", "value": IOC_SYSTEM_PROMPT},
            {
                "from": "human",
                "value": IOC_TRAINING_USER_PROMPTS[prompt_idx].format(report_text),
            },
            {
                "from": "gpt",
                "value": json.dumps(extraction_json, indent=2, sort_keys=True),
            },
        ]
    }


def stable_split_bucket(report_id: str) -> int:
    digest = hashlib.sha256(f"{SEED}:{report_id}".encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % 100


def build_negative_samples() -> Tuple[List[Dict], List[Dict], List[Dict]]:
    train = []
    valid = []
    test = []
    for idx, text in enumerate(NEGATIVE_TEXTS):
        sample = make_sample(
            text, build_empty_ioc_extraction(), idx % len(IOC_TRAINING_USER_PROMPTS)
        )
        if idx == 0:
            train.append(sample)
        elif idx == 1:
            valid.append(sample)
        else:
            test.append(sample)
    return train, valid, test


def count_iocs(extraction: Dict) -> int:
    total = 0
    total += len(extraction.get("affected_hosts", []))
    total += len(extraction.get("affected_users", []))
    for values in extraction.get("network_iocs", {}).values():
        total += len(values)
    for values in extraction.get("file_iocs", {}).values():
        total += len(values)
    for values in extraction.get("process_iocs", {}).values():
        total += len(values)
    for values in extraction.get("persistence_iocs", {}).values():
        total += len(values)
    for values in extraction.get("authentication_iocs", {}).values():
        total += len(values)
    for values in extraction.get("vulnerability_iocs", {}).values():
        total += len(values)
    for values in extraction.get("raw_artifacts", {}).values():
        total += len(values)
    return total


def write_jsonl(path: str, rows: Iterable[Dict]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def build_dataset() -> Dict:
    random.seed(SEED)
    os.makedirs(TRAINING_DATA_DIR, exist_ok=True)
    ensure_reviewed_labels_file()
    reviewed_labels = read_reviewed_labels()

    report_files = sorted(
        os.path.join(REPORTS_DIR, name)
        for name in os.listdir(REPORTS_DIR)
        if name.endswith(".txt")
    )

    manifest_rows = []
    draft_rows = []
    raw_sharegpt_rows = []
    train_rows = []
    valid_rows = []
    test_rows = []

    for filepath in report_files:
        with open(filepath, "r", encoding="utf-8", errors="replace") as handle:
            report_text = handle.read().strip()
        report_name = os.path.basename(filepath)
        report_id = os.path.splitext(report_name)[0]
        sections = split_sections(report_text)
        draft = build_draft_extraction(report_text)
        final_extraction = reviewed_labels.get(report_id, draft)

        manifest_rows.append(
            {
                "report_id": report_id,
                "relative_path": os.path.relpath(filepath, REPORTS_DIR),
                "section_names": list(sections.keys()),
                "text": report_text,
            }
        )
        draft_rows.append(
            {
                "report_id": report_id,
                "relative_path": os.path.relpath(filepath, REPORTS_DIR),
                "ioc_count": count_iocs(draft),
                "reviewed_override": report_id in reviewed_labels,
                "extraction": draft,
            }
        )

        prompt_indexes = [0, 1]
        if count_iocs(final_extraction) >= 8:
            prompt_indexes.append(2)

        target_rows = train_rows
        bucket = stable_split_bucket(report_id)
        if report_id in CURATED_HOLDOUT_REPORTS:
            target_rows = test_rows
        elif bucket < 18:
            target_rows = valid_rows

        for prompt_idx in prompt_indexes:
            sample = make_sample(report_text, final_extraction, prompt_idx)
            raw_sharegpt_rows.append(sample)
            target_rows.append(sample)

    negative_train, negative_valid, negative_test = build_negative_samples()
    train_rows.extend(negative_train)
    valid_rows.extend(negative_valid)
    test_rows.extend(negative_test)

    write_jsonl(REPORT_MANIFEST_FILE, manifest_rows)
    write_jsonl(DRAFT_LABELS_FILE, draft_rows)
    write_jsonl(RAW_SHAREGPT_FILE, raw_sharegpt_rows)
    write_jsonl(TRAIN_FILE, train_rows)
    write_jsonl(VALID_FILE, valid_rows)
    write_jsonl(TEST_FILE, test_rows)

    dataset_manifest = {
        "contract_version": IOC_CONTRACT_VERSION,
        "seed": SEED,
        "reports_dir": REPORTS_DIR,
        "report_count": len(report_files),
        "curated_holdout_reports": sorted(CURATED_HOLDOUT_REPORTS),
        "train_samples": len(train_rows),
        "valid_samples": len(valid_rows),
        "test_samples": len(test_rows),
        "files": {
            "report_manifest": REPORT_MANIFEST_FILE,
            "draft_labels": DRAFT_LABELS_FILE,
            "reviewed_labels": REVIEWED_LABELS_FILE,
            "train": TRAIN_FILE,
            "valid": VALID_FILE,
            "test": TEST_FILE,
            "raw_sharegpt": RAW_SHAREGPT_FILE,
        },
    }
    with open(DATASET_MANIFEST_FILE, "w", encoding="utf-8") as handle:
        json.dump(dataset_manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")

    return dataset_manifest


def main() -> None:
    manifest = build_dataset()
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
