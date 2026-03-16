"""Shared IOC extraction contract used by runtime and training."""

from copy import deepcopy


IOC_CONTRACT_VERSION = "2026.03.15.1"

IOC_SYSTEM_PROMPT = """Extract ALL Indicators of Compromise from the security report. Return ONLY valid JSON - no markdown, no explanation, no analysis.

RULES:
1. Extract ONLY concrete indicators that appear in the report text.
2. Do NOT classify, score, or analyze. No MITRE, no severity, no attack type.
3. Empty arrays [] for sections with no data. Never invent values.
4. Defang: hxxp->http, [.]->., [:]->:, [@]->@, [://]->://
5. Skip Huntress portal URLs (tabinc.huntress.io).
6. Preserve command lines exactly as written.
7. Keep full subdomains and full Windows paths, including spaces.
8. Do not treat victim-only private IPs, remediation guidance, or analyst narrative as adversary IOCs unless the report explicitly presents them as indicators.

OUTPUT SCHEMA:
{
  "affected_hosts": ["..."],
  "affected_users": [{"username": "...", "sid": "..."}],
  "network_iocs": {
    "ipv4": [{"value": "...", "port": null, "context": "..."}],
    "ipv6": [{"value": "...", "context": "..."}],
    "domains": [{"value": "...", "context": "..."}],
    "urls": [{"value": "...", "context": "..."}],
    "cloudflare_tunnels": ["..."]
  },
  "file_iocs": {
    "hashes": [{"value": "...", "type": "md5|sha1|sha256", "filename": "...", "context": "..."}],
    "file_paths": [{"value": "...", "context": "..."}],
    "file_names": ["..."]
  },
  "process_iocs": {
    "commands": [{"full_command": "...", "executable": "...", "parent_process": "...", "user": "...", "pid": "..."}],
    "services": [{"name": "...", "path": "...", "action": "delete|create"}],
    "scheduled_tasks": [{"name": "...", "path": "...", "command": "..."}]
  },
  "persistence_iocs": {
    "registry": [{"key": "...", "value_name": "...", "value_data": "...", "action": "delete|create"}],
    "credential_theft_indicators": [{"registry_key": "...", "value": "...", "data": "..."}]
  },
  "authentication_iocs": {
    "compromised_users": [{"username": "...", "sid": "..."}],
    "created_users": [{"username": "...", "password": "...", "groups": ["..."]}],
    "passwords_observed": [{"username": "...", "password": "..."}]
  },
  "vulnerability_iocs": {
    "cves": ["CVE-XXXX-XXXXX"],
    "webshells": [{"path": "..."}]
  },
  "raw_artifacts": {
    "encoded_powershell": ["..."],
    "vnc_connection_ids": ["..."],
    "screenconnect_ids": ["..."]
  }
}"""

IOC_USER_PROMPT_TEMPLATE = (
    "Extract ALL IOCs from this Huntress EDR security report. "
    "Be thorough - capture everything:\n\n{}"
)

IOC_TRAINING_USER_PROMPTS = [
    IOC_USER_PROMPT_TEMPLATE,
    "Analyze this Huntress EDR incident report and return every IOC in the required JSON schema:\n\n{}",
    "Parse this Huntress incident report and extract all concrete IOCs using the required JSON shape:\n\n{}",
]

IOC_ALLOWED_TOP_LEVEL_KEYS = {
    "affected_hosts",
    "affected_users",
    "network_iocs",
    "file_iocs",
    "process_iocs",
    "persistence_iocs",
    "authentication_iocs",
    "vulnerability_iocs",
    "raw_artifacts",
}

IOC_EMPTY_EXTRACTION = {
    "affected_hosts": [],
    "affected_users": [],
    "network_iocs": {
        "ipv4": [],
        "ipv6": [],
        "domains": [],
        "urls": [],
        "cloudflare_tunnels": [],
    },
    "file_iocs": {
        "hashes": [],
        "file_paths": [],
        "file_names": [],
    },
    "process_iocs": {
        "commands": [],
        "services": [],
        "scheduled_tasks": [],
    },
    "persistence_iocs": {
        "registry": [],
        "credential_theft_indicators": [],
    },
    "authentication_iocs": {
        "compromised_users": [],
        "created_users": [],
        "passwords_observed": [],
    },
    "vulnerability_iocs": {
        "cves": [],
        "webshells": [],
    },
    "raw_artifacts": {
        "encoded_powershell": [],
        "vnc_connection_ids": [],
        "screenconnect_ids": [],
    },
}


def build_empty_ioc_extraction():
    """Return a fresh copy of the canonical IOC extraction shape."""
    return deepcopy(IOC_EMPTY_EXTRACTION)


def render_ioc_modelfile(base_model: str, adapter_path: str) -> str:
    """Render a Modelfile that uses the shared IOC prompt contract."""
    return (
        f"FROM {base_model}\n"
        f"ADAPTER {adapter_path}\n"
        "PARAMETER temperature 0.0\n"
        "PARAMETER top_p 0.9\n"
        "PARAMETER num_ctx 4096\n"
        "PARAMETER num_predict 4096\n"
        "PARAMETER stop \"<|im_end|>\"\n"
        f'SYSTEM """{IOC_SYSTEM_PROMPT}"""\n'
    )
