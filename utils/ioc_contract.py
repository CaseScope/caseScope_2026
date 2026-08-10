"""Shared IOC extraction contract used by runtime and training."""

from copy import deepcopy

from utils.ai_training import build_role_system_prompt


IOC_CONTRACT_VERSION = "2026.03.15.1"

IOC_SYSTEM_PROMPT = build_role_system_prompt('ioc_extraction', """Extract ALL Indicators of Compromise from the security report. Return ONLY valid JSON - no markdown, no explanation, no analysis.

RULES:
1. Extract ONLY concrete indicators that appear in the report text.
2. Do NOT classify, score, or analyze. No MITRE, no severity, no attack type.
3. Empty arrays [] for sections with no data. Never invent values.
4. Normalize/refang: hxxp->http, [.]->., [:]->:, [@]->@, [://]->:// while preserving raw values where fields support them.
5. Skip analyst-platform or case-portal URLs that point back to the reporting platform.
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
}""")

IOC_USER_PROMPT_TEMPLATE = (
    "Extract ALL IOCs from this security report. "
    "Be thorough, but keep only concrete indicators that appear in the text:\n\n{}"
)

IOC_SEMANTIC_TASK_PROMPTS = {
    "semantic_identity_and_auth": (
        "This is one specialized pass in a multi-pass IOC extraction pipeline. Extract ONLY "
        "identity and authentication evidence from the report sections below. Other passes handle "
        "network, file, process, service, scheduled-task, registry, and persistence evidence.\n\n"
        "Preserve distinctions: affected endpoint users are not confirmed compromised accounts "
        "unless the evidence explicitly says the attacker authenticated as or misused that account. "
        "Use null for unknown optional values. Preserve raw_value and normalized_value when they "
        "differ. Include an evidence excerpt for every item.\n\n"
        "Return valid JSON only using this task schema:\n"
        "{{"
        "\"affected_users\":[{{\"username\":\"string\",\"sid\":\"string|null\",\"evidence\":\"string\"}}],"
        "\"credential_exposure_users\":[{{\"username\":\"string\",\"sid\":\"string|null\",\"evidence\":\"string\"}}],"
        "\"compromised_users\":[{{\"username\":\"string\",\"sid\":\"string|null\",\"evidence\":\"string\"}}],"
        "\"created_users\":[{{\"username\":\"string\",\"sid\":\"string|null\",\"password\":\"string|null\",\"groups\":[],\"evidence\":\"string\"}}],"
        "\"passwords_observed\":[{{\"username\":\"string|null\",\"password\":\"string\",\"evidence\":\"string\"}}]"
        "}}\n\n{}"
    ),
    "semantic_process_relationships": (
        "This is one specialized pass in a multi-pass IOC extraction pipeline. Extract ONLY "
        "process, command, executable, parent-process, service, and scheduled-task evidence from "
        "the report sections below. Other passes handle unrelated IOC classes.\n\n"
        "Use null for unknown optional values. A supported task or service name must be preserved "
        "even when path or command is unknown. Preserve raw_value and normalized_value when they "
        "differ. Include an evidence excerpt and origin for every item; remediation targets must "
        "be marked as remediation or reported_finding, not observed execution.\n\n"
        "Return valid JSON only using this task schema:\n"
        "{{"
        "\"commands\":[{{\"full_command\":\"string|null\",\"executable\":\"string|null\",\"parent_process\":\"string|null\",\"user\":\"string|null\",\"pid\":\"string|null\",\"evidence\":\"string\",\"evidence_origin\":\"observed|reported_finding|remediation\"}}],"
        "\"services\":[{{\"name\":\"string|null\",\"path\":\"string|null\",\"action\":\"create|delete|null\",\"evidence\":\"string\",\"evidence_origin\":\"observed|reported_finding|remediation\"}}],"
        "\"scheduled_tasks\":[{{\"name\":\"string|null\",\"path\":\"string|null\",\"command\":\"string|null\",\"action\":\"create|delete|null\",\"evidence\":\"string\",\"evidence_origin\":\"observed|reported_finding|remediation\"}}]"
        "}}\n\n{}"
    ),
    "semantic_persistence_actions": (
        "This is one specialized pass in a multi-pass IOC extraction pipeline. Extract ONLY "
        "persistence, registry, web shell, and credential-theft mechanism evidence from the report "
        "sections below. Other passes handle identity and process relationships.\n\n"
        "Use null for unknown optional values. Preserve raw_value and normalized_value when they "
        "differ. Include an evidence excerpt and origin for every item.\n\n"
        "Return valid JSON only using this task schema:\n"
        "{{"
        "\"registry\":[{{\"key\":\"string|null\",\"value_name\":\"string|null\",\"value_data\":\"string|null\",\"action\":\"create|delete|null\",\"evidence\":\"string\",\"evidence_origin\":\"observed|reported_finding|remediation\"}}],"
        "\"credential_theft_indicators\":[{{\"registry_key\":\"string|null\",\"value\":\"string|null\",\"data\":\"string|null\",\"evidence\":\"string\",\"evidence_origin\":\"observed|reported_finding|remediation\"}}],"
        "\"webshells\":[{{\"path\":\"string|null\",\"evidence\":\"string\",\"evidence_origin\":\"observed|reported_finding|remediation\"}}]"
        "}}\n\n{}"
    ),
}

IOC_SEMANTIC_SYSTEM_PROMPT = build_role_system_prompt('ioc_extraction', """You are running one stateless, specialized IOC extraction pass.

Return ONLY valid JSON matching the task-specific schema supplied in the user prompt.
Extract only evidence assigned to that task. Never invent values. Use null for unknown optional fields.
Every returned item must be grounded in the supplied source text and include concise evidence where the schema permits it.
Do not include markdown, explanations, analysis, or unrelated IOC classes.""")

IOC_SEMANTIC_TASK_SCHEMAS = {
    "semantic_identity_and_auth": {
        "affected_users": [],
        "credential_exposure_users": [],
        "compromised_users": [],
        "created_users": [],
        "passwords_observed": [],
    },
    "semantic_process_relationships": {
        "commands": [],
        "services": [],
        "scheduled_tasks": [],
    },
    "semantic_persistence_actions": {
        "registry": [],
        "credential_theft_indicators": [],
        "webshells": [],
    },
}

IOC_TRAINING_USER_PROMPTS = [
    IOC_USER_PROMPT_TEMPLATE,
    "Analyze this security incident report and return every IOC in the required JSON schema:\n\n{}",
    "Parse this analyst security report and extract all concrete IOCs using the required JSON shape:\n\n{}",
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
        "credential_exposure_users": [],
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


def render_ioc_audit_modelfile(base_model: str, adapter_path: str, audit_system_prompt: str) -> str:
    """Render a Modelfile for chunk-plus-candidate audit fine-tuning."""
    return (
        f"FROM {base_model}\n"
        f"ADAPTER {adapter_path}\n"
        "PARAMETER temperature 0.0\n"
        "PARAMETER top_p 0.9\n"
        "PARAMETER num_ctx 4096\n"
        "PARAMETER num_predict 2048\n"
        "PARAMETER stop \"<|im_end|>\"\n"
        f'SYSTEM """{audit_system_prompt}"""\n'
    )
