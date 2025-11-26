#!/usr/bin/env python3
"""
CaseScope AI Search Module (RAG Implementation) - V4 ATTACK PATTERNS
Provides semantic search using embeddings + LLM-powered question answering

Key features in V4:
- MITRE ATT&CK technique detection and mapping
- Attack chain analysis (find related events across kill chain)
- Multi-query expansion (search same concept multiple ways)
- Step-back prompting (abstract questions for broader context)
- Gap analysis (identify missing evidence in attack chain)
- All V3 features (exclusions, DFIR expansion, diversification)

Based on:
- MITRE ATT&CK Framework (https://attack.mitre.org/)
- RAG Survey paper (arXiv:2312.10997v5) techniques

Version: 4.0 (November 2025)
"""

import requests
import json
import logging
import re
import numpy as np
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Generator, Set
from collections import defaultdict
from logging_config import get_logger

logger = get_logger('app')

# Ollama API endpoints (for LLM generation)
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_GENERATE_URL = f"{OLLAMA_BASE_URL}/api/generate"

# Embedding model configuration
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

# LLM model for generating answers (uses your existing DFIR models on GPU)
DEFAULT_LLM_MODEL = "dfir-llama:latest"

# Lazy-loaded embedding model (loaded on first use, not at import)
_embedding_model = None
_embedding_model_load_attempted = False


# =============================================================================
# DFIR QUERY EXPANSION - Maps analyst concepts to actual indicators
# =============================================================================

DFIR_QUERY_EXPANSION = {
    'malware': [
        'powershell', 'encodedcommand', 'enc', 'base64', 'frombase64string',
        'invoke-expression', 'iex', 'downloadstring', 'downloadfile', 'webclient',
        'certutil', 'decode', 'urlcache', 'bitsadmin', 'mshta', 'wscript',
        'cscript', 'regsvr32', 'rundll32', 'msiexec',
        'hidden', 'bypass', 'noprofile', 'windowstyle',
        'shellcode', 'payload', 'dropper', 'loader',
        '4688', '1',
    ],
    
    'lateral movement': [
        'psexec', 'paexec', 'remcom', 'wmic', 'wmiexec', 'smbexec', 'wmiprvse',
        'winrm', 'winrs', 'enter-pssession', 'invoke-command', 'invoke-wmimethod',
        'mstsc', '3389', 'rdp', 'remote desktop',
        'admin$', 'c$', 'ipc$', 'net use',
        '4624', '4648', '5140', '5145', 'type 3', 'type 10',
    ],
    
    'persistence': [
        'schtasks', 'scheduled task', 'at.exe', 'taskschd',
        'currentversion\\run', 'runonce', 'userinit', 'shell',
        'sc create', 'sc config', 'new-service',
        'startup', 'appinit_dlls',
        '__eventfilter', 'commandlineeventconsumer', 'wmi subscription',
        'dll hijack', 'com hijack', 'image file execution',
        '4698', '4699', '4702', '7045', '4697', '13',
    ],
    
    'credential': [
        'lsass', 'mimikatz', 'sekurlsa', 'logonpasswords', 'wdigest',
        'sam', 'ntds', 'ntds.dit', 'dcsync', 'drsuapi', 'secretsdump',
        'kerberos', 'krbtgt', 'golden ticket', 'silver ticket', 'kerberoast',
        'procdump', 'comsvcs', 'minidump', 'sqldumper',
        'credential manager', 'vault', 'dpapi',
        '4768', '4769', '4776', '4672', '10',
    ],
    
    'exfiltration': [
        'upload', 'transfer', 'curl', 'wget', 'invoke-webrequest', 'invoke-restmethod',
        'ftp', 'sftp', 'scp', 'pscp', 'winscp',
        'onedrive', 'dropbox', 'gdrive', 'mega', 'pastebin', 'transfer.sh',
        'archive', 'zip', 'rar', '7z', 'compress-archive', 'tar',
        'dns tunnel', 'icmp', 'dnscat',
    ],
    
    'discovery': [
        'whoami', 'hostname', 'ipconfig', 'ifconfig', 'netstat', 'arp',
        'net user', 'net group', 'net localgroup', 'net share', 'net view', 'net session',
        'nltest', 'dsquery', 'get-aduser', 'get-adcomputer', 'get-adgroup',
        'systeminfo', 'tasklist', 'query user', 'quser', 'qprocess',
        'nslookup', 'dig', 'ping', 'tracert', 'pathping',
        'dir /s', 'tree', 'findstr', 'where',
    ],
    
    'defense evasion': [
        'disable', 'stop', 'tamper', 'defender', 'antivirus', 'av', 'realtime',
        'amsi', 'etw', 'clear-eventlog', 'wevtutil cl', 'remove-eventlog',
        'firewall', 'netsh advfirewall', 'set-mppreference',
        'process hollow', 'process inject', 'createremotethread',
        'timestomp', 'touch', 'attrib +h',
        '1102', '4688',
    ],
    
    'execution': [
        'powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta',
        'regsvr32', 'rundll32', 'msiexec', 'certutil', 'installutil',
        'wmic process call', 'invoke-wmimethod',
        'at.exe', 'schtasks /run',
        '4688', '1',
    ],
    
    'initial access': [
        'phishing', 'macro', 'vba', 'winword', 'excel', 'powerpnt',
        'outlook', 'msg', 'eml', 'attachment',
        'exploit', 'cve', 'vulnerability',
        'webshell', 'aspx', 'jsp', 'php',
    ],
}

# Question patterns to expansion categories
QUESTION_PATTERNS = [
    (r'malware|virus|trojan|ransomware|infection|compromis|malicious|suspicious|bad', 'malware'),
    (r'lateral|spread|pivot|move.*between|hop|remote\s+exec', 'lateral movement'),
    (r'persist|backdoor|maintain.*access|survive.*reboot|autorun|startup', 'persistence'),
    (r'credential|password|hash|ticket|authenticat|logon.*as|steal.*cred|dump|ntlm|brute|spray|failed.*logon|lockout', 'credential'),
    (r'exfil|steal.*data|data.*theft|upload|send.*out|leak|extract', 'exfiltration'),
    (r'recon|discover|enumerat|scan|map.*network|survey|footprint', 'discovery'),
    (r'evad|bypass|disable|hide|obfuscat|tamper|kill.*av|blind', 'defense evasion'),
    (r'execut|run|launch|spawn|start.*process|command|invoke', 'execution'),
    (r'initial|entry|phish|deliver|land|foothold', 'initial access'),
]


# =============================================================================
# COMMON NOISE TERMS - Suggestions for users
# =============================================================================

COMMON_EXCLUSIONS = {
    'security_tools': ['sentinelone', 'crowdstrike', 'defender', 'symantec', 'mcafee', 
                       'kaspersky', 'sophos', 'cylance', 'carbon black', 'cortex'],
    'backup_software': ['veeam', 'acronis', 'commvault', 'veritas', 'arcserve', 'backup exec'],
    'system_accounts': ['system', 'local service', 'network service', 'dwm-', 'umfd-'],
    'management_tools': ['sccm', 'intune', 'bigfix', 'tanium', 'altiris', 'landesk'],
    'monitoring': ['splunk', 'elastic', 'logstash', 'filebeat', 'winlogbeat', 'nxlog'],
}


# =============================================================================
# MITRE ATT&CK TECHNIQUE PATTERNS - Key techniques with detection indicators
# =============================================================================

MITRE_ATTACK_PATTERNS = {
    # EXECUTION
    'T1059.001': {
        'name': 'PowerShell',
        'tactic': 'Execution',
        'indicators': ['powershell', 'pwsh', 'encodedcommand', '-enc', 'bypass', 'hidden', 
                       'downloadstring', 'iex', 'invoke-expression', 'frombase64string'],
        'event_ids': ['4688', '4104', '1'],
    },
    'T1218': {
        'name': 'LOLBAS',
        'tactic': 'Execution',
        'indicators': ['certutil', 'bitsadmin', 'mshta', 'regsvr32', 'rundll32', 
                       'msiexec', 'installutil', 'cmstp', 'msbuild'],
        'event_ids': ['4688', '1'],
    },
    
    # PERSISTENCE
    'T1053.005': {
        'name': 'Scheduled Task',
        'tactic': 'Persistence',
        'indicators': ['schtasks', '/create', 'at.exe', 'taskschd'],
        'event_ids': ['4698', '4699', '4702'],
    },
    'T1543.003': {
        'name': 'Windows Service',
        'tactic': 'Persistence',
        'indicators': ['sc create', 'sc config', 'new-service', 'binpath'],
        'event_ids': ['7045', '4697'],
    },
    
    # CREDENTIAL ACCESS
    'T1003.001': {
        'name': 'LSASS Credential Dump',
        'tactic': 'Credential Access',
        'indicators': ['lsass', 'mimikatz', 'sekurlsa', 'procdump', 'comsvcs', 'minidump'],
        'event_ids': ['10', '4688', '1'],
    },
    'T1110': {
        'name': 'Brute Force / Password Spray',
        'tactic': 'Credential Access',
        'indicators': ['failed logon', 'bad password', 'account lockout'],
        'event_ids': ['4625', '4771', '4776'],
    },
    'T1558.003': {
        'name': 'Kerberoasting',
        'tactic': 'Credential Access',
        'indicators': ['kerberoast', 'tgs-req', 'serviceprincipalname', 'rc4-hmac'],
        'event_ids': ['4769'],
    },
    
    # LATERAL MOVEMENT
    'T1021.002': {
        'name': 'SMB/Admin Shares',
        'tactic': 'Lateral Movement',
        'indicators': ['admin$', 'c$', 'ipc$', 'net use', 'psexec', 'smbexec'],
        'event_ids': ['5140', '5145', '4624'],
    },
    'T1021.001': {
        'name': 'RDP',
        'tactic': 'Lateral Movement',
        'indicators': ['mstsc', 'rdp', '3389', 'remote desktop', 'termsrv'],
        'event_ids': ['4624', '4778', '4779', '1149'],
    },
    'T1550.002': {
        'name': 'Pass the Hash',
        'tactic': 'Lateral Movement',
        'indicators': ['pass the hash', 'pth', 'ntlm', 'sekurlsa::pth', 'overpass'],
        'event_ids': ['4624', '4648', '4672'],
    },
    'T1550.003': {
        'name': 'Pass the Ticket',
        'tactic': 'Lateral Movement',
        'indicators': ['pass the ticket', 'ptt', 'golden ticket', 'silver ticket', 'kirbi'],
        'event_ids': ['4768', '4769', '4770'],
    },
    
    # DEFENSE EVASION
    'T1070.001': {
        'name': 'Log Clearing',
        'tactic': 'Defense Evasion',
        'indicators': ['wevtutil cl', 'clear-eventlog', 'remove-eventlog'],
        'event_ids': ['1102', '104'],
    },
    'T1562.001': {
        'name': 'Disable Security Tools',
        'tactic': 'Defense Evasion',
        'indicators': ['set-mppreference', 'disablerealtimemonitoring', 'tamper', 
                       'sc stop', 'net stop', 'defender', 'antivirus'],
        'event_ids': ['4688', '1', '5001'],
    },
    
    # EXFILTRATION
    'T1048': {
        'name': 'Exfiltration',
        'tactic': 'Exfiltration',
        'indicators': ['curl', 'wget', 'invoke-webrequest', 'ftp', 'rclone', 
                       'mega', 'dropbox', 'transfer.sh'],
        'event_ids': ['4688', '1', '3'],
    },
}


# =============================================================================
# ATTACK CHAIN DEFINITIONS - Common attack sequences
# =============================================================================

ATTACK_CHAINS = {
    'credential_theft': {
        'name': 'Credential Theft Campaign',
        'stages': ['Execution', 'Credential Access', 'Lateral Movement'],
        'techniques': ['T1059.001', 'T1003.001', 'T1110', 'T1550.002', 'T1021.002'],
    },
    'ransomware': {
        'name': 'Ransomware Attack',
        'stages': ['Execution', 'Defense Evasion', 'Lateral Movement', 'Impact'],
        'techniques': ['T1059.001', 'T1218', 'T1562.001', 'T1021.002', 'T1486'],
    },
    'apt_intrusion': {
        'name': 'APT-Style Intrusion',
        'stages': ['Execution', 'Persistence', 'Credential Access', 'Lateral Movement', 'Exfiltration'],
        'techniques': ['T1059.001', 'T1053.005', 'T1543.003', 'T1003.001', 'T1021.002', 'T1048'],
    },
}


# =============================================================================
# MULTI-QUERY EXPANSION - Search same concept multiple ways
# =============================================================================

MULTI_QUERY_TEMPLATES = {
    'lateral movement': [
        "remote logon type 3 type 10 network authentication 4624",
        "psexec wmic winrm remote execution admin$ c$",
        "rdp mstsc 3389 remote desktop connection",
    ],
    'credential': [
        "lsass mimikatz sekurlsa credential dump procdump",
        "sam ntds.dit registry hive export",
        "kerberoast tgs ticket service principal 4769",
    ],
    'malware': [
        "powershell encodedcommand bypass hidden iex",
        "certutil bitsadmin urlcache decode download",
        "regsvr32 rundll32 mshta scrobj javascript",
    ],
    'persistence': [
        "schtasks scheduled task create 4698 4699",
        "service install sc create 7045 4697",
        "registry run key autorun startup",
    ],
    'pass the hash': [
        "4624 logon type 3 ntlm network",
        "4648 explicit credentials runas",
        "4672 special privileges admin logon",
    ],
    'password spray': [
        "4625 failed logon multiple accounts",
        "4771 kerberos pre-authentication failure",
        "authentication failure same source different users",
    ],
}


# =============================================================================
# STEP-BACK PROMPTS - Abstract questions for broader context
# =============================================================================

STEP_BACK_PROMPTS = {
    r'was there .*(malware|virus|infection)': 
        "What suspicious process executions with unusual command lines occurred?",
    r'did .*(attacker|adversary).*(lateral|move|spread)':
        "What remote authentication and share access events occurred?",
    r'any .*(persist|backdoor)':
        "What scheduled tasks, services, or registry modifications were made?",
    r'credential.*(theft|dump|steal|compromise)':
        "What processes accessed LSASS or sensitive registry hives?",
    r'(pass the hash|pth|ntlm)':
        "What network logons (type 3) with special privileges (4672) occurred?",
    r'(password spray|brute force)':
        "What patterns of failed authentication attempts exist?",
    r'(exfil|data theft)':
        "What archive creation and network transfer activity occurred?",
    r'account.*(compromise|takeover)':
        "What authentication anomalies and privilege changes occurred?",
}


def expand_query_for_dfir(question: str) -> List[str]:
    """
    Expand a natural language question into DFIR-relevant search terms.
    
    Example:
        "Do you see signs of malware?" 
        → ['powershell', 'encodedcommand', 'certutil', 'base64', ...]
    """
    expanded_terms = []
    question_lower = question.lower()
    
    # Check which categories match the question
    matched_categories = set()
    for pattern, category in QUESTION_PATTERNS:
        if re.search(pattern, question_lower):
            matched_categories.add(category)
    
    # Add expansion terms
    for category in matched_categories:
        if category in DFIR_QUERY_EXPANSION:
            expanded_terms.extend(DFIR_QUERY_EXPANSION[category])
    
    # Deduplicate
    seen = set()
    unique_terms = []
    for term in expanded_terms:
        if term.lower() not in seen:
            seen.add(term.lower())
            unique_terms.append(term)
    
    if matched_categories:
        logger.info(f"[AI_SEARCH] Query expansion matched categories: {matched_categories}")
        logger.info(f"[AI_SEARCH] Expanded to {len(unique_terms)} DFIR terms")
    
    return unique_terms[:30]


def expand_to_multi_query(question: str) -> List[str]:
    """
    Generate multiple query variations for the same question.
    Based on RAG Survey paper (arXiv:2312.10997v5) multi-query technique.
    """
    queries = [question]
    question_lower = question.lower()
    
    for pattern, variations in MULTI_QUERY_TEMPLATES.items():
        if pattern in question_lower or any(word in question_lower for word in pattern.split()):
            queries.extend(variations)
    
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for q in queries:
        if q.lower() not in seen:
            seen.add(q.lower())
            unique.append(q)
    
    return unique[:5]  # Limit to 5 variations


def get_step_back_question(question: str) -> Optional[str]:
    """
    Generate a higher-level question to retrieve broader context.
    Based on RAG Survey paper step-back prompting technique.
    """
    question_lower = question.lower()
    
    for pattern, step_back in STEP_BACK_PROMPTS.items():
        if re.search(pattern, question_lower):
            logger.info(f"[AI_SEARCH] Step-back question: {step_back}")
            return step_back
    
    return None


def identify_attack_techniques(events: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Analyze events and identify potential MITRE ATT&CK techniques.
    Returns dict mapping technique IDs to matching events.
    """
    technique_matches = defaultdict(list)
    
    for event in events:
        source = event.get('_source', event)
        search_blob = source.get('search_blob', '').lower()
        event_id = str(source.get('normalized_event_id', ''))
        
        # Get command line if available
        event_data = source.get('EventData', {})
        command_line = ''
        if isinstance(event_data, dict):
            command_line = (event_data.get('CommandLine', '') or 
                           event_data.get('command_line', '')).lower()
        
        for technique_id, pattern in MITRE_ATTACK_PATTERNS.items():
            # Check event IDs
            if event_id in pattern.get('event_ids', []):
                # Check indicators
                indicators = pattern.get('indicators', [])
                matching = [ind for ind in indicators 
                           if ind.lower() in search_blob or ind.lower() in command_line]
                
                if matching:
                    technique_matches[technique_id].append({
                        'event': event,
                        'matching_indicators': matching,
                        'technique_name': pattern['name'],
                        'tactic': pattern['tactic'],
                    })
    
    return dict(technique_matches)


def generate_attack_analysis(events: List[Dict]) -> str:
    """
    Generate MITRE ATT&CK analysis summary for LLM context.
    """
    technique_matches = identify_attack_techniques(events)
    
    if not technique_matches:
        return ""
    
    lines = ["## DETECTED ATTACK TECHNIQUES (MITRE ATT&CK)"]
    
    # Group by tactic
    by_tactic = defaultdict(list)
    for tid, matches in technique_matches.items():
        tactic = MITRE_ATTACK_PATTERNS[tid]['tactic']
        by_tactic[tactic].append((tid, matches))
    
    # Order tactics by kill chain
    tactic_order = ['Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion',
                    'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 
                    'Command and Control', 'Exfiltration']
    
    for tactic in tactic_order:
        if tactic in by_tactic:
            lines.append(f"\n**{tactic}:**")
            for tid, matches in by_tactic[tactic]:
                name = MITRE_ATTACK_PATTERNS[tid]['name']
                count = len(matches)
                indicators = set()
                for m in matches[:3]:
                    indicators.update(m['matching_indicators'][:2])
                lines.append(f"- {name} ({tid}): {count} events - indicators: {', '.join(list(indicators)[:4])}")
    
    return '\n'.join(lines)


# =============================================================================
# EMBEDDING MODEL
# =============================================================================

def _load_embedding_model():
    """Lazy-load the sentence-transformers embedding model"""
    global _embedding_model, _embedding_model_load_attempted
    
    if _embedding_model_load_attempted:
        return _embedding_model
    
    _embedding_model_load_attempted = True
    
    try:
        from sentence_transformers import SentenceTransformer
        
        logger.info(f"[AI_SEARCH] Loading embedding model: {EMBEDDING_MODEL_NAME}")
        _embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME, device='cpu')
        logger.info(f"[AI_SEARCH] Embedding model loaded successfully (CPU mode)")
        return _embedding_model
        
    except ImportError:
        logger.error("[AI_SEARCH] sentence-transformers not installed")
        return None
    except Exception as e:
        logger.error(f"[AI_SEARCH] Failed to load embedding model: {e}")
        return None


def check_embedding_model_available() -> Dict[str, Any]:
    """Check if the embedding model can be loaded"""
    try:
        import sentence_transformers
        model = _load_embedding_model()
        
        if model is not None:
            return {
                'available': True,
                'model': EMBEDDING_MODEL_NAME,
                'type': 'sentence-transformers',
                'device': 'cpu',
                'error': None
            }
        else:
            return {
                'available': False,
                'model': EMBEDDING_MODEL_NAME,
                'type': 'sentence-transformers',
                'device': 'cpu',
                'error': "Failed to load embedding model"
            }
            
    except ImportError:
        return {
            'available': False,
            'model': EMBEDDING_MODEL_NAME,
            'type': 'sentence-transformers',
            'device': 'cpu',
            'error': "sentence-transformers not installed"
        }
    except Exception as e:
        return {
            'available': False,
            'model': EMBEDDING_MODEL_NAME,
            'type': 'sentence-transformers',
            'device': 'cpu',
            'error': str(e)
        }


def get_embedding(text: str) -> Optional[np.ndarray]:
    """Generate embedding vector for text"""
    model = _load_embedding_model()
    if model is None:
        return None
    
    try:
        text = text[:2000] if len(text) > 2000 else text
        embedding = model.encode(text, convert_to_numpy=True, show_progress_bar=False)
        return embedding
        
    except Exception as e:
        logger.error(f"[AI_SEARCH] Error generating embedding: {e}")
        return None


def get_embeddings_batch(texts: List[str]) -> Optional[np.ndarray]:
    """Generate embeddings for multiple texts efficiently"""
    model = _load_embedding_model()
    if model is None:
        return None
    
    try:
        texts = [t[:2000] if len(t) > 2000 else t for t in texts]
        embeddings = model.encode(
            texts, 
            convert_to_numpy=True, 
            show_progress_bar=False,
            batch_size=32
        )
        return embeddings
        
    except Exception as e:
        logger.error(f"[AI_SEARCH] Error generating batch embeddings: {e}")
        return None


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Calculate cosine similarity between two vectors"""
    return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))


def cosine_similarity_batch(query_embedding: np.ndarray, embeddings: np.ndarray) -> np.ndarray:
    """Calculate cosine similarity between query and multiple embeddings"""
    query_norm = query_embedding / np.linalg.norm(query_embedding)
    embeddings_norm = embeddings / np.linalg.norm(embeddings, axis=1, keepdims=True)
    similarities = np.dot(embeddings_norm, query_norm)
    return similarities


# =============================================================================
# EVENT SUMMARY - Rich context for LLM
# =============================================================================

def create_event_summary(event: Dict[str, Any]) -> str:
    """
    Create DFIR-aware event summary with attack context.
    
    Key improvements:
    - Shows SIGMA rule NAME (not just "detected")
    - Shows event_title (human readable)
    - Structured key fields (process chain, command line)
    - Truncated intelligently
    """
    source = event.get('_source', event)
    parts = []
    
    # === HEADER ===
    timestamp = source.get('normalized_timestamp') or source.get('@timestamp', 'Unknown')
    computer = source.get('normalized_computer') or source.get('Computer', 'Unknown')
    event_id = source.get('normalized_event_id') or source.get('EventID', '?')
    event_title = source.get('event_title', '')
    
    header = f"**{timestamp}** | {computer} | Event {event_id}"
    if event_title:
        header += f" ({event_title})"
    parts.append(header)
    
    # === DETECTION FLAGS (critical for analyst) ===
    if source.get('is_tagged'):
        parts.append("⭐ **ANALYST TAGGED**")
    
    if source.get('has_sigma'):
        sigma_level = source.get('sigma_level', 'unknown').upper()
        sigma_rules = source.get('sigma_rules', [])
        if sigma_rules and isinstance(sigma_rules, list):
            rule_names = []
            for r in sigma_rules[:3]:
                if isinstance(r, dict):
                    rule_names.append(r.get('title') or r.get('name', 'Unknown rule'))
                elif isinstance(r, str):
                    rule_names.append(r)
            if rule_names:
                parts.append(f"⚠️ **SIGMA {sigma_level}**: {', '.join(rule_names)}")
            else:
                parts.append(f"⚠️ **SIGMA {sigma_level}**")
        else:
            parts.append(f"⚠️ **SIGMA {sigma_level}**")
    
    if source.get('has_ioc'):
        ioc_count = source.get('ioc_count', 1)
        ioc_matches = source.get('ioc_matches', [])
        if ioc_matches and isinstance(ioc_matches, list):
            match_vals = [str(m.get('value', ''))[:30] for m in ioc_matches[:2] if isinstance(m, dict)]
            if match_vals:
                parts.append(f"🎯 **IOC**: {', '.join(match_vals)}")
            else:
                parts.append(f"🎯 **IOC MATCH** ({ioc_count})")
        else:
            parts.append(f"🎯 **IOC MATCH** ({ioc_count})")
    
    # === KEY FORENSIC FIELDS ===
    event_data = source.get('EventData', {})
    if not event_data:
        event_data = source.get('Event', {}).get('EventData', {})
    if isinstance(event_data, str):
        event_data = {}
    
    if isinstance(event_data, dict):
        # User
        user = (event_data.get('TargetUserName') or 
                event_data.get('SubjectUserName') or 
                event_data.get('User'))
        if user and user not in ['-', '']:
            parts.append(f"User: {user}")
        
        # Process chain (CRITICAL for malware detection)
        process = (event_data.get('NewProcessName') or 
                   event_data.get('Image') or 
                   event_data.get('ProcessName'))
        parent = (event_data.get('ParentProcessName') or 
                  event_data.get('ParentImage'))
        if process:
            if parent:
                # Show the spawn chain
                parent_short = parent.split('\\')[-1] if '\\' in parent else parent
                process_short = process.split('\\')[-1] if '\\' in process else process
                parts.append(f"Process: {parent_short} → {process_short}")
            else:
                parts.append(f"Process: {process}")
        
        # Command line (THE KEY for detecting malware)
        cmdline = event_data.get('CommandLine') or event_data.get('command_line')
        if cmdline:
            parts.append(f"CommandLine: {cmdline[:600]}")
        
        # Network
        src_ip = event_data.get('IpAddress') or event_data.get('SourceNetworkAddress')
        if src_ip and src_ip not in ['-', '::1', '127.0.0.1', '', 'LOCAL']:
            parts.append(f"Source IP: {src_ip}")
        
        # Logon type
        logon_type = event_data.get('LogonType')
        if logon_type:
            logon_map = {
                '2': 'Interactive', '3': 'Network', '4': 'Batch',
                '5': 'Service', '7': 'Unlock', '10': 'RDP', '11': 'Cached'
            }
            lt_desc = logon_map.get(str(logon_type), '')
            parts.append(f"LogonType: {logon_type} ({lt_desc})" if lt_desc else f"LogonType: {logon_type}")
        
        # Target file/object
        target = (event_data.get('TargetFilename') or 
                  event_data.get('ObjectName') or 
                  event_data.get('ShareName'))
        if target:
            parts.append(f"Target: {target[:200]}")
        
        # Service/Task
        service = event_data.get('ServiceName')
        if service:
            parts.append(f"Service: {service}")
        task = event_data.get('TaskName')
        if task:
            parts.append(f"Task: {task}")
    
    # === FALLBACK to search_blob if no structured data ===
    if len(parts) <= 2:
        blob = source.get('search_blob', '')
        if blob:
            parts.append(f"Data: {blob[:1000]}")
    
    summary = '\n'.join(parts)
    
    # Truncate to fit context budget
    if len(summary) > 2500:
        summary = summary[:2500] + "..."
    
    return summary


# =============================================================================
# EXCLUSION EXTRACTION - Parse "excluding X and Y" from questions
# =============================================================================

def extract_keywords_with_exclusions(question: str) -> Tuple[List[str], List[str]]:
    """
    Extract keywords AND exclusion terms from question.
    
    Supports patterns like:
    - "malware excluding veeam and sentinelone"
    - "suspicious processes except defender"
    - "powershell activity but not from system32"
    - "lateral movement ignore service accounts"
    - "logon events without SYSTEM"
    - "skip backup software"
    - "filter out known good"
    
    Returns:
        (include_terms, exclude_terms)
    """
    question_lower = question.lower()
    exclude_terms = []
    
    # Patterns that indicate exclusion (order matters - more specific first)
    exclusion_patterns = [
        # "excluding X and Y and Z"
        r'exclud(?:e|ing)\s+(.+?)(?:\.|$)',
        # "except for X, Y, Z"
        r'except(?:\s+for)?\s+(.+?)(?:\.|$)',
        # "but not X or Y"
        r'but\s+not\s+(.+?)(?:\.|$)',
        # "ignoring X and Y"
        r'ignor(?:e|ing)\s+(.+?)(?:\.|$)',
        # "without X"
        r'without\s+(.+?)(?:\.|$)',
        # "not from X"
        r'not\s+(?:from|including|related\s+to|involving)\s+(.+?)(?:\.|$)',
        # "skip X"
        r'skip(?:ping)?\s+(.+?)(?:\.|$)',
        # "filter out X"
        r'filter(?:ing)?\s+out\s+(.+?)(?:\.|$)',
        # "remove X"
        r'remov(?:e|ing)\s+(.+?)(?:\.|$)',
        # "hide X"
        r'hid(?:e|ing)\s+(.+?)(?:\.|$)',
        # "no X"
        r'\bno\s+(.+?)(?:\s+events?|\s+activity|\s+logs?|$)',
    ]
    
    # Find all exclusion terms
    for pattern in exclusion_patterns:
        matches = re.findall(pattern, question_lower, re.IGNORECASE)
        for match in matches:
            # Clean up the match
            match = match.strip()
            # Remove trailing punctuation
            match = re.sub(r'[.,;:!?]+$', '', match)
            
            # Split on "and", "or", comma for multiple exclusions
            terms = re.split(r'\s+and\s+|\s+or\s+|\s*,\s*', match)
            for term in terms:
                term = term.strip()
                # Clean up common prefixes
                term = re.sub(r'^(?:any|all|the)\s+', '', term)
                if term and len(term) > 1 and term not in exclude_terms:
                    exclude_terms.append(term)
    
    # Build cleaned question (remove exclusion phrases)
    cleaned_question = question_lower
    for pattern in exclusion_patterns:
        cleaned_question = re.sub(pattern, ' ', cleaned_question, flags=re.IGNORECASE)
    
    # Also remove standalone exclusion keywords
    exclusion_keywords = ['excluding', 'except', 'ignore', 'ignoring', 'without', 
                          'skip', 'skipping', 'filter out', 'filtering out',
                          'but not', 'not from', 'remove', 'removing', 'hide', 'hiding']
    for kw in exclusion_keywords:
        cleaned_question = cleaned_question.replace(kw, ' ')
    
    # Extract include terms from cleaned question
    include_terms = extract_keywords_from_question(cleaned_question)
    
    # Remove any exclude terms that accidentally got into include terms
    exclude_lower = {e.lower() for e in exclude_terms}
    include_terms = [t for t in include_terms if t.lower() not in exclude_lower]
    
    # Also expand exclude terms to catch variations
    expanded_excludes = []
    for term in exclude_terms:
        expanded_excludes.append(term)
        # Add common variations
        if term.endswith('one'):  # sentinelone -> sentinel
            expanded_excludes.append(term[:-3])
        if not term.endswith('.exe') and ' ' not in term:
            expanded_excludes.append(f"{term}.exe")  # veeam -> veeam.exe
    
    exclude_terms = list(set(expanded_excludes))
    
    if exclude_terms:
        logger.info(f"[AI_SEARCH] Include terms: {include_terms}")
        logger.info(f"[AI_SEARCH] Exclude terms: {exclude_terms}")
    
    return include_terms, exclude_terms


# =============================================================================
# KEYWORD EXTRACTION
# =============================================================================

def extract_keywords_from_question(question: str) -> List[str]:
    """Extract search keywords from natural language question (cleaned of exclusions)"""
    
    preserve_terms = {
        'lateral movement', 'brute force', 'pass the hash', 'pass the ticket',
        'golden ticket', 'silver ticket', 'command line', 'scheduled task', 
        'privilege escalation', 'defense evasion', 'initial access',
        '4624', '4625', '4648', '4672', '4688', '4697', '4698', '4699',
        '5140', '5145', '1102', '7045', '7036',
    }
    
    stop_words = {
        'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
        'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
        'should', 'may', 'might', 'must', 'can', 'to', 'of', 'in', 'for',
        'on', 'with', 'at', 'by', 'from', 'as', 'into', 'through', 'during',
        'before', 'after', 'above', 'below', 'between', 'under', 'again',
        'then', 'once', 'here', 'there', 'when', 'where', 'why', 'how',
        'all', 'each', 'few', 'more', 'most', 'other', 'some', 'such',
        'no', 'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too',
        'very', 'just', 'and', 'but', 'if', 'or', 'because', 'until',
        'while', 'what', 'which', 'who', 'whom', 'this', 'that', 'these',
        'those', 'am', 'show', 'me', 'find', 'get', 'see', 'look', 'tell',
        'give', 'any', 'events', 'event', 'logs', 'log', 'please', 'i',
        'you', 'my', 'your', 'we', 'our', 'they', 'their', 'it', 'its',
        'summarize', 'summary', 'describe', 'explain', 'activity',
        'involved', 'happened', 'occurred', 'about', 'signs', 'evidence',
        'did', 'anything', 'something', 'everything',
    }
    
    question_lower = question.lower()
    keywords = []
    
    # Preserve multi-word DFIR terms
    for term in preserve_terms:
        if term in question_lower:
            keywords.append(term)
    
    # Extract quoted strings
    quoted = re.findall(r'"([^"]+)"', question)
    keywords.extend([q.lower() for q in quoted])
    
    # Extract usernames (e.g., rachel.b, admin.user)
    usernames = re.findall(r'\b([A-Za-z][A-Za-z0-9]*\.[A-Za-z]+)\b', question)
    for u in usernames:
        keywords.append(u.lower())
    
    # Extract individual words
    words = re.findall(r'[A-Za-z][A-Za-z0-9]*', question)
    for word in words:
        w = word.lower()
        if w not in stop_words and len(w) >= 3 and w not in keywords:
            keywords.append(w)
    
    # Deduplicate
    seen = set()
    unique = []
    for k in keywords:
        if k not in seen:
            seen.add(k)
            unique.append(k)
    
    return unique[:15]


# =============================================================================
# MAIN SEARCH FUNCTION
# =============================================================================

def semantic_search_events(
    opensearch_client,
    case_id: int,
    question: str,
    max_results: int = 20,
    include_sigma: bool = True,
    include_ioc: bool = True,
    boost_tagged: bool = True
) -> Tuple[List[Dict], str]:
    """
    Semantic search with DFIR query expansion, EXCLUSIONS, and diversification.
    
    Supports exclusion patterns:
    - "malware excluding veeam and sentinelone"
    - "suspicious activity but not defender"
    - "processes ignore backup software"
    
    Key features:
    1. Expands DFIR concepts (malware -> powershell, certutil, etc.)
    2. Searches search_blob field
    3. Diversifies results by event type
    4. Guarantees tagged events appear
    5. EXCLUDES user-specified noise (security tools, backup software, etc.)
    """
    index_name = f"case_{case_id}"
    
    # Step 1: Extract keywords WITH exclusions
    include_terms, exclude_terms = extract_keywords_with_exclusions(question)
    dfir_terms = expand_query_for_dfir(question)
    
    # Multi-query expansion (RAG Survey technique)
    multi_queries = expand_to_multi_query(question)
    if len(multi_queries) > 1:
        logger.info(f"[AI_SEARCH] Multi-query expansion: {len(multi_queries)} variations")
        # Extract keywords from additional queries
        for mq in multi_queries[1:]:
            mq_keywords = extract_keywords_from_question(mq)
            dfir_terms.extend(mq_keywords)
    
    # Step-back prompting for broader context
    step_back = get_step_back_question(question)
    if step_back:
        step_back_keywords = extract_keywords_from_question(step_back)
        dfir_terms.extend(step_back_keywords)
    
    # Combine include terms (user keywords + DFIR expansion + multi-query)
    all_include = include_terms + [t for t in dfir_terms if t.lower() not in {k.lower() for k in include_terms}]
    
    # Deduplicate
    seen = set()
    unique_include = []
    for t in all_include:
        if t.lower() not in seen:
            seen.add(t.lower())
            unique_include.append(t)
    all_include = unique_include
    
    if not all_include:
        logger.warning("[AI_SEARCH] No search terms extracted")
        return [], "Could not extract search terms from your question. Try being more specific."
    
    logger.info(f"[AI_SEARCH] Search terms: {all_include[:15]}...")
    if exclude_terms:
        logger.info(f"[AI_SEARCH] Excluding: {exclude_terms}")
    
    # Step 2: Build query with MUST_NOT for exclusions
    should_clauses = []
    must_not_clauses = []
    
    # Search fields - INCLUDE search_blob!
    search_fields = [
        "search_blob^1.5",
        "event_title^3",
        "event_description^2",
        "command_line^2",
        "process_name^1.5",
        "file_path",
        "username",
        "computer_name",
    ]
    
    # User's original keywords get high boost
    for term in include_terms[:10]:
        should_clauses.append({
            "multi_match": {
                "query": term,
                "fields": search_fields,
                "type": "best_fields",
                "fuzziness": "AUTO",
                "boost": 3.0
            }
        })
    
    # DFIR expansion terms get moderate boost
    for term in dfir_terms[:20]:
        should_clauses.append({
            "multi_match": {
                "query": term,
                "fields": search_fields,
                "type": "phrase_prefix" if ' ' in term else "best_fields",
                "boost": 1.5
            }
        })
    
    # EXCLUSIONS - must_not clauses
    for term in exclude_terms:
        must_not_clauses.append({
            "multi_match": {
                "query": term,
                "fields": search_fields,
                "type": "phrase" if ' ' in term else "best_fields"
            }
        })
    
    # Boost flagged events
    if boost_tagged:
        should_clauses.append({"term": {"is_tagged": {"value": True, "boost": 15.0}}})
    if include_sigma:
        should_clauses.append({"term": {"has_sigma": {"value": True, "boost": 8.0}}})
    if include_ioc:
        should_clauses.append({"term": {"has_ioc": {"value": True, "boost": 6.0}}})
    
    # Build query with exclusions
    query = {
        "bool": {
            "should": should_clauses,
            "minimum_should_match": 1
        }
    }
    
    # Add must_not only if we have exclusions
    if must_not_clauses:
        query["bool"]["must_not"] = must_not_clauses
    
    # Step 3: Execute search
    candidate_count = min(max_results * 8, 200)
    
    try:
        response = opensearch_client.search(
            index=index_name,
            body={
                "query": query,
                "size": candidate_count,
                "sort": [
                    {"_score": {"order": "desc"}},
                    {"normalized_timestamp": {"order": "desc"}}
                ],
                "_source": True,
                "timeout": "30s"
            },
            request_timeout=35
        )
        
        # Collect results with manual diversity (limit per event type)
        candidates = []
        event_ids_seen = set()
        event_type_counts = defaultdict(int)
        max_per_type = 5  # Limit events per event ID type for diversity
        
        for hit in response['hits']['hits']:
            event_id = hit['_id']
            event_type = str(hit['_source'].get('normalized_event_id', 'unknown'))
            
            # Skip if we've seen this exact event
            if event_id in event_ids_seen:
                continue
            
            # Apply diversity limit (but always include flagged events)
            is_flagged = (hit['_source'].get('is_tagged') or 
                         hit['_source'].get('has_sigma') or 
                         hit['_source'].get('has_ioc'))
            
            if not is_flagged and event_type_counts[event_type] >= max_per_type:
                continue
            
            candidates.append({
                '_id': event_id,
                '_index': hit['_index'],
                '_score': hit.get('_score', 0),
                '_source': hit['_source']
            })
            event_ids_seen.add(event_id)
            event_type_counts[event_type] += 1
        
        total_hits = response['hits']['total']['value'] if isinstance(response['hits']['total'], dict) else response['hits']['total']
        
        excluded_msg = f" (excluding: {', '.join(exclude_terms[:3])})" if exclude_terms else ""
        logger.info(f"[AI_SEARCH] Found {total_hits} total, diversified to {len(candidates)}{excluded_msg}")
        
    except Exception as e:
        logger.error(f"[AI_SEARCH] Search error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        
        # Fallback to simple search with exclusions
        try:
            fallback_query = {
                "bool": {
                    "should": [{"query_string": {"query": " OR ".join(all_include[:10]), "lenient": True}}],
                    "minimum_should_match": 1
                }
            }
            if must_not_clauses:
                fallback_query["bool"]["must_not"] = must_not_clauses
                
            response = opensearch_client.search(
                index=index_name,
                body={
                    "query": fallback_query,
                    "size": candidate_count,
                    "_source": True
                }
            )
            candidates = [
                {'_id': h['_id'], '_index': h['_index'], '_score': h.get('_score', 0), '_source': h['_source']}
                for h in response['hits']['hits']
            ]
            total_hits = len(candidates)
            event_ids_seen = {c['_id'] for c in candidates}
        except Exception as e2:
            logger.error(f"[AI_SEARCH] Fallback also failed: {e2}")
            return [], f"Search error: {str(e)}"
    
    # Step 4: Fetch tagged events from database (they may not match keywords)
    if boost_tagged:
        try:
            from models import TimelineTag
            from sqlalchemy import and_
            tagged_records = TimelineTag.query.filter(
                and_(TimelineTag.case_id == case_id, TimelineTag.index_name == index_name)
            ).limit(15).all()
            
            tagged_ids = [t.event_id for t in tagged_records]
            new_tagged_ids = [tid for tid in tagged_ids if tid not in event_ids_seen]
            
            if new_tagged_ids:
                tagged_response = opensearch_client.mget(index=index_name, body={"ids": new_tagged_ids})
                for doc in tagged_response.get('docs', []):
                    if doc.get('found') and doc['_id'] not in event_ids_seen:
                        # Check if tagged event matches exclusions
                        doc_source = doc.get('_source', {})
                        search_blob = doc_source.get('search_blob', '').lower()
                        excluded = any(ex.lower() in search_blob for ex in exclude_terms)
                        
                        if not excluded:
                            candidates.insert(0, {  # Insert at front
                                '_id': doc['_id'],
                                '_index': doc['_index'],
                                '_score': 100.0,
                                '_source': doc_source
                            })
                            event_ids_seen.add(doc['_id'])
                logger.info(f"[AI_SEARCH] Added tagged events from database")
        except Exception as e:
            logger.warning(f"[AI_SEARCH] Failed to fetch tagged events: {e}")
    
    if not candidates:
        return [], f"No events found matching your query{' (after exclusions)' if exclude_terms else ''}."
    
    # Step 5: Semantic re-ranking
    embedding_available = _load_embedding_model() is not None
    
    if embedding_available and len(candidates) > 1:
        try:
            question_embedding = get_embedding(question)
            if question_embedding is not None:
                summaries = [create_event_summary(c) for c in candidates]
                event_embeddings = get_embeddings_batch(summaries)
                
                if event_embeddings is not None:
                    similarities = cosine_similarity_batch(question_embedding, event_embeddings)
                    
                    os_scores = np.array([c['_score'] for c in candidates])
                    os_scores_norm = os_scores / (os_scores.max() + 0.001)
                    
                    # Base score: 50% keyword, 50% semantic
                    base_scores = 0.5 * os_scores_norm + 0.5 * similarities
                    
                    # Apply multiplicative boosts
                    combined_scores = np.zeros(len(candidates))
                    for i, c in enumerate(candidates):
                        src = c.get('_source', {})
                        boost = 1.0
                        
                        if src.get('is_tagged'):
                            boost *= 3.0  # Tagged = analyst verified important
                        if src.get('has_sigma'):
                            level = src.get('sigma_level', 'medium')
                            boost *= {'critical': 2.5, 'high': 2.0, 'medium': 1.5, 'low': 1.2}.get(level, 1.3)
                        if src.get('has_ioc'):
                            boost *= 1.5
                        
                        combined_scores[i] = base_scores[i] * boost
                    
                    ranked_idx = np.argsort(combined_scores)[::-1]
                    candidates = [candidates[i] for i in ranked_idx]
                    
                    for i, idx in enumerate(ranked_idx):
                        if i < len(candidates):
                            candidates[i]['_semantic_score'] = float(similarities[idx])
                            candidates[i]['_combined_score'] = float(combined_scores[idx])
                    
                    logger.info("[AI_SEARCH] Re-ranked with semantic similarity")
        except Exception as e:
            logger.warning(f"[AI_SEARCH] Semantic re-ranking failed: {e}")
    
    excluded_msg = f", excluded: {', '.join(exclude_terms[:3])}" if exclude_terms else ""
    explanation = f"Found {total_hits} events, showing top {min(len(candidates), max_results)} (diversified{excluded_msg})"
    return candidates[:max_results], explanation


# =============================================================================
# LLM ANSWER GENERATION
# =============================================================================

def generate_ai_answer(
    question: str,
    events: List[Dict],
    case_name: str,
    model: str = DEFAULT_LLM_MODEL,
    stream: bool = True
) -> Generator[str, None, None]:
    """Generate AI answer with MITRE ATT&CK-aware prompt"""
    
    MAX_CONTEXT_TOKENS = 6000
    CHARS_PER_TOKEN = 4
    
    event_context = []
    total_length = 0
    events_included = 0
    
    # Count flags for context
    tagged_count = sum(1 for e in events if e.get('_source', {}).get('is_tagged'))
    sigma_count = sum(1 for e in events if e.get('_source', {}).get('has_sigma'))
    ioc_count = sum(1 for e in events if e.get('_source', {}).get('has_ioc'))
    
    for i, event in enumerate(events[:15], 1):
        summary = create_event_summary(event)
        event_text = f"### Event {i}\n{summary}"
        
        est_tokens = len(event_text) // CHARS_PER_TOKEN
        if total_length + est_tokens > MAX_CONTEXT_TOKENS:
            break
        
        event_context.append(event_text)
        total_length += est_tokens
        events_included = i
    
    events_text = "\n\n".join(event_context)
    logger.info(f"[AI_SEARCH] LLM context: {events_included} events, ~{total_length} tokens")
    
    # Generate attack technique analysis
    attack_analysis = generate_attack_analysis(events)
    
    # Enhanced DFIR-aware prompt with MITRE ATT&CK
    prompt = f"""You are a senior Digital Forensics and Incident Response (DFIR) analyst with expertise in the MITRE ATT&CK framework. You are investigating a security incident.

## CASE: {case_name}

## ANALYST'S QUESTION
{question}

## EVIDENCE SUMMARY
- {events_included} events retrieved
- {tagged_count} analyst-tagged (⭐ = manually verified as important)
- {sigma_count} SIGMA detections (⚠️ = matches threat detection rule)
- {ioc_count} IOC matches (🎯 = matches known bad indicator)

{attack_analysis}

## MITRE ATT&CK QUICK REFERENCE
| Technique | Event IDs | What to Look For |
|-----------|-----------|------------------|
| T1059.001 PowerShell | 4688, 4104, 1 | -enc, bypass, downloadstring, iex |
| T1003.001 LSASS Dump | 10, 4688 | lsass access, procdump, mimikatz |
| T1021.002 SMB Lateral | 5140, 5145, 4624 | admin$, c$, type 3 logon |
| T1550.002 Pass the Hash | 4624, 4648, 4672 | type 3 + special privs |
| T1053.005 Sched Task | 4698, 4699 | schtasks /create |
| T1543.003 Service | 7045, 4697 | sc create, new-service |
| T1070.001 Log Clear | 1102 | Security log cleared |
| T1110 Password Spray | 4625, 4771 | Multiple failed logons |

## WINDOWS EVENT ID CHEAT SHEET
- **4624** = Successful logon (Type 2=Interactive, 3=Network, 10=RDP)
- **4625** = Failed logon (brute force/spray indicator)
- **4648** = Explicit credential logon (pass-the-hash indicator)
- **4672** = Special privileges assigned (admin logon)
- **4688** = Process created (look at CommandLine!)
- **4698** = Scheduled task created
- **5140/5145** = Network share accessed
- **7045** = Service installed
- **1102** = Security log cleared (CRITICAL - anti-forensics)
- **Sysmon 1** = Process with full command line
- **Sysmon 3** = Network connection
- **Sysmon 10** = Process access (credential dumping)

## EVIDENCE EVENTS

{events_text}

## YOUR ANALYSIS

Based on the evidence above, answer the analyst's question. Follow these guidelines:

1. **Map to MITRE ATT&CK**: Identify techniques you see (e.g., "This appears to be T1059.001 PowerShell execution")
2. **Reference Events**: Cite specific events (e.g., "Event 3 shows...")
3. **Identify Attack Chains**: Connect related events into a timeline/sequence
4. **Highlight Gaps**: Note what evidence is missing to confirm suspicions
5. **Prioritize Flagged Events**: ⭐ tagged events are analyst-verified important
6. **Be Specific**: Quote usernames, IPs, command lines, timestamps
7. **NO Fabrication**: Only cite what's in the events above

If you identify a potential attack pattern, structure your response as:
- **Attack Hypothesis**: What type of attack this might be
- **Supporting Evidence**: Events that support this hypothesis  
- **Missing Evidence**: What we'd need to confirm
- **Recommended Actions**: What to investigate next

YOUR ANALYSIS:
"""

    try:
        response = requests.post(
            OLLAMA_GENERATE_URL,
            json={
                "model": model,
                "prompt": prompt,
                "stream": stream,
                "options": {
                    "temperature": 0.3,
                    "num_ctx": 8192,
                    "num_thread": 8
                }
            },
            stream=stream,
            timeout=300
        )
        response.raise_for_status()
        
        if stream:
            for line in response.iter_lines():
                if line:
                    try:
                        chunk = json.loads(line.decode('utf-8'))
                        if 'response' in chunk:
                            yield chunk['response']
                        if chunk.get('done', False):
                            break
                    except json.JSONDecodeError:
                        continue
        else:
            data = response.json()
            yield data.get('response', '')
            
    except Exception as e:
        logger.error(f"[AI_SEARCH] LLM error: {e}")
        yield f"\n\n❌ Error: {str(e)}"


def ai_question_search(
    opensearch_client,
    case_id: int,
    case_name: str,
    question: str,
    model: str = DEFAULT_LLM_MODEL,
    max_events: int = 20
) -> Generator[Dict, None, None]:
    """Main entry point for AI Question feature"""
    
    yield {"type": "status", "data": "Analyzing question and searching for relevant events..."}
    
    events, explanation = semantic_search_events(
        opensearch_client, case_id, question, max_results=max_events
    )
    
    if not events:
        yield {"type": "error", "data": "No relevant events found. Try rephrasing or using DFIR terms like 'powershell', 'lateral movement', 'persistence'."}
        return
    
    yield {"type": "status", "data": f"Found {len(events)} relevant events. Generating analysis..."}
    yield {"type": "events", "data": events}
    
    for chunk in generate_ai_answer(question, events, case_name, model):
        yield {"type": "chunk", "data": chunk}
    
    yield {"type": "done", "data": "Analysis complete"}


# =============================================================================
# EXPORTS
# =============================================================================

def get_exclusion_suggestions() -> Dict[str, List[str]]:
    """
    Return common exclusion suggestions for UI hints.
    
    Usage in frontend: Show these as clickable suggestions when user types "excluding"
    """
    return COMMON_EXCLUSIONS


def get_attack_techniques() -> Dict[str, Dict]:
    """Return MITRE ATT&CK technique patterns for reference."""
    return MITRE_ATTACK_PATTERNS


def get_attack_chains() -> Dict[str, Dict]:
    """Return attack chain definitions for reference."""
    return ATTACK_CHAINS


__all__ = [
    # Core functions
    'check_embedding_model_available',
    'get_embedding',
    'get_embeddings_batch',
    'semantic_search_events',
    'generate_ai_answer',
    'ai_question_search',
    'create_event_summary',
    
    # Query expansion
    'expand_query_for_dfir',
    'expand_to_multi_query',
    'get_step_back_question',
    'extract_keywords_with_exclusions',
    
    # Attack pattern detection
    'identify_attack_techniques',
    'generate_attack_analysis',
    'get_attack_techniques',
    'get_attack_chains',
    
    # Helpers
    'get_exclusion_suggestions',
    
    # Constants
    'EMBEDDING_MODEL_NAME',
    'DEFAULT_LLM_MODEL',
    'DFIR_QUERY_EXPANSION',
    'COMMON_EXCLUSIONS',
    'MITRE_ATTACK_PATTERNS',
    'ATTACK_CHAINS',
    'MULTI_QUERY_TEMPLATES',
    'STEP_BACK_PROMPTS',
]
