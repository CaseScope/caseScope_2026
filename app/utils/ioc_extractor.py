"""
IOC Extractor - Regex Fallback
Extracts Indicators of Compromise when LLM is unavailable

Usage:
    from utils.ioc_extractor import extract_iocs
    
    results = extract_iocs(text)
"""

import re
import json
from typing import Dict, List, Set
from dataclasses import dataclass, field


@dataclass
class IOCResults:
    """Container for extracted IOCs"""
    # Network
    ip_v4: Set[str] = field(default_factory=set)
    ip_v6: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    urls: Set[str] = field(default_factory=set)
    emails: Set[str] = field(default_factory=set)
    user_agents: Set[str] = field(default_factory=set)
    
    # File
    md5: Set[str] = field(default_factory=set)
    sha1: Set[str] = field(default_factory=set)
    sha256: Set[str] = field(default_factory=set)
    sha512: Set[str] = field(default_factory=set)
    ssdeep: Set[str] = field(default_factory=set)
    imphash: Set[str] = field(default_factory=set)
    file_names: Set[str] = field(default_factory=set)
    file_paths: Set[str] = field(default_factory=set)
    
    # Host
    hostnames: Set[str] = field(default_factory=set)
    registry_keys: Set[str] = field(default_factory=set)
    registry_values: Set[str] = field(default_factory=set)
    command_lines: Set[str] = field(default_factory=set)
    process_names: Set[str] = field(default_factory=set)
    service_names: Set[str] = field(default_factory=set)
    scheduled_tasks: Set[str] = field(default_factory=set)
    mutexes: Set[str] = field(default_factory=set)
    named_pipes: Set[str] = field(default_factory=set)
    
    # Identity
    usernames: Set[str] = field(default_factory=set)
    sids: Set[str] = field(default_factory=set)
    
    # Threat Intel
    cves: Set[str] = field(default_factory=set)
    mitre_attack: Set[str] = field(default_factory=set)
    
    # Crypto
    btc_addresses: Set[str] = field(default_factory=set)
    eth_addresses: Set[str] = field(default_factory=set)
    xmr_addresses: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict:
        """Convert to JSON-serializable dict"""
        return {
            "extraction_summary": {
                "report_type": "EDR Incident Report",
                "total_iocs": self.total_count(),
                "extraction_notes": "Extracted via regex patterns - AI unavailable",
                "analysis": "Regex-based extraction (fallback mode)"
            },
            "network": {
                "ip_v4": sorted(self.ip_v4),
                "ip_v6": sorted(self.ip_v6),
                "domains": sorted(self.domains),
                "urls": sorted(self.urls),
                "emails": sorted(self.emails),
                "user_agents": sorted(self.user_agents)
            },
            "file": {
                "md5": sorted(self.md5),
                "sha1": sorted(self.sha1),
                "sha256": sorted(self.sha256),
                "sha512": sorted(self.sha512),
                "ssdeep": sorted(self.ssdeep),
                "imphash": sorted(self.imphash),
                "file_names": sorted(self.file_names),
                "file_paths": sorted(self.file_paths)
            },
            "host": {
                "hostnames": sorted(self.hostnames),
                "registry_keys": sorted(self.registry_keys),
                "registry_values": sorted(self.registry_values),
                "command_lines": sorted(self.command_lines),
                "process_names": sorted(self.process_names),
                "service_names": sorted(self.service_names),
                "scheduled_tasks": sorted(self.scheduled_tasks),
                "mutexes": sorted(self.mutexes),
                "named_pipes": sorted(self.named_pipes)
            },
            "identity": {
                "usernames": sorted(self.usernames),
                "sids": sorted(self.sids),
                "compromised_accounts": []
            },
            "threat_intel": {
                "cves": sorted(self.cves),
                "mitre_attack": sorted(self.mitre_attack),
                "malware_families": [],
                "threat_actors": [],
                "yara_rules": [],
                "sigma_rules": []
            },
            "cryptocurrency": {
                "btc_addresses": sorted(self.btc_addresses),
                "eth_addresses": sorted(self.eth_addresses),
                "xmr_addresses": sorted(self.xmr_addresses)
            },
            "timeline": []
        }
    
    def total_count(self) -> int:
        """Count total IOCs extracted"""
        return sum([
            len(self.ip_v4), len(self.ip_v6), len(self.domains), len(self.urls),
            len(self.emails), len(self.md5), len(self.sha1), len(self.sha256),
            len(self.sha512), len(self.file_names), len(self.file_paths),
            len(self.hostnames), len(self.registry_keys), len(self.command_lines),
            len(self.process_names), len(self.usernames), len(self.sids),
            len(self.cves), len(self.mitre_attack), len(self.btc_addresses),
            len(self.eth_addresses), len(self.xmr_addresses)
        ])


class IOCExtractor:
    """
    Regex-based IOC extractor
    De-obfuscates indicators automatically
    """
    
    # Common file extensions to identify file names
    FILE_EXTENSIONS = (
        '.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.vbs', '.js',
        '.hta', '.scr', '.pif', '.msi', '.jar', '.py', '.sh', '.bin',
        '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.txt', '.rtf',
        '.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.img',
        '.lnk', '.url', '.tmp', '.log', '.dat', '.db', '.sqlite'
    )
    
    # Known process names to extract
    KNOWN_PROCESSES = {
        'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe',
        'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe',
        'msiexec.exe', 'wmic.exe', 'whoami.exe', 'net.exe', 'net1.exe', 'netsh.exe',
        'schtasks.exe', 'at.exe', 'reg.exe', 'tasklist.exe', 'taskkill.exe',
        'sc.exe', 'bcdedit.exe', 'vssadmin.exe', 'wbadmin.exe', 'fsutil.exe',
        'icacls.exe', 'takeown.exe', 'attrib.exe', 'xcopy.exe', 'robocopy.exe',
        'psexec.exe', 'psexec64.exe', 'paexec.exe', 'winrm.exe', 'winrs.exe',
        'msbuild.exe', 'installutil.exe', 'regasm.exe', 'regsvcs.exe',
        'explorer.exe', 'svchost.exe', 'services.exe', 'lsass.exe', 'csrss.exe',
        'conhost.exe', 'taskhost.exe', 'taskhostw.exe', 'dllhost.exe',
        'winrar.exe', 'rar.exe', '7z.exe', '7za.exe', 'zip.exe',
        'mimikatz.exe', 'procdump.exe', 'procdump64.exe', 'nanodump.exe',
        'rubeus.exe', 'sharphound.exe', 'bloodhound.exe', 'lazagne.exe',
        'rdpclip.exe', 'mstsc.exe', 'rdesktop.exe', 'ssh.exe', 'putty.exe',
        'curl.exe', 'wget.exe', 'certreq.exe', 'bitsadmin.exe',
        'nltest.exe', 'dsquery.exe', 'ldapsearch.exe', 'adfind.exe'
    }
    
    def __init__(self):
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for performance"""
        
        # === DE-OBFUSCATION PATTERNS ===
        self.defang_patterns = [
            (re.compile(r'hxxps?://', re.I), lambda m: m.group().lower().replace('xx', 'tt')),
            (re.compile(r'hXXps?://', re.I), lambda m: m.group().lower().replace('xx', 'tt')),
            (re.compile(r'(\w+)\[:\]//'), r'\1://'),
            (re.compile(r'\[\.+\]'), '.'),
            (re.compile(r'\(\.+\)'), '.'),
            (re.compile(r'\[dot\]', re.I), '.'),
            (re.compile(r'\(dot\)', re.I), '.'),
            (re.compile(r'\[at\]', re.I), '@'),
            (re.compile(r'\(at\)', re.I), '@'),
            (re.compile(r'\[@\]'), '@'),
            (re.compile(r'\[:\]'), ':'),
            (re.compile(r'\[::\]'), '::'),
            (re.compile(r'\[/\]'), '/'),
            (re.compile(r'\\\/'), '/'),
        ]
        
        # === NETWORK PATTERNS ===
        
        # IPv4 - matches both clean and defanged
        self.ipv4_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\[?\.\]?)){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        # IPv6 (simplified - catches most common formats)
        self.ipv6_pattern = re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'  # Full
            r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'  # Compressed end
            r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|'  # Compressed middle
            r'\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b|'  # Compressed start
            r'\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b'
        )
        
        # Domain - matches both clean and defanged
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
            r'(?:\[?\.\]?)){1,}[a-zA-Z]{2,}\b'
        )
        
        # URL - matches both clean and defanged
        self.url_pattern = re.compile(
            r'(?:hxxps?|https?|ftp)(?:\[?:\]?)?//[^\s<>\"\'\)]+',
            re.I
        )
        
        # Email - matches both clean and defanged
        self.email_pattern = re.compile(
            r'\b[a-zA-Z0-9._%+-]+(?:\[?@\]?|(?:\[at\]|\(at\)))[a-zA-Z0-9.-]+\[?\.\]?[a-zA-Z]{2,}\b',
            re.I
        )
        
        # User-Agent
        self.user_agent_pattern = re.compile(
            r'(?:Mozilla|Opera|curl|wget|python-requests|Go-http-client)/[^\s]+(?:\s+\([^)]+\))?[^\s]*',
            re.I
        )
        
        # === FILE HASH PATTERNS ===
        
        # MD5 (32 hex chars)
        self.md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        
        # SHA1 (40 hex chars)
        self.sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')
        
        # SHA256 (64 hex chars)
        self.sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')
        
        # SHA512 (128 hex chars)
        self.sha512_pattern = re.compile(r'\b[a-fA-F0-9]{128}\b')
        
        # SSDEEP (format: blocksize:hash:hash - must have letters)
        self.ssdeep_pattern = re.compile(
            r'\b[0-9]+:[a-zA-Z0-9+/]{10,}:[a-zA-Z0-9+/]{10,}\b'
        )
        
        # === FILE PATH PATTERNS ===
        
        # Windows path
        self.windows_path_pattern = re.compile(
            r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
            re.I
        )
        
        # Unix path (must start at word boundary, be longer, and not be URL path)
        self.unix_path_pattern = re.compile(
            r'(?<![:/])(?:^|\s)(/(?:usr|home|var|etc|tmp|opt|root|bin|sbin|lib|mnt|dev|proc|sys)[a-zA-Z0-9._/-]+)',
            re.MULTILINE
        )
        
        # === HOST PATTERNS ===
        
        # Windows SID
        self.sid_pattern = re.compile(
            r'\bS-1-[0-9]+-[0-9]+(?:-[0-9]+)*\b'
        )
        
        # Registry keys
        self.registry_pattern = re.compile(
            r'\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|'
            r'HKEY_USERS|HKEY_CURRENT_CONFIG|HKU|HKCR)\\[^\s"\'<>]+',
            re.I
        )
        
        # Named pipes
        self.named_pipe_pattern = re.compile(
            r'\\\\\.\\pipe\\[a-zA-Z0-9_\-]+',
            re.I
        )
        
        # Mutex
        self.mutex_pattern = re.compile(
            r'(?:Global\\|Local\\)[a-zA-Z0-9_\-{}\[\]]+',
            re.I
        )
        
        # Command line (quoted strings with commands)
        self.command_line_pattern = re.compile(
            r'(?:Command(?:\s*Line)?|CMD|cmdline)[:\s]+["\']?(.+?)(?:["\']?\s*$|\n)',
            re.I | re.MULTILINE
        )
        
        # === IDENTITY PATTERNS ===
        
        # Domain\User or User
        self.username_pattern = re.compile(
            r'(?:user(?:name)?|account|logon)[:\s]+["\']?([a-zA-Z0-9_\-\\]+)["\']?',
            re.I
        )
        
        # Hostname patterns
        self.hostname_pattern = re.compile(
            r'(?:host(?:name)?|computer|machine|system)[:\s]+["\']?([a-zA-Z0-9_\-]+)["\']?',
            re.I
        )
        
        # === THREAT INTEL PATTERNS ===
        
        # CVE
        self.cve_pattern = re.compile(
            r'\bCVE-[0-9]{4}-[0-9]{4,}\b',
            re.I
        )
        
        # MITRE ATT&CK
        self.mitre_pattern = re.compile(
            r'\b[TtSsMmGg][Aa]?[0-9]{4}(?:\.[0-9]{3})?\b'
        )
        
        # === CRYPTOCURRENCY PATTERNS ===
        
        # Bitcoin (Legacy, SegWit, Bech32)
        self.btc_pattern = re.compile(
            r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b'
        )
        
        # Ethereum
        self.eth_pattern = re.compile(
            r'\b0x[a-fA-F0-9]{40}\b'
        )
        
        # Monero
        self.xmr_pattern = re.compile(
            r'\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
        )
    
    def defang(self, text: str) -> str:
        """
        De-obfuscate/refang text
        Converts hxxp, [.], [at], etc. back to clean format
        """
        result = text
        for pattern, replacement in self.defang_patterns:
            if callable(replacement):
                result = pattern.sub(replacement, result)
            else:
                result = pattern.sub(replacement, result)
        return result
    
    def extract(self, text: str) -> Dict:
        """
        Extract all IOCs from text
        
        Args:
            text: Raw text to extract IOCs from
            
        Returns:
            Dict with all extracted IOCs
        """
        # First de-obfuscate the text
        clean_text = self.defang(text)
        
        results = IOCResults()
        
        # === NETWORK ===
        
        # IPv4
        for match in self.ipv4_pattern.finditer(clean_text):
            ip = self.defang(match.group())
            # Filter out version numbers and common false positives
            if not self._is_version_number(ip):
                results.ip_v4.add(ip)
        
        # IPv6
        for match in self.ipv6_pattern.finditer(clean_text):
            results.ip_v6.add(match.group().lower())
        
        # URLs (extract before domains to avoid duplication)
        for match in self.url_pattern.finditer(clean_text):
            url = self.defang(match.group())
            results.urls.add(url)
            # Extract domain from URL
            domain = self._extract_domain_from_url(url)
            if domain:
                results.domains.add(domain)
        
        # Domains
        for match in self.domain_pattern.finditer(clean_text):
            domain = self.defang(match.group()).lower()
            if self._is_valid_domain(domain):
                results.domains.add(domain)
        
        # Emails
        for match in self.email_pattern.finditer(clean_text):
            email = self.defang(match.group()).lower()
            results.emails.add(email)
        
        # User-Agents
        for match in self.user_agent_pattern.finditer(text):  # Use original text
            results.user_agents.add(match.group())
        
        # === FILE HASHES ===
        
        # Extract hashes (order matters - check longer first)
        for match in self.sha512_pattern.finditer(clean_text):
            results.sha512.add(match.group().lower())
        
        for match in self.sha256_pattern.finditer(clean_text):
            h = match.group().lower()
            # Avoid duplicates from SHA512
            if h not in results.sha512 and not any(h in s for s in results.sha512):
                results.sha256.add(h)
        
        for match in self.sha1_pattern.finditer(clean_text):
            h = match.group().lower()
            if h not in results.sha256 and not any(h in s for s in results.sha256):
                results.sha1.add(h)
        
        for match in self.md5_pattern.finditer(clean_text):
            h = match.group().lower()
            if h not in results.sha1 and not any(h in s for s in results.sha1):
                # Additional check: not part of a GUID
                if not self._is_guid_fragment(h, clean_text, match.start()):
                    results.md5.add(h)
        
        # SSDEEP
        for match in self.ssdeep_pattern.finditer(clean_text):
            results.ssdeep.add(match.group())
        
        # === FILE PATHS ===
        
        # Windows paths
        for match in self.windows_path_pattern.finditer(text):  # Original text
            path = match.group()
            results.file_paths.add(path)
            # Extract filename
            filename = self._extract_filename(path)
            if filename:
                results.file_names.add(filename)
                # Check if it's a known process
                if filename.lower() in self.KNOWN_PROCESSES:
                    results.process_names.add(filename)
        
        # Unix paths
        for match in self.unix_path_pattern.finditer(text):
            path = match.group(1)
            results.file_paths.add(path)
            filename = self._extract_filename(path)
            if filename:
                results.file_names.add(filename)
        
        # === HOST INDICATORS ===
        
        # SIDs
        for match in self.sid_pattern.finditer(clean_text):
            results.sids.add(match.group())
        
        # Registry keys
        for match in self.registry_pattern.finditer(text):
            results.registry_keys.add(match.group())
        
        # Named pipes
        for match in self.named_pipe_pattern.finditer(text):
            results.named_pipes.add(match.group())
        
        # Mutexes
        for match in self.mutex_pattern.finditer(text):
            results.mutexes.add(match.group())
        
        # Command lines
        for match in self.command_line_pattern.finditer(text):
            cmd = match.group(1).strip()
            if cmd:
                results.command_lines.add(cmd)
        
        # Hostnames
        for match in self.hostname_pattern.finditer(text):
            hostname = match.group(1).strip()
            if hostname and len(hostname) > 1:
                results.hostnames.add(hostname)
        
        # Usernames
        for match in self.username_pattern.finditer(text):
            username = match.group(1).strip()
            if username and len(username) > 1:
                results.usernames.add(username)
        
        # === THREAT INTEL ===
        
        # CVEs
        for match in self.cve_pattern.finditer(clean_text):
            results.cves.add(match.group().upper())
        
        # MITRE ATT&CK
        for match in self.mitre_pattern.finditer(clean_text):
            technique = match.group().upper()
            # Normalize format
            if technique.startswith('T') or technique.startswith('TA'):
                results.mitre_attack.add(technique)
        
        # === CRYPTOCURRENCY ===
        
        # Bitcoin
        for match in self.btc_pattern.finditer(clean_text):
            addr = match.group()
            if self._is_valid_btc(addr):
                results.btc_addresses.add(addr)
        
        # Ethereum
        for match in self.eth_pattern.finditer(clean_text):
            results.eth_addresses.add(match.group())
        
        # Monero
        for match in self.xmr_pattern.finditer(clean_text):
            results.xmr_addresses.add(match.group())
        
        # === ADDITIONAL EXTRACTION ===
        
        # Extract file names from text mentions
        self._extract_file_mentions(text, results)
        
        # Extract process names mentioned in text
        self._extract_process_mentions(text, results)
        
        return results.to_dict()
    
    def _is_version_number(self, ip: str) -> bool:
        """Check if IP-like string is actually a version number"""
        # Version numbers often have many zeros or sequential patterns
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        # Check for common version patterns like 1.0.0.0, 2.0.0.1
        if parts[1] == '0' and parts[2] == '0':
            return True
        
        return False
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain is not a false positive"""
        # Too short
        if len(domain) < 4:
            return False
        
        # No TLD
        if '.' not in domain:
            return False
        
        # Common false positives
        false_positives = {
            'example.com', 'test.com', 'localhost.localdomain',
            'n.a', 'n.a.', 'file.exe', 'file.dll'
        }
        if domain.lower() in false_positives:
            return False
        
        # File extensions that look like TLDs
        parts = domain.split('.')
        tld = parts[-1].lower()
        file_ext_tlds = {
            'exe', 'dll', 'sys', 'bat', 'cmd', 'ps1', 'txt', 'log', 'tmp',
            'doc', 'docx', 'xls', 'xlsx', 'pdf', 'rar', 'zip', '7z', 'tar',
            'gz', 'iso', 'img', 'bin', 'dat', 'db', 'sqlite', 'msi', 'jar',
            'py', 'sh', 'js', 'vbs', 'hta', 'scr', 'pif', 'lnk', 'url', 'rtf'
        }
        if tld in file_ext_tlds:
            return False
        
        # Looks like a file with multiple dots (e.g., veeam.backup.shell.exe)
        if any(part.lower() in file_ext_tlds for part in parts):
            return False
        
        # Valid TLDs check (basic - common ones)
        valid_tlds = {
            'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'io', 'co', 'ai',
            'de', 'uk', 'fr', 'it', 'es', 'nl', 'be', 'ch', 'at', 'pl', 'ru',
            'cn', 'jp', 'kr', 'in', 'br', 'au', 'ca', 'mx', 'us', 'eu', 'info',
            'biz', 'xyz', 'online', 'site', 'tech', 'dev', 'app', 'cloud', 'top',
            'me', 'tv', 'cc', 'ws', 'to', 'tk', 'ly', 'gl', 'pw', 'su', 'ua',
            'cz', 'sk', 'hu', 'ro', 'bg', 'gr', 'pt', 'se', 'no', 'dk', 'fi'
        }
        if tld not in valid_tlds:
            return False
        
        return True
    
    def _extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            # Remove protocol
            url = re.sub(r'^https?://', '', url, flags=re.I)
            # Get domain part
            domain = url.split('/')[0].split(':')[0].split('?')[0]
            return domain.lower()
        except:
            return None
    
    def _extract_filename(self, path: str) -> str:
        """Extract filename from path"""
        # Windows path
        if '\\' in path:
            filename = path.split('\\')[-1]
        # Unix path
        elif '/' in path:
            filename = path.split('/')[-1]
        else:
            filename = path
        
        # Validate it looks like a filename
        if filename and '.' in filename:
            return filename
        return None
    
    def _is_guid_fragment(self, hash_str: str, text: str, pos: int) -> bool:
        """Check if hash is part of a GUID"""
        # GUIDs look like: 8-4-4-4-12 hex chars
        # Check surrounding context
        start = max(0, pos - 10)
        end = min(len(text), pos + len(hash_str) + 10)
        context = text[start:end]
        
        guid_pattern = r'[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}'
        return bool(re.search(guid_pattern, context))
    
    def _is_valid_btc(self, addr: str) -> bool:
        """Basic Bitcoin address validation"""
        # Length check
        if addr.startswith('bc1'):
            return 42 <= len(addr) <= 62
        elif addr.startswith('1') or addr.startswith('3'):
            return 26 <= len(addr) <= 35
        return False
    
    def _extract_file_mentions(self, text: str, results: IOCResults):
        """Extract filenames mentioned in text"""
        for ext in self.FILE_EXTENSIONS:
            pattern = re.compile(
                r'\b([a-zA-Z0-9_\-\.]+' + re.escape(ext) + r')\b',
                re.I
            )
            for match in pattern.finditer(text):
                filename = match.group(1)
                results.file_names.add(filename)
    
    def _extract_process_mentions(self, text: str, results: IOCResults):
        """Extract known process names mentioned in text"""
        text_lower = text.lower()
        for proc in self.KNOWN_PROCESSES:
            if proc.lower() in text_lower:
                # Find with proper word boundaries
                pattern = re.compile(r'\b' + re.escape(proc) + r'\b', re.I)
                for match in pattern.finditer(text):
                    results.process_names.add(match.group())


# === CONVENIENCE FUNCTIONS ===

def extract_iocs(text: str) -> Dict:
    """
    Extract IOCs from text (convenience function)
    
    Args:
        text: Raw text to extract IOCs from
        
    Returns:
        Dict with all extracted IOCs in standard format
    """
    extractor = IOCExtractor()
    return extractor.extract(text)

