"""Regex-based IOC extraction helpers."""

from __future__ import annotations

import importlib.util
import os
import re
from typing import Any, Dict, List, Optional, Tuple


def _load_local_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name,
        os.path.join(os.path.dirname(__file__), filename),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_ioc_text = _load_local_module("ioc_text_for_regex_extractor", "ioc_text.py")
_ioc_regex_catalog = _load_local_module("ioc_regex_catalog_for_regex_extractor", "ioc_regex_catalog.py")


def _normalize_extracted_file_path(value: Any) -> Tuple[Optional[str], str]:
    return _ioc_text._normalize_extracted_file_path(value)


def _defang_text(value: str) -> str:
    return _ioc_text._defang_text(value)


class RegexIOCExtractor:
    """Regex-based IOC extractor as fallback when AI is unavailable."""

    PATTERNS = _ioc_regex_catalog.REGEX_IOC_PATTERNS
    RMM_TOOLS = _ioc_regex_catalog.REGEX_EXTRACTOR_RMM_TOOLS
    MALWARE_FAMILIES = _ioc_regex_catalog.REGEX_EXTRACTOR_MALWARE_FAMILIES

    def defang(self, text: str) -> str:
        return _ioc_text._defang_text(text)

    def _line_context_hint(self, text: str) -> str:
        lowered = (text or "").lower()
        if any(
            token in lowered
            for token in (
                "delete ",
                "remove ",
                "kill process",
                "reboot",
                "recommended action",
                "remediation",
                "response guidance",
            )
        ):
            return "Remediation reference"
        if any(
            token in lowered
            for token in (
                "observed",
                "detected",
                "evidence",
                "storyline",
                "incident",
                "execution",
                "activity",
            )
        ):
            return "Observed activity"
        return ""

    def _extract_structured_entities(self, original_text: str, results: Dict[str, Any]) -> None:
        host_patterns = (
            re.compile(r"^\s*(?:Host Name|Host|Endpoint|Device)\s*[:=]\s*(.+?)\s*$", re.I),
        )
        user_patterns = (
            re.compile(r"^\s*(?:User Account|User|Actor User)\s*[:=]\s*(.+?)\s*$", re.I),
        )
        sid_pattern = re.compile(r"(S-1-\d+(?:-\d+)+)")
        seen_hosts = {
            str(host).strip().lower()
            for host in results["extraction_summary"].get("affected_hosts", [])
        }
        seen_users = {
            (
                str((item or {}).get("username", "")).strip().lower(),
                str((item or {}).get("sid", "")).strip(),
            )
            for item in results["extraction_summary"].get("affected_users", [])
            if isinstance(item, dict)
        }
        lines = original_text.splitlines()
        for index, line in enumerate(lines):
            stripped = line.strip().strip('"')
            if not stripped:
                continue
            for pattern in host_patterns:
                match = pattern.match(stripped)
                if match:
                    host = match.group(1).strip().strip('"').split()[0]
                    if host and host.lower() not in seen_hosts and not self.PATTERNS["ip_v4"].match(host):
                        seen_hosts.add(host.lower())
                        results["extraction_summary"]["affected_hosts"].append(host)
                        results["iocs"]["hostnames"].append(
                            {"value": host, "context": self._line_context_hint(line)}
                        )
            for pattern in user_patterns:
                match = pattern.match(stripped)
                if not match:
                    continue
                username = match.group(1).strip().strip('"')
                if ":" in username:
                    continue
                window = "\n".join(lines[max(0, index - 1) : min(len(lines), index + 3)])
                sid_match = sid_pattern.search(window)
                sid = sid_match.group(1) if sid_match else ""
                dedupe_key = (username.lower(), sid)
                if username and dedupe_key not in seen_users:
                    seen_users.add(dedupe_key)
                    user_item = {"username": username, "sid": sid}
                    results["extraction_summary"]["affected_users"].append(user_item)
                    results["iocs"]["users"].append(
                        {"value": username, "context": self._line_context_hint(window)}
                    )
                    if sid:
                        results["iocs"]["sids"].append(sid)

    def _extract_structured_activity(self, original_text: str, results: Dict[str, Any]) -> None:
        lines = original_text.splitlines()
        command_patterns = (
            re.compile(
                r"^\s*(?:- )?(?:Command Line|Command|ProcessCommandLine|Execution chain)\s*[:=]\s*(.+?)\s*$",
                re.I,
            ),
        )
        parent_pattern = re.compile(r"^\s*(?:Parent Process)\s*[:=]\s*(.+?)\s*$", re.I)
        user_pattern = re.compile(r"^\s*(?:User|Actor User)\s*[:=]\s*(.+?)\s*$", re.I)
        pid_pattern = re.compile(r"^\s*(?:Process ID|PID)\s*[:=]\s*(.+?)\s*$", re.I)
        service_patterns = (
            re.compile(
                r"^\s*(?:Service Name|Service Display Name|Service|service)\s*(?:=>|[:=])\s*(.+?)\s*$",
                re.I,
            ),
            re.compile(r"^\s*(?:- )?(?:Delete Service|Create Service)\s*-\s*name:\s*(.+?)\s*$", re.I),
        )
        task_patterns = (
            re.compile(r"^\s*(?:Scheduled Task|ScheduledTask|TaskName|task)\s*(?:=>|[:=])\s*(.+?)\s*$", re.I),
        )
        registry_patterns = (
            re.compile(r"^\s*(?:RegistryKey|Registry Key|registry)\s*(?:=>|[:=])\s*(.+?)\s*$", re.I),
        )
        seen_commands = {
            str((item or {}).get("value", "")).strip().lower()
            for item in results["iocs"].get("commands", [])
            if isinstance(item, dict)
        }
        seen_services = {
            str((item or {}).get("name", "")).strip().lower()
            for item in results["iocs"].get("services", [])
            if isinstance(item, dict)
        }
        seen_tasks = {
            str((item or {}).get("name", "") or (item or {}).get("path", "")).strip().lower()
            for item in results["iocs"].get("scheduled_tasks", [])
            if isinstance(item, dict)
        }
        seen_registry = {
            str((item or {}).get("value", "")).strip().lower()
            for item in results["iocs"].get("registry_keys", [])
            if isinstance(item, dict)
        }

        for index, raw_line in enumerate(lines):
            line = raw_line.strip()
            if not line:
                continue
            window_lines = lines[max(0, index - 1) : min(len(lines), index + 4)]
            window_text = "\n".join(window_lines)
            context = self._line_context_hint(window_text)

            for pattern in command_patterns:
                match = pattern.match(line)
                if not match:
                    continue
                command = self.defang(match.group(1).strip().strip('"'))
                lowered_command = command.lower()
                if not command or lowered_command in seen_commands:
                    continue
                seen_commands.add(lowered_command)
                parent_match = parent_pattern.search(window_text)
                user_match = user_pattern.search(window_text)
                pid_match = pid_pattern.search(window_text)
                results["iocs"]["commands"].append(
                    {
                        "value": command,
                        "parent": self.defang(parent_match.group(1).strip()) if parent_match else "",
                        "user": user_match.group(1).strip() if user_match else "",
                        "pid": pid_match.group(1).strip() if pid_match else "",
                        "context": context,
                    }
                )
                results["raw_artifacts"]["full_commands"].append(command)

            for pattern in service_patterns:
                match = pattern.match(line)
                if not match:
                    continue
                service_name = self.defang(match.group(1).strip().strip('"'))
                lowered_name = service_name.lower()
                if not service_name or lowered_name in seen_services:
                    continue
                seen_services.add(lowered_name)
                action = (
                    "delete"
                    if "delete service" in line.lower()
                    else "create" if "create" in line.lower() else "unknown"
                )
                results["iocs"]["services"].append(
                    {"name": service_name, "action": action, "context": context}
                )

            for pattern in task_patterns:
                match = pattern.match(line)
                if not match:
                    continue
                task_name = self.defang(match.group(1).strip().strip('"'))
                lowered_name = task_name.lower()
                if not task_name or lowered_name in seen_tasks:
                    continue
                seen_tasks.add(lowered_name)
                results["iocs"]["scheduled_tasks"].append(
                    {
                        "name": task_name,
                        "action": "delete" if "delete" in line.lower() else "unknown",
                        "context": context,
                    }
                )

            for pattern in registry_patterns:
                match = pattern.match(line)
                if not match:
                    continue
                registry_key = self.defang(match.group(1).strip().strip('"'))
                lowered_key = registry_key.lower()
                if not registry_key or lowered_key in seen_registry:
                    continue
                seen_registry.add(lowered_key)
                results["iocs"]["registry_keys"].append(
                    {
                        "value": registry_key,
                        "action": "delete" if "delete" in line.lower() or "remove" in line.lower() else "unknown",
                        "context": context,
                    }
                )

    def extract(self, text: str) -> Dict[str, Any]:
        clean_text = self.defang(text)
        original_text = text

        results = {
            "extraction_summary": {
                "method": "regex",
                "report_date": None,
                "affected_hosts": [],
                "affected_users": [],
                "severity_indicators": [],
                "threat_families": [],
                "isolated": "isolated" in text.lower(),
            },
            "iocs": {
                "hashes": [],
                "ip_addresses": [],
                "domains": [],
                "urls": [],
                "file_paths": [],
                "file_names": [],
                "users": [],
                "sids": [],
                "registry_keys": [],
                "commands": [],
                "processes": [],
                "credentials": [],
                "hostnames": [],
                "timestamps": [],
                "network_shares": [],
                "email_addresses": [],
                "mitre_indicators": [],
                "services": [],
                "scheduled_tasks": [],
                "cves": [],
                "threat_names": [],
            },
            "raw_artifacts": {
                "full_commands": [],
                "filemasks": [],
                "encoded_powershell": [],
                "vnc_connection_ids": [],
                "screenconnect_ids": [],
                "parent_child_chains": [],
            },
        }

        for match in self.PATTERNS["md5"].findall(clean_text):
            results["iocs"]["hashes"].append({"value": match.lower(), "type": "md5", "context": ""})
        for match in self.PATTERNS["sha1"].findall(clean_text):
            results["iocs"]["hashes"].append({"value": match.lower(), "type": "sha1", "context": ""})
        for match in self.PATTERNS["sha256"].findall(clean_text):
            results["iocs"]["hashes"].append({"value": match.lower(), "type": "sha256", "context": ""})

        for match in self.PATTERNS["ip_v4"].findall(clean_text):
            clean_ip = self.defang(match)
            if self._is_valid_ipv4(clean_ip):
                results["iocs"]["ip_addresses"].append(
                    {
                        "value": clean_ip,
                        "port": None,
                        "direction": "unknown",
                        "context": "",
                        "type": "ipv4",
                    }
                )

        for match in self.PATTERNS["ip_v6"].findall(clean_text):
            if match.count(":") < 4 and not match.lower().startswith("fe80"):
                continue
            results["iocs"]["ip_addresses"].append(
                {
                    "value": match,
                    "port": None,
                    "direction": "unknown",
                    "context": "IPv6 address",
                    "type": "ipv6",
                }
            )

        for match in self.PATTERNS["domain"].findall(clean_text):
            domain = self.defang(match.lower())
            if "huntress.io" in domain:
                continue
            results["iocs"]["domains"].append({"value": domain, "context": ""})

        for match in self.PATTERNS["cloudflare_tunnel"].findall(clean_text):
            results["iocs"]["domains"].append(
                {"value": match.lower(), "context": "Cloudflare Quick Tunnel (potential C2)"}
            )

        for match in self.PATTERNS["url"].findall(clean_text):
            url = self.defang(match)
            if "huntress" in url.lower() or "portal" in url.lower():
                continue
            results["iocs"]["urls"].append({"value": url, "type": "unknown", "context": ""})

        for match in self.PATTERNS["file_path_windows"].findall(clean_text):
            path, note = _normalize_extracted_file_path(match)
            if not path:
                continue
            results["iocs"]["file_paths"].append({"value": path, "action": "unknown", "context": note})

        for match in self.PATTERNS["file_path_unix"].findall(clean_text):
            path, note = _normalize_extracted_file_path(match)
            if not path:
                continue
            results["iocs"]["file_paths"].append(
                {
                    "value": path,
                    "action": "unknown",
                    "context": " | ".join(part for part in ("Unix/macOS path", note) if part),
                }
            )

        for match in self.PATTERNS["file_path_unc"].findall(clean_text):
            results["iocs"]["network_shares"].append({"value": match.rstrip(".,;:"), "context": ""})

        for match in self.PATTERNS["registry_key"].findall(clean_text):
            results["iocs"]["registry_keys"].append(
                {"value": match.rstrip(".,;:"), "action": "unknown", "context": ""}
            )

        for match in self.PATTERNS["sid"].findall(clean_text):
            results["iocs"]["sids"].append(match)

        for match in self.PATTERNS["email"].findall(clean_text):
            results["iocs"]["email_addresses"].append(match.lower())

        for match in self.PATTERNS["cve"].findall(clean_text):
            results["iocs"]["cves"].append(match.upper())

        for match in self.PATTERNS["threat_name"].findall(original_text):
            value = match.strip().strip('"').strip("'")
            if value:
                results["iocs"]["threat_names"].append(value)
        for match in self.PATTERNS["malware_family"].findall(original_text):
            value = match.strip().strip('"').strip("'")
            if value:
                results["iocs"]["threat_names"].append(value)
                results["extraction_summary"]["threat_families"].append(value)

        for match in self.PATTERNS["service_name"].findall(original_text):
            service = match.strip()
            results["iocs"]["services"].append(
                {"name": service, "action": "delete", "context": "From remediation"}
            )

        for match in self.PATTERNS["scheduled_task"].findall(clean_text):
            results["iocs"]["scheduled_tasks"].append(
                {"path": match, "action": "delete", "context": ""}
            )

        for match in self.PATTERNS["screenconnect_id"].findall(original_text):
            results["raw_artifacts"]["screenconnect_ids"].append(match)

        for match in self.PATTERNS["vnc_connection_id"].findall(clean_text):
            results["raw_artifacts"]["vnc_connection_ids"].append(match)

        for match in self.PATTERNS["encoded_powershell"].findall(clean_text):
            results["raw_artifacts"]["encoded_powershell"].append(match)

        for match in self.PATTERNS["net_user_password"].findall(clean_text):
            username, password = match
            results["iocs"]["credentials"].append(
                {
                    "type": "password",
                    "username": username,
                    "value": password,
                    "context": "From net user /add command - attacker-created account",
                }
            )

        for match in self.PATTERNS["smb_creds"].findall(clean_text):
            username, password = match
            results["iocs"]["credentials"].append(
                {
                    "type": "password",
                    "username": username,
                    "value": password,
                    "context": "SMB share credentials from net use command",
                }
            )

        for match in self.PATTERNS["parent_process"].findall(clean_text):
            parent = match.strip()
            if "sqlservr.exe" in parent.lower():
                results["raw_artifacts"]["parent_child_chains"].append(
                    {"parent": parent, "context": "SQL Server xp_cmdshell exploitation"}
                )
            elif "w3wp.exe" in parent.lower():
                results["raw_artifacts"]["parent_child_chains"].append(
                    {"parent": parent, "context": "IIS web shell activity"}
                )

        self._extract_structured_entities(original_text, results)
        self._extract_structured_activity(original_text, results)

        text_lower = text.lower()
        for family in self.MALWARE_FAMILIES:
            if family in text_lower:
                results["extraction_summary"]["threat_families"].append(family.title())

        for tool in self.RMM_TOOLS:
            if tool in text_lower:
                indicator = f"Rogue {tool.title()}"
                if indicator not in results["extraction_summary"]["severity_indicators"]:
                    results["extraction_summary"]["severity_indicators"].append(indicator)

        hostname_fields = [
            r'"Computer"\s*:\s*"([^"]+)"',
            r'"Hostname"\s*:\s*"([^"]+)"',
            r'"hostname"\s*:\s*"([^"]+)"',
            r'"WorkstationName"\s*:\s*"([^"]+)"',
            r'"SourceHostname"\s*:\s*"([^"]+)"',
            r'"DestinationHostname"\s*:\s*"([^"]+)"',
            r'"TargetServerName"\s*:\s*"([^"]+)"',
            r'"host"\s*:\s*"([^"]+)"',
            r'"ComputerName"\s*:\s*"([^"]+)"',
            r'"source_host"\s*:\s*"([^"]+)"',
        ]
        for pattern in hostname_fields:
            for match in re.findall(pattern, original_text, re.IGNORECASE):
                hostname = match.strip()
                if hostname and 2 <= len(hostname) <= 255:
                    if self.PATTERNS["ip_v4"].match(hostname):
                        continue
                    if hostname.lower() in ("-", "localhost", "unknown", "n/a", "none", "null"):
                        continue
                    netbios = hostname.split(".")[0].upper()
                    results["iocs"]["hostnames"].append(
                        {
                            "value": netbios,
                            "fqdn": hostname if "." in hostname else None,
                            "context": "",
                        }
                    )

        results["iocs"]["hashes"] = self._dedupe_list_of_dicts(results["iocs"]["hashes"], "value")
        results["iocs"]["ip_addresses"] = self._dedupe_list_of_dicts(results["iocs"]["ip_addresses"], "value")
        results["iocs"]["urls"] = self._dedupe_list_of_dicts(results["iocs"]["urls"], "value")
        results["iocs"]["domains"] = self._dedupe_list_of_dicts(results["iocs"]["domains"], "value")
        results["iocs"]["file_paths"] = self._dedupe_list_of_dicts(results["iocs"]["file_paths"], "value")
        results["iocs"]["network_shares"] = self._dedupe_list_of_dicts(
            results["iocs"]["network_shares"],
            "value",
        )
        results["iocs"]["registry_keys"] = self._dedupe_list_of_dicts(
            results["iocs"]["registry_keys"],
            "value",
        )
        results["iocs"]["commands"] = self._dedupe_list_of_dicts(results["iocs"]["commands"], "value")
        results["iocs"]["services"] = self._dedupe_list_of_dicts(results["iocs"]["services"], "name")
        results["iocs"]["scheduled_tasks"] = self._dedupe_list_of_dicts(
            results["iocs"]["scheduled_tasks"],
            "name",
        )
        results["iocs"]["hostnames"] = self._dedupe_list_of_dicts(results["iocs"]["hostnames"], "value")
        results["iocs"]["sids"] = list(set(results["iocs"]["sids"]))
        results["iocs"]["email_addresses"] = list(set(results["iocs"]["email_addresses"]))
        results["iocs"]["cves"] = list(set(results["iocs"]["cves"]))
        results["extraction_summary"]["threat_families"] = list(
            set(results["extraction_summary"]["threat_families"])
        )
        results["raw_artifacts"]["full_commands"] = list(
            dict.fromkeys(results["raw_artifacts"]["full_commands"])
        )
        results["extraction_summary"]["affected_hosts"] = list(
            dict.fromkeys(results["extraction_summary"]["affected_hosts"])
        )
        seen_users = set()
        deduped_users = []
        for item in results["extraction_summary"]["affected_users"]:
            if not isinstance(item, dict):
                continue
            key = (
                str(item.get("username", "")).strip().lower(),
                str(item.get("sid", "")).strip(),
            )
            if key in seen_users:
                continue
            seen_users.add(key)
            deduped_users.append(item)
        results["extraction_summary"]["affected_users"] = deduped_users

        return results

    def _is_valid_ipv4(self, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            except ValueError:
                return False
        return True

    def _dedupe_list_of_dicts(self, items: List[Dict], key: str) -> List[Dict]:
        seen = set()
        unique = []
        for item in items:
            val = item.get(key, "").lower()
            if val and val not in seen:
                seen.add(val)
                unique.append(item)
        return unique


def extract_derived_indicator_candidates(
    ioc_value: str,
    context_values: Optional[List[str]] = None,
) -> List[Dict[str, str]]:
    """Extract related IOC candidates from the canonical IOC boundary."""
    extractor = RegexIOCExtractor()
    candidate_map: Dict[str, Dict[str, str]] = {}
    values = [ioc_value]
    values.extend(context_values or [])

    def _add_candidate(source_value: str, value: str, indicator_type: str) -> None:
        normalized_value = _defang_text(value).strip()
        if not normalized_value:
            return
        key = f"{indicator_type}::{normalized_value.lower()}"
        if key in candidate_map:
            return
        candidate_map[key] = {
            "source_value": source_value[:300],
            "extracted_value": normalized_value,
            "extracted_type": indicator_type,
        }

    for source_value in values:
        if not isinstance(source_value, str) or not source_value.strip():
            continue
        clean_source = _defang_text(source_value)
        extracted = extractor.extract(clean_source)
        iocs = extracted.get("iocs", {})

        for hash_item in iocs.get("hashes", []):
            hash_type = str(hash_item.get("type", "")).lower()
            mapped_type = {
                "md5": "MD5 Hash",
                "sha1": "SHA1 Hash",
                "sha256": "SHA256 Hash",
            }.get(hash_type)
            if mapped_type:
                _add_candidate(source_value, hash_item.get("value", ""), mapped_type)

        for url_item in iocs.get("urls", []):
            _add_candidate(source_value, url_item.get("value", ""), "URL")
        for domain_item in iocs.get("domains", []):
            _add_candidate(source_value, domain_item.get("value", ""), "Domain")
        for ip_item in iocs.get("ip_addresses", []):
            value = ip_item.get("value", "")
            if ":" in value:
                _add_candidate(source_value, value, "IP Address (IPv6)")
            else:
                _add_candidate(source_value, value, "IP Address (IPv4)")
        for email_item in iocs.get("email_addresses", []):
            _add_candidate(source_value, email_item, "Email Address")

    return list(candidate_map.values())[:10]
