#!/usr/bin/env python3
"""Build a vendor-agnostic IOC benchmark corpus with explicit source labels."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import types
from copy import deepcopy
from typing import Any, Dict, Iterable, List


def _load_local_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name,
        os.path.join(os.path.dirname(__file__), filename),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

if "utils" not in sys.modules:
    fake_utils = types.ModuleType("utils")
    fake_utils.__path__ = []
    sys.modules["utils"] = fake_utils
if "utils.ai_training" not in sys.modules:
    fake_ai_training = types.ModuleType("utils.ai_training")
    fake_ai_training.build_role_system_prompt = lambda _route, extra_instructions="": extra_instructions
    sys.modules["utils.ai_training"] = fake_ai_training

_ioc_contract = _load_local_module("ioc_vendor_corpus_contract_shared", "ioc_contract.py")

TRAINING_DATA_DIR = os.path.join(REPO_ROOT, "training_data")
SOURCE_HUNTRESS_DATASET = os.path.join(TRAINING_DATA_DIR, "ioc_test.jsonl")
OUTPUT_CORPUS = os.path.join(TRAINING_DATA_DIR, "ioc_vendor_corpus.jsonl")
OUTPUT_MANIFEST = os.path.join(TRAINING_DATA_DIR, "ioc_vendor_corpus_manifest.json")
MDR_REPORT_DIR = os.path.join(REPO_ROOT, "example_reports", "reports_mdr")

MIN_REPORTS_PER_VENDOR = 10
MIN_VENDOR_COUNT = 5
MIN_TOTAL_REPORTS = 50

SYNTHETIC_VENDOR_TEMPLATES = {
    "crowdstrike": """CrowdStrike Falcon Incident Summary
=================================
Host: {host}
User: {user}
Severity: High
Observed Activity:
- Process execution: {command}
- Network connection: {ipv4} -> {domain}
- URL observed: {url}
- File written: {file_path}
- Hash: {hash}
- Persistence key: {registry_key}
- Service created: {service}
Recommended Actions:
- Remove service {service}
- Delete file {file_path}
""",
    "defender_xdr": """Microsoft Defender XDR Incident
Incident details
The affected device {host} showed suspicious execution by {user}.
Evidence:
ProcessCommandLine = {command}
RemoteUrl = {url}
RemoteIP = {ipv4}
FileName = {file_name}
FilePath = {file_path}
SHA256 = {hash}
RegistryKey = {registry_key}
ScheduledTask = {scheduled_task}
Analyst note: remediation guidance references portal.security.microsoft.com and should not become an IOC.
""",
    "sentinelone": """SentinelOne Deep Visibility Storyline
Storyline Summary
Endpoint: {host}
Actor User: {user}
Execution chain: {command}
Artifacts:
domain => {domain}
url => {url}
ipv4 => {ipv4}
sha256 => {hash}
path => {file_path}
service => {service}
task => {scheduled_task}
encoded powershell => {encoded_powershell}
""",
    "sophos": """Sophos MDR Analyst Report
Report Overview
The host {host} and user {user} were involved in suspicious activity.
Observed indicators:
* Domain: {domain}
* URL: {url}
* IPv4: {ipv4}
* File path: {file_path}
* File hash: {hash}
* Registry key: {registry_key}
* Service: {service}
* ScreenConnect identifier: {screenconnect_id}
Response guidance:
* Remove registry entry {registry_key}
* Block vendor portal sophos.example.invalid only if present in logs
""",
}

LAYOUT_FAMILIES = (
    "bullet-heavy",
    "prose-heavy",
    "remediation-heavy",
    "alert-summary",
    "analyst-narrative",
)

SYNTHETIC_CASES = [
    {
        "host": "WKSTN-441",
        "user": "alice.wheeler",
        "domain": "cdn-auth-update[.]com",
        "url": "hxxps://cdn-auth-update[.]com/bootstrap",
        "ipv4": "45[.]77[.]18[.]91",
        "hash": "2a4d7d9bc79e7dd4bd6d1c94f6b5698ef9ecdd9f7b5b2552fe6d1efc1e5aa0c9",
        "file_path": r"C:\Users\alice.wheeler\AppData\Roaming\svc\bootstrap.exe",
        "file_name": "bootstrap.exe",
        "command": r"powershell.exe -windowstyle hidden -enc SQBFAFgA",
        "registry_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\BootstrapSvc",
        "service": "BootstrapSvc",
        "scheduled_task": r"\Microsoft\Windows\Bootstrap\Updater",
        "encoded_powershell": "SQBFAFgA",
        "screenconnect_id": "6100c8e237f6b876",
    },
    {
        "host": "SRV-ACCT-02",
        "user": "svc-backup",
        "domain": "sync-cache[.]net",
        "url": "hxxp://sync-cache[.]net/api/v2",
        "ipv4": "103[.]44[.]19[.]200",
        "hash": "65b6790c6e5f2da4af0d21d337db0a6f1b7e7ef20da95520f62f592f5551e0f4",
        "file_path": r"C:\ProgramData\sync\syncsvc.dll",
        "file_name": "syncsvc.dll",
        "command": r"cmd.exe /c rundll32.exe C:\ProgramData\sync\syncsvc.dll,Start",
        "registry_key": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\SyncCache",
        "service": "SyncCacheSvc",
        "scheduled_task": r"\SyncCache\Daily",
        "encoded_powershell": "",
        "screenconnect_id": "7b11f4a98c0d521e",
    },
    {
        "host": "FIN-LAPTOP-9",
        "user": "maria.lopez",
        "domain": "billing-sharepoint[.]org",
        "url": "hxxps://billing-sharepoint[.]org/login",
        "ipv4": "185[.]188[.]210[.]12",
        "hash": "f8b3ec0d216af61fd8d90b3f5924f6b7d48f9e7c4d2e7ef93831ddbb19903182",
        "file_path": r"C:\Users\maria.lopez\Downloads\InvoiceViewer.hta",
        "file_name": "InvoiceViewer.hta",
        "command": r"mshta.exe C:\Users\maria.lopez\Downloads\InvoiceViewer.hta",
        "registry_key": r"HKCU\Software\Classes\ms-settings\Shell\Open\command",
        "service": "InvoiceUpdater",
        "scheduled_task": r"\Invoice\Refresh",
        "encoded_powershell": "",
        "screenconnect_id": "c93e0212f3919b2c",
    },
    {
        "host": "ENG-VDI-07",
        "user": "thomas.ng",
        "domain": "quickpatch-now[.]top",
        "url": "hxxps://quickpatch-now[.]top/patch",
        "ipv4": "91[.]218[.]114[.]71",
        "hash": "b8d4ec1983db1d2d3a5a18d63a90cfd2d0fcb0d4d3db3fe89a6d0a22f8f0a133",
        "file_path": r"C:\Users\thomas.ng\AppData\Local\Temp\quickpatch.ps1",
        "file_name": "quickpatch.ps1",
        "command": r"powershell.exe -executionpolicy bypass -file C:\Users\thomas.ng\AppData\Local\Temp\quickpatch.ps1",
        "registry_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\QuickPatch",
        "service": "QuickPatchAgent",
        "scheduled_task": r"\QuickPatch\Hourly",
        "encoded_powershell": "",
        "screenconnect_id": "4fdd20d6bc41e7a9",
    },
    {
        "host": "HR-WS-13",
        "user": "pat.lee",
        "domain": "hr-benefits-auth[.]co",
        "url": "hxxps://hr-benefits-auth[.]co/connect",
        "ipv4": "172[.]93[.]102[.]4",
        "hash": "1ce75c25d8c68f9559e181b979dc7bc7d66a6fdb1a2477ed7cd8d3e45592fd2a",
        "file_path": r"C:\Users\pat.lee\AppData\Local\Temp\benefits.vbs",
        "file_name": "benefits.vbs",
        "command": r"wscript.exe C:\Users\pat.lee\AppData\Local\Temp\benefits.vbs",
        "registry_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\BenefitsSync",
        "service": "BenefitsSyncSvc",
        "scheduled_task": r"\Benefits\Updater",
        "encoded_powershell": "",
        "screenconnect_id": "1a2b3c4d5e6f7890",
    },
    {
        "host": "DC-01",
        "user": "administrator",
        "domain": "dc-sync-support[.]xyz",
        "url": "hxxp://dc-sync-support[.]xyz/report",
        "ipv4": "66[.]175[.]216[.]19",
        "hash": "6a324f31a7b4b2169a5f6f1feab0269f34b942177eab2e011053670cbefad31d",
        "file_path": r"C:\Windows\Temp\adfind.exe",
        "file_name": "adfind.exe",
        "command": r"cmd.exe /c C:\Windows\Temp\adfind.exe -f objectclass=*",
        "registry_key": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\ServicesHost",
        "service": "ServicesHost",
        "scheduled_task": r"\ServicesHost\Boot",
        "encoded_powershell": "",
        "screenconnect_id": "deadc0deffeebabe",
    },
    {
        "host": "SQL-REPORT-4",
        "user": "sqlservice",
        "domain": "reporting-fix[.]info",
        "url": "hxxps://reporting-fix[.]info/agent",
        "ipv4": "146[.]70[.]24[.]181",
        "hash": "e9eb33d6494ee1f71b9ffb5eb07cfdc9bfe48da4be954f7037441f778c1d2e99",
        "file_path": r"C:\ProgramData\agent\agent.exe",
        "file_name": "agent.exe",
        "command": r"C:\ProgramData\agent\agent.exe --service",
        "registry_key": r"HKLM\SYSTEM\CurrentControlSet\Services\ReportingFix",
        "service": "ReportingFix",
        "scheduled_task": r"\ReportingFix\Every15Min",
        "encoded_powershell": "",
        "screenconnect_id": "1122334455667788",
    },
    {
        "host": "OPS-KIOSK-22",
        "user": "ops.runner",
        "domain": "asset-viewer[.]site",
        "url": "hxxps://asset-viewer[.]site/update",
        "ipv4": "193[.]29[.]57[.]30",
        "hash": "ca55828f08927b0ae28ce2f58e1dfb60c8303ab9dfa592f85ddc3ec1af4bd4aa",
        "file_path": r"C:\Users\ops.runner\AppData\Roaming\viewer\viewer.exe",
        "file_name": "viewer.exe",
        "command": r"C:\Users\ops.runner\AppData\Roaming\viewer\viewer.exe --update",
        "registry_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\AssetViewer",
        "service": "AssetViewerAgent",
        "scheduled_task": r"\AssetViewer\Daily",
        "encoded_powershell": "",
        "screenconnect_id": "77889900aabbccdd",
    },
    {
        "host": "IT-JUMP-03",
        "user": "helpdesk.temp",
        "domain": "support-federation[.]ru",
        "url": "hxxps://support-federation[.]ru/connect",
        "ipv4": "87[.]251[.]67[.]150",
        "hash": "fd6200d6772fb8741f70fb880f4d6c6cc4bf715c4af07b4e6b38bc0a8a0f5128",
        "file_path": r"C:\Program Files\SupportFederation\support.exe",
        "file_name": "support.exe",
        "command": r"powershell.exe -nop -w hidden -enc UwB1AHAAcABvAHIAdAA=",
        "registry_key": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\SupportFederation",
        "service": "SupportFederation",
        "scheduled_task": r"\SupportFederation\Startup",
        "encoded_powershell": "UwB1AHAAcABvAHIAdAA=",
        "screenconnect_id": "8899aabbccddeeff",
    },
    {
        "host": "MKT-DESK-18",
        "user": "oliver.kim",
        "domain": "creative-review[.]buzz",
        "url": "hxxps://creative-review[.]buzz/share",
        "ipv4": "5[.]42[.]199[.]88",
        "hash": "8aa1ca25afaa31e64e01b44f8c6ec05870e5224b37d3ab355f34be6ef9f7f6c5",
        "file_path": r"C:\Users\oliver.kim\Downloads\CreativeReview.iso",
        "file_name": "CreativeReview.iso",
        "command": r"explorer.exe C:\Users\oliver.kim\Downloads\CreativeReview.iso",
        "registry_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\CreativeReview",
        "service": "CreativeReviewSvc",
        "scheduled_task": r"\CreativeReview\Logon",
        "encoded_powershell": "",
        "screenconnect_id": "feedfacecafebeef",
    },
]


def _load_jsonl(path: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _build_empty_contract() -> Dict[str, Any]:
    return deepcopy(_ioc_contract.build_empty_ioc_extraction())


def _build_expected_extraction(case: Dict[str, str]) -> Dict[str, Any]:
    payload = _build_empty_contract()
    payload["affected_hosts"] = [case["host"]]
    payload["affected_users"] = [{"username": case["user"], "sid": ""}]
    payload["authentication_iocs"]["compromised_users"] = [{"username": case["user"], "sid": ""}]
    payload["network_iocs"]["ipv4"] = [{"value": case["ipv4"].replace("[.]", "."), "port": None, "context": "Observed network IOC"}]
    payload["network_iocs"]["domains"] = [{"value": case["domain"].replace("[.]", "."), "context": "Observed domain IOC"}]
    payload["network_iocs"]["urls"] = [{"value": case["url"].replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", "."), "context": "Observed URL IOC"}]
    payload["file_iocs"]["hashes"] = [{"value": case["hash"], "type": "sha256", "filename": case["file_name"], "context": "Observed file hash"}]
    payload["file_iocs"]["file_paths"] = [{"value": case["file_path"], "context": "Observed file path"}]
    payload["file_iocs"]["file_names"] = [case["file_name"]]
    payload["process_iocs"]["commands"] = [{"full_command": case["command"], "executable": "", "parent_process": "", "user": case["user"], "pid": ""}]
    payload["process_iocs"]["services"] = [{"name": case["service"], "path": "", "action": "create"}]
    payload["process_iocs"]["scheduled_tasks"] = [{"name": case["scheduled_task"], "path": "", "command": ""}]
    payload["persistence_iocs"]["registry"] = [{"key": case["registry_key"], "value_name": "", "value_data": "", "action": "create"}]
    if case.get("encoded_powershell"):
        payload["raw_artifacts"]["encoded_powershell"] = [case["encoded_powershell"]]
    if case.get("screenconnect_id"):
        payload["raw_artifacts"]["screenconnect_ids"] = [case["screenconnect_id"]]
    return payload


def _extract_raw_report_text(row: Dict[str, Any]) -> str:
    report_text = str(row.get("report_text") or "").strip()
    if report_text:
        return report_text
    conversations = row.get("conversations", [])
    human_value = next((item["value"] for item in conversations if item.get("from") == "human"), "")
    if "\n\n" not in human_value:
        return human_value.strip()
    return human_value.split("\n\n", 1)[1].strip()


def _build_huntress_rows(limit: int = 10) -> List[Dict[str, Any]]:
    rows = _load_jsonl(SOURCE_HUNTRESS_DATASET)
    selected = []
    seen_reports = set()
    for row in rows:
        report_text = _extract_raw_report_text(row)
        expected = row.get("expected_extraction")
        if not report_text or not expected:
            conversations = row.get("conversations", [])
            expected = expected or json.loads(next(item["value"] for item in conversations if item.get("from") == "gpt"))
        report_id = str(row.get("report_id") or f"huntress-{len(selected) + 1:02d}")
        if report_id in seen_reports:
            continue
        seen_reports.add(report_id)
        selected.append(
            {
                "report_id": report_id,
                "vendor": "huntress",
                "source_type": "real_user_provided",
                "layout_family": LAYOUT_FAMILIES[len(selected) % len(LAYOUT_FAMILIES)],
                "report_text": report_text,
                "expected_extraction": expected,
            }
        )
        if len(selected) >= limit:
            break
    return selected


def _synthetic_row(vendor: str, case: Dict[str, str], index: int) -> Dict[str, Any]:
    template = SYNTHETIC_VENDOR_TEMPLATES[vendor]
    report_text = template.format(**case)
    return {
        "report_id": f"{vendor}-{index + 1:02d}",
        "vendor": vendor,
        "source_type": "synthetic_backfill",
        "layout_family": LAYOUT_FAMILIES[index % len(LAYOUT_FAMILIES)],
        "report_text": report_text,
        "expected_extraction": _build_expected_extraction(case),
    }


def build_vendor_corpus_rows() -> List[Dict[str, Any]]:
    rows = _build_huntress_rows(limit=10)
    for vendor in SYNTHETIC_VENDOR_TEMPLATES:
        rows.extend(
            _synthetic_row(vendor, case, index)
            for index, case in enumerate(SYNTHETIC_CASES[:MIN_REPORTS_PER_VENDOR])
        )
    return rows


def _manifest_rows(rows: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = list(rows)
    vendor_counts: Dict[str, int] = {}
    source_counts: Dict[str, int] = {}
    for row in rows:
        vendor_counts[row["vendor"]] = vendor_counts.get(row["vendor"], 0) + 1
        source_counts[row["source_type"]] = source_counts.get(row["source_type"], 0) + 1
    return {
        "minimums": {
            "vendors": MIN_VENDOR_COUNT,
            "reports_per_vendor": MIN_REPORTS_PER_VENDOR,
            "total_reports": MIN_TOTAL_REPORTS,
        },
        "counts": {
            "total_reports": len(rows),
            "vendors": len(vendor_counts),
            "by_vendor": vendor_counts,
            "by_source_type": source_counts,
        },
        "decision_thresholds": {
            "core_regex_coverage_target": 0.90,
            "command_and_process_coverage_floor": 0.70,
            "remediation_separation_floor": 0.80,
        },
        "real_report_priority": [
            "Use real public or user-provided reports first.",
            "Use synthetic backfill only where real samples are sparse.",
            "Drive design decisions from real-report results before synthetic results.",
        ],
        "available_real_unlabeled_reports": {
            "reports_mdr_dir": MDR_REPORT_DIR,
            "count": len([name for name in os.listdir(MDR_REPORT_DIR) if name.endswith(".txt")]) if os.path.isdir(MDR_REPORT_DIR) else 0,
        },
    }


def write_vendor_corpus(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    os.makedirs(TRAINING_DATA_DIR, exist_ok=True)
    with open(OUTPUT_CORPUS, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")
    manifest = _manifest_rows(rows)
    manifest["files"] = {"corpus": OUTPUT_CORPUS}
    with open(OUTPUT_MANIFEST, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=True)
        handle.write("\n")
    return manifest


def main() -> None:
    rows = build_vendor_corpus_rows()
    manifest = write_vendor_corpus(rows)
    print(json.dumps({"rows_written": len(rows), "manifest": OUTPUT_MANIFEST, "counts": manifest["counts"]}, ensure_ascii=True))


if __name__ == "__main__":
    main()
