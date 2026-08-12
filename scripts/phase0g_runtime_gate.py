#!/usr/bin/env python3
"""Collect Phase 0G runtime-gate evidence without touching production data."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(command: list[str], *, timeout: int = 15) -> dict:
    try:
        completed = subprocess.run(
            command,
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return {
            "command": command,
            "exit_code": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
        }
    except Exception as exc:
        return {"command": command, "exit_code": None, "stdout": "", "stderr": f"{type(exc).__name__}: {exc}"}


def _git_sha() -> str:
    return _run(["git", "rev-parse", "HEAD"])["stdout"] or "UNKNOWN"


def _os_release() -> dict:
    data = {}
    path = Path("/etc/os-release")
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                data[key] = value.strip().strip('"')
    return data


def _isolation() -> dict:
    tools = {
        "docker": shutil.which("docker"),
        "podman": shutil.which("podman"),
        "lxc": shutil.which("lxc"),
        "incus": shutil.which("incus"),
        "multipass": shutil.which("multipass"),
        "qemu-system-x86_64": shutil.which("qemu-system-x86_64"),
    }
    probes = {}
    if tools["docker"]:
        probes["docker_info"] = _run(["docker", "info"], timeout=10)
    if tools["podman"]:
        probes["podman_info"] = _run(["podman", "info"], timeout=10)
    if tools["lxc"]:
        probes["lxc_version"] = _run(["lxc", "version"], timeout=10)
    if tools["incus"]:
        probes["incus_version"] = _run(["incus", "version"], timeout=10)
    if tools["multipass"]:
        probes["multipass_version"] = _run(["multipass", "version"], timeout=10)
    usable = any(
        result.get("exit_code") == 0 and result.get("stdout")
        for result in probes.values()
        if isinstance(result, dict)
    )
    return {
        "tools": tools,
        "probes": probes,
        "usable_disposable_ubuntu_2404_environment_found": bool(usable),
        "fresh_install_gate": "NOT_EXECUTED" if not usable else "REQUIRES_EXPLICIT_RUN",
        "notes": "This probe does not initialize LXD/Incus, launch containers, or install virtualization tooling.",
    }


def _services() -> dict:
    names = ["postgresql", "clickhouse-server", "redis-server", "casescope-web", "casescope-workers", "casescope-beat"]
    return {name: _run(["systemctl", "is-active", name], timeout=5)["stdout"] for name in names}


def _github(repo: str, sha: str) -> dict:
    status = _run(["curl", "-fsSL", f"https://api.github.com/repos/{repo}/commits/{sha}/status"], timeout=20)
    runs = _run(["curl", "-fsSL", f"https://api.github.com/repos/{repo}/actions/runs?per_page=100"], timeout=20)
    parsed_status = {}
    associated_runs = []
    if status["exit_code"] == 0 and status["stdout"]:
        try:
            parsed_status = json.loads(status["stdout"])
        except json.JSONDecodeError:
            parsed_status = {"parse_error": True}
    if runs["exit_code"] == 0 and runs["stdout"]:
        try:
            payload = json.loads(runs["stdout"])
            associated_runs = [
                {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "status": item.get("status"),
                    "conclusion": item.get("conclusion"),
                    "head_sha": item.get("head_sha"),
                }
                for item in payload.get("workflow_runs", [])
                if item.get("head_sha") == sha
            ]
        except json.JSONDecodeError:
            associated_runs = [{"parse_error": True}]
    return {
        "repo": repo,
        "sha": sha,
        "method": "GitHub REST API",
        "combined_status_state": parsed_status.get("state"),
        "commit_status_contexts": parsed_status.get("total_count", 0),
        "workflow_runs": associated_runs,
        "workflow_run_count": len(associated_runs),
        "status_probe_exit_code": status["exit_code"],
        "runs_probe_exit_code": runs["exit_code"],
    }


def _load_json(path: str | None) -> dict | None:
    if not path:
        return None
    target = Path(path)
    if not target.exists():
        raise SystemExit(f"Result file does not exist: {target}")
    return json.loads(target.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="CaseScope/caseScope_2026")
    parser.add_argument("--scale-result")
    parser.add_argument("--fresh-install-result")
    parser.add_argument("--upgrade-result")
    parser.add_argument("--lifecycle-result")
    parser.add_argument("--permissions-result")
    parser.add_argument("--output", default=str(ROOT / "docs" / "investigation_graph_phase0g_runtime.json"))
    args = parser.parse_args()

    sha = _git_sha()
    scale = _load_json(args.scale_result)
    payload = {
        "tested_sha": sha,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "NOT_READY",
        "scale": scale or {"status": "FAIL", "reason": "No explicit Phase 0G scale result supplied."},
        "fresh_install": _load_json(args.fresh_install_result) or {"status": "FAIL", "reason": "Fresh Ubuntu 24.04 install validation not executed."},
        "upgrade_cohorts": (_load_json(args.upgrade_result) or {"status": "FAIL", "reason": "Supported upgrade cohorts not executed."}),
        "migration_convergence": {"status": "FAIL", "reason": "Complete migration sequence was not rerun twice on disposable databases."},
        "lifecycle": _load_json(args.lifecycle_result) or {"status": "FAIL", "reason": "Deployed CaseFile/PCAP/Memory/IOC lifecycle validation not executed."},
        "permanent_case_deletion": {"status": "FAIL", "reason": "Permanent case deletion E2E not executed."},
        "permissions": _load_json(args.permissions_result) or {"status": "FAIL", "reason": "Viewer/Analyst/Administrator deployed capability matrix not executed."},
        "cross_case": {"status": "FAIL", "reason": "Cross-case runtime negative corpus not executed."},
        "deployment_smoke": {"status": "FAIL", "reason": "Full disposable deployed smoke not executed."},
        "services": _services(),
        "host": {
            "os_release": _os_release(),
            "isolation": _isolation(),
        },
        "full_repo_baseline_comparison": {"status": "FAIL", "reason": "4.17.2 pytest collection baseline comparison not executed in this pass."},
        "github": _github(args.repo, sha),
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"event": "phase0g_runtime_gate", "output": str(output), "status": payload["status"]}))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
