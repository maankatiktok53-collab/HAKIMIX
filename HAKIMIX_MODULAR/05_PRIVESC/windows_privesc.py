#!/usr/bin/env python3
"""PRIVESC / windows_privesc: read-only local Windows privilege checks.

Standalone:
    python3 05_PRIVESC/windows_privesc.py -y

Importable:
    run(target, workspace, config, logger, options) -> dict
"""

from __future__ import annotations

import argparse
import platform
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cli import base_parser, prepare  # noqa: E402
from core.utils import clean_lines, ensure_logger, module_envelope, run_command, truncate, utcnow, write_text  # noqa: E402


def _shell(cmd: List[str], timeout: int, workspace: Any, filename: str, logger: Any, limit: int = 400) -> Dict[str, Any]:
    result = run_command(cmd, timeout=timeout)
    text = result.get("stdout", "") + ("\n" + result.get("stderr", "") if result.get("stderr", "") else "")
    if filename:
        write_text(workspace.file("privesc", filename), truncate(text, 100000))
    if result.get("error"):
        logger.debug("%s: %s", cmd[0], result["error"])
    return {"command": cmd, "returncode": result.get("returncode"), "output": truncate(text, 20000), "lines": clean_lines(text, limit), "error": result.get("error", "")}


def _findings(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for item in data.get("unquoted_service_paths", []):
        findings.append({
            "title": "Unquoted service path with spaces",
            "severity": "medium",
            "status": "needs_verification",
            "evidence": item,
            "recommendation": "Verify service binary permissions and path parsing before reporting; no service was modified.",
            "source": "privesc-windows",
        })
    for item in data.get("writable_service_dirs", []):
        findings.append({
            "title": "Service binary directory writable by current user",
            "severity": "high",
            "status": "needs_verification",
            "evidence": item,
            "recommendation": "Confirm the service account and ACLs; no binary was replaced.",
            "source": "privesc-windows",
        })
    for item in data.get("always_install_elevated", []):
        findings.append({
            "title": "AlwaysInstallElevated registry setting observed",
            "severity": "high",
            "status": "confirmed",
            "evidence": item,
            "recommendation": "Verify both registry values before reporting; no MSI was executed.",
            "source": "privesc-windows",
        })
    for item in data.get("scheduled_tasks", {}).get("lines", []):
        if re.search(r"\b(SYSTEM|admin)\b", item, re.IGNORECASE):
            findings.append({
                "title": "Scheduled task appears to run with elevated account",
                "severity": "low",
                "status": "needs_verification",
                "evidence": item[:300],
                "recommendation": "Verify the task action and file permissions before reporting.",
                "source": "privesc-windows",
            })
    return findings[:100]


def run(
    target: str,
    workspace: Any,
    config: Dict[str, Any],
    logger: Any,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Collect read-only Windows local privilege-escalation information."""
    options = options or {}
    logger = ensure_logger(logger, "windows")
    started = utcnow()
    cached = workspace.fresh_json(
        "privesc", "windows.json",
        config.get("general", {}).get("max_result_age_hours", 24),
        options.get("reuse", False),
    )
    if isinstance(cached, dict) and cached.get("status") in ("success", "partial", "skipped"):
        logger.info("reusing cached Windows privesc results")
        return cached
    if platform.system() != "Windows":
        data = {"skipped": True, "reason": f"windows_privesc requires Windows (detected {platform.system()})"}
        envelope = module_envelope("windows", target, data, "skipped", [], started)
        workspace.save("privesc", "windows.json", envelope)
        return envelope

    timeout = int(options.get("timeout", config.get("general", {}).get("default_timeout", 120)))
    errors: List[str] = []
    data: Dict[str, Any] = {
        "platform": "Windows",
        "system": {},
        "user": {},
        "privileges": {},
        "services": {},
        "unquoted_service_paths": [],
        "writable_service_dirs": [],
        "scheduled_tasks": {},
        "software": {},
        "always_install_elevated": [],
        "findings": [],
        "read_only": True,
    }
    try:
        data["system"]["systeminfo"] = _shell(["systeminfo"], min(timeout, 60), workspace, "systeminfo.txt", logger, limit=80)
        data["user"]["whoami"] = _shell(["whoami", "/all"], min(timeout, 20), workspace, "whoami_all.txt", logger, limit=100)
        data["user"]["groups"] = _shell(["net", "user"], min(timeout, 30), workspace, "net_user.txt", logger, limit=100)
        data["privileges"] = _shell(["whoami", "/priv"], min(timeout, 20), workspace, "whoami_priv.txt", logger, limit=100)
        data["services"] = _shell(["sc", "query", "type=", "service", "state=", "all"], min(timeout, 60), workspace, "services.txt", logger, limit=300)
        paths = _shell(
            ["wmic", "service", "get", "name,pathname,startmode,startname", "/format:csv"],
            min(timeout, 60), workspace, "service_paths.txt", logger, limit=300,
        )
        for line in paths["lines"]:
            stripped = line.strip()
            if " " in stripped and re.search(r":[\\/].*\s.*", stripped) and not re.search(r'"[^"]+"', stripped):
                data["unquoted_service_paths"].append(stripped[:300])
        data["scheduled_tasks"] = _shell(["schtasks", "/query", "/fo", "LIST", "/v"], min(timeout, 60), workspace, "schtasks.txt", logger, limit=300)
        data["software"] = _shell(
            ["wmic", "product", "get", "name,version,vendor", "/format:csv"],
            min(timeout, 60), workspace, "software.txt", logger, limit=300,
        )
        for key in (
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        ):
            result = _shell(["reg", "query", key, "/v", "AlwaysInstallElevated"], min(timeout, 15), workspace, "", logger, limit=20)
            if result.get("returncode") == 0 and "0x1" in result.get("output", ""):
                data["always_install_elevated"].append(f"{key}: {result['output'][:200]}")
        for directory in (Path(r"C:\Program Files"), Path(r"C:\Program Files (x86)"), Path(r"C:\Windows\Temp")):
            if directory.exists():
                try:
                    if __import__("os").access(str(directory), __import__("os").W_OK):
                        data["writable_service_dirs"].append(str(directory))
                except OSError as exc:
                    logger.debug("access check failed for %s: %s", directory, exc)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"local collection error: {type(exc).__name__}: {exc}")

    data["findings"] = _findings(data)
    status = "partial" if errors else "success"
    envelope = module_envelope("windows", target, data, status, errors, started)
    workspace.save("privesc", "windows.json", envelope)
    logger.info("windows privesc complete: %d finding(s)", len(data["findings"]))
    return envelope


def main(argv: Optional[List[str]] = None) -> int:
    parser = base_parser(
        "HAKIMIX PRIVESC - read-only Windows local privilege-escalation checks",
        "Run only on a system you are authorized to inspect. No changes or exploitation are performed.",
    )
    args = parser.parse_args(argv)
    if not args.target:
        args.target = "localhost"
    target, workspace, config, logger, options = prepare(args, "windows")
    envelope = run(target, workspace, config, logger, options)
    print(f"[windows] status={envelope['status']} findings={len(envelope['data'].get('findings', []))} output={workspace.dir('privesc')}")
    if envelope["data"].get("reason"):
        print(f"[note] {envelope['data']['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
