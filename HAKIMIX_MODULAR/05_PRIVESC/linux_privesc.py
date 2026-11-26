#!/usr/bin/env python3
"""PRIVESC / linux_privesc: read-only local Linux privilege checks.

Standalone:
    python3 05_PRIVESC/linux_privesc.py -y

Importable:
    run(target, workspace, config, logger, options) -> dict
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cli import base_parser, prepare  # noqa: E402
from core.utils import clean_lines, ensure_logger, module_envelope, run_command, tool_available, truncate, utcnow, write_text  # noqa: E402

SUID_INTERESTING = {
    "nmap", "vim", "vi", "find", "python", "python3", "perl", "ruby", "bash", "sh",
    "cp", "nano", "awk", "less", "more", "tar", "zip", "rsync", "env", "php",
    "node", "lua", "irb", "gdb", "gcc", "man",
}
SENSITIVE_FILES = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d", "/root/.ssh", "/etc/crontab"]


def _shell(cmd: List[str], timeout: int, workspace: Any, filename: str, logger: Any, limit: int = 500) -> Dict[str, Any]:
    result = run_command(cmd, timeout=timeout)
    text = result.get("stdout", "") + ("\n" + result.get("stderr", "") if result.get("stderr", "") else "")
    if filename:
        write_text(workspace.file("privesc", filename), truncate(text, 100000))
    if result.get("error"):
        logger.debug("%s: %s", cmd[0], result["error"])
    return {"command": cmd, "returncode": result.get("returncode"), "output": truncate(text, 20000), "error": result.get("error", ""), "timed_out": result.get("timed_out", False), "lines": clean_lines(text, limit)}


def _find(workspace: Any, paths: List[str], permission: str, timeout: int, filename: str, logger: Any, limit: int) -> List[str]:
    existing = [path for path in paths if Path(path).exists()]
    results: List[str] = []
    for path in existing:
        cmd = ["find", path, "-xdev", "-perm", permission, "-type", "f" if permission.startswith("-") else "d"]
        result = _shell(cmd, min(timeout, 60), workspace, "", logger, limit=limit)
        results.extend(result["lines"])
        if len(results) >= limit:
            break
    write_text(workspace.file("privesc", filename), "\n".join(results[:limit]))
    return results[:limit]


def _cron(workspace: Any, timeout: int, logger: Any) -> Dict[str, Any]:
    collected: Dict[str, str] = {}
    sources: List[Path] = [Path("/etc/crontab")]
    cron_dir = Path("/etc/cron.d")
    if cron_dir.exists():
        sources.extend(sorted(cron_dir.glob("*")))
    for path in sources:
        if path.is_file():
            try:
                collected[str(path)] = truncate(path.read_text(encoding="utf-8", errors="replace"), 10000)
            except OSError as exc:
                logger.debug("cannot read %s: %s", path, exc)
    crontab = run_command(["crontab", "-l"], timeout=min(timeout, 10))
    if crontab.get("returncode") == 0 and crontab.get("stdout"):
        collected["user crontab"] = truncate(crontab["stdout"], 10000)
    write_text(workspace.file("privesc", "cron.txt"), "\n\n".join(f"--- {key} ---\n{value}" for key, value in collected.items()))
    return collected


def _packages(timeout: int, logger: Any, workspace: Any) -> Dict[str, List[str]]:
    output: Dict[str, List[str]] = {}
    if tool_available("dpkg-query"):
        result = _shell(["dpkg-query", "-W", "-f=${Package} ${Version}\n"], min(timeout, 40), workspace, "packages_dpkg.txt", logger, limit=1000)
        output["dpkg"] = result["lines"][:1000]
    elif tool_available("rpm"):
        result = _shell(["rpm", "-qa"], min(timeout, 40), workspace, "packages_rpm.txt", logger, limit=1000)
        output["rpm"] = result["lines"][:1000]
    elif tool_available("pacman"):
        result = _shell(["pacman", "-Q"], min(timeout, 40), workspace, "packages_pacman.txt", logger, limit=1000)
        output["pacman"] = result["lines"][:1000]
    return output


def _findings(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for item in data.get("suid", []) + data.get("sgid", []):
        name = Path(item).name
        if name in SUID_INTERESTING:
            findings.append({
                "title": f"Unusual SUID/SGID binary: {name}",
                "severity": "medium",
                "status": "needs_verification",
                "evidence": item,
                "recommendation": "Check whether this binary has a documented privilege-escalation path; do not exploit without explicit approval.",
                "source": "privesc-linux",
            })

    for item in data.get("writable_files", []):
        if item in SENSITIVE_FILES:
            findings.append({
                "title": f"Sensitive path writable by current user: {item}",
                "severity": "high",
                "status": "confirmed",
                "evidence": f"os.access({item}, W_OK) returned True for current user",
                "recommendation": "Verify file permissions and intended configuration before reporting.",
                "source": "privesc-linux",
            })

    sudo_output = str(data.get("sudo", {}).get("output", ""))
    if "nopasswd" in sudo_output.lower():
        findings.append({
            "title": "NOPASSWD sudo entries present",
            "severity": "medium",
            "status": "confirmed",
            "evidence": sudo_output[:400],
            "recommendation": "Review sudoers policy; no command was executed and no privilege change was attempted.",
            "source": "privesc-linux",
        })

    cron_text = "\n".join(str(v) for v in (data.get("cron", {}) or {}).values())
    if re.search(r"^\s*\*?\s*\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+.*root", cron_text, re.IGNORECASE | re.MULTILINE) or "root" in cron_text.lower():
        for writable in data.get("writable_files", []):
            if writable in cron_text:
                findings.append({
                    "title": "Cron job references a writable path",
                    "severity": "high",
                    "status": "needs_verification",
                    "evidence": f"cron content references {writable}, which is writable by current user",
                    "recommendation": "Confirm the cron entry runs with higher privileges before reporting.",
                    "source": "privesc-linux",
                })

    for capability in data.get("capabilities", {}).get("lines", []):
        if re.search(r"cap_(setuid|setgid|dac_override|sys_admin|sys_ptrace|net_raw)", capability, re.IGNORECASE):
            findings.append({
                "title": "Potentially sensitive file capability",
                "severity": "medium",
                "status": "needs_verification",
                "evidence": capability[:300],
                "recommendation": "Confirm the capability on the exact binary before claiming escalation.",
                "source": "privesc-linux",
            })
    return findings[:100]


def run(
    target: str,
    workspace: Any,
    config: Dict[str, Any],
    logger: Any,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Collect read-only Linux local privilege-escalation information."""
    options = options or {}
    logger = ensure_logger(logger, "linux")
    started = utcnow()
    cached = workspace.fresh_json(
        "privesc", "linux.json",
        config.get("general", {}).get("max_result_age_hours", 24),
        options.get("reuse", False),
    )
    if isinstance(cached, dict) and cached.get("status") in ("success", "partial", "skipped"):
        logger.info("reusing cached Linux privesc results")
        return cached
    if platform.system() != "Linux":
        data = {"skipped": True, "reason": f"linux_privesc requires Linux (detected {platform.system()})"}
        envelope = module_envelope("linux", target, data, "skipped", [], started)
        workspace.save("privesc", "linux.json", envelope)
        return envelope

    timeout = int(options.get("timeout", config.get("general", {}).get("default_timeout", 120)))
    privesc_config = config.get("scan", {}).get("privesc", {})
    max_suid = int(privesc_config.get("max_suid_results", 500))
    max_writable = int(privesc_config.get("max_writable_results", 300))
    errors: List[str] = []

    data: Dict[str, Any] = {
        "platform": platform.system(),
        "system": {},
        "kernel": platform.release(),
        "user": {},
        "sudo": {},
        "suid": [],
        "sgid": [],
        "writable_files": [],
        "writable_dirs": [],
        "cron": {},
        "processes": {},
        "capabilities": {},
        "packages": {},
        "findings": [],
        "read_only": True,
    }

    try:
        uname = _shell(["uname", "-a"], min(timeout, 15), workspace, "uname.txt", logger)
        data["system"]["uname"] = uname["lines"][0] if uname["lines"] else ""
        os_release = Path("/etc/os-release")
        if os_release.is_file():
            data["system"]["os_release"] = truncate(os_release.read_text(encoding="utf-8", errors="replace"), 4000)
        data["system"]["hostname"] = platform.node()
        data["user"]["id"] = _shell(["id"], min(timeout, 10), workspace, "id.txt", logger)["lines"]
        data["user"]["groups"] = _shell(["groups"], min(timeout, 10), workspace, "groups.txt", logger)["lines"]
        data["sudo"] = _shell(["sudo", "-n", "-l"], min(timeout, 15), workspace, "sudo_l.txt", logger, limit=200)
        data["suid"] = _find(workspace, privesc_config.get("suid_scan_paths", ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]), "-u=s", timeout, "suid.txt", logger, max_suid)
        data["sgid"] = _find(workspace, privesc_config.get("suid_scan_paths", ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]), "-g=s", timeout, "sgid.txt", logger, max_suid)
        data["writable_dirs"] = _find(workspace, privesc_config.get("writable_scan_paths", ["/etc", "/opt", "/tmp"]), "-o=w", timeout, "writable_dirs.txt", logger, max_writable)
        data["writable_files"] = [path for path in SENSITIVE_FILES if Path(path).exists() and os.access(path, os.W_OK)]
        data["cron"] = _cron(workspace, timeout, logger)
        data["processes"] = _shell(["ps", "auxww"], min(timeout, 20), workspace, "processes.txt", logger, limit=300)
        if tool_available("getcap"):
            data["capabilities"] = _shell(["getcap", "-r", "/usr", "/bin", "/sbin"], min(timeout, 60), workspace, "capabilities.txt", logger, limit=500)
        data["packages"] = _packages(timeout, logger, workspace)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"local collection error: {type(exc).__name__}: {exc}")

    data["findings"] = _findings(data)
    status = "partial" if errors else "success"
    envelope = module_envelope("linux", target, data, status, errors, started)
    workspace.save("privesc", "linux.json", envelope)
    logger.info("linux privesc complete: %d finding(s)", len(data["findings"]))
    return envelope


def main(argv: Optional[List[str]] = None) -> int:
    parser = base_parser(
        "HAKIMIX PRIVESC - read-only Linux local privilege-escalation checks",
        "Run only on a system you are authorized to inspect. No changes or exploitation are performed.",
    )
    args = parser.parse_args(argv)
    if not args.target:
        args.target = "localhost"
    target, workspace, config, logger, options = prepare(args, "linux")
    envelope = run(target, workspace, config, logger, options)
    print(f"[linux] status={envelope['status']} findings={len(envelope['data'].get('findings', []))} output={workspace.dir('privesc')}")
    for error in envelope.get("errors", []):
        print(f"[warn] {error}")
    return 0 if envelope["status"] != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
