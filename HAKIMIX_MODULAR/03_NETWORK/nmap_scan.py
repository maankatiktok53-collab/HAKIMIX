#!/usr/bin/env python3
"""NETWORK / nmap_scan: controlled TCP port scan with XML output.

Standalone:
    python3 03_NETWORK/nmap_scan.py 10.10.11.25 -y
    python3 03_NETWORK/nmap_scan.py 10.10.11.25 -y --full-scan --timeout 900

Importable:
    run(target, workspace, config, logger, options) -> dict
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cli import base_parser, prepare  # noqa: E402
from core.nmap import (  # noqa: E402
    fallback_connect_scan,
    open_ports as collect_open_ports,
    parse_nmap_xml,
    web_ports as collect_web_ports,
    write_minimal_xml,
)
from core.utils import (  # noqa: E402
    ensure_logger,
    module_envelope,
    parse_port_spec,
    run_command,
    tool_available,
    truncate,
    utcnow,
    validate_target,
    write_text,
)


def run(
    target: str,
    workspace: Any,
    config: Dict[str, Any],
    logger: Any,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Scan TCP ports and save network/nmap.json plus XML results."""
    options = options or {}
    logger = ensure_logger(logger, "nmap")
    started = utcnow()
    errors: List[str] = []
    timeout = int(options.get("timeout", config.get("general", {}).get("default_timeout", 120)))
    scan_config = config.get("scan", {}).get("nmap", {})
    web_config = config.get("scan", {}).get("web", {})

    validation = validate_target(target)
    if not validation["valid"]:
        errors.append(f"invalid target: {validation['error']}")
        envelope = module_envelope("nmap", target, {}, "failed", errors, started)
        workspace.save("network", "nmap.json", envelope)
        return envelope
    value = validation["value"]

    cached = workspace.fresh_json(
        "network", "nmap.json",
        config.get("general", {}).get("max_result_age_hours", 24),
        options.get("reuse", False),
    )
    if isinstance(cached, dict) and cached.get("status") in ("success", "partial"):
        logger.info("reusing cached nmap results for %s", value)
        return cached

    full = bool(options.get("full_scan", False))
    spec = "1-65535" if full else str(scan_config.get("common_ports", "1-1000"))
    ports_requested = parse_port_spec(spec)
    xml_path = workspace.file("network", "nmap.xml")
    normal_path = workspace.file("network", "nmap.txt")
    tool = "nmap"
    command: list[str] = []
    warnings: List[str] = []

    if tool_available("nmap"):
        command = [
            "nmap",
            "-sS" if hasattr(os, "geteuid") and os.geteuid() == 0 else "-sT",
            "-p", spec,
            "-oX", str(xml_path),
            "-oN", str(normal_path),
            "--host-timeout", f"{max(timeout, 60)}s",
        ]
        if scan_config.get("service_version", False):
            command.extend(["-sV", "--version-intensity", str(scan_config.get("version_intensity", 2))])
        if scan_config.get("script_scan", False):
            command.append("-sC")
        command.append(value)
        if full:
            warnings.append("full 1-65535 TCP scan requested - this is slow and noisy")
        logger.info("running nmap: %s", " ".join(command))
        result = run_command(command, timeout=timeout)
        write_text(workspace.file("network", "nmap_raw.txt"), truncate(result.get("stdout", "") + "\n" + result.get("stderr", ""), 100000))
        if result.get("timed_out"):
            warnings.append(f"nmap timed out after {timeout}s; partial XML was kept if produced")
        if result.get("error"):
            errors.append(result["error"])
        if not xml_path.is_file():
            errors.append("nmap did not produce XML output")
    elif scan_config.get("tcp_connect_fallback", True):
        tool = "python-connect-scan"
        warnings.append("nmap not installed - using limited TCP connect() fallback")
        logger.warning("nmap missing; falling back to connect() scan")
        ports_requested = ports_requested[:2000]
        found = fallback_connect_scan(value, ports_requested, timeout=min(timeout, 300))
        write_minimal_xml(xml_path, value, found)
        write_text(normal_path, "\n".join(str(entry["port"]) for entry in found))
    else:
        errors.append("nmap is not installed and fallback scanning is disabled")

    parsed = parse_nmap_xml(xml_path)
    ports = parsed["ports"]
    if tool == "python-connect-scan" and not ports:
        ports = [
            {"port": entry["port"], "protocol": "tcp", "state": "open", "service": "", "product": "", "version": "", "banner": entry.get("banner", "")}
            for entry in fallback_connect_scan(value, ports_requested, timeout=min(timeout, 300))
        ]

    opened = collect_open_ports(ports)
    candidates = web_config.get("top_ports", [80, 443, 8080, 8443])
    data: Dict[str, Any] = {
        "tool": tool,
        "scan_profile": "full" if full else "common",
        "port_spec": spec,
        "command": command,
        "hosts": parsed["hosts"],
        "scan_info": parsed["scan_info"],
        "ports": ports,
        "open_ports": opened,
        "web_ports": collect_web_ports(ports, candidates),
        "nmap_xml": str(xml_path.relative_to(workspace.base)) if xml_path.is_file() else "",
        "nmap_normal": str(normal_path.relative_to(workspace.base)) if normal_path.is_file() else "",
        "warnings": warnings,
    }
    if not opened and not errors:
        warnings.append("no open TCP ports found in the requested range")

    status = "partial" if errors and opened else ("failed" if not opened and errors else "success")
    envelope = module_envelope("nmap", value, data, status, errors, started)
    workspace.save("network", "nmap.json", envelope)
    logger.info("nmap complete: %d open port(s)", len(opened))
    return envelope


def main(argv: Optional[List[str]] = None) -> int:
    parser = base_parser(
        "HAKIMIX NETWORK - TCP port scanning (Nmap XML output)",
        "examples:\n  python3 nmap_scan.py 10.10.11.25 -y\n  python3 nmap_scan.py 10.10.11.25 -y --full-scan --timeout 900",
    )
    parser.add_argument("--full-scan", action="store_true", help="scan all 65535 TCP ports (slow)")
    args = parser.parse_args(argv)
    target, workspace, config, logger, options = prepare(args, "nmap")
    options["full_scan"] = args.full_scan
    envelope = run(target, workspace, config, logger, options)
    print(
        f"[nmap] status={envelope['status']} open={len(envelope['data'].get('open_ports', []))} "
        f"output={workspace.dir('network')}"
    )
    for error in envelope.get("errors", []):
        print(f"[warn] {error}")
    for warning in envelope["data"].get("warnings", []):
        print(f"[note] {warning}")
    return 0 if envelope["status"] != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
