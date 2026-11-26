#!/usr/bin/env python3
"""NETWORK / service_enum: service/version detection and banner grabbing.

Standalone:
    python3 03_NETWORK/service_enum.py 10.10.11.25 -y
    python3 03_NETWORK/service_enum.py 10.10.11.25 -y --force-version

Importable:
    run(target, workspace, config, logger, options) -> dict
"""

from __future__ import annotations

import argparse
import re
import socket
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cli import base_parser, prepare  # noqa: E402
from core.nmap import fallback_connect_scan, parse_nmap_xml  # noqa: E402
from core.utils import (  # noqa: E402
    ensure_logger,
    module_envelope,
    parse_port_spec,
    run_command,
    tool_available,
    utcnow,
    validate_target,
    write_text,
)

HTTP_PORTS = {80, 443, 8000, 8008, 8080, 8443, 8888, 3000, 5000, 7000, 9000}
PROBES = {
    21: b"",
    22: b"",
    25: b"EHLO hakimix\r\n",
    110: b"",
    143: b"",
    587: b"EHLO hakimix\r\n",
    3306: b"",
    5432: b"",
}


def _clean_banner(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace")
    text = "".join(ch if ch.isprintable() or ch in "\r\n\t" else "." for ch in text)
    return text.strip()[:2000]


def _grab_banner(host: str, port: int, timeout: int, service: str = "") -> Dict[str, Any]:
    result: Dict[str, Any] = {"port": port, "banner": "", "error": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(max(1, min(timeout, 5)))
    try:
        sock.connect((host, port))
        probe = b""
        if port in HTTP_PORTS or "http" in service.lower():
            probe = f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: HAKIMIX/1.0\r\n\r\n".encode()
        elif port in PROBES:
            probe = PROBES[port]
        elif service.lower() in ("smtp", "ftp", "ssh"):
            probe = b"\r\n"
        if probe:
            sock.sendall(probe)
        sock.settimeout(max(1, min(timeout, 3)))
        result["banner"] = _clean_banner(sock.recv(2048))
    except (OSError, socket.timeout) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()
    return result


def _version_scan(target: str, ports: List[int], workspace: Any, config: Dict[str, Any], timeout: int, logger: Any) -> Dict[str, Any]:
    if not ports or not tool_available("nmap"):
        return {}
    xml_path = workspace.file("network", "services_nmap.xml")
    port_spec = ",".join(str(port) for port in ports[:100])
    command = ["nmap", "-sV", "--version-intensity", str(config.get("scan", {}).get("nmap", {}).get("version_intensity", 2)), "-p", port_spec, "-oX", str(xml_path), target]
    logger.info("running service version detection on %d port(s)", len(ports[:100]))
    result = run_command(command, timeout=timeout)
    write_text(workspace.file("network", "services_nmap_raw.txt"), result.get("stdout", "") + "\n" + result.get("stderr", ""))
    if result.get("timed_out"):
        logger.warning("service version scan timed out; partial results kept")
    return parse_nmap_xml(xml_path)


def run(
    target: str,
    workspace: Any,
    config: Dict[str, Any],
    logger: Any,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Identify services on ports already discovered by the nmap script."""
    options = options or {}
    logger = ensure_logger(logger, "service")
    started = utcnow()
    errors: List[str] = []
    warnings: List[str] = []
    timeout = int(options.get("timeout", config.get("general", {}).get("default_timeout", 120)))
    banner_timeout = int(config.get("scan", {}).get("service", {}).get("banner_timeout", 3))

    validation = validate_target(target)
    if not validation["valid"]:
        errors.append(f"invalid target: {validation['error']}")
        envelope = module_envelope("service", target, {}, "failed", errors, started)
        workspace.save("network", "service.json", envelope)
        return envelope
    value = validation["value"]

    cached = workspace.fresh_json(
        "network", "service.json",
        config.get("general", {}).get("max_result_age_hours", 24),
        options.get("reuse", False),
    )
    if isinstance(cached, dict) and cached.get("status") in ("success", "partial"):
        logger.info("reusing cached service results for %s", value)
        return cached

    nmap_payload = workspace.load("network", "nmap.json", {})
    nmap_data = nmap_payload.get("data", nmap_payload) if isinstance(nmap_payload, dict) else {}
    known_ports = nmap_data.get("ports", []) if isinstance(nmap_data, dict) else []
    discovered = sorted({int(p["port"]) for p in known_ports if p.get("state") == "open" and p.get("port")})
    if not discovered:
        warnings.append("no nmap results found; running a limited connect() scan")
        spec = config.get("scan", {}).get("nmap", {}).get("common_ports", "1-1000")
        found = fallback_connect_scan(value, parse_port_spec(spec)[:200], timeout=min(timeout, 60))
        discovered = [int(entry["port"]) for entry in found]

    versioned = {int(p["port"]): p for p in known_ports if p.get("state") == "open" and p.get("version")}
    need_version = [port for port in discovered if port not in versioned]
    if options.get("force_version"):
        need_version = discovered[:]
    version_data = _version_scan(value, need_version, workspace, config, timeout, logger) if need_version else {}
    version_entries = {int(p["port"]): p for p in version_data.get("ports", []) if p.get("state") == "open"}

    services: List[Dict[str, Any]] = []
    banners: Dict[str, str] = {}
    for port in discovered:
        base = dict(versioned.get(port, {}))
        base.update(version_entries.get(port, {}))
        name = str(base.get("service") or base.get("name") or "unknown")
        banner = _grab_banner(value, port, banner_timeout, name)
        if banner["banner"]:
            banners[str(port)] = banner["banner"]
        entry = {
            "port": port,
            "protocol": base.get("protocol", "tcp"),
            "name": name,
            "product": base.get("product", ""),
            "version": base.get("version", ""),
            "extrainfo": base.get("extrainfo", ""),
            "method": base.get("method", ""),
            "confidence": base.get("confidence", ""),
            "banner": banner["banner"],
            "banner_error": banner["error"],
            "source": "nmap+socket" if base else "socket",
        }
        services.append(entry)

    write_text(
        workspace.file("network", "banners.txt"),
        "\n\n".join(f"--- port {port} ---\n{banner}" for port, banner in banners.items()),
    )
    if not discovered:
        errors.append("no open ports available for service enumeration")
    status = "partial" if errors or warnings else "success"
    data: Dict[str, Any] = {
        "tool": "nmap -sV + python sockets" if tool_available("nmap") else "python sockets",
        "services": services,
        "service_details": services,
        "banners": banners,
        "ports_scanned": discovered,
        "version_scan_ports": need_version[:100],
        "version_scan_xml": "services_nmap.xml" if version_data else "",
        "warnings": warnings,
    }
    envelope = module_envelope("service", value, data, status, errors, started)
    workspace.save("network", "service.json", envelope)
    logger.info("service enumeration complete: %d service(s)", len(services))
    return envelope


def main(argv: Optional[List[str]] = None) -> int:
    parser = base_parser(
        "HAKIMIX NETWORK - service identification, versions and banners",
        "examples:\n  python3 service_enum.py 10.10.11.25 -y\n  python3 service_enum.py 10.10.11.25 -y --force-version",
    )
    parser.add_argument("--force-version", action="store_true", help="run nmap -sV even if versions are cached")
    args = parser.parse_args(argv)
    target, workspace, config, logger, options = prepare(args, "service")
    options["force_version"] = args.force_version
    envelope = run(target, workspace, config, logger, options)
    print(f"[service] status={envelope['status']} services={len(envelope['data'].get('services', []))} output={workspace.dir('network')}")
    for error in envelope.get("errors", []):
        print(f"[warn] {error}")
    return 0 if envelope["status"] != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
