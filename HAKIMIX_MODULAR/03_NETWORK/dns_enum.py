#!/usr/bin/env python3
"""NETWORK / dns_enum: DNS record enumeration and subdomain reuse.

Standalone:
    python3 03_NETWORK/dns_enum.py target.htb -y
    python3 03_NETWORK/dns_enum.py 10.10.11.25 -y -v

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
from core.utils import (  # noqa: E402
    clean_lines,
    dedupe,
    ensure_logger,
    module_envelope,
    run_command,
    tool_available,
    utcnow,
    validate_target,
    write_text,
)

FALLBACK_SUBDOMAINS = ["www", "mail", "ns1", "ns2", "admin", "dev", "test", "api", "ftp", "web"]


def _dig_query(kind: str, domain: str, timeout: int, logger: Any) -> List[str]:
    if not tool_available("dig"):
        return []
    result = run_command(["dig", "+short", kind, domain], timeout=min(timeout, 15))
    lines = clean_lines(result.get("stdout", ""))
    if result.get("error"):
        logger.debug("dig %s %s: %s", kind, domain, result["error"])
    return lines[:100]


def _socket_records(domain: str, timeout: int) -> Dict[str, List[str]]:
    records: Dict[str, List[str]] = {"A": [], "AAAA": []}
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(min(timeout, 5))
        for family, _, _, _, sockaddr in socket.getaddrinfo(domain, None):
            address = sockaddr[0]
            key = "AAAA" if family == socket.AF_INET6 else "A"
            if address not in records[key]:
                records[key].append(address)
    except (OSError, socket.gaierror):
        pass
    finally:
        socket.setdefaulttimeout(old)
    return records


def _fallback_subdomains(domain: str, timeout: int) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(min(timeout, 3))
        for prefix in FALLBACK_SUBDOMAINS:
            name = f"{prefix}.{domain}"
            try:
                _, _, addresses = socket.gethostbyname_ex(name)
                found.append({"name": name, "ips": sorted(set(addresses))})
            except (OSError, socket.gaierror):
                continue
    finally:
        socket.setdefaulttimeout(old)
    return found


def run(
    target: str,
    workspace: Any,
    config: Dict[str, Any],
    logger: Any,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Enumerate DNS records and hand off subdomains without rescanning recon."""
    options = options or {}
    logger = ensure_logger(logger, "dns")
    started = utcnow()
    errors: List[str] = []
    timeout = int(options.get("timeout", config.get("general", {}).get("default_timeout", 120)))
    dns_config = config.get("scan", {}).get("dns", {})
    record_types = list(dns_config.get("record_types", ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]))

    validation = validate_target(target)
    if not validation["valid"]:
        errors.append(f"invalid target: {validation['error']}")
        envelope = module_envelope("dns", target, {}, "failed", errors, started)
        workspace.save("network", "dns.json", envelope)
        return envelope
    value, target_type = validation["value"], validation["type"]

    cached = workspace.fresh_json(
        "network", "dns.json",
        config.get("general", {}).get("max_result_age_hours", 24),
        options.get("reuse", False),
    )
    if isinstance(cached, dict) and cached.get("status") in ("success", "partial"):
        logger.info("reusing cached DNS results for %s", value)
        return cached

    recon = workspace.load("recon", "recon.json", {})
    recon_data = recon.get("data", recon) if isinstance(recon, dict) else {}
    handoff = recon_data.get("handoff", {}) if isinstance(recon_data, dict) else {}
    domains = [name for name in handoff.get("domains", []) if isinstance(name, str) and "." in name]
    if target_type == "domain" and value not in domains:
        domains.insert(0, value)
    if not domains and target_type == "ip":
        domains = [name for name in recon_data.get("reverse_dns", []) if "." in name]

    data: Dict[str, Any] = {
        "tool": "dig" if tool_available("dig") else "python-socket",
        "queried_domains": domains,
        "dns_records": {},
        "reverse_dns": [],
        "subdomains": [],
        "subdomain_source": "",
        "warnings": [],
    }

    if target_type == "ip":
        data["reverse_dns"] = _dig_query("-x", value, timeout, logger)
        write_text(workspace.file("network", "dns_reverse.txt"), "\n".join(data["reverse_dns"]))
        if not data["reverse_dns"]:
            data["warnings"].append("no reverse DNS record for target IP")

    for domain in domains[:10]:
        records: Dict[str, List[str]] = {}
        for kind in record_types:
            values = _dig_query(kind, domain, timeout, logger)
            if values:
                records[kind] = values
            write_text(workspace.file("network", f"dns_{re.sub(r'[^A-Za-z0-9]', '', kind)}_{re.sub(r'[^A-Za-z0-9]', '_', domain)[:60]}.txt"), "\n".join(values))
        if not tool_available("dig"):
            records = _socket_records(domain, timeout)
            data["warnings"].append("dig unavailable; only A/AAAA records could be queried")
        data["dns_records"][domain] = records

    reused = handoff.get("subdomains", []) or []
    if reused:
        data["subdomains"] = dedupe(reused)
        data["subdomain_source"] = "recon"
    elif domains and target_type == "domain":
        data["subdomains"] = _fallback_subdomains(domains[0], timeout)
        data["subdomain_source"] = "dns_enum_fallback"
        data["warnings"].append("recon subdomain data absent; used small fallback wordlist")
    else:
        data["subdomain_source"] = "none"

    if not domains and not data["reverse_dns"]:
        errors.append("no domain names available for DNS enumeration")
    status = "partial" if errors or data["warnings"] else "success"
    envelope = module_envelope("dns", value, data, status, errors, started)
    workspace.save("network", "dns.json", envelope)
    logger.info("dns complete: %d domains, %d subdomains", len(domains), len(data["subdomains"]))
    return envelope


def main(argv: Optional[List[str]] = None) -> int:
    parser = base_parser(
        "HAKIMIX NETWORK - DNS A/AAAA/MX/NS/TXT/CNAME/SOA and subdomains",
        "examples:\n  python3 dns_enum.py target.htb -y\n  python3 dns_enum.py 10.10.11.25 -y",
    )
    args = parser.parse_args(argv)
    target, workspace, config, logger, options = prepare(args, "dns")
    envelope = run(target, workspace, config, logger, options)
    print(f"[dns] status={envelope['status']} domains={len(envelope['data'].get('queried_domains', []))} output={workspace.dir('network')}")
    for error in envelope.get("errors", []):
        print(f"[warn] {error}")
    return 0 if envelope["status"] != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
