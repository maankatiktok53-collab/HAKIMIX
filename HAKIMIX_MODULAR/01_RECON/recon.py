#!/usr/bin/env python3
"""RECON module: passive target validation, DNS/WHOIS and profiling.

Standalone:
    python3 01_RECON/recon.py 10.10.11.25 --yes
    python3 01_RECON/recon.py target.htb -y -v

Importable:
    run(target, workspace, config, logger, options) -> dict
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import re
import socket
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cli import base_parser, prepare  # noqa: E402
from core.utils import (
    clean_lines,
    ensure_logger,
    module_envelope,
    run_command,
    tool_available,
    truncate,
    utcnow,
    validate_target,
    write_text,
)

DEFAULT_SUBDOMAINS = [
    "www", "web", "mail", "ftp", "dns", "ns1", "ns2", "dev", "test", "admin",
    "portal", "blog", "api", "vpn", "remote", "git", "svn", "db", "sql", "mysql",
    "smtp", "pop", "imap", "cloud", "cdn", "static", "assets", "media", "img",
    "shop", "store", "support", "help", "wiki", "docs", "staging", "prod",
    "internal", "intranet", "auth", "sso", "login", "secure", "server", "backup",
]

WHOIS_FIELDS = ("org", "organization", "org-name", "netname", "country", "registrar", "abuse-mailbox", "descr")


def _load_wordlist(config: Dict[str, Any], options: Dict[str, Any], limit: int) -> List[str]:
    path = options.get("wordlist") or config.get("scan", {}).get("dns", {}).get("subdomain_wordlist", "")
    words: List[str] = []
    if path and Path(path).is_file():
        try:
            words = [
                line.strip().lower()
                for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip() and not line.startswith(("#", ";"))
            ]
        except OSError:
            words = []
    if not words:
        words = list(DEFAULT_SUBDOMAINS)
    return list(dict.fromkeys(words))[:limit]


def _reverse_dns(target: str, timeout: int, logger: Any) -> List[str]:
    names: List[str] = []
    if tool_available("dig"):
        result = run_command(["dig", "+short", "-x", target], timeout=min(timeout, 15))
        names.extend(clean_lines(result.get("stdout", ""))[:20])
    if not names:
        old_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(min(timeout, 5))
            names.append(socket.gethostbyaddr(target)[0])
        except (OSError, socket.herror, socket.gaierror):
            pass
        finally:
            socket.setdefaulttimeout(old_timeout)
    names = [n.rstrip(".") for n in names if n and "NXDOMAIN" not in n.upper()]
    logger.debug("reverse DNS for %s: %s", target, names)
    return list(dict.fromkeys(names))


def _resolution(domain: str, timeout: int, logger: Any) -> Dict[str, Any]:
    info: Dict[str, Any] = {"canonical": "", "aliases": [], "ipv4": [], "ipv6": []}
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(min(timeout, 8))
        canonical, aliases, addresses = socket.gethostbyname_ex(domain)
        info["canonical"] = canonical.rstrip(".")
        info["aliases"] = [a.rstrip(".") for a in aliases]
        info["ipv4"] = sorted(set(addresses))
    except (OSError, socket.gaierror) as exc:
        logger.debug("gethostbyname_ex failed for %s: %s", domain, exc)
    finally:
        socket.setdefaulttimeout(old_timeout)

    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(domain, None):
            address = sockaddr[0]
            if family == socket.AF_INET6 and address not in info["ipv6"]:
                info["ipv6"].append(address)
    except (OSError, socket.gaierror):
        pass
    return info


def _resolve_one(name: str, timeout: int) -> Optional[Dict[str, Any]]:
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(min(timeout, 4))
        _, _, addresses = socket.gethostbyname_ex(name)
        return {"name": name, "ips": sorted(set(addresses))}
    except (OSError, socket.gaierror):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def _subdomains(domain: str, config: Dict[str, Any], options: Dict[str, Any], logger: Any) -> List[Dict[str, Any]]:
    dns_config = config.get("scan", {}).get("dns", {})
    limit = min(int(dns_config.get("subdomain_limit", 200)), 500)
    words = _load_wordlist(config, options, limit)
    candidates = [f"{word}.{domain}" for word in words]
    found: List[Dict[str, Any]] = []
    workers = 10
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_resolve_one, name, options.get("timeout", 60)): name for name in candidates}
        for future in concurrent.futures.as_completed(futures):
            try:
                item = future.result()
                if item:
                    found.append(item)
            except Exception as exc:  # noqa: BLE001
                logger.debug("subdomain lookup error: %s", exc)
    found.sort(key=lambda item: item["name"])
    logger.info("subdomains found: %d", len(found))
    return found


def _whois(target: str, timeout: int, workspace: Any, logger: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"available": False, "raw": "", "fields": {}}
    if not tool_available("whois"):
        return data
    result = run_command(["whois", target], timeout=min(timeout, 20))
    raw = truncate(result.get("stdout", ""), 20000)
    if not raw.strip():
        raw = truncate(result.get("stderr", ""), 20000)
    write_text(workspace.file("recon", "whois.txt"), raw)
    data["raw"] = raw[:4000]
    data["available"] = bool(raw.strip())
    lowered = raw.lower()
    for field in WHOIS_FIELDS:
        match = re.search(rf"^\s*{re.escape(field)}\s*:?\s+(.+)$", raw, re.IGNORECASE | re.MULTILINE)
        if match:
            data["fields"][field] = match.group(1).strip()[:200]
    data["fields"]["mentions_hackthebox"] = "hackthebox" in lowered or "htb" in lowered
    logger.debug("whois available for %s: %s", target, data["available"])
    return data


def _profile(target: str, addresses: List[str], target_type: str, timeout: int, workspace: Any) -> Dict[str, Any]:
    profile: Dict[str, Any] = {"target_type": target_type, "is_private": None, "classification": "", "icmp": "not_tested"}
    if target_type == "ip":
        try:
            address = ipaddress.ip_address(target)
            profile["is_private"] = bool(address.is_private or address.is_loopback or address.is_link_local)
            profile["classification"] = (
                "loopback" if address.is_loopback else
                "link-local" if address.is_link_local else
                "private" if address.is_private else
                "public" if address.is_global else "reserved/special"
            )
        except ValueError:
            profile["classification"] = "unknown"
    else:
        profile["classification"] = "hostname"
        profile["resolved_count"] = len(addresses)

    if tool_available("ping") and target_type == "ip":
        result = run_command(["ping", "-c", "1", "-W", "1", target], timeout=min(timeout, 6))
        write_text(workspace.file("recon", "ping.txt"), result.get("stdout", "") + result.get("stderr", ""))
        if result.get("returncode") == 0:
            profile["icmp"] = "reachable"
            match = re.search(r"time=([\d.]+)\s*ms", result.get("stdout", ""))
            if match:
                profile["icmp_rtt_ms"] = float(match.group(1))
        elif result.get("timed_out"):
            profile["icmp"] = "timeout"
        elif result.get("error"):
            profile["icmp"] = "unavailable"
        else:
            profile["icmp"] = "no_reply"
    return profile


def run(
    target: str,
    workspace: Any,
    config: Dict[str, Any],
    logger: Any,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run passive reconnaissance for one target and save recon.json."""
    options = options or {}
    logger = ensure_logger(logger, "recon")
    started = utcnow()
    errors: List[str] = []
    timeout = int(options.get("timeout", config.get("general", {}).get("default_timeout", 120)))

    validation = validate_target(target)
    if not validation["valid"]:
        errors.append(f"invalid target: {validation['error']}")
        envelope = module_envelope("recon", target, {}, "failed", errors, started)
        workspace.save("recon", "recon.json", envelope)
        return envelope

    value, target_type = validation["value"], validation["type"]
    data: Dict[str, Any] = {
        "target": value,
        "target_type": target_type,
        "reverse_dns": [],
        "resolved_ips": [],
        "domains": [],
        "domain_info": {},
        "subdomains": [],
        "whois": {},
        "ip_info": {},
        "profile": {},
        "handoff": {},
    }

    cached = workspace.fresh_json(
        "recon", "recon.json",
        config.get("general", {}).get("max_result_age_hours", 24),
        options.get("reuse", False),
    )
    if isinstance(cached, dict) and cached.get("status") in ("success", "partial"):
        logger.info("reusing cached recon results for %s", value)
        return cached

    if target_type == "ip":
        data["reverse_dns"] = _reverse_dns(value, timeout, logger)
        write_text(workspace.file("recon", "reverse_dns.txt"), "\n".join(data["reverse_dns"]))
        data["ip_info"] = _whois(value, timeout, workspace, logger)
        data["domains"] = [name for name in data["reverse_dns"] if "." in name]
        data["resolved_ips"] = [value]
    else:
        data["domain_info"] = _resolution(value, timeout, logger)
        data["resolved_ips"] = list(dict.fromkeys(data["domain_info"]["ipv4"] + data["domain_info"]["ipv6"]))
        data["domains"] = [value]
        data["reverse_dns"] = data["domain_info"]["aliases"]
        data["whois"] = _whois(value, timeout, workspace, logger)
        data["subdomains"] = _subdomains(value, config, options, logger)
        write_text(
            workspace.file("recon", "subdomains.txt"),
            "\n".join(item["name"] for item in data["subdomains"]),
        )
        for item in data["subdomains"]:
            for address in item["ips"]:
                if address not in data["resolved_ips"]:
                    data["resolved_ips"].append(address)
        if not data["resolved_ips"]:
            errors.append("target hostname did not resolve to any IP address")

    data["profile"] = _profile(value, data["resolved_ips"], target_type, timeout, workspace)
    data["handoff"] = {
        "target_type": target_type,
        "domains": list(dict.fromkeys(data["domains"] + [item["name"] for item in data["subdomains"]])),
        "ips": data["resolved_ips"],
        "subdomains": data["subdomains"],
        "web_hints": [name for name in data["domains"] + [item["name"] for item in data["subdomains"]] if name],
        "note": "Use these values with NETWORK and WEB; do not rescan unchanged results.",
    }

    status = "partial" if errors else "success"
    envelope = module_envelope("recon", value, data, status, errors, started)
    workspace.save("recon", "recon.json", envelope)
    logger.info("recon complete: %d domains, %d IPs", len(data["domains"]), len(data["resolved_ips"]))
    return envelope


def main(argv: Optional[List[str]] = None) -> int:
    parser = base_parser(
        "HAKIMIX RECON - validation, reverse DNS, WHOIS, subdomains and profiling",
        "examples:\n  python3 recon.py 10.10.11.25 -y\n  python3 recon.py target.htb -y --wordlist /usr/share/wordlists/amass/subdomains.txt",
    )
    parser.add_argument("--wordlist", help="subdomain wordlist")
    args = parser.parse_args(argv)
    target, workspace, config, logger, options = prepare(args, "recon")
    options["wordlist"] = args.wordlist
    envelope = run(target, workspace, config, logger, options)
    print(f"[recon] status={envelope['status']} output={workspace.dir('recon')}")
    for error in envelope.get("errors", []):
        print(f"[warn] {error}")
    return 0 if envelope["status"] != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
