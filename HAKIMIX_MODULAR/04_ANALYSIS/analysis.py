#!/usr/bin/env python3
"""ANALYSIS module: correlate recon/web/network data without overclaiming.

Standalone:
    python3 04_ANALYSIS/analysis.py 10.10.11.25 -y
    python3 04_ANALYSIS/analysis.py 10.10.11.25 -y --reuse

Importable:
    run(target, workspace, config, logger, options) -> dict
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cli import base_parser, prepare  # noqa: E402
from core.utils import dedupe, ensure_logger, module_envelope, utcnow  # noqa: E402

INTERESTING_SERVICES = {
    "ssh": "Remote access; check authentication policy and version",
    "ftp": "Often allows anonymous access or exposes files",
    "smb": "Samba/SMB may expose shares or sign issues",
    "microsoft-ds": "SMB service; enumerate shares if authorized",
    "http": "Web application attack surface",
    "https": "Web application and TLS surface",
    "http-alt": "Alternate HTTP service",
    "mysql": "Database service; check exposed credentials/config",
    "postgresql": "Database service; check exposed credentials/config",
    "mssql": "Database service; check exposed credentials/config",
    "smtp": "Mail service; check relaying configuration",
    "rdp": "Remote desktop; check version and authentication",
    "ms-wbt-server": "Remote desktop service",
    "telnet": "Cleartext remote access",
    "vnc": "Remote display; check authentication",
    "redis": "Redis service; check exposure",
    "docker": "Docker API may be unauthenticated",
    "ldap": "Directory service may leak information",
}

VERSION_WATCHLIST = [
    (r"apache[/ ]?2\.4\.(49|50)\b", "Apache 2.4.49/2.4.50", "Publicly documented path-traversal advisories exist for these versions", "high"),
    (r"vsftpd\s*2\.3\.4", "vsftpd 2.3.4", "This version is historically associated with a backdoor in public references", "critical"),
    (r"openssh[/ ]?(?:[1-6]\.|7\.[0-4]\b)", "Old OpenSSH version", "Review version-specific advisories before reporting", "medium"),
    (r"iis[/ ]?(?:6\.0|7\.5|8\.5)\b", "Old IIS version", "Review version-specific advisories before reporting", "medium"),
    (r"php[/ ]?(?:5\.|7\.[0-3]\b)", "End-of-life PHP line", "Confirm exact version and supported status", "medium"),
    (r"tomcat.*(?:8\.0|9\.0\.[0-8]\b)", "Older Tomcat line", "Check exposed manager/examples applications manually", "medium"),
    (r"smbv1|samba.*3\.[0-5]\b", "Legacy SMB/Samba version", "Verify SMBv1 support and signing configuration", "medium"),
    (r"wordpress", "WordPress detected", "Check plugin/theme versions only after confirming them", "info"),
    (r"phpmyadmin", "phpMyAdmin detected", "Check exposed setup/config pages manually", "medium"),
    (r"jenkins", "Jenkins detected", "Check exposed script console and version", "medium"),
]

HIGH_VALUE_PORTS = {21, 22, 23, 25, 80, 443, 445, 1433, 1521, 3306, 3389, 5432, 5985, 6379, 8080, 8443}


def _payload(workspace: Any, module: str) -> Dict[str, Any]:
    raw = workspace.load_module(module, {})
    if not isinstance(raw, dict):
        return {}
    data = raw.get("data", raw)
    return data if isinstance(data, dict) else {}


def _finding(title: str, status: str, severity: str, evidence: str, recommendation: str, source: str) -> Dict[str, Any]:
    return {
        "title": title,
        "status": status,
        "severity": severity,
        "evidence": evidence[:500],
        "recommendation": recommendation,
        "source": source,
    }


def _analyse(workspace: Any) -> Dict[str, Any]:
    recon = _payload(workspace, "recon")
    network = _payload(workspace, "network")
    web = _payload(workspace, "web")
    privesc = _payload(workspace, "privesc")
    crypto = _payload(workspace, "hash")

    ports = network.get("ports", []) or []
    services = network.get("services", []) or []
    open_ports = network.get("open_ports", []) or []
    urls = web.get("urls", []) or []
    technologies = web.get("technologies", []) or []

    findings: List[Dict[str, Any]] = []
    priorities: List[Dict[str, Any]] = []
    next_steps: List[str] = []
    inventory: Dict[str, Any] = {}

    resolved = recon.get("resolved_ips", []) or []
    domains = (recon.get("handoff", {}) or {}).get("domains", []) or []
    inventory["domains"] = domains
    inventory["ips"] = resolved or ([workspace.target] if recon.get("target_type") == "ip" else [])
    inventory["open_ports"] = open_ports
    inventory["services"] = [
        {
            "port": service.get("port"),
            "name": service.get("name") or service.get("service", ""),
            "product": service.get("product", ""),
            "version": service.get("version", ""),
        }
        for service in services
    ]
    inventory["web_urls"] = [item.get("url") if isinstance(item, dict) else item for item in urls]
    inventory["technologies"] = technologies
    inventory["dns_records"] = network.get("dns_records", {}) or {}

    for service in services:
        name = str(service.get("name") or service.get("service") or "").lower()
        port = service.get("port")
        product = str(service.get("product", ""))
        version = str(service.get("version", ""))
        banner = str(service.get("banner", ""))
        label = f"{product} {version}".strip() or name or f"port {port}"
        if name in INTERESTING_SERVICES or int(port or 0) in HIGH_VALUE_PORTS:
            priorities.append({
                "rank": 0,
                "target": f"{workspace.target}:{port}",
                "service": label,
                "reason": INTERESTING_SERVICES.get(name, "High-value port observed"),
                "evidence": f"service={name} product={product} version={version}",
            })
        blob = f"{name} {product} {version} {banner}".lower()
        for pattern, title, note, severity in VERSION_WATCHLIST:
            if re.search(pattern, blob):
                findings.append(_finding(
                    f"Version worth verifying: {title}",
                    "needs_verification",
                    severity,
                    f"Observed on port {port}: {label}. {note}",
                    "Confirm the exact version and test the specific behaviour manually before claiming a vulnerability.",
                    "analysis:version-watchlist",
                ))

    for item in open_ports:
        if int(item) not in HIGH_VALUE_PORTS:
            continue
        if not any(s.get("port") == item for s in services):
            priorities.append({
                "rank": 0,
                "target": f"{workspace.target}:{item}",
                "service": "unidentified",
                "reason": "High-value port open but service not identified",
                "evidence": f"Nmap state=open for port {item}",
            })

    for url_data in urls:
        url = url_data.get("url", "") if isinstance(url_data, dict) else str(url_data)
        status = url_data.get("status", "") if isinstance(url_data, dict) else ""
        findings.append(_finding(
            "HTTP service available",
            "confirmed",
            "info",
            f"{url} responded with HTTP {status}",
            "Inspect the application manually and enumerate content with the WEB module results.",
            "analysis:observation",
        ))
        next_steps.append(f"Review web findings for {url} (headers, paths, technologies) before testing anything actively.")

    for technology in technologies:
        label = technology if isinstance(technology, str) else str(technology.get("name", technology))
        next_steps.append(f"Confirm the exact version of {label} before searching for version-specific advisories.")

    for existing in (web.get("findings") or []):
        if not isinstance(existing, dict):
            continue
        status = str(existing.get("status", "needs_verification"))
        findings.append(_finding(
            str(existing.get("title", "Web finding")),
            "confirmed" if status == "confirmed" else "needs_verification",
            str(existing.get("severity", "info")),
            str(existing.get("evidence", "")),
            str(existing.get("recommendation", "Verify manually before reporting.")),
            str(existing.get("source", "web")),
        ))

    whois_fields = (recon.get("whois", {}) or {}).get("fields", {}) or {}
    if whois_fields:
        findings.append(_finding(
            "Public registration / ownership information available",
            "confirmed",
            "info",
            "; ".join(f"{key}={value}" for key, value in list(whois_fields.items())[:5]),
            "Use for context and scope confirmation only.",
            "analysis:recon",
        ))
    if recon.get("subdomains"):
        findings.append(_finding(
            "Subdomains discovered",
            "confirmed",
            "info",
            ", ".join(str(item.get("name", item)) for item in recon["subdomains"][:10]),
            "Expand scope only if these hosts are inside your authorization.",
            "analysis:recon",
        ))

    for finding in (privesc.get("linux_findings") or []) + (privesc.get("windows_findings") or []):
        if isinstance(finding, dict):
            findings.append(_finding(
                str(finding.get("title", "Local finding")),
                "confirmed" if finding.get("status") == "confirmed" else "needs_verification",
                str(finding.get("severity", "info")),
                str(finding.get("evidence", "")),
                str(finding.get("recommendation", "Verify locally before acting.")),
                str(finding.get("source", "privesc")),
            ))
    for item in (crypto.get("hashes") or []):
        if isinstance(item, dict) and item.get("identified_types"):
            findings.append(_finding(
                f"Hash identified: {item.get('hash', '')[:16]}...",
                "confirmed",
                "info",
                f"identified types: {', '.join(str(t) for t in item['identified_types'][:4])}",
                "Use the HASH module in offline mode with an authorized wordlist.",
                "hash",
            ))

    priorities = dedupe(priorities)
    for index, item in enumerate(sorted(priorities, key=lambda entry: (0 if str(entry["service"]) != "unidentified" else 1, str(entry["target"]))), start=1):
        item["rank"] = index
    if not priorities:
        next_steps.append("No high-value services identified from available data; review all open ports manually.")
    if open_ports:
        next_steps.append(f"Verify service versions on ports {', '.join(str(p) for p in open_ports[:10])} before any vulnerability claim.")
    if not recon:
        next_steps.append("Run the RECON module to add target context to this analysis.")
    if not network:
        next_steps.append("Run the NETWORK module to add ports and services to this analysis.")
    if not web:
        next_steps.append("Run the WEB module to add HTTP findings to this analysis.")
    next_steps.append("If local access is obtained, run the PRIVESC module in read-only mode.")
    next_steps.append("Keep all testing inside the authorized scope; no exploitation is performed by HAKIMIX.")

    confirmed = [f for f in findings if f["status"] == "confirmed"]
    potential = [f for f in findings if f["status"] != "confirmed"]
    summary = (
        f"Analysis of {workspace.target}: {len(open_ports)} open port(s), "
        f"{len(services)} identified service(s), {len(urls)} web URL(s), "
        f"{len(confirmed)} confirmed observation(s) and {len(potential)} item(s) requiring verification. "
        "No vulnerability is claimed without direct supporting evidence."
    )
    return {
        "summary": summary,
        "inventory": inventory,
        "prioritized_targets": priorities[:20],
        "findings": findings,
        "confirmed_findings": confirmed,
        "potential_findings": potential,
        "next_steps": dedupe(next_steps)[:30],
        "evidence_policy": "confirmed = directly observed; needs_verification = interpretation requiring manual validation",
    }


def run(
    target: str,
    workspace: Any,
    config: Dict[str, Any],
    logger: Any,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Correlate all available module JSON into analysis.json."""
    options = options or {}
    logger = ensure_logger(logger, "analysis")
    started = utcnow()
    cached = workspace.fresh_json(
        "analysis", "analysis.json",
        config.get("general", {}).get("max_result_age_hours", 24),
        options.get("reuse", False),
    )
    if isinstance(cached, dict) and cached.get("status") in ("success", "partial") and not options.get("force"):
        logger.info("reusing cached analysis results for %s", target)
        return cached
    data = _analyse(workspace)
    envelope = module_envelope("analysis", target, data, "success", [], started)
    workspace.save("analysis", "analysis.json", envelope)
    logger.info(
        "analysis complete: %d findings (%d confirmed), %d priorities",
        len(data["findings"]), len(data["confirmed_findings"]), len(data["prioritized_targets"]),
    )
    return envelope


def main(argv: Optional[List[str]] = None) -> int:
    parser = base_parser(
        "HAKIMIX ANALYSIS - correlate results, classify evidence and prioritise",
        "examples:\n  python3 analysis.py 10.10.11.25 -y\n  python3 analysis.py 10.10.11.25 -y --force",
    )
    parser.add_argument("--force", action="store_true", help="rebuild analysis even with --reuse")
    args = parser.parse_args(argv)
    target, workspace, config, logger, options = prepare(args, "analysis")
    options["force"] = args.force
    envelope = run(target, workspace, config, logger, options)
    print(f"[analysis] status={envelope['status']} findings={len(envelope['data']['findings'])} output={workspace.dir('analysis')}")
    print(f"[analysis] {envelope['data']['summary']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
