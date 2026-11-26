#!/usr/bin/env python3
"""Final report builder: TXT, JSON and HTML from shared module JSON files."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .paths import Workspace
from .utils import utcnow, write_json, write_text

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def _data(workspace: Workspace, module: str) -> Dict[str, Any]:
    payload = workspace.load_module(module, {})
    if not isinstance(payload, dict):
        return {}
    data = payload.get("data", payload)
    return data if isinstance(data, dict) else {}


def _lines(items: Any, formatter, empty: str = "  (none)") -> List[str]:
    values = items if isinstance(items, list) else []
    if not values:
        return [empty]
    return ["  " + formatter(item) for item in values]


def collect(workspace: Workspace) -> Dict[str, Any]:
    """Read every module result and build one normalised report structure."""
    recon = _data(workspace, "recon")
    network = _data(workspace, "network")
    web = _data(workspace, "web")
    analysis = _data(workspace, "analysis")
    privesc = _data(workspace, "privesc")
    crypto = _data(workspace, "hash")
    manifest = workspace.load_manifest()

    findings: List[Dict[str, Any]] = list(analysis.get("findings") or [])
    findings.extend(_as_findings(web.get("findings"), "web"))
    findings.extend(_as_findings(crypto.get("findings"), "hash"))
    findings.extend(_as_findings(privesc.get("linux_findings"), "privesc-linux"))
    findings.extend(_as_findings(privesc.get("windows_findings"), "privesc-windows"))
    findings = _dedupe_findings(findings)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(str(f.get("severity", "unknown")).lower(), 5), str(f.get("title", ""))))

    return {
        "generated_at": utcnow(),
        "target": {
            "value": workspace.target,
            "type": recon.get("target_type", "unknown"),
            "resolved_ips": recon.get("resolved_ips") or [],
            "reverse_dns": recon.get("reverse_dns") or [],
            "whois_available": bool(recon.get("whois")),
            "profile": recon.get("profile") or {},
        },
        "module_status": {
            name: entry.get("status", "not_run") for name, entry in manifest.get("modules", {}).items()
        },
        "open_ports": network.get("open_ports") or [],
        "ports": network.get("ports") or [],
        "services": network.get("services") or network.get("service_details") or [],
        "dns": {
            "records": network.get("dns_records") or {},
            "subdomains": network.get("subdomains") or recon.get("subdomains") or [],
        },
        "web": {
            "urls": web.get("urls") or [],
            "technologies": web.get("technologies") or [],
            "headers": web.get("headers") or {},
            "security_headers": web.get("security_headers") or {},
            "directory_hits": web.get("directory_hits") or [],
            "file_hits": web.get("file_hits") or [],
            "robots_txt": web.get("robots_txt", ""),
            "sitemap_xml": web.get("sitemap_xml", ""),
            "tls": web.get("tls") or {},
            "vhosts": web.get("vhosts") or [],
        },
        "analysis": {
            "summary": analysis.get("summary", "Analysis module has not been run."),
            "prioritized_targets": analysis.get("prioritized_targets") or [],
            "next_steps": analysis.get("next_steps") or [],
        },
        "findings": findings,
        "confirmed_findings": [f for f in findings if _status(f) == "confirmed"],
        "potential_findings": [f for f in findings if _status(f) != "confirmed"],
        "hash_analysis": {
            "hashes": crypto.get("hashes") or [],
            "file_analysis": crypto.get("file_analysis") or {},
            "crack_results": crypto.get("crack_results") or {},
        },
        "privesc": {
            "linux": privesc.get("linux") or {},
            "windows": privesc.get("windows") or {},
            "findings": [f for f in findings if str(f.get("source", "")).startswith("privesc")],
        },
        "data_files": workspace.tree_summary(),
        "disclaimer": "For authorized HTB / CTF / penetration testing only. No exploitation performed.",
    }


def _status(finding: Dict[str, Any]) -> str:
    return str(finding.get("status", "")).lower()


def _as_findings(items: Any, source: str) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    if not isinstance(items, list):
        return output
    for item in items:
        if isinstance(item, dict):
            entry = dict(item)
            entry.setdefault("source", source)
            output.append(entry)
    return output


def _dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    output = []
    for finding in findings:
        key = (str(finding.get("title", "")).lower(), str(finding.get("evidence", ""))[:200])
        if key not in seen:
            seen.add(key)
            output.append(finding)
    return output


def render_text(report: Dict[str, Any], max_lines: int = 400) -> str:
    target = report["target"]
    web = report["web"]
    out: List[str] = []

    def section(title: str) -> None:
        out.append("")
        out.append("=" * 72)
        out.append(title)
        out.append("=" * 72)

    out.append("HAKIMIX - FINAL REPORT")
    out.append(f"Generated: {report['generated_at']}")
    out.append(f"Target:    {target['value']} ({target['type']})")

    section("MODULE STATUS")
    for name, status in sorted(report["module_status"].items()):
        out.append(f"  {name:<12} {status}")

    section("TARGET INFORMATION")
    out.extend(_lines(target["resolved_ips"], lambda x: f"resolved IP: {x}"))
    out.extend(_lines(target["reverse_dns"], lambda x: f"reverse DNS: {x}"))
    out.append(f"  WHOIS data available: {target['whois_available']}")
    for key, value in (target["profile"] or {}).items():
        out.append(f"  {key}: {_short(value)}")

    section("OPEN PORTS")
    for port in report["open_ports"]:
        out.append(f"  {_port_text(port)}")

    section("DETECTED SERVICES")
    for service in report["services"]:
        out.append(f"  {_service_text(service)}")

    section("DNS FINDINGS")
    for rrtype, values in (report["dns"]["records"] or {}).items():
        out.extend(_lines(values, lambda x, t=rrtype: f"{t}: {x}", empty=""))
    out.extend(_lines(report["dns"]["subdomains"], lambda x: f"subdomain: {_short(x)}"))

    section("WEB FINDINGS")
    out.extend(_lines(web["urls"], lambda x: f"URL: {x}"))
    out.extend(_lines(web["technologies"], lambda x: f"technology: {_short(x)}"))
    for name, value in (web["security_headers"] or {}).items():
        out.append(f"  header {name}: {_short(value)}")
    out.extend(_lines(web["directory_hits"], lambda x: f"path: {_short(x)}"))
    out.extend(_lines(web["file_hits"], lambda x: f"file: {_short(x)}"))
    if web["tls"]:
        out.append(f"  TLS: {_short(web['tls'])}")
    out.extend(_lines(web["vhosts"], lambda x: f"vhost: {_short(x)}"))

    section("CONFIRMED FINDINGS")
    out.extend(_lines(report["confirmed_findings"], _finding_text, "  (none - no claim without evidence)"))

    section("POTENTIAL FINDINGS / NEEDS VERIFICATION")
    out.extend(_lines(report["potential_findings"], _finding_text))

    section("ANALYSIS")
    out.append(f"  {_short(report['analysis']['summary'], 4000)}")
    out.append("")
    out.append("  Prioritized targets:")
    out.extend(_lines(report["analysis"]["prioritized_targets"], lambda x: _short(x)))

    section("RECOMMENDED NEXT STEPS")
    out.extend(_lines(report["analysis"]["next_steps"], lambda x: _short(x)))

    section("HASH ANALYSIS")
    for item in report["hash_analysis"]["hashes"]:
        out.append(f"  {_short(item)}")
    if report["hash_analysis"]["crack_results"]:
        out.append(f"  crack results: {_short(report['hash_analysis']['crack_results'])}")

    section("PRIVILEGE ESCALATION FINDINGS")
    out.extend(_lines(report["privesc"]["findings"], _finding_text))

    section("OUTPUT FILES")
    for module, files in sorted(report["data_files"].items()):
        out.append(f"  {module}: {', '.join(files) if files else '(none)'}")

    out.append("")
    out.append(report["disclaimer"])
    text = "\n".join(out) + "\n"
    if len(out) > max_lines:
        text += f"\n[report truncated to {max_lines} lines; full data in report.json]\n"
        text = "\n".join(out[:max_lines]) + text
    return text


def render_html(report: Dict[str, Any]) -> str:
    esc = lambda value: html.escape(str(value), quote=True)

    def rows(items, formatter) -> str:
        if not items:
            return "<tr><td colspan='2' class='empty'>none</td></tr>"
        return "".join(f"<tr><td colspan='2'>{esc(formatter(item))}</td></tr>" for item in items)

    findings_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            esc(f.get("severity", "unknown")),
            esc(f.get("status", "unknown")),
            esc(f.get("title", "")),
            esc(f.get("evidence", "")),
        )
        for f in report["findings"]
    ) or "<tr><td colspan='4' class='empty'>No findings recorded.</td></tr>"

    ports = ", ".join(_port_text(p) for p in report["open_ports"]) or "none"
    services = "<br>".join(_service_text(s) for s in report["services"]) or "none"
    next_steps = "".join(f"<li>{esc(_short(x))}</li>" for x in report["analysis"]["next_steps"]) or "<li>none</li>"
    dns_rows = "".join(
        f"<tr><td>{esc(k)}</td><td>{esc(', '.join(str(v) for v in values))}</td></tr>"
        for k, values in (report["dns"]["records"] or {}).items()
    ) or "<tr><td colspan='2' class='empty'>none</td></tr>"

    status_rows = "".join(
        f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in sorted(report["module_status"].items())
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HAKIMIX report - {esc(report['target']['value'])}</title>
<style>
body {{ font-family: ui-monospace, monospace; background:#11151c; color:#d7e0ea; margin:0; padding:2rem; }}
h1 {{ color:#4fd1c5; }} h2 {{ color:#8ab4f8; border-bottom:1px solid #334; padding-bottom:.3rem; margin-top:2rem; }}
table {{ border-collapse:collapse; width:100%; margin:.8rem 0; }}
th, td {{ border:1px solid #334; padding:.45rem .6rem; text-align:left; vertical-align:top; font-size:.9rem; }}
th {{ background:#1c2430; color:#9ad; }} tr:nth-child(even) {{ background:#161c25; }}
.empty {{ color:#788; font-style:italic; }}
.note {{ color:#e6b450; }} pre {{ white-space:pre-wrap; }}
</style>
</head>
<body>
<h1>HAKIMIX - Final Report</h1>
<p>Target: <strong>{esc(report['target']['value'])}</strong> ({esc(report['target']['type'])}) &middot; Generated: {esc(report['generated_at'])}</p>
<p class="note">{esc(report['disclaimer'])}</p>

<h2>Module status</h2>
<table><tr><th>Module</th><th>Status</th></tr>{status_rows}</table>

<h2>Open ports</h2><pre>{esc(ports)}</pre>
<h2>Detected services</h2><pre>{esc(services)}</pre>

<h2>DNS findings</h2>
<table><tr><th>Type</th><th>Value</th></tr>{dns_rows}</table>
<p>Subdomains: {esc(', '.join(str(x) for x in report['dns']['subdomains'])) or 'none'}</p>

<h2>Web findings</h2>
<table>
<tr><th>URLs</th><td>{esc(', '.join(str(x) for x in report['web']['urls'])) or 'none'}</td></tr>
<tr><th>Technologies</th><td>{esc(', '.join(_short(x) for x in report['web']['technologies'])) or 'none'}</td></tr>
<tr><th>Directories</th><td>{esc(', '.join(_short(x) for x in report['web']['directory_hits'])) or 'none'}</td></tr>
<tr><th>Files</th><td>{esc(', '.join(_short(x) for x in report['web']['file_hits'])) or 'none'}</td></tr>
<tr><th>Security headers</th><td>{esc(', '.join(f'{k}={_short(v)}' for k, v in (report['web']['security_headers'] or {}).items())) or 'none'}</td></tr>
<tr><th>TLS</th><td>{esc(_short(report['web']['tls'])) or 'none'}</td></tr>
</table>

<h2>Findings (confirmed and potential)</h2>
<table><tr><th>Severity</th><th>Status</th><th>Title</th><th>Evidence</th></tr>{findings_rows}</table>

<h2>Analysis</h2><pre>{esc(_short(report['analysis']['summary'], 4000))}</pre>
<h2>Recommended next steps</h2><ul>{next_steps}</ul>

<h2>Hash analysis</h2><pre>{esc('\n'.join(_short(x) for x in report['hash_analysis']['hashes']) or 'none')}</pre>
<h2>Privilege escalation findings</h2>
<table><tr><th colspan='4'>{esc('; '.join(_short(x.get('title','')) for x in report['privesc']['findings']) or 'none')}</th></tr></table>
</body>
</html>
"""


def _short(value: Any, limit: int = 180) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, default=str)
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "..."


def _port_text(port: Any) -> str:
    if isinstance(port, dict):
        return f"{port.get('port', '?')}/{port.get('protocol', 'tcp')} {port.get('state', '')} {port.get('service', '')} {port.get('version', '')}".strip()
    return str(port)


def _service_text(service: Any) -> str:
    if isinstance(service, dict):
        return f"{service.get('port', '?')} {service.get('name', service.get('service', ''))} {service.get('version', '')} - {_short(service.get('product', service.get('info', '')), 120)}".strip()
    return str(service)


def _finding_text(finding: Any) -> str:
    if isinstance(finding, dict):
        return "[{}] {} ({}) - {}".format(
            finding.get("severity", "unknown"),
            finding.get("title", ""),
            finding.get("status", "unknown"),
            _short(finding.get("evidence", ""), 220),
        )
    return str(finding)


def generate(workspace: Workspace, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Write report.json, report.txt and report.html; return the collected data."""
    workspace.ensure()
    report = collect(workspace)
    max_lines = int((config or {}).get("general", {}).get("max_report_lines", 400))
    paths = {
        "json": workspace.file("report", "report.json"),
        "txt": workspace.file("report", "report.txt"),
        "html": workspace.file("report", "report.html"),
    }
    write_json(paths["json"], report)
    write_text(paths["txt"], render_text(report, max_lines))
    write_text(paths["html"], render_html(report))
    workspace.record("report", "success", data_files=[p.name for p in paths.values()])
    return report
