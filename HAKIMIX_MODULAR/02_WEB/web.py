#!/usr/bin/env python3
"""WEB module: HTTP detection, headers, technologies, paths, TLS and vhosts.

Standalone:
    python3 02_WEB/web.py 10.10.11.25 -y
    python3 02_WEB/web.py target.htb -y --nikto

Importable:
    run(target, workspace, config, logger, options) -> dict
"""

from __future__ import annotations

import argparse
import hashlib
import re
import socket
import ssl
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cli import base_parser, prepare  # noqa: E402
from core.utils import (  # noqa: E402
    build_url,
    clean_lines,
    dedupe,
    ensure_logger,
    guess_scheme,
    module_envelope,
    read_json,
    run_command,
    tool_available,
    truncate,
    utcnow,
    write_text,
)

DEFAULT_DIRS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "phpmyadmin",
    "robots.txt", "sitemap.xml", "index.html", "index.php", "README.md",
    ".git/HEAD", ".env", "config.php", "backup", "backup.zip", "uploads",
    "images", "css", "js", "assets", "static", "api", "docs", "test", "dev",
    "shell", "cgi-bin", "server-status", "server-info", "console", "dashboard",
    "mail", "webmail", "cpanel", "xmlrpc.php", "trace.axd", "git", "svn",
]

DEFAULT_VHOSTS = ["www", "admin", "dev", "test", "mail", "api", "portal", "static", "internal"]
SECURITY_HEADERS = (
    "strict-transport-security", "content-security-policy", "x-content-type-options",
    "x-frame-options", "referrer-policy", "permissions-policy",
)
COMMON_FILES = ["robots.txt", "sitemap.xml", ".git/HEAD", ".env", "index.html", "index.php", "README.md"]


def _web_targets(target: str, workspace: Any, config: Dict[str, Any], target_type: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Prefer ports discovered by NETWORK; never rescan already-known URLs."""
    network = workspace.load("network", "network.json", {}) or {}
    nmap = workspace.load("network", "nmap.json", {}) or {}
    payload = network.get("data", network)
    nmap_payload = nmap.get("data", nmap)
    discovered = payload.get("web_ports") or nmap_payload.get("web_ports") or []
    targets: List[Dict[str, Any]] = []
    for entry in discovered:
        if isinstance(entry, dict):
            port = int(entry.get("port", 0))
            scheme = entry.get("scheme") or guess_scheme(port)
            host = entry.get("host") or target
        else:
            port = int(entry)
            scheme = guess_scheme(port)
            host = target
        if not port:
            continue
        url = build_url(host, port, scheme, target_type == "ip")
        targets.append({"url": url, "port": port, "host": host, "scheme": scheme, "source": "network"})
    if not targets:
        for port in config.get("scan", {}).get("web", {}).get("top_ports", [80, 443, 8080, 8443]):
            targets.append({
                "url": build_url(target, int(port), guess_scheme(int(port)), target_type == "ip"),
                "port": int(port),
                "host": target,
                "scheme": guess_scheme(int(port)),
                "source": "config_default",
            })

    recon = workspace.load("recon", "recon.json", {})
    domains = (recon.get("data", recon).get("handoff", {}) or {}).get("domains", []) or []
    if target_type == "domain" and target not in domains:
        domains.insert(0, target)
    return dedupe(targets), domains


def _fetch(url: str, timeout: int, method: str = "GET", host_header: Optional[str] = None) -> Dict[str, Any]:
    cmd = ["curl", "-sS", "-k", "-L", "-m", str(max(2, timeout)), "-D", "-", "-o", "/dev/null", "-X", method]
    if host_header:
        cmd.extend(["-H", f"Host: {host_header}"])
    cmd.extend(["-w", "\n__HAKIMIX_STATUS__:%{http_code}\n__HAKIMIX_URL__:%{url_effective}", url])
    result = run_command(cmd, timeout=max(3, timeout + 5))
    output = result.get("stdout", "")
    status_match = re.search(r"__HAKIMIX_STATUS__:(\d+)", output)
    final_match = re.search(r"__HAKIMIX_URL__:([^\s]+)", output)
    header_text = output.split("__HAKIMIX_STATUS__")[0]
    headers: Dict[str, str] = {}
    for line in header_text.splitlines():
        if ":" in line and not line.startswith("HTTP/"):
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return {
        "url": url,
        "method": method,
        "status": int(status_match.group(1)) if status_match else 0,
        "final_url": final_match.group(1) if final_match else url,
        "headers": headers,
        "header_text": header_text.strip(),
        "error": result.get("error", ""),
        "stderr": truncate(result.get("stderr", ""), 1000),
    }


def _body(url: str, timeout: int, host_header: Optional[str] = None, limit: int = 20000) -> str:
    cmd = ["curl", "-sS", "-k", "-L", "-m", str(max(2, timeout)), url]
    if host_header:
        cmd[1:1] = ["-H", f"Host: {host_header}"]
    result = run_command(cmd, timeout=max(3, timeout + 5))
    return truncate(result.get("stdout", ""), limit)


def _tls(host: str, port: int, timeout: int) -> Dict[str, Any]:
    info: Dict[str, Any] = {"checked": True, "host": host, "port": port}
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=min(timeout, 6)) as raw:
            with context.wrap_socket(raw, server_hostname=host if not _is_ip(host) else None) as secure:
                cert = secure.getpeercert()
                info["version"] = secure.version()
                info["cipher"] = secure.cipher()[0] if secure.cipher() else ""
        if cert:
            info["subject"] = _cert_pairs(cert.get("subject", ()))
            info["issuer"] = _cert_pairs(cert.get("issuer", ()))
            info["not_before"] = cert.get("notBefore", "")
            info["not_after"] = cert.get("notAfter", "")
            info["san"] = [value for _, value in cert.get("subjectAltName", ())][:30]
            info["self_signed"] = info["subject"] == info["issuer"]
    except Exception as exc:  # noqa: BLE001
        info["error"] = f"{type(exc).__name__}: {exc}"
    return info


def _is_ip(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9.]+|[0-9A-Fa-f:]+", value))


def _cert_pairs(entries: Any) -> Dict[str, str]:
    output: Dict[str, str] = {}
    for item in entries:
        for key, value in item:
            output[str(key)] = str(value)
    return output


def _technologies(headers: Dict[str, str], body: str, whatweb_output: str) -> List[str]:
    found: set[str] = set()
    server = headers.get("server", "")
    if server:
        found.add(server.split()[0].title() if server else "")
    powered = headers.get("x-powered-by", "")
    if powered:
        found.add(powered.strip()[:80])
    cookies = headers.get("set-cookie", "")
    if "phpsessid" in cookies.lower():
        found.add("PHP (PHPSESSID)")
    if "jsessionid" in cookies.lower():
        found.add("Java (JSESSIONID)")
    if "asp.net_sessionid" in cookies.lower():
        found.add("ASP.NET")
    lowered = (body or "").lower()
    patterns = {
        "WordPress": ("wp-content", "wp-includes"),
        "Joomla": ("/administrator/", "joomla"),
        "Drupal": ("drupal.settings", "/sites/default/"),
        "Laravel": ("laravel_session", "laravel"),
        "Django": ("csrftoken", "django"),
        "phpMyAdmin": ("phpmyadmin",),
        "Bootstrap": ("bootstrap.min.css",),
        "jQuery": ("jquery.min.js", "jquery-"),
        "nginx": ("nginx",),
        "Apache": ("apache",),
        "Nextcloud": ("nextcloud",),
    }
    for name, needles in patterns.items():
        if any(needle in lowered for needle in needles):
            found.add(name)
    for match in re.finditer(r"^[^\[\n]+\[\d+\]\s+(.+)$", whatweb_output or "", re.MULTILINE):
        for token in re.split(r",\s*", match.group(1))[:12]:
            cleaned = re.sub(r"\[.*?\]", "", token).strip()
            if cleaned:
                found.add(cleaned[:80])
    return sorted(value for value in found if value)


def _wordlist(workspace: Any, config: Dict[str, Any], options: Dict[str, Any], kind: str) -> Optional[Path]:
    configured = options.get("wordlist") or config.get("scan", {}).get("web", {}).get(
        "directory_wordlist" if kind == "dir" else "vhost_wordlist", ""
    )
    if configured and Path(configured).is_file():
        return Path(configured)
    fallback = workspace.file("web", f"{kind}_wordlist.txt")
    words = DEFAULT_DIRS if kind == "dir" else DEFAULT_VHOSTS
    write_text(fallback, "\n".join(words) + "\n")
    return fallback


def _directory_scan(url: str, workspace: Any, config: Dict[str, Any], options: Dict[str, Any], timeout: int, logger: Any) -> List[Dict[str, Any]]:
    web_config = config.get("scan", {}).get("web", {})
    if not web_config.get("directory_scan", True) or not tool_available("gobuster"):
        return []
    wordlist = _wordlist(workspace, config, options, "dir")
    if wordlist is None:
        return []
    output_file = workspace.file("web", f"gobuster_{hashlib.md5(url.encode()).hexdigest()[:8]}.txt")
    cmd = [
        "gobuster", "dir", "-u", url, "-w", str(wordlist),
        "-t", str(int(web_config.get("directory_threads", 10))),
        "-k", "-q", "--no-error", "-o", str(output_file),
    ]
    result = run_command(cmd, timeout=min(timeout, int(web_config.get("directory_timeout", 90))))
    if result.get("timed_out"):
        logger.warning("directory scan timed out for %s (partial results kept)", url)
    hits: List[Dict[str, Any]] = []
    limit = int(web_config.get("directory_limit", 200))
    for line in (result.get("stdout", "") + "\n" + _safe_read(output_file)).splitlines():
        match = re.match(r"^(\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]", line)
        if match:
            hits.append({"path": match.group(1), "status": int(match.group(2)), "size": int(match.group(3)), "url": url})
            if len(hits) >= limit:
                break
    return hits


def _safe_read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _file_checks(url: str, timeout: int, workspace: Any, logger: Any) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    inspected: Dict[str, Any] = {"robots_txt": "", "sitemap_xml": ""}
    files: List[Dict[str, Any]] = []
    for name in COMMON_FILES:
        probe = _fetch(f"{url.rstrip('/')}/{name}", timeout, host_header=None)
        if probe["status"] in (200, 301, 302, 403):
            files.append({"file": name, "status": probe["status"], "url": probe["final_url"]})
            if name == "robots.txt" and probe["status"] == 200:
                body = _body(probe["final_url"], timeout)
                inspected["robots_txt"] = truncate(body, 8000)
                write_text(workspace.file("web", "robots.txt"), body)
            if name == "sitemap.xml" and probe["status"] == 200:
                body = _body(probe["final_url"], timeout)
                inspected["sitemap_xml"] = truncate(body, 8000)
                write_text(workspace.file("web", "sitemap.xml"), body)
            logger.debug("file found: %s (%s)", name, probe["status"])
    return inspected, files


def _vhost_scan(target: str, domains: List[str], workspace: Any, config: Dict[str, Any], timeout: int, logger: Any) -> List[Dict[str, Any]]:
    web_config = config.get("scan", {}).get("web", {})
    if not web_config.get("vhost_scan", True):
        return []
    named_domains = [name for name in domains if "." in name and not re.fullmatch(r"[0-9.]+", name)]
    if not named_domains:
        return []
    base_domain = named_domains[0]
    wordlist = _wordlist(workspace, config, {}, "vhost")
    if wordlist is None:
        return []
    candidates = [line.strip() for line in _safe_read(wordlist).splitlines() if line.strip()][: int(web_config.get("vhost_limit", 30))]
    base_url = f"http://{base_domain}"
    baseline = _body(base_url, timeout, limit=20000)
    baseline_hash = hashlib.md5(baseline.encode()).hexdigest()
    found: List[Dict[str, Any]] = []
    for prefix in candidates:
        name = f"{prefix}.{base_domain}"
        body = _body(base_url, timeout, host_header=name, limit=20000)
        status = _fetch(base_url, timeout, host_header=name)["status"]
        if status and hashlib.md5(body.encode()).hexdigest() != baseline_hash:
            found.append({"vhost": name, "status": status, "note": "differs from baseline - verify manually"})
    logger.info("vhost candidates flagged: %d", len(found))
    return found


def _findings(headers: Dict[str, str], data: Dict[str, Any], url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for header in SECURITY_HEADERS:
        if header not in headers:
            findings.append({
                "title": f"Missing security header: {header}",
                "severity": "info",
                "status": "confirmed",
                "evidence": f"HTTP response from {url} did not include {header}",
                "recommendation": "Verify whether the control is implemented elsewhere before treating as a weakness.",
                "source": "web",
            })
    server = headers.get("server", "")
    if re.search(r"\d+\.\d+", server):
        findings.append({
            "title": "Server version disclosed in HTTP header",
            "severity": "low",
            "status": "confirmed",
            "evidence": f"{url} returned Server: {server}",
            "recommendation": "Check the disclosed version against known advisories; do not claim a CVE without a version-specific test.",
            "source": "web",
        })
    if "x-powered-by" in headers:
        findings.append({
            "title": "Technology disclosed in X-Powered-By",
            "severity": "info",
            "status": "confirmed",
            "evidence": f"{url} returned X-Powered-By: {headers['x-powered-by']}",
            "recommendation": "Use for fingerprinting only; confirm versions independently.",
            "source": "web",
        })
    for hit in data.get("directory_hits", []):
        if str(hit.get("path", "")).rstrip("/") in (".git", ".git/HEAD", ".env", "backup", "backup.zip"):
            findings.append({
                "title": "Potentially sensitive path accessible",
                "severity": "medium",
                "status": "needs_verification",
                "evidence": f"{hit.get('url', url)}{hit.get('path', '')} -> HTTP {hit.get('status')}",
                "recommendation": "Manually confirm the response contains sensitive data before reporting.",
                "source": "web",
            })
    tls = data.get("tls", {})
    if tls.get("self_signed") and not tls.get("error"):
        findings.append({
            "title": "Self-signed TLS certificate",
            "severity": "info",
            "status": "confirmed",
            "evidence": f"certificate subject equals issuer for {tls.get('host')}:{tls.get('port')}",
            "recommendation": "Expected in many labs; note in report only.",
            "source": "web",
        })
    return findings


def run(
    target: str,
    workspace: Any,
    config: Dict[str, Any],
    logger: Any,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run controlled web enumeration and save web.json."""
    options = options or {}
    logger = ensure_logger(logger, "web")
    started = utcnow()
    errors: List[str] = []
    timeout = int(options.get("timeout", config.get("general", {}).get("default_timeout", 120)))
    web_config = config.get("scan", {}).get("web", {})
    probe_timeout = int(web_config.get("connect_timeout", 5))

    if not tool_available("curl"):
        errors.append("curl is not installed - web module cannot run")
        envelope = module_envelope("web", target, {}, "failed", errors, started)
        workspace.save("web", "web.json", envelope)
        return envelope

    cached = workspace.fresh_json(
        "web", "web.json",
        config.get("general", {}).get("max_result_age_hours", 24),
        options.get("reuse", False),
    )
    if isinstance(cached, dict) and cached.get("status") in ("success", "partial"):
        logger.info("reusing cached web results for %s", target)
        return cached

    target_type = options.get("target_type", "")
    candidates, domains = _web_targets(target, workspace, config, target_type)
    max_urls = int(web_config.get("max_scan_urls", 2))
    data: Dict[str, Any] = {
        "urls": [], "web_ports": [], "headers": {}, "security_headers": {},
        "technologies": [], "server": "", "directory_hits": [], "file_hits": [],
        "robots_txt": "", "sitemap_xml": "", "tls": {}, "vhosts": [], "nikto": {},
        "findings": [], "source_of_ports": [],
    }

    for candidate in candidates[:max_urls]:
        url = candidate["url"]
        logger.info(" probing %s", url)
        probe = _fetch(url, probe_timeout)
        if not probe["status"]:
            errors.append(f"no HTTP response from {url}: {probe['error'] or probe['stderr'] or 'unknown'}")
            continue
        data["urls"].append({"url": url, "status": probe["status"], "final_url": probe["final_url"], "source": candidate.get("source", "")})
        data["web_ports"].append({"port": candidate["port"], "scheme": candidate["scheme"], "host": candidate["host"], "status": probe["status"]})
        data["source_of_ports"].append(candidate.get("source", ""))
        data["headers"][url] = probe["headers"]
        data["security_headers"][url] = {key: probe["headers"][key] for key in SECURITY_HEADERS if key in probe["headers"]}
        write_text(workspace.file("web", f"headers_{candidate['port']}.txt"), probe["header_text"])

        body = _body(url, probe_timeout)
        write_text(workspace.file("web", f"body_{candidate['port']}.html"), body)

        whatweb_output = ""
        if tool_available("whatweb"):
            ww = run_command(["whatweb", "--no-errors", "--colour=never", url], timeout=min(timeout, 30))
            whatweb_output = ww.get("stdout", "")
            write_text(workspace.file("web", f"whatweb_{candidate['port']}.txt"), whatweb_output)
        techs = _technologies(probe["headers"], body, whatweb_output)
        if techs:
            data["technologies"] = dedupe(data["technologies"] + techs)
        if probe["headers"].get("server"):
            data["server"] = probe["headers"]["server"]

        if candidate["scheme"] == "https":
            data["tls"] = _tls(candidate["host"], int(candidate["port"]), probe_timeout)

        inspected, files = _file_checks(url, probe_timeout, workspace, logger)
        data["file_hits"].extend(files)
        data["robots_txt"] = data["robots_txt"] or inspected["robots_txt"]
        data["sitemap_xml"] = data["sitemap_xml"] or inspected["sitemap_xml"]
        data["directory_hits"].extend(_directory_scan(url, workspace, config, options, timeout, logger))

        if options.get("nikto") or web_config.get("nikto_enabled", False):
            if tool_available("nikto"):
                nikto = run_command(["nikto", "-h", url, "-T", "4"], timeout=min(timeout, 180))
                raw = nikto.get("stdout", "") + "\n" + nikto.get("stderr", "")
                write_text(workspace.file("web", f"nikto_{candidate['port']}.txt"), truncate(raw, 30000))
                data["nikto"] = {"lines": clean_lines(raw)[:100], "note": "raw nikto output saved; verify every item manually"}
            else:
                errors.append("nikto requested but not installed")

    if domains:
        data["vhosts"] = _vhost_scan(target, domains, workspace, config, probe_timeout, logger)

    data["directory_hits"] = dedupe(data["directory_hits"])[: int(web_config.get("directory_limit", 200))]
    data["file_hits"] = dedupe(data["file_hits"])
    for url_data in data["urls"]:
        headers = data["headers"].get(url_data["url"], {})
        data["findings"].extend(_findings(headers, data, url_data["url"]))
    data["findings"] = dedupe(data["findings"])

    if not data["urls"]:
        errors.append("no reachable HTTP/HTTPS service found on candidate ports")
    status = "partial" if errors and data["urls"] else ("failed" if not data["urls"] else "success")
    envelope = module_envelope("web", target, data, status, errors, started)
    workspace.save("web", "web.json", envelope)
    logger.info("web complete: %d URL(s), %d path(s)", len(data["urls"]), len(data["directory_hits"]))
    return envelope


def main(argv: Optional[List[str]] = None) -> int:
    parser = base_parser(
        "HAKIMIX WEB - HTTP detection, headers, technologies, paths and TLS",
        "examples:\n  python3 web.py 10.10.11.25 -y\n  python3 web.py target.htb -y --nikto -v",
    )
    parser.add_argument("--nikto", action="store_true", help="include a controlled Nikto scan (slower, noisy)")
    args = parser.parse_args(argv)
    target, workspace, config, logger, options = prepare(args, "web")
    options["nikto"] = args.nikto
    envelope = run(target, workspace, config, logger, options)
    print(f"[web] status={envelope['status']} urls={len(envelope['data'].get('urls', []))} output={workspace.dir('web')}")
    for error in envelope.get("errors", []):
        print(f"[warn] {error}")
    return 0 if envelope["status"] != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
