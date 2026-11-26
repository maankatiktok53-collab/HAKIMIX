#!/usr/bin/env python3
"""Nmap helpers shared by the NETWORK scripts."""

from __future__ import annotations

import socket
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from xml.sax.saxutils import escape


def parse_nmap_xml(path: Optional[str | Path]) -> Dict[str, Any]:
    """Parse an Nmap XML file into a simple structure. Never raises."""
    result: Dict[str, Any] = {"hosts": [], "ports": [], "scan_info": {}}
    if not path or not Path(path).is_file():
        return result
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except (ET.ParseError, OSError):
        return result

    info = root.find("scaninfo")
    if info is not None:
        result["scan_info"] = dict(info.attrib)

    for host in root.findall("host"):
        address = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                address = addr.get("addr", "")
                break
        status_node = host.find("status")
        status = status_node.get("state", "") if status_node is not None else ""
        result["hosts"].append({"ip": address, "status": status})

        ports_node = host.find("ports")
        if ports_node is None:
            continue
        for port_node in ports_node.findall("port"):
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            state = state_node.get("state", "") if state_node is not None else ""
            entry: Dict[str, Any] = {
                "port": int(port_node.get("portid", 0) or 0),
                "protocol": port_node.get("protocol", "tcp"),
                "state": state,
                "reason": state_node.get("reason", "") if state_node is not None else "",
            }
            if service_node is not None:
                entry.update(
                    service=service_node.get("name", ""),
                    product=service_node.get("product", ""),
                    version=service_node.get("version", ""),
                    extrainfo=service_node.get("extrainfo", ""),
                    method=service_node.get("method", ""),
                    confidence=service_node.get("confidence", ""),
                    ostype=service_node.get("ostype", ""),
                )
            scripts = []
            for script in port_node.findall("script"):
                scripts.append({"id": script.get("id", ""), "output": script.get("output", "")[:500]})
            if scripts:
                entry["scripts"] = scripts
            if entry["port"]:
                result["ports"].append(entry)
    result["ports"].sort(key=lambda item: (item["port"], item["protocol"]))
    return result


def open_ports(ports: Iterable[Dict[str, Any]]) -> List[int]:
    return sorted({int(p["port"]) for p in ports if p.get("state") == "open"})


def web_ports(ports: Iterable[Dict[str, Any]], candidates: Iterable[int], known_services: Iterable[str] = ()) -> List[Dict[str, Any]]:
    """Return only ports worth handing to the WEB module."""
    candidate_set = {int(p) for p in candidates}
    service_set = {str(s).lower() for s in known_services}
    result: List[Dict[str, Any]] = []
    for port in open_ports(ports):
        entry = next((p for p in ports if int(p["port"]) == port and p.get("state") == "open"), {})
        name = str(entry.get("service", "")).lower()
        if port in candidate_set or any(key in name for key in ("http", "ssl", "https")) or name in service_set:
            result.append({
                "port": port,
                "scheme": "https" if port in (443, 8443, 9443) or "ssl" in name or "https" in name else "http",
                "service": name,
            })
    return result


def fallback_connect_scan(target: str, ports: Iterable[int], timeout: float = 0.7, workers: int = 64) -> List[Dict[str, Any]]:
    """Minimal TCP connect scan when nmap is unavailable (no raw sockets)."""
    try:
        host = socket.gethostbyname(target)
    except (OSError, socket.gaierror):
        host = target
    found: List[Dict[str, Any]] = []

    def probe(port: int) -> Optional[Dict[str, Any]]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((host, port)) != 0:
                return None
            banner = ""
            try:
                sock.settimeout(0.5)
                data = sock.recv(512)
                banner = data.decode("utf-8", "replace").strip()[:300]
            except (OSError, socket.timeout):
                pass
            return {"port": port, "protocol": "tcp", "state": "open", "service": "", "product": "", "version": "", "banner": banner, "method": "connect()"}
        except (OSError, socket.timeout):
            return None
        finally:
            sock.close()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(probe, port) for port in ports]
        for future in as_completed(futures):
            try:
                item = future.result()
                if item:
                    found.append(item)
            except Exception:  # noqa: BLE001
                continue
    found.sort(key=lambda item: item["port"])
    return found


def write_minimal_xml(path: str | Path, target: str, ports: Iterable[Dict[str, Any]]) -> bool:
    """Write a small Nmap-compatible XML file for fallback scans."""
    lines = ['<?xml version="1.0" ?>', '<nmaprun scanner="hakimix-connect-scan" version="1.0">', '  <scaninfo type="connect" protocol="tcp" />', f'  <host><address addr="{escape(target)}" addrtype="ipv4" /><status state="up" /><ports>']
    for port in ports:
        lines.append(
            f'    <port portid="{int(port["port"])}" protocol="{escape(str(port.get("protocol", "tcp")))}">'
            f'<state state="open" reason="connect" />'
            f'<service name="{escape(str(port.get("service", "")))}" method="connect" /></port>'
        )
    lines.extend(["  </ports></host>", "</nmaprun>", ""])
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text("\n".join(lines), encoding="utf-8")
        return True
    except OSError:
        return False
