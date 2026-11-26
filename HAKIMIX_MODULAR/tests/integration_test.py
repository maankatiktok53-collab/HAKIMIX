#!/usr/bin/env python3
"""HAKIMIX integration tests - standard library only, no live scanning.

Run:
    python3 tests/integration_test.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import hakimix  # noqa: E402
from core import Workspace  # noqa: E402
from core.nmap import open_ports, parse_nmap_xml, web_ports  # noqa: E402
from core.report import collect, generate, render_html, render_text  # noqa: E402
from core.utils import module_envelope, parse_port_spec, validate_target  # noqa: E402

FIXTURE_XML = """<?xml version="1.0" ?>
<nmaprun scanner="nmap" version="7.94">
  <scaninfo type="connect" protocol="tcp" numservices="3" services="21,22,80"/>
  <host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port portid="21" protocol="tcp"><state state="open" reason="syn-ack"/><service name="ftp" product="vsftpd" version="2.3.4" method="probed" conf="10"/></port>
      <port portid="22" protocol="tcp"><state state="closed" reason="reset"/><service name="ssh"/></port>
      <port portid="80" protocol="tcp"><state state="open" reason="syn-ack"/><service name="http" product="Apache" version="2.4.49" method="probed" conf="10"/><script id="http-title" output="Test page"/></port>
    </ports>
  </host>
</nmaprun>
"""


def seed_workspace(workspace: Workspace) -> None:
    """Seed every module with synthetic cached JSON so tests stay offline."""
    recon_data = {
        "target": workspace.target, "target_type": "ip", "resolved_ips": [workspace.target],
        "reverse_dns": ["lab.example.htb"], "domains": ["lab.example.htb"],
        "subdomains": [{"name": "www.lab.example.htb", "ips": [workspace.target]}],
        "whois": {"available": True, "fields": {"org": "Test Lab"}},
        "profile": {"classification": "private"},
        "handoff": {"target_type": "ip", "domains": ["lab.example.htb"], "ips": [workspace.target],
                    "subdomains": [{"name": "www.lab.example.htb", "ips": [workspace.target]}], "web_hints": ["lab.example.htb"]},
    }
    ports = [
        {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp", "product": "vsftpd", "version": "2.3.4"},
        {"port": 22, "protocol": "tcp", "state": "closed", "service": "ssh", "product": "", "version": ""},
        {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "product": "Apache", "version": "2.4.49"},
    ]
    services = [
        {"port": 21, "name": "ftp", "product": "vsftpd", "version": "2.3.4", "banner": "220 (vsFTPd 2.3.4)"},
        {"port": 80, "name": "http", "product": "Apache", "version": "2.4.49", "banner": "HTTP/1.1 200 OK"},
    ]
    web_data = {
        "urls": [{"url": f"http://{workspace.target}", "status": 200, "final_url": f"http://{workspace.target}/", "source": "network"}],
        "web_ports": [{"port": 80, "scheme": "http", "host": workspace.target, "status": 200}],
        "headers": {f"http://{workspace.target}": {"server": "Apache/2.4.49"}},
        "security_headers": {}, "technologies": ["Apache", "PHP"], "server": "Apache/2.4.49",
        "directory_hits": [{"path": "/admin", "status": 200, "size": 120, "url": f"http://{workspace.target}"}],
        "file_hits": [], "robots_txt": "User-agent: *", "sitemap_xml": "", "tls": {}, "vhosts": [], "nikto": {},
        "findings": [{"title": "Missing security header: x-frame-options", "severity": "info", "status": "confirmed",
                      "evidence": "header absent", "recommendation": "verify manually", "source": "web"}],
    }
    network_data = {
        "ports": ports, "open_ports": [21, 80],
        "web_ports": [{"port": 80, "scheme": "http", "service": "http"}],
        "services": services, "dns_records": {"lab.example.htb": {"A": [workspace.target]}},
        "subdomains": [{"name": "www.lab.example.htb", "ips": [workspace.target]}],
        "nmap": module_envelope("nmap", workspace.target, {"ports": ports, "open_ports": [21, 80], "web_ports": [{"port": 80, "scheme": "http"}]}),
        "dns": module_envelope("dns", workspace.target, {"dns_records": {"lab.example.htb": {"A": [workspace.target]}}}),
        "service": module_envelope("service", workspace.target, {"services": services}),
    }

    seeds = {
        "recon/recon.json": module_envelope("recon", workspace.target, recon_data),
        "network/nmap.json": module_envelope("nmap", workspace.target, network_data["nmap"]["data"]),
        "network/dns.json": module_envelope("dns", workspace.target, network_data["dns"]["data"]),
        "network/service.json": module_envelope("service", workspace.target, network_data["service"]["data"]),
        "network/network.json": module_envelope("network", workspace.target, network_data),
        "web/web.json": module_envelope("web", workspace.target, web_data),
        "privesc/linux.json": module_envelope("linux", workspace.target, {"findings": [], "read_only": True}),
        "privesc/windows.json": module_envelope("windows", workspace.target, {"skipped": True, "reason": "Linux host"}),
        "hash/hash.json": module_envelope("hash", workspace.target, {"hashes": [], "file_analysis": {}, "crack_results": {}, "findings": []}),
    }
    for relative, payload in seeds.items():
        module, filename = relative.split("/")
        workspace.save(module, filename, payload)


class CoreTests(unittest.TestCase):
    def test_validate_target(self) -> None:
        self.assertEqual(validate_target("10.10.11.25")["type"], "ip")
        self.assertEqual(validate_target("http://target.htb:80/path")["value"], "target.htb")
        self.assertEqual(validate_target("::1")["type"], "ip")
        self.assertFalse(validate_target("bad target!!")["valid"])

    def test_parse_port_spec(self) -> None:
        self.assertEqual(parse_port_spec("80,443,8000-8002"), [80, 443, 8000, 8001, 8002])
        self.assertEqual(parse_port_spec("bad,0,70000"), [])

    def test_workspace_roundtrip_and_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Workspace("10.0.0.5", root=tmp).ensure()
            self.assertTrue(workspace.save("recon", "recon.json", module_envelope("recon", "10.0.0.5", {"ok": True})))
            self.assertEqual(workspace.load("recon", "recon.json")["data"]["ok"], True)
            self.assertIsNone(workspace.fresh_json("recon", "recon.json", 24, False))
            self.assertIsNotNone(workspace.fresh_json("recon", "recon.json", 24, True))
            workspace.record("recon", "success", data_files=["recon.json"])
            self.assertEqual(workspace.status("recon"), "success")

    def test_nmap_xml_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nmap.xml"
            path.write_text(FIXTURE_XML, encoding="utf-8")
            parsed = parse_nmap_xml(path)
            self.assertEqual(open_ports(parsed["ports"]), [21, 80])
            self.assertEqual([entry["port"] for entry in web_ports(parsed["ports"], [80])], [80])
            self.assertEqual(parsed["ports"][0]["version"], "2.3.4")
            self.assertEqual(parsed["ports"][2]["scripts"][0]["id"], "http-title")


class ModuleTests(unittest.TestCase):
    def test_all_scripts_load(self) -> None:
        for name, scripts in hakimix.REGISTRY.items():
            for key, script in scripts:
                runner, error = hakimix.load_runner(script)
                self.assertIsNotNone(runner, f"{name}/{key}: {error}")

    def test_hash_identification(self) -> None:
        runner, error = hakimix.load_runner("06_HASH/hash.py")
        self.assertIsNotNone(runner, error)
        identify = getattr(sys.modules[runner.__module__], "identify")
        self.assertIn("md5", identify("5d41402abc4b2a76b9719d911017c592")["identified_types"])
        self.assertEqual(identify("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")["identified_types"], ["sha1"])
        self.assertEqual(identify("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")["identified_types"], ["sha256"])
        bcrypt = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYq2uOmZPeq"
        self.assertEqual(identify(bcrypt)["identified_types"], ["bcrypt"])
        self.assertEqual(identify("user:5d41402abc4b2a76b9719d911017c592")["possible_user"], "user")

    def test_analysis_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Workspace("10.10.11.25", root=tmp).ensure()
            seed_workspace(workspace)
            runner, error = hakimix.load_runner("04_ANALYSIS/analysis.py")
            self.assertIsNotNone(runner, error)
            envelope = runner(workspace.target, workspace, hakimix.load_config(), None, {})
            self.assertEqual(envelope["status"], "success")
            potential = envelope["data"]["potential_findings"]
            self.assertTrue(any("vsftpd 2.3.4" in item["title"] for item in potential))
            for item in envelope["data"]["findings"]:
                self.assertIn(item["status"], ("confirmed", "needs_verification"))

            workspace.save("analysis", "analysis.json", envelope)
            report = generate(workspace)
            self.assertEqual(len(report["open_ports"]), 2)
            self.assertTrue(report["confirmed_findings"])
            self.assertTrue(report["potential_findings"])
            for filename in ("report.json", "report.txt", "report.html"):
                self.assertTrue(workspace.file("report", filename).is_file(), filename)
            text = render_text(report)
            html = render_html(report)
            self.assertIn("CONFIRMED FINDINGS", text)
            self.assertIn("10.10.11.25", html)
            self.assertEqual(collect(workspace)["target"]["value"], "10.10.11.25")

    def test_windows_privesc_skipped_on_linux(self) -> None:
        if sys.platform == "win32":
            self.skipTest("running on Windows")
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Workspace("localhost", root=tmp).ensure()
            runner, error = hakimix.load_runner("05_PRIVESC/windows_privesc.py")
            self.assertIsNotNone(runner, error)
            envelope = runner("localhost", workspace, hakimix.load_config(), None, {})
            self.assertEqual(envelope["status"], "skipped")


class ControllerTests(unittest.TestCase):
    def test_info_commands(self) -> None:
        self.assertEqual(hakimix.main(["--list-modules"]), 0)
        self.assertEqual(hakimix.main(["--check-tools"]), 0)
        with self.assertRaises(SystemExit) as context:
            hakimix.main(["--help"])
        self.assertEqual(context.exception.code, 0)

    def test_invalid_target(self) -> None:
        self.assertEqual(hakimix.main(["bad target!!", "--yes"]), 2)

    def test_authorization_gate(self) -> None:
        with patch("builtins.input", side_effect=EOFError):
            self.assertEqual(hakimix.main(["127.0.0.1", "--module", "analysis"]), 3)

    def test_full_run_reuses_cached_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = hakimix.load_config()
            config["general"]["output_dir"] = str(Path(tmp) / "output")
            config_path = Path(tmp) / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            workspace = Workspace("10.10.11.25", root=ROOT, config=config).ensure()
            seed_workspace(workspace)
            code = hakimix.main(["10.10.11.25", "--yes", "--reuse", "--config", str(config_path)])
            self.assertEqual(code, 0)
            for filename in ("report.json", "report.txt", "report.html"):
                self.assertTrue(workspace.file("report", filename).is_file(), filename)
            report = json.loads(workspace.file("report", "report.json").read_text(encoding="utf-8"))
            self.assertEqual(len(report["open_ports"]), 2)
            self.assertTrue(report["findings"])
            self.assertEqual(report["module_status"].get("recon"), "success")


if __name__ == "__main__":
    unittest.main(verbosity=2)
