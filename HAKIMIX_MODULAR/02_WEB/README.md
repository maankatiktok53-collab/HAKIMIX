# 02_WEB / web.py

HTTP/HTTPS detection, headers, technology fingerprinting, directory/file discovery, robots.txt, sitemap.xml, TLS certificate, server identification, security-header checks iyo vhost probing.

```bash
python3 02_WEB/web.py 10.10.11.25 -y
python3 02_WEB/web.py target.htb -y --nikto
python3 hakimix.py target.htb --module web
```

Output: `output/TARGET/web/web.json` + raw `headers_*.txt`, `body_*.html`, `whatweb_*.txt`, `gobuster_*.txt`.

Ports-ka waxaa laga akhriyaa `network/network.json` ama `network/nmap.json` (`web_ports`). Haddii uusan jirin, `config.json → scan.web.top_ports` ayaa la isticmaalaa. Hal URL ayaa la bixiyaa (`max_scan_urls`, default 2) si looga fogaado scans aan loo baahnayn. Nikto waa opt-in (`--nikto`).

API: `run(target, workspace, config, logger, options) -> envelope`.

Help buuxa: `python3 02_WEB/web.py --help`.
