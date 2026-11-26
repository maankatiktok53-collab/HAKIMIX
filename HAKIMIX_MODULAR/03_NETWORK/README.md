# 03_NETWORK

Saddex script oo madax-bannaan, hal workspace ah:

- `nmap_scan.py` — TCP scan (common ama `--full-scan`), open ports, XML (`network/nmap.xml`) iyo `nmap.json`. Haddii nmap maqan yahay waxaa la isticmaalaa `connect()` fallback oo JSON/XML u gaar ah.
- `dns_enum.py` — A, AAAA, MX, NS, TXT, CNAME, SOA, reverse DNS iyo subdomains (recon laga soo xigtay si aan loo ku celin).
- `service_enum.py` — service/version (`nmap -sV` kaliya port-yada la helay), banner grabbing, SSH/FTP/SMTP/HTTP probes.

```bash
python3 03_NETWORK/nmap_scan.py 10.10.11.25 -y
python3 03_NETWORK/nmap_scan.py 10.10.11.25 -y --full-scan --timeout 900
python3 03_NETWORK/dns_enum.py target.htb -y
python3 03_NETWORK/service_enum.py 10.10.11.25 -y --force-version
python3 hakimix.py 10.10.11.25 --module network
```

Output: `output/TARGET/network/{nmap,dns,service,network}.json` + `nmap.xml`, `nmap.txt`, `dns_*.txt`, `services_nmap.xml`, `banners.txt`.

Socodka: `nmap.json → service.json → network.json → web.py`.

API kasta: `run(target, workspace, config, logger, options) -> envelope`.

Help buuxa: `python3 03_NETWORK/<script>.py --help`.
