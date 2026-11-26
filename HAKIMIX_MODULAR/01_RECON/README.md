# 01_RECON / recon.py

Passive reconnaissance: target validation, reverse DNS, domain resolution, subdomain discovery, WHOIS/IP information iyo basic profiling.

```bash
python3 01_RECON/recon.py 10.10.11.25 -y
python3 01_RECON/recon.py target.htb -y --wordlist wordlists.txt -v
python3 hakimix.py target.htb --module recon
```

Output: `output/TARGET/recon/recon.json` (+ `whois.txt`, `reverse_dns.txt`, `subdomains.txt`, `ping.txt`).

`recon.json.data.handoff` ayaa loo gudbiyaa WEB iyo NETWORK: `domains`, `ips`, `subdomains`, `web_hints`.

API: `run(target, workspace, config, logger, options) -> envelope`. Marka `--reuse` la isticmaalo natiijo hore oo fresher ah ayaa la soo celinayaa.

Help buuxa: `python3 01_RECON/recon.py --help`.
