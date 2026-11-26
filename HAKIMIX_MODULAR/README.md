# HAKIMIX

Qaab-dhismeed otomaatig ah oo loogu talagalay **HTB labs, CTF challenges iyo authorized penetration testing**. Waa toolkit modular ah: module kasta wuxuu leeyahay script u gaar ah, wuu si gooni ah u shaqayn karaa, wuxuuna xogta ku dhaafsadaa JSON files.

> **DIGNIIN:** U isticmaal kaliya nidaamyo aad fasax cad u hayso. HAKIMIX ma sameeyo exploitation, ma beddelo nidaamka la tijaabinayo, mana sameeyo online password attacks.

## Bilow degdeg ah

```bash
cd HAKIMIX
chmod +x run.sh
./run.sh 10.10.11.25                 # dhammaan modules-ka
python3 hakimix.py 10.10.11.25       # isku mid
python3 hakimix.py 10.10.11.25 --module recon
python3 hakimix.py 10.10.11.25 --module network
python3 hakimix.py 10.10.11.25 --module web
python3 hakimix.py 10.10.11.25 --module analysis
python3 hakimix.py 10.10.11.25 --module privesc
python3 hakimix.py 10.10.11.25 --module hash
python3 hakimix.py                   # menu interactive ah
python3 hakimix.py --check-tools
python3 tests/integration_test.py    # 12 integration tests
```

## Qaab-dhismeedka

```text
HAKIMIX/
├── hakimix.py              # controller: modules, status, report
├── run.sh                  # launcher: Python + tools + permissions
├── config.json             # timeouts, scan profiles, tool settings
├── requirements.txt        # stdlib only (no pip packages)
├── core/                   # koodhka wadaagga ah (utils, paths, cli, nmap, report)
├── 01_RECON/recon.py
├── 02_WEB/web.py
├── 03_NETWORK/nmap_scan.py
├── 03_NETWORK/dns_enum.py
├── 03_NETWORK/service_enum.py
├── 04_ANALYSIS/analysis.py
├── 05_PRIVESC/linux_privesc.py
├── 05_PRIVESC/windows_privesc.py
├── 06_HASH/hash.py
├── tests/integration_test.py
└── output/TARGET/{recon,web,network,analysis,privesc,hash,report}/
```

## Modules

| Module | Shaqada | Output JSON |
|---|---|---|
| `recon` | target validation, reverse DNS, domain info, subdomains, WHOIS, profiling | `recon/recon.json` |
| `network` | Nmap TCP scan + XML, DNS records, service/version/banners | `network/{nmap,dns,service,network}.json` |
| `web` | HTTP/HTTPS, headers, technologies, paths, robots/sitemap, TLS, vhosts | `web/web.json` |
| `analysis` | isku-xigasho xogta, kala saarid `confirmed` vs `needs_verification`, mudnaanta | `analysis/analysis.json` |
| `privesc` | hubin local ah oo akhris-keliya (Linux/Windows) | `privesc/{linux,windows}.json` |
| `hash` | aqoonsi hash offline ah + wordlist audit (john/hashcat) | `hash/hash.json` |
| `report` | TXT / JSON / HTML final report | `report/report.*` |

## Isku-xirka JSON (module communication)

Module kasta wuxuu kaydiyaa `module_envelope`:

```json
{
  "module": "recon",
  "target": "10.10.11.25",
  "status": "success",
  "started_at": "...", "finished_at": "...",
  "errors": [],
  "data": { "...": "..." }
}
```

Socodka xogta:

- RECON → `handoff.domains`, `handoff.ips`, `subdomains`
- NETWORK → `open_ports`, `web_ports`, `services`, `dns_records`
- WEB ← `web_ports` ka NETWORK (haddii uusan jirin wuxuu isticmaalaa `config.json` default ports)
- ANALYSIS ← dhammaan natiijooyinka; ma sheegna vulnerability aan caddayn lahayn
- PRIVESC ← xogta local system-ka marka shell la hayo
- HASH ← `--hash` ama `--hashfile` uu user-ku bixiyo
- `manifest.json` → heerka module kasta (status, waqtiga, files)

**Dib-u-isticmaalka:** `--reuse` wuxuu soo celinayaa natiijo jirta oo ka yar `max_result_age_hours` (default 24h). Markaas lama sameeyo scan cusub. Haddii module uu fashilmo, natiijadiisa hore waa la hayaa, kuwa kalena way sii shaqaynayaan.

## Options muhiim ah

```text
--module NAME        module gaar ah (recon|network|web|analysis|privesc|hash|all)
--all                dhammaan modules
-y, --yes            xaqiijinta authorization (adigoo mas'uul ah)
--reuse              isticmaal natiijooyin hore oo fresher ah
--full-scan          1-65535 TCP (gaabis ah, oo la xakameeyo)
--timeout N          waqtiga ugu badan ee command
--config FILE        config kale
--output-dir DIR     meesha output-ka
--wordlist FILE      subdomain/directory wordlist
--hash / --hashfile  hash(es) offline ah
--hash-type TYPE     md5|sha1|sha256|sha512|ntlm|bcrypt
--no-crack           aqoonsi keliya, john/hashcat ma shaqeeyaan
-v, --verbose        debug logging
```

Tusaale HASH:

```bash
python3 06_HASH/hash.py localhost -y --hash 5d41402abc4b2a76b9719d911017c592
python3 06_HASH/hash.py localhost -y --hashfile hashes.txt --wordlist /usr/share/wordlists/rockyou.txt --hash-type ntlm
python3 hakimix.py 10.10.11.25 --module hash --yes --hashfile hashes.txt --wordlist rockyou.txt
```

## Safety

- Target kasta waa la xaqiijiyaa (IP/hostname valid) waxaana loo baahan yahay ogolaansho cad (`--yes` ama prompt).
- Scan-ku waa la xakameeyaa: default waa common ports, `__full_scan` waa opt-in.
- Ma jiro automatic exploitation, ma jiro wax ka beddel nidaamka, ma jiro online password attack.
- PRIVESC waa akhris-keliya; Windows module wuxuu noqdaa `skipped` marka uusan Windows ahayn.
- Analysis wuxuu u kala saaraa `confirmed` (wax la arkay) iyo `needs_verification` (falanqayn u baahan xaqiijin).

## Shuruudaha

Python 3.8+. Ma jiraan pip dependencies. Tools-ka optional waa `nmap`, `curl`, `dig`, `whois`, `whatweb`, `gobuster`, `john`, `hashcat`; kuwa maqan si fiican ayaa loo calaamadeeyaa waxaana la isticmaalaa fallback-yar (tusaale TCP connect() scan). Kali Linux 4GB RAM si fiican ayuu u maamuli karaa.

## Help

```bash
python3 hakimix.py --help
python3 01_RECON/recon.py --help
python3 02_WEB/web.py --help
python3 03_NETWORK/nmap_scan.py --help
python3 04_ANALYSIS/analysis.py --help
python3 05_PRIVESC/linux_privesc.py --help
python3 06_HASH/hash.py --help
```
