# 04_ANALYSIS / analysis.py

Wuxuu akhriyaa RECON, WEB, NETWORK (iyo PRIVESC/HASH haddii la heli karo), wuxuuna isku geeyaa xogta:

- inventory: domains, IPs, open ports, services, web URLs, technologies, DNS
- `prioritized_targets`: service muhiim ah/port ballanqaad leh (sabab + caddayn)
- `findings`: `confirmed` (wax si toos ah loo arkay) vs `needs_verification` (tarjumaan u baahan xaqiijin)
- `next_steps`: tallaabooyin la soo jeediyey, ma aha exploitation

Muhiim: ma jiro sheegasho vulnerability ah oo aan caddayn lahayn. Tusaale: `vsftpd 2.3.4` wuxuu noqonayaa *"Version worth verifying"* (`needs_verification`), ma aha *"vulnerable"*.

```bash
python3 04_ANALYSIS/analysis.py 10.10.11.25 -y
python3 04_ANALYSIS/analysis.py 10.10.11.25 -y --force
python3 hakimix.py 10.10.11.25 --module analysis
```

Output: `output/TARGET/analysis/analysis.json`.

API: `run(target, workspace, config, logger, options) -> envelope`.

Help buuxa: `python3 04_ANALYSIS/analysis.py --help`.
