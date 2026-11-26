# 05_PRIVESC

Hubinta **local** system-ka marka user-ku helay shell/access. Waa **akhris-keliya**: ma jiro exploitation, ma jiro beddelid files/permissions, ma jiro sudo isbeddel.

## linux_privesc.py

System/kernel, current user/groups, `sudo -n -l`, SUID/SGID, writable paths, cron, processes, capabilities, packages, iyo misconfigurations (tusaale NOPASSWD, SUID aan caadi ahayn).

```bash
python3 05_PRIVESC/linux_privesc.py -y
python3 hakimix.py localhost --module privesc
```

## windows_privesc.py

Windows version, user/groups, privileges, services, service permissions, scheduled tasks, software, unquoted service paths, writable directories. Marka nidaamku uusan Windows ahayn wuxuu soo celinayaa `status: skipped`.

```bash
python3 05_PRIVESC/windows_privesc.py -y
```

Output: `output/TARGET/privesc/{linux,windows}.json` + raw text files (`suid.txt`, `sudo_l.txt`, `capabilities.txt`, iwm).

API kasta: `run(target, workspace, config, logger, options) -> envelope`.

Help buuxa: `python3 05_PRIVESC/<script>.py --help`.
