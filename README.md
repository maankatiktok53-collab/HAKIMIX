# HAKIMIX 🛡️

> **A powerful, all-in-one Cybersecurity CLI Framework** — built for penetration testers, security researchers, and cybersecurity students who work from the terminal.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Version](https://img.shields.io/badge/Version-3.0%20Ultimate-red?style=flat-square)

---

## 🔥 What is HAKIMIX?

**HAKIMIX** is a terminal-based cybersecurity assistant that gives you instant access to:

- **100+ powerful commands** across 8 hacking categories
- **Live cybersecurity news** scraped in real-time from top sources
- **Encoder/Decoder toolkit** (Base64, URL, Hex, Binary, Hash Generator)
- **Ports Encyclopedia** — instant info on any network port
- **Network Diagnostic tools** — port checker, listener helper, IP lookup
- **Search engine** — find any tool or command instantly
- **Export to Markdown** — save your cheatsheets as reports

No internet-dependent docs. No switching tabs. Everything in one terminal window.

---

## 📦 Requirements

- Python 3.8 or higher
- pip
- Git

---

## ⚡ Quick Install (Kali Linux / Debian)

```bash
# 1. Clone the repository
git clone https://github.com/maankatiktok53-collab/HAKIMIX.git

# 2. Enter the project folder
cd HAKIMIX

# 3. Install dependencies
pip install -r requirements.txt --break-system-packages

# 4. Launch HAKIMIX
python3 hakimix.py
```

---

## ⚡ Quick Install (Windows)

```bash
# 1. Clone the repository
git clone https://github.com/maankatiktok53-collab/HAKIMIX.git

# 2. Enter the project folder
cd HAKIMIX

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch HAKIMIX
python hakimix.py
```

---

## 🚀 One-Click Kali Linux Setup (Install ALL Tools)

```bash
chmod +x install.sh
./install.sh
```

This script automatically installs all 30+ security tools used in HAKIMIX (Nmap, Nuclei, SQLmap, Hydra, Metasploit, and more).

---

## 📂 Project Structure

```
HAKIMIX/
├── hakimix.py          # Main entry point — run this
├── install.sh          # One-click tool installer for Kali Linux
├── requirements.txt    # Python dependencies
├── README.md
├── .gitignore
├── core/               # All feature modules
│   ├── viewer.py       # Cheatsheet browser & command runner
│   ├── runner.py       # Interactive command executor
│   ├── encoder.py      # Encoder / Decoder / Hash toolkit
│   ├── scraper.py      # Live cybersecurity news scraper
│   ├── ports.py        # Ports & protocols encyclopedia
│   ├── search.py       # Global search engine
│   ├── network.py      # Network diagnostics & listener helper
│   └── exporter.py     # Export cheatsheets to Markdown
└── data/
    └── commands.json   # Full command database (100+ commands)
```

---

## 🗂️ Tool Categories

| # | Category | Tools Included |
|---|----------|----------------|
| 1 | 🕵️ Anonymity & OpSec | Proxychains, Tor, Macchanger, Anonsurf, DNSCrypt |
| 2 | 🔍 Reconnaissance & OSINT | theHarvester, Sherlock, Subfinder, Amass, PhoneInfoga, Holehe, WhatWeb, Recon-ng, SpiderFoot, Whois/Dig |
| 3 | 🌐 Web Vulnerability Scanning | Nuclei, Nikto, SQLmap, Dalfox, Katana, Wapiti, WPScan, Commix |
| 4 | 📡 Network Scanning | Nmap, Ffuf, Masscan, Rustscan, Gobuster |
| 5 | 💥 Exploitation | Metasploit, Hydra, Searchsploit |
| 6 | ⬆️ Privilege Escalation | LinPEAS, WinPEAS, SUID Audit, Linux Capabilities, PowerUp, HashID |
| 7 | 🔒 Persistence & Backdoor Audit | Rkhunter, Chkrootkit, Netstat/Lsof, Cron Audit, Autoruns |
| 8 | 🎭 Social Engineering | SET, Gophish, King Phisher, Email SPF/DMARC |

---

## 🛠️ Special Utilities

| Key | Feature |
|-----|---------|
| `[S]` | 🔍 Search across all tools and commands |
| `[C]` | 🔤 Encoder / Decoder / Hash Generator (Base64, URL, Hex, Binary, MD5, SHA256, NTLM) |
| `[P]` | 📖 Ports Encyclopedia (port info, vulnerabilities, and tools) |
| `[N]` | 📡 Network Diagnostics (port checker, listener generator, IP lookup, HTTP server) |
| `[E]` | 📁 Export cheatsheets to Markdown file |
| `[9]` | 📰 Live Cyber News (real-time from The Hacker News, BleepingComputer, SecurityWeek) |
| `[10]` | ⚠️ Live CVE & Vulnerability News |

---

## 💻 Usage Demo

```
  ┌─────────────────────────────────────────────────────────────┐
  │  [ CYBERSECURITY ASSISTANT & COMMAND KNOWLEDGE HUB ]        │
  │  Created by: HAKIMI  │  v3.0 Ultimate Edition               │
  └─────────────────────────────────────────────────────────────┘

┌── SPECIAL UTILITIES ───────────────────────────────────────────┐
│  [S] Search all tools & commands                               │
│  [C] Encoder / Decoder & Hash Toolkit                          │
│  [P] Ports Encyclopedia                                        │
│  [N] Network Diagnostics & Listener Helper                     │
│  [E] Export Cheatsheets to Markdown                            │
└────────────────────────────────────────────────────────────────┘

┌── TOOL CATEGORIES ─────────────────────────────────────────────┐
│  [1] Anonymity & OpSec                                         │
│  [2] Reconnaissance & OSINT                                    │
│  [3] Web Vulnerability Scanning & Auditing                     │
│  [4] Network Scanning & Enumeration                            │
│  [5] Exploitation & Vulnerability Assessment                   │
│  [6] Privilege Escalation & Auditing                           │
│  [7] Persistence & Backdoor Auditing                           │
│  [8] Social Engineering & Awareness                            │
│  [9] Live Cyber News                                           │
│  [10] Live CVE & Vulnerability News                            │
└────────────────────────────────────────────────────────────────┘
```

---

## 📋 Dependencies

```
requests
beautifulsoup4
colorama
```

Install with:
```bash
pip install -r requirements.txt
```

---

## ⚠️ Disclaimer

> HAKIMIX is built **strictly for educational purposes**, authorized penetration testing, and cybersecurity research. The author is not responsible for any misuse of this tool. Always obtain proper written authorization before testing any system you do not own.

---

## 👤 Author

**HAKIMI** — Cybersecurity Student & Researcher

---

*"Knowledge is the best weapon." — HAKIMI* 🛡️
