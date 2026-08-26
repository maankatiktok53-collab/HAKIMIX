from colorama import Fore, Style, init

init(autoreset=True)

PORT_DATABASE = {
    "21": {
        "service": "FTP (File Transfer Protocol)",
        "transport": "TCP",
        "description": "Wareejinta faylalka server-ka iyo macmiilka.",
        "security_notes": "Anonymous login baaris (`ftp-anon`), qoraal aan sir ahayn (Plaintext credentials), brute-force testing.",
        "top_tools": "Nmap (`--script ftp-*`), Hydra (`hydra ... ftp`), FileZilla."
    },
    "22": {
        "service": "SSH (Secure Shell)",
        "transport": "TCP",
        "description": "Maamulka server-ka meel fog iyadoo xiriirku yahay mid si buuxda u sir-qoran (Encrypted).",
        "security_notes": "Password auditing, SSH key authentication inspection, banner grabbing version checking.",
        "top_tools": "SSH Client, Hydra (`hydra ... ssh`), Nmap (`--script ssh-*`)."
    },
    "23": {
        "service": "Telnet",
        "transport": "TCP",
        "description": "Maamul fog oo aan ammaan ahayn (dhammaan furayaasha waxay maraan plaintext).",
        "security_notes": "Aad u khatar badan, xogta oo dhan waa la dhagaysan karaa (Sniffing), ku beddel SSH.",
        "top_tools": "Wireshark, Telnet client, Nmap."
    },
    "25": {
        "service": "SMTP (Simple Mail Transfer Protocol)",
        "transport": "TCP",
        "description": "Dirista email-lada.",
        "security_notes": "User Enumeration (VRFY, EXPN, RCPT TO commands), Open Mail Relay testing.",
        "top_tools": "Nmap (`--script smtp-enum-users`), Swaks, Telnet."
    },
    "53": {
        "service": "DNS (Domain Name System)",
        "transport": "TCP / UDP",
        "description": "U beddelista magacyada domains-ka IP addresses.",
        "security_notes": "DNS Zone Transfer (`AXFR`), DNS Poisoning, Subdomain Brute-forcing, Amplification attacks.",
        "top_tools": "Dig (`dig axfr @server domain`), Nslookup, Dnsrecon, Subfinder."
    },
    "80": {
        "service": "HTTP (Hypertext Transfer Protocol)",
        "transport": "TCP",
        "description": "Web traffic aan sir-qornayn.",
        "security_notes": "Web Vulnerabilities (XSS, SQLi, LFI/RFI, Misconfiguration, Directory traversal).",
        "top_tools": "Nuclei, Nikto, Gobuster, Ffuf, Burp Suite, SQLmap."
    },
    "88": {
        "service": "Kerberos (Active Directory Authentication)",
        "transport": "TCP / UDP",
        "description": "Xarunta xaqiijinta aqoonsiga ee Windows Active Directory Domains.",
        "security_notes": "AS-REP Roasting, Kerberoasting, Golden/Silver Ticket analysis, User enumeration.",
        "top_tools": "Impacket (`GetNPUsers.py`, `GetUserSPNs.py`), Rubeus, Kerbrute."
    },
    "110": {
        "service": "POP3 (Post Office Protocol v3)",
        "transport": "TCP",
        "description": "Soo dejinta email-lada.",
        "security_notes": "Plaintext authentication, password brute-forcing.",
        "top_tools": "Hydra, Nmap, Telnet."
    },
    "139": {
        "service": "NetBIOS-SSN",
        "transport": "TCP",
        "description": "Wadaagista faylalka iyo daabacadaha ee nidaamyada hore ee Windows.",
        "security_notes": "SMB null session, NetBIOS name scanning, share enumeration.",
        "top_tools": "Nbtscan, Enum4linux, Nmap (`--script smb-os-discovery`)."
    },
    "161": {
        "service": "SNMP (Simple Network Management Protocol)",
        "transport": "UDP",
        "description": "Kormeerka iyo maamulka aaladaha shabakadda (Routers, Switches, Servers).",
        "security_notes": "SNMP Community Strings (e.g. `public`, `private`) oo furan, xog ururin baahsan (System info, routing, users).",
        "top_tools": "Snmpwalk (`snmpwalk -v2c -c public <ip>`), Onesixtyone, Nmap (`--script snmp-*`)."
    },
    "389": {
        "service": "LDAP (Lightweight Directory Access Protocol)",
        "transport": "TCP / UDP",
        "description": "Raadinta iyo maamulka macluumaadka isticmaalayaasha iyo ururka (Active Directory).",
        "security_notes": "Anonymous/Null LDAP binding, Domain user/group harvesting, LDAP Injection.",
        "top_tools": "Ldapsearch (`ldapsearch -x -H ldap://<ip>`), BloodHound, Windapsearch."
    },
    "443": {
        "service": "HTTPS (HTTP over SSL/TLS)",
        "transport": "TCP",
        "description": "Web traffic sir-qoran oo ammaan ah.",
        "security_notes": "SSL/TLS misconfigurations, weak ciphers (Heartbleed, POODLE), Web Application Vulnerabilities.",
        "top_tools": "Testssl.sh, SSLyze, Nuclei, Burp Suite, Nikto."
    },
    "445": {
        "service": "SMB (Server Message Block)",
        "transport": "TCP",
        "description": "Wadaagista faylalka, daabacadaha, iyo xiriirka tooska ah ee Windows Active Directory.",
        "security_notes": "Null Sessions, SMB Signing disabled (Relay attacks), EternalBlue (MS17-010), Anonymous shares.",
        "top_tools": "CrackMapExec / NetExec, Enum4linux-ng, Smbclient, Nmap (`--script smb-vuln*`)."
    },
    "1433": {
        "service": "Microsoft SQL Server (MSSQL)",
        "transport": "TCP",
        "description": "Database-ka shirkadda Microsoft.",
        "security_notes": "Default SA password, `xp_cmdshell` execution, SQL Injection testing.",
        "top_tools": "Impacket (`mssqlclient.py`), SQLmap, Metasploit."
    },
    "1521": {
        "service": "Oracle Database",
        "transport": "TCP",
        "description": "Database-ka shirkadda Oracle ee shirkadaha waaweyn.",
        "security_notes": "SID/Service Name enumeration, Default credentials, TNS Poisoning.",
        "top_tools": "Odat (Oracle Database Attacking Tool), Nmap (`--script oracle-*`)."
    },
    "3306": {
        "service": "MySQL Database",
        "transport": "TCP",
        "description": "Database-ka ugu caansan Web applications-ka.",
        "security_notes": "Root login adoon furaha lahayn (Blank root password), Remote access misconfiguration, UDF command execution.",
        "top_tools": "Mysql client (`mysql -u root -h <ip>`), Hydra, Nmap (`--script mysql-*`)."
    },
    "3389": {
        "service": "RDP (Remote Desktop Protocol)",
        "transport": "TCP / UDP",
        "description": "Maamulka muuqaalka ah (GUI) ee Windows meel fog.",
        "security_notes": "BlueKeep (CVE-2019-0708), Password brute-forcing, NLA (Network Level Authentication) disabled.",
        "top_tools": "Xfreerdp, Remmina, Hydra (`hydra ... rdp`), Nmap (`--script rdp-enum-encryption`)."
    },
    "5432": {
        "service": "PostgreSQL Database",
        "transport": "TCP",
        "description": "Database-ka furan ee PostgreSQL.",
        "security_notes": "Default user `postgres`, weak passwords, RCE via `COPY FROM PROGRAM`.",
        "top_tools": "Psql client (`psql -U postgres -h <ip>`), Metasploit, Hydra."
    },
    "5900": {
        "service": "VNC (Virtual Network Computing)",
        "transport": "TCP",
        "description": "Maamulka fog ee desktop-ka ee Linux/Windows/Mac.",
        "security_notes": "VNC Authentication disabled (No password), Weak 8-character max passwords.",
        "top_tools": "Vncviewer, Nmap (`--script vnc-info,vnc-brute`), Hydra."
    },
    "8080": {
        "service": "HTTP Alternate / Web Proxy / Apache Tomcat",
        "transport": "TCP",
        "description": "Dakad labaad oo badanaa loo isticmaalo Web Applications ama Admin Consoles.",
        "security_notes": "Tomcat Manager default credentials (`tomcat:s3cret`), Web vulnerabilities, Jenkins consoles.",
        "top_tools": "Nuclei, Burp Suite, Nikto, Gobuster."
    }
}

def run_port_encyclopedia():
    while True:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}╔{'═'*70}╗")
        print(f"║  {Fore.WHITE}📖 COMMON PORTS & PROTOCOLS ENCYCLOPEDIA (QAAMUUSKA DAKADAHA){Fore.CYAN.center(10)}║")
        print(f"╚{'═'*70}╝{Style.RESET_ALL}")
        
        print(f"{Fore.WHITE}{Style.BRIGHT}DOOKHYADA RAADINTA:{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}[Lambar]{Style.RESET_ALL} Geli lambarka dakadda aad rabto (tusaale: 21, 22, 53, 80, 88, 445, 3389)")
        print(f"  {Fore.CYAN}[L]{Style.RESET_ALL} Muuji liiska dhammaan dakadaha ku jira database-ka")
        print(f"  {Fore.RED}[0]{Style.RESET_ALL} Dib ugu noqo Menu-ga guud\n")
        
        query = input(f"{Fore.LIGHTCYAN_EX}Dooro ama geli lambarka dakadda: {Style.RESET_ALL}").strip().lower()
        
        if query == "0":
            break
            
        elif query == "l":
            print(f"\n{Fore.CYAN}┌── {Fore.YELLOW}{Style.BRIGHT}LIISKA DAKADAHA CAANKA AH EE KU JIRA DATABASE-KA{Fore.CYAN} ───────────┐{Style.RESET_ALL}")
            for p, info in PORT_DATABASE.items():
                print(f"  {Fore.GREEN}Port {p:<5}{Style.RESET_ALL} │ {Fore.WHITE}{info['service']}")
            print(f"{Fore.CYAN}└──{Fore.CYAN}──────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}Riix Enter si aad u sii wadato...{Style.RESET_ALL}")
            
        elif query in PORT_DATABASE:
            data = PORT_DATABASE[query]
            print(f"\n{Fore.CYAN}╔{'═'*70}╗")
            print(f"║  {Fore.YELLOW}{Style.BRIGHT}DAKADDA: {query} / {data['transport']} - {data['service'].upper()}{Fore.CYAN.center(10)}║")
            print(f"╚{'═'*70}╝{Style.RESET_ALL}")
            print(f"  {Fore.CYAN}📌 Sharaxaadda:{Style.RESET_ALL}     {Fore.WHITE}{data['description']}{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}⚠️  Qodobada Amniga:{Style.RESET_ALL} {Fore.WHITE}{data['security_notes']}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}🛠️  Aaladaha Baarista:{Style.RESET_ALL} {Fore.LIGHTGREEN_EX}{data['top_tools']}{Style.RESET_ALL}\n")
            input(f"{Fore.YELLOW}Riix Enter si aad u sii wadato...{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}Dakadda '{query}' lagama helin database-ka aasaasiga ah. Hubi inaad gelisay lambar sax ah.{Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}Riix Enter si aad dib ugu noqoto...{Style.RESET_ALL}")
