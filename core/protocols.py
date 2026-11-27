from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich import box

from .runner import parse_and_customize_command, execute_command_safely
from .session import get_current_session

console = Console()

REPOS = {
    "nmap": "https://github.com/nmap/nmap",
    "masscan": "https://github.com/robertdavidgraham/masscan",
    "rustscan": "https://github.com/RustScan/RustScan",
    "dnsx": "https://github.com/projectdiscovery/dnsx",
    "subfinder": "https://github.com/projectdiscovery/subfinder",
    "amass": "https://github.com/owasp-amass/amass",
    "theharvester": "https://github.com/laramies/theHarvester",
    "dnsenum": "https://github.com/fwaeytens/dnsenum",
    "fierce": "https://github.com/mschwager/fierce",
    "ffuf": "https://github.com/ffuf/ffuf",
    "gobuster": "https://github.com/OJ/gobuster",
    "nikto": "https://github.com/sullo/nikto",
    "nuclei": "https://github.com/projectdiscovery/nuclei",
    "katana": "https://github.com/projectdiscovery/katana",
    "testssl": "https://github.com/drwetter/testssl.sh",
    "sslyze": "https://github.com/nabla-c0d3/sslyze",
    "ssh-audit": "https://github.com/jtesta/ssh-audit",
    "hydra": "https://github.com/vanhauser-thc/thc-hydra",
    "samba": "https://github.com/samba-team/samba",
    "enum4linux": "https://github.com/CiscoCXSecurity/enum4linux",
    "impacket": "https://github.com/fortra/impacket",
    "kerbrute": "https://github.com/ropnop/kerbrute",
    "ncrack": "https://github.com/nmap/ncrack",
    "netsnmp": "https://github.com/net-snmp/net-snmp",
    "bettercap": "https://github.com/bettercap/bettercap",
    "sqlmap": "https://github.com/sqlmapproject/sqlmap",
}


def tool(name, cmd, repo=None, note=""):
    return {"name": name, "cmd": cmd, "repo": repo, "note": note}


PROTOCOLS = [
    {"name": "TCP", "layer": "Transport", "description": "Port scanning iyo service fingerprinting", "tools": [
        tool("Nmap", "nmap -sS -sV -p- <target>", "nmap", "SYN + version + all ports"),
        tool("Masscan", "masscan -p1-65535 <target> --rate=1000", "masscan", "Fast TCP scan"),
        tool("Rustscan", "rustscan -a <target> -- -sV", "rustscan", "Modern port scanner"),
        tool("Netcat", "nc -vz <target> <port>", None, "Manual TCP connect"),
    ]},
    {"name": "UDP", "layer": "Transport", "description": "UDP port discovery iyo NSE scripts", "tools": [
        tool("Nmap UDP", "nmap -sU --top-ports 100 <target>", "nmap", "Top UDP ports"),
        tool("Nmap Discovery", "nmap -sU -p 53,67,68,161 --script discovery <target>", "nmap", "UDP service enum"),
    ]},
    {"name": "ICMP", "layer": "Network", "description": "Host discovery iyo ping sweep", "tools": [
        tool("Nmap Ping Sweep", "nmap -sn <target>/24", "nmap", "Alive host discovery"),
        tool("hping3", "hping3 -1 <target>", None, "Custom ICMP packets"),
        tool("Nmap Traceroute", "nmap --traceroute <target>", "nmap", "Path discovery"),
    ]},
    {"name": "IP / IPv4", "layer": "Network", "description": "Routing, tracing iyo host discovery", "tools": [
        tool("traceroute", "traceroute <target>", None, "Hop-by-hop path"),
        tool("Nmap Trace", "nmap --traceroute -Pn <target>", "nmap", "Trace + scan"),
    ]},
    {"name": "IPv6", "layer": "Network", "description": "IPv6 scanning iyo AAAA records", "tools": [
        tool("Nmap IPv6", "nmap -6 -sV <target>", "nmap", "IPv6 port scan"),
        tool("dnsx AAAA", "dnsx -d <domain> -aaaa -resp", "dnsx", "IPv6 address records"),
    ]},
    {"name": "ARP", "layer": "Link", "description": "MAC resolution iyo ARP spoof audit", "tools": [
        tool("Nmap ARP Discovery", "nmap -sn --arp <target>/24", "nmap", "Local network hosts"),
        tool("Bettercap", "bettercap -iface eth0", "bettercap", "ARP/MITM audit"),
    ]},
    {"name": "DNS", "layer": "Application", "description": "Resolution, subdomains iyo zone transfer", "tools": [
        tool("dig", "dig @<target> <domain> ANY", None, "Direct DNS query"),
        tool("dnsx", "dnsx -d <domain> -a -aaaa -resp", "dnsx", "Fast DNS resolution"),
        tool("theHarvester", "theHarvester -d <domain> -b all", "theharvester", "OSINT subdomains"),
        tool("Subfinder", "subfinder -d <domain>", "subfinder", "Passive subdomain enum"),
        tool("Amass", "amass enum -d <domain>", "amass", "Deep DNS enumeration"),
        tool("dnsenum", "dnsenum <domain>", "dnsenum", "Zone transfer + brute"),
        tool("Fierce", "fierce --domain <domain>", "fierce", "DNS reconnaissance"),
    ]},
    {"name": "DHCP", "layer": "Application", "description": "DHCP discovery iyo rogue server checks", "tools": [
        tool("Nmap dhcp-discover", "nmap -sU -p 67 --script dhcp-discover <target>", "nmap", "DHCP info enum"),
    ]},
    {"name": "HTTP", "layer": "Application", "description": "Web fuzzing, crawling iyo vulnerability scan", "tools": [
        tool("FFuf", "ffuf -u http://<target>/FUZZ -w wordlist.txt", "ffuf", "Web fuzzing"),
        tool("Gobuster", "gobuster dir -u http://<target> -w wordlist.txt", "gobuster", "Directory brute"),
        tool("Nikto", "nikto -h http://<target>", "nikto", "Web server scan"),
        tool("Nuclei", "nuclei -u http://<target>", "nuclei", "Template-based scan"),
        tool("Katana", "katana -u http://<target>", "katana", "Web crawler"),
    ]},
    {"name": "HTTPS / TLS", "layer": "Application", "description": "Certificate, cipher iyo TLS configuration audit", "tools": [
        tool("testssl.sh", "./testssl.sh https://<target>", "testssl", "Full TLS/SSL audit"),
        tool("sslyze", "sslyze --regular <target>:443", "sslyze", "TLS settings scan"),
        tool("Nmap ssl-enum-ciphers", "nmap -p 443 --script ssl-enum-ciphers <target>", "nmap", "Cipher enumeration"),
    ]},
    {"name": "SSH", "layer": "Application", "description": "SSH config audit iyo credential testing", "tools": [
        tool("ssh-audit", "ssh-audit <target>", "ssh-audit", "SSH algorithms audit"),
        tool("Hydra", "hydra -l root -P passwords.txt ssh://<target>", "hydra", "SSH brute audit"),
        tool("Nmap ssh2-enum-algos", "nmap -p 22 --script ssh2-enum-algos <target>", "nmap", "Algorithm enum"),
    ]},
    {"name": "FTP", "layer": "Application", "description": "Anonymous login iyo FTP service enum", "tools": [
        tool("Nmap FTP scripts", "nmap -p 21 --script ftp-anon,ftp-syst <target>", "nmap", "Anonymous + banner"),
        tool("Hydra", "hydra -l anonymous -P passwords.txt ftp://<target>", "hydra", "FTP brute audit"),
    ]},
    {"name": "SMTP", "layer": "Application", "description": "Mail relay, user enum iyo banner checks", "tools": [
        tool("Nmap SMTP scripts", "nmap -p 25,465,587 --script smtp-enum-users <target>", "nmap", "SMTP user enum"),
        tool("Swaks", "swaks --to user@<target> --server <target>", None, "Mail relay test"),
    ]},
    {"name": "POP3 / IMAP", "layer": "Application", "description": "Mail retrieval protocol audit", "tools": [
        tool("Nmap capabilities", "nmap -p 110,143 --script pop3-capabilities,imap-capabilities <target>", "nmap", "Mail banner enum"),
        tool("Hydra", "hydra -L users.txt -P passwords.txt imap://<target>", "hydra", "IMAP brute audit"),
    ]},
    {"name": "SMB / CIFS", "layer": "Application", "description": "Share enumeration iyo SMB service audit", "tools": [
        tool("smbclient", "smbclient -L //<target> -N", "samba", "List SMB shares"),
        tool("enum4linux", "enum4linux -a <target>", "enum4linux", "Full SMB enumeration"),
        tool("Nmap SMB scripts", "nmap -p 445 --script smb-enum-shares,smb-os-discovery <target>", "nmap", "Shares + OS info"),
        tool("Impacket smbclient.py", "python3 smbclient.py <user>@<target>", "impacket", "Authenticated SMB"),
    ]},
    {"name": "NetBIOS / NBNS", "layer": "Application", "description": "NetBIOS name service iyo NBNS enumeration", "tools": [
        tool("Nmap nbstat", "nmap -sU -p 137 --script nbstat.nse <target>", "nmap", "NetBIOS name table"),
        tool("nbtscan", "nbtscan <target>/24", None, "NetBIOS scanner"),
    ]},
    {"name": "LDAP", "layer": "Application", "description": "Directory services iyo Active Directory query", "tools": [
        tool("Nmap LDAP scripts", "nmap -p 389 --script ldap-rootdse <target>", "nmap", "Root DSE enum"),
        tool("ldapsearch", 'ldapsearch -x -H ldap://<target> -b "" -s base', None, "Anonymous LDAP query"),
    ]},
    {"name": "Kerberos", "layer": "Application", "description": "User enum, AS-REP roasting iyo ticket audit", "tools": [
        tool("kerbrute", "kerbrute userenum --dc <dc> -d <domain> users.txt", "kerbrute", "Kerberos user enum"),
        tool("Impacket GetNPUsers", "python3 GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <dc>", "impacket", "AS-REP roasting"),
    ]},
    {"name": "RDP", "layer": "Application", "description": "Remote Desktop protocol audit", "tools": [
        tool("Nmap RDP scripts", "nmap -p 3389 --script rdp-enum-encryption <target>", "nmap", "RDP security enum"),
        tool("Ncrack", "ncrack -p 3389 -U users.txt -P passwords.txt <target>", "ncrack", "RDP credential audit"),
    ]},
    {"name": "SNMP", "layer": "Application", "description": "Community strings iyo device enumeration", "tools": [
        tool("Nmap SNMP scripts", "nmap -sU -p 161 --script snmp-sysdescr <target>", "nmap", "SNMP sysDescr"),
        tool("snmpwalk", "snmpwalk -v2c -c public <target>", "netsnmp", "SNMP walk"),
    ]},
    {"name": "NTP", "layer": "Application", "description": "Time sync info iyo amplification checks", "tools": [
        tool("Nmap ntp-info", "nmap -sU -p 123 --script ntp-info <target>", "nmap", "NTP server enum"),
        tool("ntpq", "ntpq -p <target>", None, "NTP peers query"),
    ]},
    {"name": "SQL (MySQL/PostgreSQL)", "layer": "Application", "description": "Database service enum iyo SQL injection scan", "tools": [
        tool("sqlmap", 'sqlmap -u "http://<target>/?id=1" --batch', "sqlmap", "SQL injection scan"),
        tool("Nmap mysql-info", "nmap -p 3306 --script mysql-info <target>", "nmap", "MySQL banner enum"),
    ]},
]


def find_protocol_tools(cheatsheets, protocol):
    results = []
    for entry in protocol["tools"]:
        results.append({
            "tool": entry["name"],
            "commands": [{"command": entry["cmd"], "description": entry.get("note", "")}],
            "sample": entry["cmd"],
            "github": REPOS.get(entry.get("repo"), "-"),
        })
    return results


def _show_protocols():
    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold cyan", title="[bold cyan]NETWORK PROTOCOLS[/bold cyan]")
    table.add_column("#", style="bold green", width=4)
    table.add_column("PROTOCOL", style="bold yellow", width=24)
    table.add_column("LAYER", style="cyan", width=14)
    table.add_column("DESCRIPTION", style="white")
    for index, protocol in enumerate(PROTOCOLS, 1):
        table.add_row(str(index), protocol["name"], protocol["layer"], protocol["description"])
    console.print(table)


def _show_protocol_tools(protocol, matches):
    console.print(Panel(
        f"[bold yellow]{protocol['name']}[/bold yellow] [cyan]({protocol['layer']})[/cyan]\n{protocol['description']}\n"
        f"[green]{len(matches)}[/green] scan tools / scripts oo GitHub source ah.",
        title="[bold cyan]PROTOCOL DETAILS[/bold cyan]", border_style="cyan"
    ))
    if not matches:
        console.print("  [red]Tools lama helin.[/red]")
        return []
    commands = []
    counter = 1
    for match in matches:
        console.print(f"  [bold green][{counter}][/bold green] [bold yellow]{match['tool']}[/bold yellow] [magenta]({match['commands'][0]['description']})[/magenta]")
        console.print(f"      [cyan]$[/cyan] {match['sample']}")
        console.print(f"      [dim]source: {match['github']}[/dim]")
        for command in match["commands"]:
            commands.append((match["tool"], command))
            counter += 1
    console.print()
    return commands


def run_protocol_browser(cheatsheets):
    while True:
        _show_protocols()
        console.print("  [dim]0 = Dib ugu noqo menu-ga guud[/dim]")
        choice = Prompt.ask("  [green]Dooro protocol[/green]").strip()

        if choice in ("0", "q", "Q"):
            break
        if not choice.isdigit() or not 1 <= int(choice) <= len(PROTOCOLS):
            console.print("  [red]Doorasho aan sax ahayn.[/red]")
            continue

        protocol = PROTOCOLS[int(choice) - 1]
        matches = find_protocol_tools(cheatsheets, protocol)
        commands = _show_protocol_tools(protocol, matches)
        if not commands:
            Prompt.ask("  [yellow]Riix Enter si aad dib ugu noqoto[/yellow]")
            continue

        console.print("  [dim]Ku qor lambarka amarka si aad u habayso/u kiciso, 0 = dib[/dim]")
        action = Prompt.ask("  [green]Dooro amar[/green]").strip()
        if action == "0":
            continue
        if not action.isdigit() or not 1 <= int(action) <= len(commands):
            console.print("  [red]Doorasho aan sax ahayn.[/red]")
            continue

        tool_name, command = commands[int(action) - 1]
        console.print(f"  [cyan]Tool:[/cyan] [bold yellow]{tool_name}[/bold yellow]")
        target = get_current_session().get("target", "")
        customized = parse_and_customize_command(command.get("command", ""), default_target=target or None)
        execute_command_safely(customized)
        Prompt.ask("  [yellow]Riix Enter si aad dib ugu noqoto[/yellow]")
