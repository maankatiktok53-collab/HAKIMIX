import sys, os, io

if hasattr(sys.stdout, 'buffer') and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box
from rich.columns import Columns

from core.viewer import load_cheatsheets, show_tools_for_category
from core.scraper import fetch_cyber_news, fetch_vulnerability_news
from core.search import search_framework
from core.exporter import export_cheatsheet_to_file, export_news_to_file, export_web_audit_html
from core.encoder import run_crypto_encoder
from core.ports import run_port_encyclopedia
from core.network import run_network_listener_helper
from core.session import get_current_session, set_target, clear_session, add_note
from core.web_audit import check_http_headers

console = Console()
VERSION = "4.0 Ultimate"

def print_banner():
    art = (
        "[bold green] HAKIMIX[/bold green] [bold yellow]v" + VERSION + "[/bold yellow]\n"
        "[bold cyan] CYBERSECURITY ASSISTANT & COMMAND KNOWLEDGE HUB[/bold cyan]\n"
        "[dim] Created by: HAKIMI  |  For authorized security research only.[/dim]"
    )
    console.print(Panel(art, border_style="cyan", padding=(1, 4)))

def show_session_status():
    session = get_current_session()
    target = session.get("target", "")
    notes_count = len(session.get("notes", []))
    if target:
        console.print(f"  [bold green][SESSION][/bold green] Target: [bold yellow]{target}[/bold yellow]  |  Notes: [cyan]{notes_count}[/cyan]")
    else:
        console.print("  [dim][SESSION] Target lama cayimin. Geli [T] si aad u cayimto.[/dim]")

def show_menu():
    util = Table(box=box.ROUNDED, border_style="cyan", show_header=True,
                 header_style="bold cyan", title="[bold cyan]SPECIAL UTILITIES[/bold cyan]")
    util.add_column("Key", style="bold yellow", width=6)
    util.add_column("Feature")
    util.add_row("[S]", "Search - Raadi Amaro iyo Qalab")
    util.add_row("[C]", "Encoder / Decoder / Hash Toolkit")
    util.add_row("[P]", "Ports Encyclopedia")
    util.add_row("[N]", "Network Diagnostics & Listener")
    util.add_row("[E]", "Export Cheatsheets (Markdown)")
    util.add_row("[W]", "[bold green]Web Security & SSL Audit [NEW][/bold green]")
    util.add_row("[T]", "[bold green]Set / View Target Session [NEW][/bold green]")
    util.add_row("[9]", "Live Cyber News (RSS)")
    util.add_row("[10]", "Live CVE & Vuln News (RSS)")
    util.add_row("[Q]", "[red]Bax (Quit)[/red]")

    cats = Table(box=box.ROUNDED, border_style="red", show_header=True,
                 header_style="bold red", title="[bold red]TOOL CATEGORIES[/bold red]")
    cats.add_column("#", style="bold yellow", width=4)
    cats.add_column("Category")
    cats.add_row("1", "Anonymity & OpSec")
    cats.add_row("2", "Reconnaissance & OSINT")
    cats.add_row("3", "Web Vulnerability Scanning")
    cats.add_row("4", "Network Scanning & Enumeration")
    cats.add_row("5", "Exploitation & Vuln Assessment")
    cats.add_row("6", "Privilege Escalation & Audit")
    cats.add_row("7", "Persistence & Backdoor Audit")
    cats.add_row("8", "Social Engineering & Awareness")

    console.print(Columns([util, cats], equal=True, expand=True))

def handle_session():
    console.print(Panel("[bold cyan]TARGET SESSION MANAGER[/bold cyan]", border_style="cyan"))
    session = get_current_session()
    current = session.get("target", "")
    console.print(f"  Target Hadda: [bold yellow]{current if current else 'Waa maran'}[/bold yellow]\n")
    console.print("  [yellow][1][/yellow] Set Target cusub (IP / Domain)")
    console.print("  [yellow][2][/yellow] Add Note")
    console.print("  [yellow][3][/yellow] Clear Session")
    console.print("  [yellow][4][/yellow] Ku noqo Menu")
    ch = Prompt.ask("\n  Dooro", default="4")
    if ch == "1":
        t = Prompt.ask("  [green]Geli Target (IP ama Domain)[/green]")
        if t.strip():
            console.print(f"  [green]Target: {set_target(t)}[/green]")
    elif ch == "2":
        n = Prompt.ask("  [green]Geli Note[/green]")
        if n.strip():
            add_note(n)
            console.print("  [green]Note waa la kaydiyay.[/green]")
    elif ch == "3":
        clear_session()
        console.print("  [red]Session waa la nadiifiyay.[/red]")

def handle_web_audit():
    console.print(Panel("[bold cyan]WEB SECURITY HEADERS & SSL AUDIT[/bold cyan]", border_style="cyan"))
    session = get_current_session()
    default = session.get("target", "")
    url = Prompt.ask("  Geli URL ama Domain", default=default if default else "")
    if not url.strip():
        console.print("  [red]URL lama geliyo.[/red]")
        return
    with console.status(f"[cyan]Baaraya {url} ...[/cyan]"):
        result = check_http_headers(url)
    if "error" in result:
        console.print(f"  [red]Cilad: {result['error']}[/red]")
        return
    grade = result.get("grade", "?")
    score = result.get("score", 0)
    gc = {"A":"bold green","B":"green","C":"yellow","D":"orange1","F":"bold red"}.get(grade,"white")
    console.print(f"\n  Grade: [{gc}]{grade}[/{gc}]   Score: [bold]{score}/100[/bold]   HTTP: [cyan]{result.get('status_code','?')}[/cyan]\n")
    t = Table(box=box.SIMPLE_HEAVY)
    t.add_column("Header", style="cyan", width=35)
    t.add_column("Status", width=10)
    t.add_column("Value", style="dim")
    for h, d in result.get("headers", {}).items():
        s = "[green]OK[/green]" if d["present"] else "[red]MISSING[/red]"
        v = d.get("value", "-")
        v = v[:50] + "..." if len(v) > 50 else v
        t.add_row(h, s, v)
    console.print(t)
    issues = result.get("issues", [])
    if issues:
        console.print("\n  [bold red]Dhibaatooyinka:[/bold red]")
        for i in issues:
            console.print(f"  [red]  x {i}[/red]")
    else:
        console.print("\n  [bold green]  OK - Dhibaato muhiim ah lama helin![/bold green]")
    ssl = result.get("ssl_info", {})
    if ssl and "error" not in ssl:
        console.print(f"  [cyan]SSL:[/cyan] {ssl.get('version','')} | Expires: {ssl.get('expires','')}")
    elif "error" in ssl:
        console.print(f"  [dim]SSL: {ssl.get('error','')}[/dim]")
    if Prompt.ask("\n  Keydi warbixinta HTML? (y/n)", default="n").lower() == "y":
        path = export_web_audit_html(result)
        console.print(f"  [green]Warbixin HTML: {path}[/green]")

def handle_news(news_type="general"):
    if news_type == "vulnerability":
        with console.status("[cyan]Soo jiidaya CVE wararka...[/cyan]"):
            items = fetch_vulnerability_news(limit=6)
        title = "LIVE CVE & VULNERABILITY NEWS"
    else:
        with console.status("[cyan]Soo jiidaya Cyber wararka...[/cyan]"):
            items = fetch_cyber_news(limit=6)
        title = "LIVE CYBER SECURITY NEWS"
    console.print(Panel(f"[bold red]{title}[/bold red]", border_style="red"))
    nt = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    nt.add_column("#", width=3)
    nt.add_column("Source", width=20, style="yellow")
    nt.add_column("Title")
    nt.add_column("Date", width=22, style="dim")
    for i, item in enumerate(items, 1):
        nt.add_row(str(i), item.get("source","")[:18], item.get("title","")[:70], item.get("date","")[:20])
    console.print(nt)
    if Prompt.ask("\n  Keydi Markdown? (y/n)", default="n").lower() == "y":
        path = export_news_to_file(items, news_type)
        console.print(f"  [green]Warka: {path}[/green]")

def main():
    cheatsheets = load_cheatsheets()
    while True:
        console.clear()
        print_banner()
        show_session_status()
        console.print()
        show_menu()
        console.print()
        choice = Prompt.ask("[bold yellow]  Dooro[/bold yellow]").strip().upper()
        console.print()
        if choice == "Q":
            console.print(Panel("[bold cyan]Mahadsanid! Nabad gelyo. - HAKIMI[/bold cyan]", border_style="cyan"))
            break
        elif choice == "S":
            q = Prompt.ask("  [green]Geli raadinta[/green]")
            search_framework(cheatsheets, q)
        elif choice == "C":
            run_crypto_encoder()
            continue
        elif choice == "P":
            run_port_encyclopedia()
            continue
        elif choice == "N":
            run_network_listener_helper()
            continue
        elif choice == "E":
            cn = Prompt.ask("  [green]Geli nambarada qaybta (1-8)[/green]")
            try:
                idx = int(cn) - 1
                keys = list(cheatsheets.keys())
                if 0 <= idx < len(keys):
                    path = export_cheatsheet_to_file(keys[idx], cheatsheets[keys[idx]])
                    console.print(f"  [green]Waxaa la keydsaday: {path}[/green]")
                else:
                    console.print("  [red]Nambarka saxda ma aha.[/red]")
            except ValueError:
                console.print("  [red]Geli nambar.[/red]")
        elif choice == "W":
            handle_web_audit()
        elif choice == "T":
            handle_session()
        elif choice == "9":
            handle_news("general")
        elif choice == "10":
            handle_news("vulnerability")
        elif choice in [str(i) for i in range(1, 9)]:
            keys = list(cheatsheets.keys())
            idx = int(choice) - 1
            if 0 <= idx < len(keys):
                show_tools_for_category(cheatsheets, keys[idx])
        else:
            console.print("  [red]Dooro aan saxnayn. Isku day mar kale.[/red]")
        Prompt.ask("\n  [dim]Riix Enter si aad u sii wadato[/dim]")

if __name__ == "__main__":
    main()