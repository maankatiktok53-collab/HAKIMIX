import sys
import os
from colorama import Fore, Style, init

from core.viewer import load_cheatsheets, show_tools_for_category
from core.scraper import fetch_cyber_news, fetch_vulnerability_news
from core.search import search_framework
from core.exporter import export_cheatsheet_to_file, export_news_to_file
from core.encoder import run_crypto_encoder
from core.ports import run_port_encyclopedia
from core.network import run_network_listener_helper

init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}  ┌─────────────────────────────────────────────────────────────┐
  │  {Fore.GREEN}██╗  ██╗ █████╗ ██╗  ██╗██╗███╗   ███╗██╗██╗  ██╗{Fore.CYAN}            │
  │  {Fore.GREEN}██║  ██║██╔══██╗██║ ██╔╝██║████╗ ████║██║╚██╗██╔╝{Fore.CYAN}            │
  │  {Fore.GREEN}███████║███████║█████═╝ ██║██╔████╔██║██║ ╚███╔╝ {Fore.CYAN}            │
  │  {Fore.GREEN}██╔══██║██╔══██║██╔═██╗ ██║██║╚██╔╝██║██║ ██╔██╗ {Fore.CYAN}            │
  │  {Fore.GREEN}██║  ██║██║  ██║██║ ╚██╗██║██║ ╚═╝ ██║██║██╔╝ ██╗{Fore.CYAN}            │
  │  {Fore.GREEN}╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═╝{Fore.CYAN}            │
  │                                                             │
  │  {Fore.WHITE}{Style.BRIGHT}[ CYBERSECURITY ASSISTANT & COMMAND KNOWLEDGE HUB ]{Fore.CYAN}        │
  │  {Fore.YELLOW}Created by: HAKIMI  │  v3.0 Ultimate Edition{Fore.CYAN}              │
  └─────────────────────────────────────────────────────────────┘{Style.RESET_ALL}"""
    print(banner)

def handle_news(news_type="general"):
    if news_type == "vulnerability":
        print(f"\n{Fore.CYAN}⏳ Fadlan sug, waxaan toos internet-ka uga soo jiidayaa wararka Dayac-baylaha & CVE-yada...{Style.RESET_ALL}")
        news_items = fetch_vulnerability_news(limit=6)
        title_text = "WARARKII TOOSKA AHAA EE NUGLAANTA & CVE-YADA (VULNERABILITIES)"
    else:
        print(f"\n{Fore.CYAN}⏳ Fadlan sug, waxaan toos internet-ka uga soo jiidayaa wararkii guud ee amniga...{Style.RESET_ALL}")
        news_items = fetch_cyber_news(limit=6)
        title_text = "WARARKII TOOSKA AHAA EE GUUD EE AMNIGA SAYBERKA"

    print(f"\n{Fore.CYAN}{Style.BRIGHT}╔{'═'*70}╗")
    print(f"║  {Fore.WHITE}{title_text.center(66)}{Fore.CYAN}  ║")
    print(f"╚{'═'*70}╝{Style.RESET_ALL}\n")

    for idx, item in enumerate(news_items, 1):
        source_tag = f"[{item.get('source', 'Cyber Feed')}]"
        print(f"{Fore.GREEN}{Style.BRIGHT}● ({idx}) {item['title']}{Style.RESET_ALL}")
        print(f"   {Fore.CYAN}Isha:{Style.RESET_ALL} {Fore.YELLOW}{source_tag}{Style.RESET_ALL}  │  {Fore.CYAN}Taariikhda:{Style.RESET_ALL} {item.get('date', 'Hadda')}")
        print(f"   {Fore.WHITE}{item['description']}{Style.RESET_ALL}")
        if item.get("link"):
            print(f"   {Fore.BLUE}{Style.BRIGHT}Link:{Style.RESET_ALL} {Fore.LIGHTBLUE_EX}{item['link']}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}{'─'*72}{Style.RESET_ALL}\n")

    print(f"{Fore.WHITE}{Style.BRIGHT}DOOKHYADA:{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}[E]{Style.RESET_ALL} Dhoofi wararkaan fayl Markdown ah (.md)")
    print(f"  {Fore.YELLOW}[R]{Style.RESET_ALL} Dib u cusboonaysii (Refresh News)")
    print(f"  {Fore.CYAN}[Enter]{Style.RESET_ALL} Dib ugu noqo Menu-ga guud")

    user_act = input(f"\n{Fore.LIGHTCYAN_EX}Dooro: {Style.RESET_ALL}").strip().lower()
    if user_act == "e":
        export_news_to_file(news_items, title_text)
        input(f"\n{Fore.YELLOW}Riix Enter si aad dib ugu noqoto...{Style.RESET_ALL}")
    elif user_act == "r":
        handle_news(news_type)

def main():
    cheatsheet_data = load_cheatsheets()

    category_map = {
        "1": "Anonymity & Privacy (Make Yourself Anonymous)",
        "2": "Reconnaissance & OSINT",
        "3": "Web Vulnerability Scanning & Auditing",
        "4": "Scanning & Network Enumeration",
        "5": "Exploitation & Vulnerability Assessment",
        "6": "Privilege Escalation & Auditing",
        "7": "Persistence & Backdoors Auditing",
        "8": "Social Engineering & Awareness Simulation"
    }

    while True:
        print_banner()
        print(f"{Fore.CYAN}┌── {Fore.YELLOW}{Style.BRIGHT}ASTAAMAHA GAARKA AH (SPECIAL UTILITIES){Fore.CYAN} ────────────────────────┐")
        print(f"│  {Fore.GREEN}[S]{Style.RESET_ALL} 🔍 Raadinta Tooska ah (Search all tools & commands)             {Fore.CYAN}│")
        print(f"│  {Fore.GREEN}[C]{Style.RESET_ALL} 🔤 Encoder / Decoder & Hash Toolkit (Base64, URL, Hashes)       {Fore.CYAN}│")
        print(f"│  {Fore.GREEN}[P]{Style.RESET_ALL} 📖 Ports Encyclopedia (Qaamuuska Dakadaha & Protocols)          {Fore.CYAN}│")
        print(f"│  {Fore.GREEN}[N]{Style.RESET_ALL} 📡 Network Diagnostics & Listener Helper                        {Fore.CYAN}│")
        print(f"│  {Fore.GREEN}[E]{Style.RESET_ALL} 📁 Dhoofi dhammaan Cheatsheet-yada (Export to Markdown)         {Fore.CYAN}│")
        print(f"└──{Fore.CYAN}──────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}\n")

        print(f"{Fore.CYAN}┌── {Fore.WHITE}{Style.BRIGHT}QEYBAHA GUUD EE AALADAHA & AMARADA{Fore.CYAN} ─────────────────────────────┐")
        print(f"│  {Fore.GREEN}[1]{Style.RESET_ALL} Make Yourself Anonymous (Qarsoodiga & OpSec)                 {Fore.CYAN}│")
        print(f"│  {Fore.GREEN}[2]{Style.RESET_ALL} Reconnaissance & OSINT (11 Tools)                            {Fore.CYAN}│")
        print(f"│  {Fore.GREEN}[3]{Style.RESET_ALL} Web Vulnerability Scanning & Auditing (8 Tools)              {Fore.CYAN}│")
        print(f"│  {Fore.GREEN}[4]{Style.RESET_ALL} Scanning & Network Enumeration                               {Fore.CYAN}│")
        print(f"│  {Fore.GREEN}[5]{Style.RESET_ALL} Exploitation & Vulnerability Assessment                      {Fore.CYAN}│")
        print(f"│  {Fore.GREEN}[6]{Style.RESET_ALL} Privilege Escalation & Auditing                              {Fore.CYAN}│")
        print(f"│  {Fore.GREEN}[7]{Style.RESET_ALL} Persistence & Backdoors Auditing                             {Fore.CYAN}│")
        print(f"│  {Fore.GREEN}[8]{Style.RESET_ALL} Social Engineering & Awareness Simulation                    {Fore.CYAN}│")
        print(f"│  {Fore.CYAN}[9]{Style.RESET_ALL} Cyber News (Wararka Guud ee Amniga)                          {Fore.CYAN}│")
        print(f"│  {Fore.CYAN}[10]{Style.RESET_ALL} Vulnerabilities & CVEs News (Wararka Nuglaanta)              {Fore.CYAN}│")
        print(f"│  {Fore.RED}[11]{Style.RESET_ALL} Ka bax (Exit)                                                {Fore.CYAN}│")
        print(f"└──{Fore.CYAN}──────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")

        choice = input(f"\n{Fore.LIGHTCYAN_EX}Geli doorashadaada: {Style.RESET_ALL}").strip().lower()

        if choice == "s":
            search_framework(cheatsheet_data)
        elif choice == "c":
            run_crypto_encoder()
        elif choice == "p":
            run_port_encyclopedia()
        elif choice == "n":
            run_network_listener_helper()
        elif choice == "e":
            export_cheatsheet_to_file(cheatsheet_data)
            input(f"\n{Fore.YELLOW}Riix Enter si aad dib ugu noqoto...{Style.RESET_ALL}")
        elif choice in category_map:
            selected_cat = category_map[choice]
            show_tools_for_category(cheatsheet_data, selected_cat)
        elif choice == "9":
            handle_news("general")
        elif choice == "10":
            handle_news("vulnerability")
        elif choice == "11":
            print(f"\n{Fore.GREEN}Mahadsanid Hakimi! Guul iyo barasho wanaagsan. Nabadgelyo! 🔥👋{Style.RESET_ALL}\n")
            sys.exit(0)
        else:
            print(f"\n{Fore.RED}Doorasho aan jirin! Fadlan dooro lambar sax ah ama xaraf (S/C/P/N/E).{Style.RESET_ALL}\n")
            input(f"{Fore.YELLOW}Riix Enter si aad dib ugu noqoto...{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
