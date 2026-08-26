import socket
import os
import requests
from colorama import Fore, Style, init

init(autoreset=True)

def check_port_open(host, port, timeout=3):
    """Hubinta in dakad gaar ah ay furan tahay (TCP Connection check)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        return result == 0
    except Exception:
        return False

def run_network_listener_helper():
    while True:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}╔{'═'*70}╗")
        print(f"║  {Fore.WHITE}📡 NETWORK DIAGNOSTICS & LISTENER HELPER TOOLKIT{Fore.CYAN.center(22)}║")
        print(f"╚{'═'*70}╝{Style.RESET_ALL}")
        
        print(f"{Fore.WHITE}{Style.BRIGHT}DOORO HAWSHA AAD RABTO:{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}[1]{Style.RESET_ALL} Hubi Dakad Furan (TCP Port Connectivity Checker)")
        print(f"  {Fore.GREEN}[2]{Style.RESET_ALL} Diyaari Amarada Dhegeysiga Dakadaha (Netcat & Socat Listeners)")
        print(f"  {Fore.GREEN}[3]{Style.RESET_ALL} Kici Local HTTP Server (Python File Server)")
        print(f"  {Fore.GREEN}[4]{Style.RESET_ALL} Ogaanshaha IP Address-kaaga (Local & Public IP)")
        print(f"  {Fore.RED}[0]{Style.RESET_ALL} Dib ugu noqo Menu-ga guud\n")
        
        choice = input(f"{Fore.LIGHTCYAN_EX}Dooro hawl (0-4): {Style.RESET_ALL}").strip()
        
        if choice == "0":
            break
            
        elif choice == "1":
            print(f"\n{Fore.YELLOW}--- TCP PORT CONNECTIVITY CHECKER ---{Style.RESET_ALL}")
            target_host = input(f"{Fore.WHITE}Geli Host / IP (tusaale: 127.0.0.1 ama target_ip): {Style.RESET_ALL}").strip()
            target_port = input(f"{Fore.WHITE}Geli Dakadda (tusaale: 80, 443, 445, 22): {Style.RESET_ALL}").strip()
            
            if target_host and target_port.isdigit():
                print(f"{Fore.CYAN}Baaraya xiriirka {target_host}:{target_port}...{Style.RESET_ALL}")
                is_open = check_port_open(target_host, target_port)
                if is_open:
                    print(f"\n{Fore.GREEN}{Style.BRIGHT}✅ DAKADDA {target_port} WAA FURAN TAHAY (OPEN / REACHABLE)!{Style.RESET_ALL}")
                else:
                    print(f"\n{Fore.RED}{Style.BRIGHT}❌ DAKADDA {target_port} WAA XIRAN TAHAY AMA LAMA GAARI KARO (CLOSED / FILTERED).{Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}Riix Enter si aad u sii wadato...{Style.RESET_ALL}")

        elif choice == "2":
            print(f"\n{Fore.YELLOW}--- NETCAT & SOCAT LISTENER CHEATSHEET ---{Style.RESET_ALL}")
            port = input(f"{Fore.WHITE}Geli dakadda aad rabto inaad dhegeysato (tusaale: 4444): {Style.RESET_ALL}").strip()
            if not port:
                port = "4444"
                
            print(f"\n{Fore.CYAN}┌── {Fore.YELLOW}{Style.BRIGHT}AMARADA DHEGEYSIGA (PORT {port}){Fore.CYAN} ─────────────────────────────────┐")
            print(f"│  {Fore.WHITE}1. Netcat Standard:   {Fore.GREEN}nc -lvnp {port}")
            print(f"│  {Fore.WHITE}2. Ncat (SSL/TLS):     {Fore.GREEN}ncat -lvnp {port} --ssl")
            print(f"│  {Fore.WHITE}3. Socat Interactive:  {Fore.GREEN}socat file:`tty`,raw,echo=0 tcp-listen:{port}")
            print(f"│  {Fore.WHITE}4. Rlwrap (History):   {Fore.GREEN}rlwrap nc -lvnp {port}")
            print(f"{Fore.CYAN}└────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}Riix Enter si aad u sii wadato...{Style.RESET_ALL}")

        elif choice == "3":
            print(f"\n{Fore.YELLOW}--- LOCAL HTTP SERVER BUILDER ---{Style.RESET_ALL}")
            port = input(f"{Fore.WHITE}Geli dakadda aad rabto in server-ku ka shaqeeyo (Default: 8000): {Style.RESET_ALL}").strip()
            if not port:
                port = "8000"
            print(f"\n{Fore.GREEN}Amarka lagu kiciyo galka aad joogto:{Style.RESET_ALL}")
            print(f"  {Fore.CYAN}{Style.BRIGHT}python3 -m http.server {port}{Style.RESET_ALL}")
            print(f"\n{Fore.WHITE}Miyaad doonaysaa inaad hadda kiciso? (1=Haa, 2=Maya): {Style.RESET_ALL}")
            act = input("Dooro: ").strip()
            if act == "1":
                print(f"{Fore.YELLOW}Server-ka wuu bilaabmay dakadda {port}... (Riix Ctrl+C si aad u joojiso){Style.RESET_ALL}")
                try:
                    os.system(f"python -m http.server {port}")
                except Exception as e:
                    print(f"{Fore.RED}Khalad: {e}{Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}Riix Enter si aad u sii wadato...{Style.RESET_ALL}")

        elif choice == "4":
            print(f"\n{Fore.YELLOW}--- IP ADDRESS LOOKUP ---{Style.RESET_ALL}")
            try:
                # Local IP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
            except Exception:
                local_ip = "127.0.0.1"
                
            try:
                # Public IP
                public_ip = requests.get("https://ifconfig.me/ip", timeout=5).text.strip()
            except Exception:
                public_ip = "Lama xiriiri karin internet-ka"
                
            print(f"  {Fore.CYAN}🏠 Local Network IP:{Style.RESET_ALL}  {Fore.GREEN}{local_ip}{Style.RESET_ALL}")
            print(f"  {Fore.CYAN}🌐 Public Internet IP:{Style.RESET_ALL} {Fore.YELLOW}{public_ip}{Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}Riix Enter si aad u sii wadato...{Style.RESET_ALL}")
