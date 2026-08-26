import os
import re
from colorama import Fore, Style, init

init(autoreset=True)

def parse_and_customize_command(raw_command):
    placeholders = re.findall(r"<[^>]+>", raw_command)
    
    if not placeholders:
        return raw_command
        
    print(f"\n{Fore.CYAN}┌── {Fore.YELLOW}{Style.BRIGHT}HABEYNTA AMARKA (COMMAND CUSTOMIZER){Fore.CYAN} ────────────────────┐")
    print(f"│  {Fore.WHITE}Amarka asalka ah: {Fore.GREEN}{raw_command}")
    print(f"│  {Fore.LIGHTBLACK_EX}Fadlan geli xogta target-kaaga si amarka loogu diyaariyo:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}└────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}\n")
    
    customized_cmd = raw_command
    unique_placeholders = list(dict.fromkeys(placeholders))
    
    for ph in unique_placeholders:
        clean_name = ph.strip("<>").replace("_", " ").title()
        user_val = input(f"  {Fore.GREEN}● Geli {clean_name} {Fore.YELLOW}(tusaale: {ph}): {Style.RESET_ALL}").strip()
        if user_val:
            customized_cmd = customized_cmd.replace(ph, user_val)
            
    return customized_cmd

def execute_command_safely(cmd_str):
    print(f"\n{Fore.CYAN}╔{'═'*70}╗")
    print(f"║  {Fore.WHITE}AMARKA OO DIYAAR AH (READY TO EXECUTE):{Fore.CYAN.center(33)}║")
    print(f"╚{'═'*70}╝{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}{Style.BRIGHT}$ {cmd_str}{Style.RESET_ALL}\n")
    
    print(f"{Fore.WHITE}{Style.BRIGHT}DOORO HAWSHA:{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}[1]{Style.RESET_ALL} Toos u kici amarka (Run Command)")
    print(f"  {Fore.YELLOW}[2]{Style.RESET_ALL} Kaliya arag amarka oo ha kicin (Cancel/View only)")
    
    action = input(f"\n{Fore.LIGHTCYAN_EX}Dooro (1 ama 2): {Style.RESET_ALL}").strip()
    
    if action == "1":
        print(f"\n{Fore.YELLOW}⏳ Amarku wuu bilaabmayaa... (Riix Ctrl+C haddii aad rabto inaad joojiso){Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}{'─'*72}{Style.RESET_ALL}\n")
        try:
            os.system(cmd_str)
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Amarka waa la joojiyay (Interrupted).{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}Khalad ayaa dhacay: {str(e)}{Style.RESET_ALL}")
        print(f"\n{Fore.LIGHTBLACK_EX}{'─'*72}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}Amarka lama kicin.{Style.RESET_ALL}")
