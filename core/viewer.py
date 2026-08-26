import json
import os
from colorama import Fore, Style, init
from core.runner import parse_and_customize_command, execute_command_safely

init(autoreset=True)

def load_cheatsheets():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    file_path = os.path.join(base_dir, "data", "commands.json")
    
    if not os.path.exists(file_path):
        return {}
        
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

def show_tools_for_category(data, category_name):
    if category_name not in data:
        print(f"{Fore.RED}Qaybtaan lama helin!{Style.RESET_ALL}")
        return
        
    while True:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}╔{'═'*65}╗")
        print(f"║  {Fore.WHITE}AALADAHA: {category_name.upper().center(51)}{Fore.CYAN}║")
        print(f"╚{'═'*65}╝{Style.RESET_ALL}")
        
        tools = list(data[category_name].keys())
        for idx, tool in enumerate(tools, 1):
            print(f"  {Fore.GREEN}[{idx:02d}]{Style.RESET_ALL} {Fore.WHITE}{tool}{Style.RESET_ALL}")
        print(f"  {Fore.RED}[00]{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}Dib ugu noqo Menu-ga guud{Style.RESET_ALL}")
        
        choice = input(f"\n{Fore.LIGHTCYAN_EX}Fadlan dooro lambarka aaladda: {Style.RESET_ALL}").strip()
        
        if choice in ["0", "00"]:
            break
            
        if choice.isdigit() and 1 <= int(choice) <= len(tools):
            selected_tool = tools[int(choice) - 1]
            show_tool_details(data, category_name, selected_tool)
        else:
            print(f"\n{Fore.RED}Doorasho khaldan! Fadlan dooro lambar sax ah.{Style.RESET_ALL}")

def show_tool_details(data, category, tool):
    while True:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}╔{'═'*70}╗")
        print(f"║  {Fore.YELLOW}FAAHFAAHINTA & AMARADA: {tool.upper().center(44)}{Fore.CYAN}║")
        print(f"╚{'═'*70}╝{Style.RESET_ALL}\n")
        
        tool_info = data[category][tool]
        
        if isinstance(tool_info, dict) and "installation" in tool_info:
            print(f"{Fore.CYAN}┌── {Fore.YELLOW}{Style.BRIGHT}SIDA LOO SOO DEGSADO (INSTALLATION){Fore.CYAN} ────────────────────────┐")
            print(f"│  {Fore.GREEN}{tool_info['installation']}")
            print(f"{Fore.CYAN}└────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}\n")
            commands = tool_info.get("commands", [])
        elif isinstance(tool_info, list):
            commands = tool_info
        else:
            commands = []
            
        print(f"{Fore.WHITE}{Style.BRIGHT}AMARADA AWOODDA BADAN ({len(commands)} COMMANDS):{Style.RESET_ALL}")
        for idx, item in enumerate(commands, 1):
            print(f"\n  {Fore.CYAN}[{idx:02d}]{Style.RESET_ALL} {Fore.GREEN}{Style.BRIGHT}{item['command']}{Style.RESET_ALL}")
            print(f"       {Fore.WHITE}Micnaha:{Style.RESET_ALL} {item['description']}")
            
        print(f"\n{Fore.LIGHTBLACK_EX}{'─'*72}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{Style.BRIGHT}DOOKHYADA:{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}[Lambar 1-{len(commands)}]{Style.RESET_ALL} Habee oo Orod amarka (Customize & Run Command)")
        print(f"  {Fore.RED}[0]{Style.RESET_ALL} Dib ugu noqo liiska aaladaha")
        
        cmd_choice = input(f"\n{Fore.LIGHTCYAN_EX}Dooro amar (1-{len(commands)}) ama 0: {Style.RESET_ALL}").strip()
        
        if cmd_choice in ["0", "00"]:
            break
            
        if cmd_choice.isdigit() and 1 <= int(cmd_choice) <= len(commands):
            selected_cmd = commands[int(cmd_choice) - 1]
            customized = parse_and_customize_command(selected_cmd['command'])
            execute_command_safely(customized)
            input(f"\n{Fore.YELLOW}Riix Enter si aad dib ugu noqoto faahfaahinta aaladda...{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}Doorasho khaldan!{Style.RESET_ALL}")
