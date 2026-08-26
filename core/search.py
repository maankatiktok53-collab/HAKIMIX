import re
from colorama import Fore, Style, init
from core.runner import parse_and_customize_command, execute_command_safely

init(autoreset=True)

def search_framework(cheatsheet_data):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}╔{'═'*70}╗")
    print(f"║  {Fore.WHITE}🔍 RAADINTA TOOSKA AH EE HAKIMIX (SEARCH ENGINE){Fore.CYAN.center(26)}║")
    print(f"╚{'═'*70}╝{Style.RESET_ALL}")
    
    query = input(f"\n{Fore.LIGHTCYAN_EX}Geli ereyga aad baarayso (tusaale: nuclei, nmap, xss, sqli, port, wifi): {Style.RESET_ALL}").strip()
    
    if not query:
        print(f"{Fore.RED}Ma jiro wax erey ah oo aad gelisay.{Style.RESET_ALL}")
        return
        
    query_lower = query.lower()
    matches = []
    
    for category, tools in cheatsheet_data.items():
        for tool_name, tool_data in tools.items():
            install_info = ""
            commands = []
            if isinstance(tool_data, dict):
                install_info = tool_data.get("installation", "")
                commands = tool_data.get("commands", [])
            elif isinstance(tool_data, list):
                commands = tool_data
                
            tool_matched = (query_lower in tool_name.lower()) or (query_lower in install_info.lower()) or (query_lower in category.lower())
            
            for cmd_item in commands:
                cmd_str = cmd_item.get("command", "")
                desc_str = cmd_item.get("description", "")
                
                if tool_matched or (query_lower in cmd_str.lower()) or (query_lower in desc_str.lower()):
                    matches.append({
                        "category": category,
                        "tool": tool_name,
                        "installation": install_info,
                        "command": cmd_str,
                        "description": desc_str
                    })
                    
    if not matches:
        print(f"\n{Fore.RED}Wax natiijo ah lagama helin ereyga: '{query}'{Style.RESET_ALL}")
        input(f"\n{Fore.YELLOW}Riix Enter si aad ugu noqoto Menu-ga guud...{Style.RESET_ALL}")
        return
        
    print(f"\n{Fore.GREEN}{Style.BRIGHT}Waxaa la helay {len(matches)} natiijo oo ku saabsan '{query}':{Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLACK_EX}{'─'*72}{Style.RESET_ALL}")
    
    for idx, item in enumerate(matches, 1):
        highlighted_tool = re.sub(f"(?i)({re.escape(query)})", f"{Fore.YELLOW}\\1{Fore.CYAN}", item['tool'])
        highlighted_cmd = re.sub(f"(?i)({re.escape(query)})", f"{Fore.YELLOW}\\1{Fore.GREEN}", item['command'])
        
        print(f"\n{Fore.CYAN}[{idx:02d}] Qeybta:{Style.RESET_ALL} {item['category']} ➔ {Fore.CYAN}{Style.BRIGHT}{highlighted_tool}{Style.RESET_ALL}")
        if item['installation']:
            print(f"     {Fore.LIGHTBLACK_EX}Shubashada:{Style.RESET_ALL} {item['installation']}")
        print(f"     {Fore.GREEN}{Style.BRIGHT}Amarka:{Style.RESET_ALL} {highlighted_cmd}")
        print(f"     {Fore.WHITE}Micnaha:{Style.RESET_ALL} {item['description']}")
        
    print(f"\n{Fore.LIGHTBLACK_EX}{'─'*72}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{Style.BRIGHT}DOOKHYADA:{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}[Lambar 1-{len(matches)}]{Style.RESET_ALL} Dooro amarka aad rabto inaad habeyso oo aad kiciso (Customize & Run)")
    print(f"  {Fore.RED}[0]{Style.RESET_ALL} Dib ugu noqo Menu-ga guud")
    
    choice = input(f"\n{Fore.LIGHTCYAN_EX}Dooro (1-{len(matches)} ama 0): {Style.RESET_ALL}").strip()
    
    if choice.isdigit() and 1 <= int(choice) <= len(matches):
        selected_item = matches[int(choice) - 1]
        customized_cmd = parse_and_customize_command(selected_item['command'])
        execute_command_safely(customized_cmd)
        input(f"\n{Fore.YELLOW}Riix Enter si aad dib ugu noqoto...{Style.RESET_ALL}")
