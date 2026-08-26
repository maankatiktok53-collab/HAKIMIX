import os
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

def get_exports_dir():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    exports_dir = os.path.join(base_dir, "exports")
    os.makedirs(exports_dir, exist_ok=True)
    return exports_dir

def export_cheatsheet_to_file(cheatsheet_data):
    """
    Waxay dhammaan cheatsheets-ka u dhoofinaysaa fayl Markdown ah (.md) oo nidaamsan.
    """
    exports_dir = get_exports_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f"hakimix_cheatsheets_{timestamp}.md"
    file_path = os.path.join(exports_dir, file_name)
    
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("# HAKIMIX FRAMEWORK - COMPLETE CHEATSHEET REPORT\n")
        f.write(f"Created by: Hakimi | Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("---\n\n")
        
        for category, tools in cheatsheet_data.items():
            f.write(f"## 📂 {category}\n\n")
            for tool_name, tool_data in tools.items():
                f.write(f"### 🛠️ {tool_name}\n")
                if isinstance(tool_data, dict):
                    if tool_data.get("installation"):
                        f.write(f"**Installation:** `{tool_data['installation']}`\n\n")
                    f.write("**Commands:**\n")
                    for cmd in tool_data.get("commands", []):
                        f.write(f"- `{cmd['command']}`\n")
                        f.write(f"  - *Sharaxaadda:* {cmd['description']}\n")
                f.write("\n")
            f.write("---\n\n")
            
    print(f"\n{Fore.GREEN}✅ Dhammaan Cheatsheets-ka waxaa si guul leh loogu dhoofiyay:{Style.RESET_ALL}")
    print(f"  📁 {Fore.CYAN}{file_path}{Style.RESET_ALL}")
    return file_path

def export_news_to_file(news_items, news_type="General News"):
    """
    Waxay wararka tooska ah ee la soo jiiday ku kaydinaysaa fayl qoraal ah.
    """
    exports_dir = get_exports_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f"hakimix_news_{timestamp}.md"
    file_path = os.path.join(exports_dir, file_name)
    
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(f"# HAKIMIX - {news_type.upper()} REPORT\n")
        f.write(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("---\n\n")
        
        for idx, item in enumerate(news_items, 1):
            f.write(f"### {idx}. {item.get('title', 'No Title')}\n")
            if item.get("date"):
                f.write(f"**Date:** {item.get('date')}\n")
            if item.get("link"):
                f.write(f"**Link:** [{item.get('link')}]({item.get('link')})\n")
            f.write(f"\n**Summary:**\n{item.get('description', '')}\n\n")
            f.write("---\n\n")
            
    print(f"\n{Fore.GREEN}✅ Wararka waxaa si guul leh loogu dhoofiyay:{Style.RESET_ALL}")
    print(f"  📁 {Fore.CYAN}{file_path}{Style.RESET_ALL}")
    return file_path
