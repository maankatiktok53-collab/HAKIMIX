import os
from datetime import datetime

EXPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "exports")

def _ensure_dir():
    os.makedirs(EXPORTS_DIR, exist_ok=True)

def export_cheatsheet_to_file(category_name, commands_list):
    _ensure_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(EXPORTS_DIR, "cheatsheet_" + category_name + "_" + ts + ".md")
    with open(fname, "w", encoding="utf-8") as f:
        f.write("# HAKIMIX Cheatsheet: " + category_name + "\n")
        f.write("Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n---\n\n")
        if isinstance(commands_list, dict):
            for tool, cmds in commands_list.items():
                f.write("## " + tool + "\n")
                if isinstance(cmds, list):
                    for c in cmds:
                        if isinstance(c, dict):
                            f.write("### " + c.get("name","") + "\n" + c.get("description","") + "\n\n```bash\n" + c.get("command","") + "\n```\n\n")
    return fname

def export_news_to_file(news_items, news_type="cyber"):
    _ensure_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(EXPORTS_DIR, "news_" + news_type + "_" + ts + ".md")
    with open(fname, "w", encoding="utf-8") as f:
        f.write("# HAKIMIX " + news_type.title() + " News\n")
        f.write("Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n---\n\n")
        for i, item in enumerate(news_items, 1):
            f.write("## " + str(i) + ". " + item.get("title","") + "\n")
            f.write("**Source:** " + item.get("source","") + "  |  **Date:** " + item.get("date","") + "\n\n")
            f.write(item.get("summary","") + "\n\n")
            if item.get("link"): f.write("[Read More](" + item["link"] + ")\n\n---\n\n")
    return fname

def export_web_audit_html(audit_result):
    _ensure_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = audit_result.get("url","unknown").replace("https://","").replace("http://","").replace("/","_")
    fname = os.path.join(EXPORTS_DIR, "web_audit_" + target + "_" + ts + ".html")
    grade = audit_result.get("grade","?")
    score = audit_result.get("score",0)
    gc = {"A":"#27ae60","B":"#2ecc71","C":"#f39c12","D":"#e67e22","F":"#e74c3c"}.get(grade,"#7f8c8d")
    rows = ""
    for h, d in audit_result.get("headers", {}).items():
        s  = "PRESENT" if d["present"] else "MISSING"
        sc = "#27ae60" if d["present"] else "#e74c3c"
        v  = d.get("value","")[:80] or "-"
        rows += "<tr><td>" + h + "</td><td style=\"color:" + sc + ";font-weight:bold\">" + s + "</td><td>" + v + "</td></tr>\n"
    issues_li = "".join(["<li>" + i + "</li>" for i in audit_result.get("issues",[])])
    ssl = audit_result.get("ssl_info", {})
    ssl_rows = "".join(["<tr><td>" + str(k) + "</td><td>" + str(v) + "</td></tr>" for k,v in ssl.items() if not isinstance(v,dict)])
    html = "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>HAKIMIX Web Audit</title>"
    html += "<style>body{font-family:Segoe UI,sans-serif;background:#1a1a2e;color:#eee;padding:20px}"
    html += ".hdr{background:linear-gradient(135deg,#16213e,#0f3460);padding:30px;border-radius:10px;text-align:center}"
    html += "h1{color:#e94560}h2{color:#53d8fb;border-bottom:1px solid #333;padding-bottom:6px}"
    html += ".grade{display:inline-block;background:" + gc + ";color:#fff;font-size:3em;font-weight:bold;padding:12px 28px;border-radius:8px;margin:10px}"
    html += "table{width:100%;border-collapse:collapse;background:#16213e;border-radius:8px;overflow:hidden;margin-bottom:20px}"
    html += "th{background:#0f3460;padding:10px;text-align:left;color:#53d8fb}td{padding:10px;border-bottom:1px solid #1a1a2e}"
    html += ".card{background:#16213e;border-radius:10px;padding:20px;margin:16px 0;border-left:4px solid #e94560}</style></head>"
    html += "<body><div class=\"hdr\"><h1>HAKIMIX v4.0 - Web Security Audit</h1>"
    html += "<p>Target: <strong style=\"color:#53d8fb\">" + audit_result.get("url","") + "</strong></p>"
    html += "<div class=\"grade\">" + grade + "</div><p>Score: <strong>" + str(score) + "/100</strong></p>"
    html += "<p style=\"color:#aaa;font-size:12px\">Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "</p></div>"
    html += "<div class=\"card\"><h2>HTTP Security Headers</h2><table><thead><tr><th>Header</th><th>Status</th><th>Value</th></tr></thead><tbody>" + rows + "</tbody></table></div>"
    html += "<div class=\"card\"><h2>Issues Found</h2><ul>" + (issues_li if issues_li else "<li style=\"color:#27ae60\">No major issues!</li>") + "</ul></div>"
    html += "<div class=\"card\"><h2>SSL Info</h2><table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>" + (ssl_rows or "<tr><td colspan=2>No SSL info</td></tr>") + "</tbody></table></div>"
    html += "<footer style=\"text-align:center;margin-top:20px;color:#555;font-size:12px\">HAKIMIX v4.0 | Created by HAKIMI</footer></body></html>"
    with open(fname, "w", encoding="utf-8") as f:
        f.write(html)
    return fname