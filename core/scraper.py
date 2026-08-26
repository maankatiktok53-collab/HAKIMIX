import time
import requests
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET

def get_fresh_headers():
    return {
        "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (Hakimix-LiveNews-{int(time.time())})",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    }

def fetch_cyber_news(limit=6):
    """
    Waxay toos internet-ka uga soo jiidaysaa wararkii ugu dambeeyay ee tooska ah (Live Real-Time News)
    iyadoo adeegsanaysa ilo badan (The Hacker News, BleepingComputer, SecurityWeek).
    """
    sources = [
        ("https://feeds.feedburner.com/TheHackersNews", "The Hacker News"),
        ("https://www.bleepingcomputer.com/feed/", "BleepingComputer"),
        ("https://www.securityweek.com/feed/", "SecurityWeek")
    ]
    
    all_news = []
    
    for url, source_name in sources:
        try:
            cache_bust_url = f"{url}?_t={int(time.time())}"
            res = requests.get(cache_bust_url, headers=get_fresh_headers(), timeout=6)
            if res.status_code == 200:
                root = ET.fromstring(res.content)
                for item in root.findall(".//item")[:3]:
                    title = item.find("title").text if item.find("title") is not None else ""
                    link = item.find("link").text if item.find("link") is not None else ""
                    pub_date = item.find("pubDate").text if item.find("pubDate") is not None else ""
                    desc = item.find("description").text if item.find("description") is not None else ""
                    
                    if title:
                        clean_desc = BeautifulSoup(desc, "html.parser").text.strip()
                        clean_desc = (clean_desc[:140] + "...") if len(clean_desc) > 140 else clean_desc
                        all_news.append({
                            "title": title.strip(),
                            "link": link.strip(),
                            "date": pub_date[:22] if pub_date else "Hadda la soo daabacay",
                            "description": clean_desc if clean_desc else "Faahfaahin dheeraad ah ka eeg link-ga hoose.",
                            "source": source_name
                        })
        except Exception:
            continue
            
    if all_news:
        # Kala sooc si kuwa ugu cusub u soo horeeyaan
        return all_news[:limit]
        
    # Fallback to direct HTML scrape if RSS fails
    return scrape_thn_direct(limit)

def fetch_vulnerability_news(limit=6):
    """
    Waxay toos internet-ka uga soo jiidaysaa wararka ku saabsan Dayac-baylaha cusub (Zero-days, CVEs, Exploits).
    """
    vuln_sources = [
        ("https://www.bleepingcomputer.com/feed/tag/vulnerabilities/", "BleepingComputer (Vulns)"),
        ("https://feeds.feedburner.com/TheHackersNews", "The Hacker News (CVEs)")
    ]
    
    all_vulns = []
    
    for url, source_name in vuln_sources:
        try:
            cache_bust_url = f"{url}?_t={int(time.time())}"
            res = requests.get(cache_bust_url, headers=get_fresh_headers(), timeout=6)
            if res.status_code == 200:
                root = ET.fromstring(res.content)
                for item in root.findall(".//item")[:4]:
                    title = item.find("title").text if item.find("title") is not None else ""
                    link = item.find("link").text if item.find("link") is not None else ""
                    pub_date = item.find("pubDate").text if item.find("pubDate") is not None else ""
                    desc = item.find("description").text if item.find("description") is not None else ""
                    
                    if title:
                        clean_desc = BeautifulSoup(desc, "html.parser").text.strip()
                        clean_desc = (clean_desc[:140] + "...") if len(clean_desc) > 140 else clean_desc
                        all_vulns.append({
                            "title": title.strip(),
                            "link": link.strip(),
                            "date": pub_date[:22] if pub_date else "Hadda la soo saaray",
                            "description": clean_desc if clean_desc else "Warbixin ku saabsan dayac-baylahaan cusub.",
                            "source": source_name
                        })
        except Exception:
            continue
            
    if all_vulns:
        return all_vulns[:limit]
        
    return scrape_thn_direct(limit)

def scrape_thn_direct(limit=6):
    try:
        url = f"https://thehackernews.com?_t={int(time.time())}"
        response = requests.get(url, headers=get_fresh_headers(), timeout=8)
        soup = BeautifulSoup(response.text, "html.parser")
        articles = soup.find_all("div", class_="body-post", limit=limit)
        news_list = []
        for article in articles:
            title_elem = article.find("h2", class_="home-title")
            link_elem = article.find("a", class_="story-link")
            desc_elem = article.find("div", class_="home-desc")
            date_elem = article.find("span", class_="h-datetime")
            if title_elem and link_elem:
                news_list.append({
                    "title": title_elem.text.strip(),
                    "link": link_elem.get("href", "").strip(),
                    "description": desc_elem.text.strip() if desc_elem else "Faahfaahin lagama hayo.",
                    "date": date_elem.text.strip() if date_elem else "Hadda",
                    "source": "The Hacker News"
                })
        return news_list
    except Exception as e:
        return [{
            "title": "Laguma guuleysan soo jiidashada wararka tooska ah",
            "link": "",
            "description": f"Khalad: {str(e)}. Fadlan hubi xiriirka internet-ka.",
            "date": "",
            "source": ""
        }]
