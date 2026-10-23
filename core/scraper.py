import requests
import xml.etree.ElementTree as ET

FEEDS = {
    'general': [
        ('The Hacker News', 'https://feeds.feedburner.com/TheHackersNews'),
        ('BleepingComputer', 'https://www.bleepingcomputer.com/feed/'),
    ],
    'vulnerability': [
        ('CISA', 'https://www.cisa.gov/cybersecurity-advisories/all.xml'),
        ('BleepingComputer', 'https://www.bleepingcomputer.com/feed/'),
    ],
}

def _parse_rss(url, limit=5):
    items = []
    try:
        r = requests.get(url, timeout=10, headers={'User-Agent': 'HAKIMIX/4.0'})
        r.raise_for_status()
        root = ET.fromstring(r.content)
        for elem in root.iter('item'):
            title = elem.findtext('title', '').strip()
            link  = elem.findtext('link',  '').strip()
            pub   = elem.findtext('pubDate', '').strip()
            desc  = elem.findtext('description', '').strip()[:200]
            if title:
                items.append({'title': title, 'link': link, 'date': pub, 'summary': desc})
            if len(items) >= limit:
                break
    except Exception as e:
        items.append({'title': '[CILAD] ' + str(e), 'link': '', 'date': '', 'summary': ''})
    return items

def fetch_cyber_news(limit=5):
    results = []
    for name, url in FEEDS['general']:
        for item in _parse_rss(url, limit=limit):
            item['source'] = name
            results.append(item)
        if len(results) >= limit:
            break
    return results[:limit]

def fetch_vulnerability_news(limit=5):
    results = []
    for name, url in FEEDS['vulnerability']:
        for item in _parse_rss(url, limit=limit):
            item['source'] = name
            results.append(item)
        if len(results) >= limit:
            break
    return results[:limit]
