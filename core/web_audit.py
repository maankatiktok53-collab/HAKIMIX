import ssl, socket, requests

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

def check_http_headers(url):
    if not url.startswith("http"):
        url = "https://" + url
    result = {"url": url, "headers": {}, "grade": "A", "issues": [], "cookie_issues": [], "ssl_info": {}}
    try:
        r = requests.get(url, timeout=10, allow_redirects=True, headers={"User-Agent": "HAKIMIX-Audit/4.0"})
        result["status_code"] = r.status_code
        hdrs = dict(r.headers)
        score = 100
        for sh in SECURITY_HEADERS:
            found = any(h.lower() == sh.lower() for h in hdrs)
            val = hdrs.get(sh, "")
            result["headers"][sh] = {"present": found, "value": val}
            if not found:
                result["issues"].append("Missing: " + sh)
                score -= 12
        for c in r.cookies:
            if not c.secure:
                result["cookie_issues"].append("Cookie " + c.name + " - No Secure flag")
        if score >= 90: result["grade"] = "A"
        elif score >= 75: result["grade"] = "B"
        elif score >= 60: result["grade"] = "C"
        elif score >= 45: result["grade"] = "D"
        else: result["grade"] = "F"
        result["score"] = max(0, score)
    except Exception as e:
        result["error"] = str(e)
    try:
        host = url.replace("https://", "").replace("http://", "").split("/")[0]
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((host, 443), timeout=8), server_hostname=host) as ss:
            cert = ss.getpeercert()
            result["ssl_info"] = {"version": ss.version(), "expires": cert.get("notAfter", "Unknown")}
    except Exception as e:
        result["ssl_info"] = {"error": str(e)}
    return result