import re
from urllib.parse import urlparse, urljoin
import requests

URL_RE = re.compile(r"https?://[^\s'\"<>]+")

def extract_links_from_text(text):
    found = set(re.findall(URL_RE, text or ""))
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(text or "", "html.parser")
        for a in soup.find_all("a", href=True):
            found.add(a["href"])
    except Exception:
        pass
    return list(found)

def check_link(url, timeout=5):
    """Perform a safe HEAD (fallback to GET) and return simple info."""
    info = {"url": url, "domain": None, "status": None, "final_url": None, "error": None}
    try:
        p = urlparse(url)
        domain = p.hostname
        info["domain"] = domain
        try:
            r = requests.head(url, timeout=timeout, allow_redirects=True)
            info["status"] = r.status_code
            info["final_url"] = r.url
        except Exception:
            r = requests.get(url, timeout=timeout, allow_redirects=True, stream=True)
            info["status"] = r.status_code
            info["final_url"] = r.url
            r.close()
    except Exception as e:
        info["error"] = f"{type(e).__name__}: {str(e)}"
    return info
