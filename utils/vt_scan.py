import os
import requests
import time
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

def scan_url(url):
    """Scan a URL using VirusTotal API v3."""
    if not VT_API_KEY:
        return {"error": "API key not configured"}

    headers = {
        "x-apikey": VT_API_KEY
    }
    
    # VT v3 uses a specific base64 encoding for URL IDs (no padding)
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    try:
        # Check if report already exists
        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        report_response = requests.get(report_url, headers=headers)
        
        if report_response.status_code == 200:
            data = report_response.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "link": f"https://www.virustotal.com/gui/url/{url_id}"
            }
        
        # If not found, submit for analysis
        payload = {"url": url}
        submit_response = requests.post("https://www.virustotal.com/api/v3/urls", data=payload, headers=headers)
        
        if submit_response.status_code == 200:
            return {"status": "Submitted for analysis", "link": f"https://www.virustotal.com/gui/url/{url_id}"}
        else:
            return {"error": f"VT API error: {submit_response.status_code}"}
            
    except Exception as e:
        return {"error": str(e)}

def scan_file(file_path):
    """Scan a file using VirusTotal API v3."""
    if not VT_API_KEY:
        return {"error": "API key not configured"}

    headers = {
        "x-apikey": VT_API_KEY
    }
    
    try:
        import hashlib
        with open(file_path, "rb") as f:
            file_bytes = f.read()
            file_hash = hashlib.sha256(file_bytes).hexdigest()
            
        # Check if report already exists
        report_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        report_response = requests.get(report_url, headers=headers)
        
        if report_response.status_code == 200:
            data = report_response.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "link": f"https://www.virustotal.com/gui/file/{file_hash}"
            }
        
        # If not found, submit the file
        files = {"file": (os.path.basename(file_path), file_bytes)}
        submit_response = requests.post("https://www.virustotal.com/api/v3/files", files=files, headers=headers)
        
        if submit_response.status_code == 200:
            return {"status": "Submitted for analysis", "link": f"https://www.virustotal.com/gui/file/{file_hash}"}
        else:
            return {"error": f"VT API error: {submit_response.status_code}"}
            
    except Exception as e:
        return {"error": str(e)}
