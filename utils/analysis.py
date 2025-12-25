import re
import dns.resolver
from urllib.parse import urlparse
from email.utils import parseaddr

SHORTENER_DOMAINS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","buff.ly","is.gd","w.ly","rebrand.ly"
}

def domain_of(email_addr):
    name, addr = parseaddr(email_addr or "")
    if "@" in addr:
        return addr.split("@", 1)[1].lower()
    return None

def is_ip_host(host):
    if not host:
        return False
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) is not None

def check_dmarc(domain):
    try:
        txtname = "_dmarc." + domain
        answers = dns.resolver.resolve(txtname, "TXT", lifetime=3)
        records = []
        for r in answers:
            try:
                records.append(b"".join(r.strings).decode(errors="ignore"))
            except Exception:
                records.append("".join([s.decode(errors="ignore") if isinstance(s,(bytes,bytearray)) else str(s) for s in r.strings]))
        return "; ".join(records)
    except Exception:
        return None

def analyze_email(parsed):
    headers = parsed.get("headers", {}) or {}
    body = parsed.get("body_text", "") or ""
    attachments = parsed.get("attachments", []) or []

    score = 50
    reasons = []
    details = {}

    auth_results = (headers.get("Authentication-Results") or headers.get("ARC-Authentication-Results") or "").lower()
    received_spf = (headers.get("Received-SPF") or "").lower()
    dkim_header = "DKIM-Signature" in headers or "X-Google-DKIM-Signature" in headers
    from_domain = domain_of(headers.get("From"))

    if "fail" in auth_results or "fail" in received_spf:
        score -= 30
        reasons.append("SPF/DKIM claim: FAIL")
    elif "pass" in auth_results or "pass" in received_spf:
        score += 10
        reasons.append("SPF/DKIM claim: PASS")

    if dkim_header:
        score += 6
        reasons.append("DKIM-Signature header present")
    else:
        score -= 5
        reasons.append("No DKIM-Signature header")

    if from_domain:
        dmarc = check_dmarc(from_domain)
        details["dmarc_record"] = dmarc
        if dmarc:
            if "p=reject" in dmarc.lower() or "p=quarantine" in dmarc.lower():
                score += 6
                reasons.append("DMARC policy present (reject/quarantine)")
            else:
                score += 2
                reasons.append("DMARC TXT found")
        else:
            score -= 2
            reasons.append("No DMARC record found")
    else:
        details["dmarc_record"] = None

    return_path = (headers.get("Return-Path") or headers.get("Envelope-To") or "").strip()
    return_domain = domain_of(return_path) if return_path else None

    if from_domain and return_domain and from_domain != return_domain:
        score -= 25
        reasons.append("From domain differs from Return-Path/Envelope domain")

    if "dkim=fail" in auth_results or "dkim=neutral" in auth_results:
        score -= 20
        reasons.append("Authentication-Results indicates DKIM failure/neutral")

    url_re = re.compile(r"https?://[^\s'\"<>]+")
    found_links = set(re.findall(url_re, body or ""))
    suspicious_link_score = 0
    link_details = []

    for link in found_links:
        try:
            p = urlparse(link)
            host = (p.hostname or "").lower()
            ld = {"url": link, "host": host}
            if is_ip_host(host):
                suspicious_link_score += 4
                ld["reason"] = "link uses raw IP"
            if host and any(short in host for short in SHORTENER_DOMAINS):
                suspicious_link_score += 4
                ld["reason"] = (ld.get("reason", "") + " uses URL shortener").strip()
            if from_domain and host and host != from_domain:
                suspicious_link_score += 2
                ld["host_mismatch"] = True
            link_details.append(ld)
        except Exception:
            continue

    details["found_links"] = link_details
    if suspicious_link_score >= 6:
        score -= 35
        reasons.append("Multiple suspicious links detected (IPs/shorteners/host mismatch)")
    elif suspicious_link_score >= 3:
        score -= 18
        reasons.append("Some suspicious links detected")

    lower_body = body.lower()
    if "<form" in lower_body or "action=" in lower_body:
        score -= 15
        reasons.append("HTML form or action present in email body (credential harvesting risk)")

    img_count = lower_body.count("<img")
    if img_count >= 3:
        score -= 4
        reasons.append("Multiple remote image tags found (possible tracking/obfuscation)")

    exe_exts = (".exe", ".scr", ".pif", ".bat", ".cmd", ".js", ".vbs", ".msi")
    attach_suspicious = 0
    attach_reports = []

    for att in attachments:
        fname = (att.get("filename") or "").lower()
        ctype = (att.get("content_type") or "").lower()
        rep = {"filename": fname, "content_type": ctype, "size": att.get("size")}
        if any(fname.endswith(ext) for ext in exe_exts) or "application/x-msdownload" in ctype:
            attach_suspicious += 6
            rep["reason"] = "executable-like attachment"
        if fname.endswith(".pdf"):
            attach_suspicious += 2
            rep["reason"] = (rep.get("reason", "") + " pdf").strip()
        attach_reports.append(rep)

    details["attachment_reports"] = attach_reports
    if attach_suspicious >= 6:
        score -= 20
        reasons.append("Suspicious attachments detected (executable-like)")
    elif attach_suspicious >= 2:
        score -= 10
        reasons.append("Attachments present that warrant caution")

    subj = (headers.get("Subject") or "").lower()
    urgent_words = ["verify", "urgent", "update", "reset", "password", "confirm", "account suspended", "payment", "verify your"]
    found_urgent = [w for w in urgent_words if w in (subj + " " + body).lower()]
    if found_urgent:
        score -= 12
        reasons.append("Urgent/security words detected: " + ", ".join(found_urgent[:6]))

    if score < 0:
        score = 0
    if score > 100:
        score = 100

    verdict = "phishing" if score < 45 else "not_phishing"

    return {
        "score": int(score),
        "verdict": verdict,
        "reasons": reasons,
        "details": details,
    }
