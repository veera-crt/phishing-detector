# utils/parse_email.py
import email
from email import policy
from email.parser import BytesParser
import re
from bs4 import BeautifulSoup
import base64

def _extract_text(msg):
    """Return best-effort plain text from email message."""
    if msg.is_multipart():
        parts_text = []
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = part.get_content_disposition()
            if disp == "attachment":
                continue
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
            if payload:
                if ctype == "text/plain":
                    try:
                        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                    except:
                        parts_text.append(payload.decode("utf-8", errors="replace"))
                elif ctype == "text/html":
                    html = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                    soup = BeautifulSoup(html, "html.parser")
                    parts_text.append(soup.get_text(separator="\n"))
        return "\n".join(parts_text).strip()
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            return payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
    return ""

def parse_eml_file(eml_bytes):
    msg = BytesParser(policy=policy.default).parsebytes(eml_bytes)
    return _parse_msg(msg)

def parse_raw_email(raw_text):
    try:
        msg = email.message_from_string(raw_text, policy=policy.default)
    except Exception:
        msg = email.message_from_string(raw_text)
    return _parse_msg(msg)

def _parse_msg(msg):
    headers = {}
    for k, v in msg.items():
        headers[k] = str(v)

    body_text = _extract_text(msg)

    attachments = []
    for part in msg.walk():
        disp = part.get_content_disposition()
        if disp == "attachment" or (part.get_filename()):
            filename = part.get_filename() or "attachment"
            try:
                content = part.get_payload(decode=True) or b""
            except Exception:
                content = b""
            ctype = part.get_content_type()
            attachments.append({
                "filename": filename,
                "content": content,
                "content_type": ctype
            })

    return {"headers": headers, "body_text": body_text, "attachments": attachments}
