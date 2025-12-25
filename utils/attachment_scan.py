import os, hashlib
from PIL import Image
from PyPDF2 import PdfReader

def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def save_bytes(filename, data, outdir):
    safe = filename.replace("/", "_").replace("\\", "_")
    path = os.path.join(outdir, safe)
    with open(path, "wb") as f:
        f.write(data)
    return path

def handle_attachments(att, outdir):
    """
    att: dict {filename, content (bytes), content_type}
    returns report dict
    """
    filename = att.get("filename", "attachment")
    content = att.get("content", b"")
    ctype = att.get("content_type", "application/octet-stream")
    report = {"filename": filename, "content_type": ctype, "size": len(content), "sha256": sha256_bytes(content)}
    try:
        saved = save_bytes(filename, content, outdir)
        report["saved_path"] = saved
    except Exception as e:
        report["saved_error"] = str(e)

    if "pdf" in ctype or filename.lower().endswith(".pdf"):
        try:
            reader = PdfReader(saved)
            info = reader.metadata
            report["pdf_pages"] = len(reader.pages)
            report["pdf_meta"] = {k: str(v) for k, v in (info.items() if info else [])}
        except Exception as e:
            report["pdf_error"] = str(e)

    if ctype.startswith("image/") or any(filename.lower().endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif"]):
        try:
            with Image.open(saved) as im:
                report["image_format"] = im.format
                report["image_size"] = im.size  
        except Exception as e:
            report["image_error"] = str(e)

    return report
