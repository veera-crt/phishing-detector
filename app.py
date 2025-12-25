from flask import Flask, render_template, request, redirect, url_for, flash
from utils.parse_email import parse_raw_email, parse_eml_file
from utils.link_scan import extract_links_from_text, check_link
from utils.attachment_scan import handle_attachments
from utils.analysis import analyze_email
from utils.vt_scan import scan_url, scan_file
import os
import threading
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change-me")
UPLOAD_DIR = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
def safe_check_links(links):
    results = []
    for u in links:
        try:
            results.append(check_link(u))
        except Exception as e:
            results.append({"url": u, "error": f"{type(e).__name__}: {e}"})
    return results

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    raw = request.form.get("raw_email", "").strip()
    eml_file = request.files.get("eml_file")

    if not raw and (not eml_file or eml_file.filename == ""):
        flash("Provide raw email text or upload a .eml file.")
        return redirect(url_for("index"))

    if eml_file and eml_file.filename:
        eml_bytes = eml_file.read()
        parsed = parse_eml_file(eml_bytes)
    else:
        parsed = parse_raw_email(raw)

    headers = parsed.get("headers", {})
    body_text = parsed.get("body_text", "") or ""
    attachments_meta = parsed.get("attachments", []) or []

    attachment_reports = []
    for att in attachments_meta:
        payload = {
            "filename": att.get("filename"),
            "content": att.get("content") or b"",
            "content_type": att.get("content_type")
        }
        payload["size"] = len(payload["content"])
        try:
            rep = handle_attachments(payload, UPLOAD_DIR)
        except Exception as e:
            rep = {"filename": payload.get("filename"), "error": str(e)}
        attachment_reports.append(rep)

    parsed_for_analysis = {
        "headers": headers,
        "body_text": body_text,
        "attachments": [{"filename": a.get("filename"), "content_type": a.get("content_type"), "size": len(a.get("content") or b"")} for a in attachments_meta]
    }
    analysis = analyze_email(parsed_for_analysis)

    links = extract_links_from_text(body_text)
    link_results = []
    for u in links:
        try:
            res = check_link(u)
            # Add VT scan for each link
            vt_res = scan_url(u)
            res["vt"] = vt_res
            link_results.append(res)
        except Exception as e:
            link_results.append({"url": u, "error": f"{type(e).__name__}: {e}"})

    # Add VT scan for each attachment
    for att in attachment_reports:
        if "saved_path" in att:
            vt_att_res = scan_file(att["saved_path"])
            att["vt"] = vt_att_res

    return render_template("result.html",
                           headers=headers,
                           links=link_results,
                           attachments=attachment_reports,
                           raw_body=body_text,
                           analysis=analysis)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
