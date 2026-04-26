from flask import Flask, render_template, request, send_file, jsonify
import json
import os
from datetime import datetime, timezone
from scanner import run_scan as aws_run_scan  # avoid name conflict

app = Flask(__name__)

REPORTS_FOLDER = "reports"


# -------------------------
# Helpers
# -------------------------

def get_all_reports():
    if not os.path.exists(REPORTS_FOLDER):
        return []

    files = [f for f in os.listdir(REPORTS_FOLDER) if f.endswith(".json")]
    files.sort(reverse=True)  # latest first
    return files


def load_report(filename):
    path = os.path.join(REPORTS_FOLDER, filename)
    if not os.path.exists(path):
        return []

    with open(path) as f:
        return json.load(f)


def format_timestamp(filename):
    try:
        name = filename.replace("report_", "").replace(".json", "")
        return name.replace("_", " ")
    except:
        return filename


def get_latest_report_time():
    reports = get_all_reports()
    if not reports:
        return None

    latest = reports[0]
    timestamp = latest.replace("report_", "").replace(".json", "")

    try:
        # NEW FORMAT WITH SECONDS
        return datetime.strptime(timestamp, "%Y-%m-%d_%H-%M-%S")
    except:
        return None



# -------------------------
# Routes
# -------------------------

@app.route("/")
def dashboard():
    reports = get_all_reports()

    if not reports:
        return render_template(
            "index.html",
            data=[],
            reports=[],
            selected=None,
            critical=0,
            high=0,
            medium=0
        )

    selected = request.args.get("report", reports[0])
    data = load_report(selected)

    critical = sum(1 for d in data if d["severity"] == "CRITICAL")
    high = sum(1 for d in data if d["severity"] == "HIGH")
    medium = sum(1 for d in data if d["severity"] == "MEDIUM")

    formatted_reports = [(r, format_timestamp(r)) for r in reports]

    return render_template(
        "index.html",
        data=data,
        reports=formatted_reports,
        selected=selected,
        critical=critical,
        high=high,
        medium=medium
    )


# -------------------------
# RUN SCAN (REAL AWS)
# -------------------------

@app.route("/run_scan", methods=["POST"])
def run_scan_api():
    findings = aws_run_scan()  # call real scanner

    reports = get_all_reports()
    latest = reports[0] if reports else None

    return jsonify({
        "status": "success",
        "data": findings,
        "latest_report": latest,
        "all_reports": reports
    })


# -------------------------
# DOWNLOAD REPORT
# -------------------------

@app.route("/download/<filename>")
def download(filename):
    path = os.path.join(REPORTS_FOLDER, filename)
    return send_file(path, as_attachment=True)


# -------------------------
# LAST SCAN TIME
# -------------------------

@app.route("/last_scan")
def last_scan():
    dt = get_latest_report_time()

    if not dt:
        return {"last_scan": None}

    return {"last_scan": dt.isoformat()}

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store"
    return response
# -------------------------
# MAIN
# -------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5002))
    app.run(host="0.0.0.0", port=port)