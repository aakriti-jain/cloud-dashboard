from flask import Flask, render_template, request, send_file
import json
from scanner import run_scan
import os
from datetime import datetime
app = Flask(__name__)

REPORTS_FOLDER = "reports"

def load_report(filename):
    with open(os.path.join(REPORTS_FOLDER, filename)) as f:
        return json.load(f)

def get_all_reports():
    files = os.listdir(REPORTS_FOLDER)
    files.sort(reverse=True)  # latest first
    return files

def format_timestamp(filename):
    try:
        name = filename.replace("report_", "").replace(".json", "")
        return name.replace("_", " ")
    except:
        return filename

def get_latest_report():
    files = os.listdir("reports")
    files = [f for f in files if f.endswith(".json")]

    latest = sorted(files)[-1]

    timestamp = latest.replace("report_", "").replace(".json", "")
    from datetime import timezone

    dt = datetime.strptime(timestamp, "%Y-%m-%d_%H-%M")
    dt = dt.replace(tzinfo=timezone.utc)

    return latest, dt
@app.route("/")
def dashboard():
    reports = get_all_reports()
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
@app.route("/run_scan", methods=["POST"])
def run_scan_api():
    findings = run_scan()
    return {
        "status": "success",
        "data": findings
    }

@app.route("/download/<filename>")
def download(filename):
    path = os.path.join(REPORTS_FOLDER, filename)
    return send_file(path, as_attachment=True)

@app.route("/run-scan")
def run_scan():
    return "Scan triggered (mock for now)"

@app.route("/last_scan")
def last_scan():
    file, dt = get_latest_report()
    return {"last_scan": dt.isoformat()}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port)