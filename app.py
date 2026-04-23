from flask import Flask, render_template, request, send_file
import json
import os

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

@app.route("/download/<filename>")
def download(filename):
    path = os.path.join(REPORTS_FOLDER, filename)
    return send_file(path, as_attachment=True)

@app.route("/run-scan")
def run_scan():
    return "Scan triggered (mock for now)"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port)