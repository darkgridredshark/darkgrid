import os
import time
import sqlite3
import requests
from flask import Flask, request, jsonify, render_template_string

# ---------------------------
# App Configuration
# ---------------------------
app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

VT_API_KEY = os.getenv("VT_API_KEY")
ANYRUN_API_KEY = os.getenv("ANYRUN_API_KEY")
DB_FILE = os.getenv("DB_FILE", "malware.db")

# ---------------------------
# Database Initialization
# ---------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            vt_positives INTEGER,
            anyrun_score INTEGER,
            ai_score INTEGER,
            ai_summary TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------------------------
# VirusTotal Integration
# ---------------------------
def check_virustotal(file_path):
    if not VT_API_KEY:
        return {}
    headers = {"x-apikey": VT_API_KEY}
    try:
        with open(file_path, "rb") as f:
            upload = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers=headers,
                files={"file": f},
                timeout=60
            )
        upload.raise_for_status()
        analysis_id = upload.json().get("data", {}).get("id")
        if not analysis_id:
            return {}
        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=60
        )
        return report.json()
    except Exception as e:
        print("VirusTotal error:", e)
        return {}

# ---------------------------
# Any.Run Integration
# ---------------------------
def submit_anyrun(file_path):
    if not ANYRUN_API_KEY:
        return {}
    headers = {"Authorization": f"Bearer {ANYRUN_API_KEY}"}
    try:
        with open(file_path, "rb") as f:
            response = requests.post(
                "https://any.run/api/v2/tasks",
                headers=headers,
                files={"file": f},
                timeout=60
            )
        response.raise_for_status()
        task_id = response.json().get("id")
        if not task_id:
            return {}
        report_url = f"https://any.run/api/v2/tasks/{task_id}/report/json"
        for _ in range(20):
            r = requests.get(report_url, headers=headers, timeout=30)
            if r.status_code == 200:
                return r.json()
            time.sleep(6)
        return {}
    except Exception as e:
        print("Any.Run error:", e)
        return {}

# ---------------------------
# AI Risk Scoring
# ---------------------------
def ai_risk_score(vt_report, anyrun_report):
    score = 0
    positives = (
        vt_report.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
        .get("malicious", 0)
    )
    score += min(positives * 5, 50)
    behavior = anyrun_report.get("behavior", {})
    anyrun_score = 50 if behavior else 20
    score += anyrun_score
    if score >= 80:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"
    summary = f"AI Risk Level: {level}, Score: {score}/100"
    return score, summary, positives, anyrun_score

# ---------------------------
# Analyze Endpoint
# ---------------------------
@app.route("/analyze", methods=["POST"])
def analyze_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    vt_report = check_virustotal(filepath)
    anyrun_report = submit_anyrun(filepath)
    ai_score, summary, vt_pos, any_score = ai_risk_score(vt_report, anyrun_report)
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO reports
        (filename, vt_positives, anyrun_score, ai_score, ai_summary)
        VALUES (?, ?, ?, ?, ?)
    """, (file.filename, vt_pos, any_score, ai_score, summary))
    report_id = cur.lastrowid
    conn.commit()
    conn.close()
    return jsonify({
        "report_id": report_id,
        "filename": file.filename,
        "ai_score": ai_score,
        "summary": summary
    })

# ---------------------------
# Get Single Report
# ---------------------------
@app.route("/report/<int:report_id>", methods=["GET"])
def get_report(report_id):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT * FROM reports WHERE id=?", (report_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Report not found"}), 404
    keys = ["id", "filename", "vt_positives", "anyrun_score", "ai_score", "ai_summary", "created_at"]
    return jsonify(dict(zip(keys, row)))

# ---------------------------
# Dashboard JSON
# ---------------------------
@app.route("/dashboard", methods=["GET"])
def dashboard_json():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT * FROM reports ORDER BY created_at DESC LIMIT 50")
    rows = cur.fetchall()
    conn.close()
    keys = ["id", "filename", "vt_positives", "anyrun_score", "ai_score", "ai_summary", "created_at"]
    return jsonify([dict(zip(keys, r)) for r in rows])

# ---------------------------
# DarkGrid HTML Dashboard
# ---------------------------
@app.route("/darkgrid", methods=["GET"])
def darkgrid_dashboard():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT * FROM reports ORDER BY created_at DESC LIMIT 50")
    rows = cur.fetchall()
    conn.close()
    keys = ["id", "filename", "vt_positives", "anyrun_score", "ai_score", "ai_summary", "created_at"]

    html = render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DarkGrid | RedShark R&D</title>
<style>
body {
    font-family: Arial, sans-serif;
    background-color: #1e1e1e;
    color: #ccc;
    margin: 20px;
}
h1 { color: #00f5a0; }
table { width: 100%; border-collapse: collapse; margin-top: 20px; }
th, td { padding: 10px; border: 1px solid #333; text-align: left; }
th { color: #888; }
tr:nth-child(even) { background-color: #2a2a2a; }
.badge { padding: 3px 6px; border-radius: 4px; font-weight: bold; }
.low { background-color: #444; color: #fff; }
.medium { background-color: #ff9800; color: #000; }
.high { background-color: #ff4444; color: #fff; }
</style>
</head>
<body>
<h1>DarkGrid</h1>
<p>A division of RedShark’s R&D Division</p>
<table>
    <thead>
        <tr>
            <th>ID</th>
            <th>Filename</th>
            <th>VT Positives</th>
            <th>Any.Run Score</th>
            <th>AI Score</th>
            <th>Summary</th>
            <th>Created At</th>
        </tr>
    </thead>
    <tbody>
        {% for r in rows %}
        <tr>
            <td>{{ r['id'] }}</td>
            <td>{{ r['filename'] }}</td>
            <td>{{ r['vt_positives'] }}</td>
            <td>{{ r['anyrun_score'] }}</td>
            <td>{{ r['ai_score'] }}</td>
            <td>
                <span class="badge {% if r['ai_score'] >= 80 %}high{% elif r['ai_score'] >=40 %}medium{% else %}low{% endif %}">
                {{ r['ai_summary'] }}
                </span>
            </td>
            <td>{{ r['created_at'] }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
</body>
</html>
""", rows=[dict(zip(keys, r)) for r in rows])

    return html

# ---------------------------
# Health Check
# ---------------------------
@app.route("/")
def health():
    return jsonify({"status": "RedShark API running"})

# ---------------------------
# Local Run
# ---------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
