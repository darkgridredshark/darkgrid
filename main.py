import os
import requests
import sqlite3
from flask import Flask, request, jsonify
import time

# ---------------------------
# Flask App & Uploads
# ---------------------------
app = Flask(_name_)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------------------------
# Environment Variables
# ---------------------------
VT_API_KEY = os.environ.get("VT_API_KEY")
ANYRUN_API_KEY = os.environ.get("ANYRUN_API_KEY")
DB_FILE = os.environ.get("DB_FILE", "malware.db")

# ---------------------------
# Database Setup
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
# VirusTotal API Integration
# ---------------------------
def check_virustotal(file_path=None, file_hash=None):
    headers = {"x-apikey": VT_API_KEY}
    if file_path:
        with open(file_path, "rb") as f:
            response = requests.post("https://www.virustotal.com/api/v3/files",
                                     headers=headers, files={"file": f})
        result = response.json()
        vt_id = result.get("data", {}).get("id")
        report_resp = requests.get(f"https://www.virustotal.com/api/v3/analyses/{vt_id}", headers=headers)
        return report_resp.json()
    elif file_hash:
        response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)
        return response.json()

# ---------------------------
# Any.Run API Integration
# ---------------------------
def submit_anyrun(file_path):
    """
    Submit file to Any.Run for dynamic analysis.
    Polls report until ready (~2 mins max).
    """
    url = "https://any.run/api/v2/tasks"
    headers = {"Authorization": f"Bearer {ANYRUN_API_KEY}"}
    with open(file_path, "rb") as f:
        files = {"file": f}
        response = requests.post(url, headers=headers, files=files)
    task = response.json()
    task_id = task.get("id")

    # Poll for report
    report_url = f"https://any.run/api/v2/tasks/{task_id}/report/json"
    for _ in range(20):  # 20 attempts, ~2 mins
        r = requests.get(report_url, headers=headers)
        if r.status_code == 200:
            return r.json()
        time.sleep(6)
    return {"error": "Any.Run report not ready"}

# ---------------------------
# AI Risk Scoring
# ---------------------------
def ai_risk_score(vt_report, anyrun_report):
    score = 0

    # VT detections
    positives = vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    score += min(positives * 5, 50)  # Max 50 points from VT

    # Any.Run behavior scoring
    behavior_summary = anyrun_report.get("behavior", {}).get("summary", {})
    anyrun_score = 50 if behavior_summary else 20
    score += anyrun_score

    # Risk level
    if score >= 80:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    summary = f"AI Risk Level: {level}, Score: {score}/100"
    return score, summary, positives, anyrun_score

# ---------------------------
# Upload & Analyze Endpoint
# ---------------------------
@app.route("/analyze", methods=["POST"])
def analyze_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    # Get reports
    vt_report = check_virustotal(filepath)
    anyrun_report = submit_anyrun(filepath)

    # AI scoring
    ai_score, summary, vt_positives, anyrun_score = ai_risk_score(vt_report, anyrun_report)

    # Store in DB
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO reports (filename, vt_positives, anyrun_score, ai_score, ai_summary)
        VALUES (?, ?, ?, ?, ?)
    """, (file.filename, vt_positives, anyrun_score, ai_score, summary))
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
# Get Report by ID
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

    keys = ["id","filename","vt_positives","anyrun_score","ai_score","ai_summary","created_at"]
    report = dict(zip(keys, row))
    return jsonify(report)

# ---------------------------
# Dashboard Endpoint
# ---------------------------
@app.route("/dashboard", methods=["GET"])
def dashboard():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT * FROM reports ORDER BY created_at DESC LIMIT 50")
    rows = cur.fetchall()
    conn.close()

    keys = ["id","filename","vt_positives","anyrun_score","ai_score","ai_summary","created_at"]
    return jsonify([dict(zip(keys, r)) for r in rows])

# ---------------------------
# Main
# ---------------------------
if _name_ == "_main_":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
