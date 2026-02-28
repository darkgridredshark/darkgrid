import os
import time
import sqlite3
import requests
from flask import Flask, request, jsonify

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
# Database
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
# VirusTotal
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

        # Poll once (VT free tier may delay)
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
# Any.Run
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

        # Poll up to 2 minutes
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

    ai_score, summary, vt_pos, any_score = ai_risk_score(
        vt_report, anyrun_report
    )

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

    keys = [
        "id", "filename", "vt_positives",
        "anyrun_score", "ai_score",
        "ai_summary", "created_at"
    ]

    return jsonify(dict(zip(keys, row)))


# ---------------------------
# Dashboard (JSON)
# ---------------------------
@app.route("/dashboard", methods=["GET"])
def dashboard():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT * FROM reports ORDER BY created_at DESC LIMIT 50")
    rows = cur.fetchall()
    conn.close()

    keys = [
        "id", "filename", "vt_positives",
        "anyrun_score", "ai_score",
        "ai_summary", "created_at"
    ]

    return jsonify([dict(zip(keys, r)) for r in rows])


# ---------------------------
# Health Check (For Render)
# ---------------------------
@app.route("/")
def health():
    return jsonify({"status": "RedShark API running"})


# ---------------------------
# Local Run (Gunicorn handles production)
# ---------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
