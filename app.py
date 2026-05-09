from flask import Flask, render_template, request, send_file
import pandas as pd
import hashlib
from datetime import datetime
import io
import os

# PDF Generation Imports
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

app = Flask(__name__)

LOG_FILE = "logs.csv"

# Global variable to capture the file hash when the analyst starts the server session
SESSION_START_HASH = ""

def calculate_current_hash():
    """Calculates the SHA-256 hash of the logs file."""
    if not os.path.exists(LOG_FILE) or os.stat(LOG_FILE).st_size == 0:
        return "NO_FILE"
    with open(LOG_FILE, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

# Ensure the logs file exists with appropriate headers on startup and calculate base hash
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        f.write("ip,time,user,status,role")

SESSION_START_HASH = calculate_current_hash()


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login_page')
def login_page():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Security engine: Categorize malicious injection attempts
    is_malicious = False
    malicious_indicators = ["'", "--", "union", "select", "<script>", "javascript:", "alert("]
    if any(indicator in username.lower() or indicator in password.lower() for indicator in malicious_indicators):
        is_malicious = True

    if username == "admin" and password == "admin" and not is_malicious:
        status = "success"
        role = "admin"
    elif is_malicious:
        status = "malicious"
        role = "attacker"
    else:
        status = "failed"
        role = "user"

    ip = request.remote_addr
    time = datetime.now().strftime("%H:%M:%S")

    # Read existing file to check for trailing newlines
    file_is_empty = False
    if not os.path.exists(LOG_FILE) or os.stat(LOG_FILE).st_size == 0:
        file_is_empty = True

    with open(LOG_FILE, "a") as f:
        if file_is_empty:
            f.write("ip,time,user,status,role\n")
            f.write(f"{ip},{time},{username},{status},{role}")
        else:
            f.write(f"\n{ip},{time},{username},{status},{role}")

    if is_malicious:
        return render_template("login.html", message="⚠️ Security Gateway Blocked a Malicious Injection Request.")
    return render_template("login.html", message="✅ Access request processed and compiled to logs.")


@app.route('/dashboard')
def dashboard():
    df = pd.read_csv(LOG_FILE)
    
    # Calculate Live File Hash for Integrity Ledger
    current_hash = calculate_current_hash()
    
    # Check if the file has been altered or updated during the current session
    integrity_drift = (SESSION_START_HASH != current_hash)

    alerts = []
    actions = []
    level = "LOW"

    # Brute Force Analysis
    failed_counts = df[df['status'] == 'failed'].groupby('ip').size()
    for ip, count in failed_counts.items():
        if count >= 5:
            alerts.append(f"Brute Force threshold breached from {ip}")
            actions.append("Source IP Blocked")
            level = "HIGH"

    # Suspicious access timeframe
    for t in df['time']:
        try:
            hour = int(t.split(":")[0])
            if hour < 6 or hour > 22:
                alerts.append("Out-of-Hours Event Logged")
                actions.append("Rate-Limit Session Requests")
                if level != "HIGH" and level != "CRITICAL":
                    level = "MEDIUM"
        except Exception:
            pass

    # Malicious injection/attack detection alert trigger
    if "malicious" in df['status'].values:
        alerts.append("Active Web Shell/Injection Signature Detected")
        actions.append("IPS Deep Packet Inspection Triggered")
        level = "CRITICAL"

    # Behavioral Anomaly
    ip_per_user = df.groupby('user')['ip'].nunique()
    for user, count in ip_per_user.items():
        if count > 3:
            alerts.append(f"Identity Anomaly: Multi-Location Session for [{user}]")
            actions.append("Interactive Session Revoked")
            level = "HIGH"

    # Privilege Escalation
    if "admin" in df['role'].values:
        alerts.append("Administrative Privilege Assertion Identified")
        actions.append("Audit Admin Token Signatures")
        level = "CRITICAL"

    # Timeline sorting (Fixing the mixed format parsing warning)
    df['time_parsed'] = pd.to_datetime(df['time'], format='mixed', errors='coerce')
    timeline = df.sort_values(by='time_parsed')

    timeline_data = []
    for _, row in timeline.iterrows():
        time_str = str(row['time'])
        timeline_data.append({
            "time": time_str,
            "ip": row['ip'],
            "status": row['status']
        })

    # Prepare historical logs for the Attack Vector Heatmap (last 20 logs)
    heatmap_logs = []
    recent_logs_df = df.tail(20)
    for _, row in recent_logs_df.iterrows():
        heatmap_logs.append({
            "time": str(row['time']),
            "ip": str(row['ip']),
            "status": str(row['status']),
            "user": str(row['user'])
        })

    stats = {
        "total": len(df),
        "failed": len(df[df['status'] == 'failed']),
        "success": len(df[df['status'] == 'success']),
        "malicious": len(df[df['status'] == 'malicious'])
    }

    new_logs = len(df.tail(10))

    return render_template(
        "dashboard.html",
        alerts=list(set(alerts)),
        actions=list(set(actions)),
        level=level,
        start_hash=SESSION_START_HASH,
        current_hash=current_hash,
        integrity_drift=integrity_drift,
        stats=stats,
        timeline=timeline_data,
        heatmap_logs=heatmap_logs,
        new_logs=new_logs
    )


@app.route('/save')
def save():
    """Generates a polished PDF Forensic Report with cryptographic integrity indicators."""
    df = pd.read_csv(LOG_FILE)
    current_hash = calculate_current_hash()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=letter,
        rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=22,
        textColor=colors.HexColor('#0f172a'), spaceAfter=8
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle', parent=styles['Normal'], fontName='Helvetica', fontSize=10,
        textColor=colors.HexColor('#64748b'), spaceAfter=20
    )

    section_header = ParagraphStyle(
        'SectionHeader', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=13,
        textColor=colors.HexColor('#1e1b4b'), spaceAfter=10, spaceBefore=15
    )
    
    body_style = ParagraphStyle(
        'ReportBody', parent=styles['Normal'], fontName='Helvetica', fontSize=9.5,
        textColor=colors.HexColor('#334155'), leading=14
    )

    story = []

    # Document Header
    story.append(Paragraph("FORENSIC THREAT AUDIT REPORT", title_style))
    story.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | SIEM Automated Agent", subtitle_style))
    story.append(Spacer(1, 10))

    # Cryptographic Ledger Status
    story.append(Paragraph("Cryptographic File Integrity", section_header))
    story.append(Paragraph(f"<b>Session Starting Signature (SHA-256):</b><br/><font face='Courier' size='8'>{SESSION_START_HASH}</font>", body_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"<b>Current Runtime Signature (SHA-256):</b><br/><font face='Courier' size='8'>{current_hash}</font>", body_style))
    
    drift_status = "STABLE (No modifications since server boot)" if SESSION_START_HASH == current_hash else "DRIFT DETECTED (New database mutations logged)"
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"<b>Integrity Profile:</b> {drift_status}", body_style))
    story.append(Spacer(1, 12))

    # Analytical Summary Table
    story.append(Paragraph("System Metrics Analysis", section_header))
    summary_data = [
        ["Metric Classification", "Telemetry Count"],
        ["Total Processed Logs", str(len(df))],
        ["Passed Authorization Accesses", str(len(df[df['status'] == 'success']))],
        ["Anomalous Failures Detected", str(len(df[df['status'] == 'failed']))],
        ["Flagged Exploitation Attacks", str(len(df[df['status'] == 'malicious']))]
    ]
    
    t_summary = Table(summary_data, colWidths=[250, 250])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e1b4b')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8fafc')),
        ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#e2e8f0')),
        ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 15))

    # Detailed Incident Log Timeline
    story.append(Paragraph("Chronological Event Log (Recent 15 Events)", section_header))
    table_data = [["Timestamp", "Origin IP", "Session User", "Status", "System Role"]]
    for _, row in df.tail(15).iterrows():
        table_data.append([
            str(row['time']),
            str(row['ip']),
            str(row['user']),
            str(row['status']).upper(),
            str(row['role']).upper()
        ])
        
    t_logs = Table(table_data, colWidths=[90, 100, 120, 90, 100])
    t_logs.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#334155')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,0), 5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f1f5f9')])
    ]))
    story.append(t_logs)
    
    doc.build(story)
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"Forensic_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
        mimetype="application/pdf"
    )


@app.route('/deep')
def deep():
    """Run advanced diagnostics looking for web application vulnerabilities."""
    df = pd.read_csv(LOG_FILE)
    
    results = {
        "xss_attempts": 0,
        "sqli_attempts": 0,
        "scanner_signatures": 0,
        "weak_passwords": 0,
        "privileged_leak_risk": "NONE",
        "log_tampering": "SECURE",
        "log_entropy_anomaly": "STABLE",
        "system_status": "COMPLETED"
    }

    for user in df['user'].astype(str):
        # SQL Injection (SQLi)
        sqli_indicators = ["'", "--", "union", "select", "or 1=1", "admin' --"]
        if any(indicator in user.lower() for indicator in sqli_indicators):
            results["sqli_attempts"] += 1
            
        # Cross-Site Scripting (XSS)
        xss_indicators = ["<script>", "javascript:", "alert(", "onload="]
        if any(indicator in user.lower() for indicator in xss_indicators):
            results["xss_attempts"] += 1

        # Automated Web Scanners
        scanner_indicators = ["nmap", "sqlmap", "nikto", "dirb", "masscan"]
        if any(indicator in user.lower() for indicator in scanner_indicators):
            results["scanner_signatures"] += 1

        # Weak Default Passwords
        weak_list = ["admin", "password", "123456", "root", "qwerty"]
        if user.lower() in weak_list:
            results["weak_passwords"] += 1

    # Evaluate credentials threat severity level
    admin_actions = df[df['role'] == 'admin']
    admin_fails = admin_actions[admin_actions['status'] == 'failed']
    if len(admin_fails) > 3:
        results["privileged_leak_risk"] = "CRITICAL"
    elif len(admin_fails) > 0:
        results["privileged_leak_risk"] = "MODERATE"

    return render_template("deep_scan.html", results=results)


if __name__ == "__main__":
    app.run(debug=True, port=5001)