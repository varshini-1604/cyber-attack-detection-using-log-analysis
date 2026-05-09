# Cyber Attack Detection Using Log Analysis

A Flask-based SIEM (Security Information and Event Management) project developed to detect suspicious activities and cyber attacks using real-time log analysis and forensic monitoring.

---

# Features

- Login authentication monitoring
- Brute force attack detection
- SQL Injection (SQLi) detection
- Cross-Site Scripting (XSS) detection
- Threat severity analysis
- Interactive forensic dashboard
- Deep vulnerability scan module
- PDF forensic report generation
- Cryptographic file integrity monitoring
- Attack timeline visualization
- Heatmap-based attack tracking

---

# Technologies Used

- Python
- Flask
- Pandas
- HTML5
- Tailwind CSS
- JavaScript
- ReportLab

---

# Project Structure

```text
cyber_attack_detection/
│
├── app.py
├── templates/
│   ├── index.html
│   ├── login.html
│   ├── dashboard.html
│   └── deep_scan.html
│
├── logs.csv
├── forensic_log.csv
├── requirements.txt
├── .gitignore
└── README.md
```

---

# Installation

## Clone Repository

```bash
git clone https://github.com/varshini-1604/cyber-attack-detection-using-log-analysis.git
```

## Move Into Project Folder

```bash
cd cyber-attack-detection-using-log-analysis
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Run the Project

```bash
python app.py
```

Server starts at:

```text
http://127.0.0.1:5001
```

---

# Default Login

```text
Username: admin
Password: admin
```

---

# Attack Detection Capabilities

- SQL Injection Detection
- Cross-Site Scripting (XSS)
- Brute Force Login Attempts
- Suspicious Login Time Detection
- Multi-IP User Anomaly Detection
- Scanner Signature Detection
- Weak Credential Identification

---

# Dashboard Modules

## Forensic Dashboard

Displays:
- Threat severity
- Active alerts
- Automated interventions
- Login timeline
- Attack heatmap

## Deep Scan Module

Performs:
- Vulnerability analysis
- SQLi/XSS detection
- Credential audits
- Threat diagnostics

## PDF Report Generator

Exports forensic reports containing:
- Security metrics
- Integrity hashes
- Attack records
- Timeline logs

---

# Team Collaboration Using GitHub

## Adding Team Members

Repository owner should:

1. Open GitHub repository
2. Go to **Settings**
3. Click **Collaborators**
4. Click **Add people**
5. Enter teammate GitHub usernames
6. Send invitation

Team members must accept the invitation.

---

# Steps for Team Members

## Clone Repository

```bash
git clone https://github.com/varshini-1604/cyber-attack-detection-using-log-analysis.git
```

## Move Into Folder

```bash
cd cyber-attack-detection-using-log-analysis
```

## Pull Latest Changes

```bash
git pull origin main
```

## Add Changes

```bash
git add .
```

## Commit Changes

```bash
git commit -m "Updated dashboard module"
```

## Push Changes

```bash
git push origin main
```

---

# Important Notes

- Dynamic log files should not be tracked continuously.
- Add these files in `.gitignore`:

```text
logs.csv
forensic_log.csv
```

- Always pull latest updates before pushing changes.

---

# Future Enhancements

- AI-based anomaly detection
- Machine learning threat analysis
- Real-time packet monitoring
- Email alert integration
- Cloud log integration
- Role-based access control

---

# Team Members

- Varshini
- Chandana
- Navya Sindhu

---

# License

This project is developed for academic and educational purposes.