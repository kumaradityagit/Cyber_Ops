# CyberOps⚡AI-Driven-Automated-Malware-Analysis-System
Welcome to **CyberOps GRID 2077** — a futuristic, fully-automated cybersecurity threat detection and incident response system.

This project integrates:
- Static Malware Analysis (VirusTotal Intelligence)
- Dynamic Malware Behavior Execution & Monitoring
- Real-Time Process Anomaly Detection using Machine Learning (Isolation Forest)
- Threat Scoring Consolidation
- Automated Incident Response (process kill, network isolation, backup)
- Master Threat Reporting (PDF Generation + Google Drive Upload)
- Twilio SMS Alert Integration

All modules operate from a **centralized TRON-styled CLI Control System** for smooth operation, real-time decision making, and seamless threat reporting.

---

## 🧠 System Features:

| Module | Description |
|:-------|:------------|
| **Static Malware Analysis** | Scans files against VirusTotal and generates a threat verdict. |
| **Dynamic Behavior Analysis** | Executes suspicious files inside a monitored subprocess environment. |
| **Process Anomaly Detection** | Uses AI (Isolation Forest) to flag suspicious process behaviors live. |
| **Threat Score Consolidation** | Aggregates data and assigns Risk Levels for prioritization. |
| **Incident Response Engine** | Automates defense actions: Process termination, network shutdown, backup. |
| **Unified Master Reporting** | Generates a clean Master PDF with all operations in one place. |
| **Google Drive Integration** | Uploads the final report to Google Drive for backup. |
| **Twilio SMS Alert** | Sends real-time threat notifications to a configured mobile number. |

---

## 🛠️ Installation Instructions:

1. Clone or Download the Project.
2. Install the required Python packages:
```bash
pip install -r requirements.txt


# Your Mini `requirements.txt`:

plaintext
CopyEdit
psutil
pandas
scikit-learn
fpdf
requests
google-auth-oauthlib
google-api-python-client
twilio
colorama
