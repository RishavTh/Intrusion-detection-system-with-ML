# Linux Authentication Intrusion Detection System (Auth-IDS)

A real-time Machine Learning based Intrusion Detection System for Linux authentication log monitoring, built as a Final Year Project at Islington College, Nepal.

**Student:** Rishav Kumar Thapa | **ID:** 23047504
**Module:** CS6P05NI Final Year Project

---

## Project Structure
```
Auth_IDS/
├── app.py                  # Flask server & 5 API endpoints
├── monitor.py              # Real-time log watcher (3s polling)
├── parser.py               # Log parser (11 regex patterns)
├── detector.py             # Random Forest ML detection engine
├── database.py             # SQLite alert storage
├── slack_notify.py         # Slack webhook notifications
├── report_generator.py     # NIST SP 800-61 Rev 2 PDF generator
├── linux_auth_model.pkl    # Trained ML model (100 trees)
├── model_columns.pkl       # 39 feature columns
└── dashboard/
    ├── index.html          # 6-tab dashboard
    ├── style.css           # Dark theme
    └── app.js              # Charts & real-time polling
```

---

## Features

- Real-time SSH Brute Force detection
- Sudo Privilege Abuse detection
- Foreign IP geographic anomaly detection (Nepal ISP whitelist)
- Port Scan detection (SSH + HTTP)
- Live 6-tab web dashboard with Chart.js and Leaflet.js
- GeoIP world attack map
- Slack instant alert notifications
- NIST SP 800-61 Rev 2 compliant PDF report generator
- API health status monitor

---

## Tech Stack

| Component | Technology |
|---|---|
| Backend | Python 3.12, Flask |
| ML Model | Random Forest (100 trees, 39 features) |
| Database | SQLite |
| Frontend | Vanilla JavaScript, Chart.js, Leaflet.js |
| Notifications | Slack Webhooks |
| Training Dataset | 5,026 balanced records |
| Model Accuracy | 100% on test set |

---

## Installation
```bash
git clone https://github.com/abhisek-bhattarai/SIEM-System.git
cd SIEM-System
python3 -m venv venv
source venv/bin/activate
pip install flask flask-cors pandas scikit-learn requests reportlab
sudo python3 app.py
```

Open browser: `http://localhost:5000`

---

## Detection Results

| Threat Type | Alerts | Percentage |
|---|---|---|
| SSH Brute Force | 4,500 | 58.6% |
| Suspicious | 3,072 | 40.0% |
| Port Scan | 73 | 0.9% |
| Foreign IP | 59 | 0.8% |
| Sudo Abuse | 44 | 0.6% |
| **Total** | **7,677** | **100%** |

---

## System Requirements

- Ubuntu 20.04 or 22.04
- Python 3.10+
- `/var/log/auth.log` readable
