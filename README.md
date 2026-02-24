# 🛡️ Linux Authentication IDS (Auth-IDS)

> Real-time Machine Learning based Intrusion Detection System for Linux authentication monitoring with live web dashboard.

**Student:** Rishav Kumar Thapa | **ID:** 23047504  
**Institution:** Islington College, Nepal | **Module:** CS6P05NI Final Year Project  
**Supervisor:** Lecturer, Islington College Nepal

---

## 📸 Dashboard Preview

> Live 6-tab security dashboard with real-time threat detection



---

## 🚀 Features

| Feature | Status |
|---|---|
| SSH Brute Force Detection | ✅ Active |
| Sudo Privilege Abuse Detection | ✅ Active |
| Foreign IP Geographic Detection | ✅ Active |
| Port Scan Detection (SSH + HTTP) | ✅ Active |
| Live 6-Tab Web Dashboard | ✅ Active |
| GeoIP World Attack Map | ✅ Active |
| Slack Instant Notifications | ✅ Active |
| NIST SP 800-61 Rev 2 PDF Reports | ✅ Active |
| API Health Status Monitor | ✅ Active |

---

## 📁 Project Structure
```
Auth_IDS/
├── app.py                  # Flask server & API endpoints
├── monitor.py              # Real-time log watcher (3s polling)
├── parser.py               # Log parser (11 regex patterns)
├── detector.py             # Random Forest ML detection engine
├── database.py             # SQLite alert storage
├── slack_notify.py         # Slack webhook notifications
├── report_generator.py     # NIST SP 800-61 Rev 2 PDF generator
├── linux_auth_model.pkl    # Trained ML model (100 trees)
├── model_columns.pkl       # 39 feature columns
└── dashboard/
    ├── index.html          # 6-tab dashboard UI
    ├── style.css           # Dark theme styling
    └── app.js              # Real-time charts & polling
```

---

## ⚙️ Tech Stack

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

## 📦 Installation
```bash
# Clone repository
git clone https://github.com/abhisek-bhattarai/Linux-Auth-IDS.git
cd Linux-Auth-IDS

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install flask flask-cors pandas scikit-learn requests reportlab

# Run system (requires sudo for auth.log access)
sudo python3 app.py
```

Open browser: **http://localhost:5000**

---

## 🔧 Configuration

**Slack Notifications:**
```python
# In slack_notify.py — replace with your webhook
WEBHOOK_URL = "https://hooks.slack.com/services/YOUR/WEBHOOK/HERE"
```

---

## 🌐 API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Dashboard UI |
| `/api/health` | GET | System health check |
| `/api/stats` | GET | Alert statistics |
| `/api/alerts` | GET | Last 100 alerts |
| `/api/alerts/live/<id>` | GET | Live polling every 4s |
| `/api/generate-report` | GET | NIST PDF report |

---

## 📊 Live Detection Results
> ⚡ Current stats as of **February 23, 2026** — updated during active deployment

| Threat Type | Alerts | Percentage |
|---|---|---|
| 🔴 SSH Brute Force | 4,500 | 58.6% |
| ⚫ Suspicious | 3,072 | 40.0% |
| 🟠 Port Scan | 73 | 0.9% |
| 🟣 Foreign IP | 59 | 0.8% |
| 🟡 Sudo Abuse | 44 | 0.6% |
| **Total** | **7,677** | **100%** |

> These are **real detections** captured during live testing with Kali Linux attack simulation.

---

## 🖥️ System Requirements

- Ubuntu 20.04 / 22.04 / 24.04
- Python 3.10+
- `/var/log/auth.log` read access
- Minimum 2GB RAM

---

## 📄 License

This project is for academic purposes only — Islington College Final Year Project 2025/2026.
