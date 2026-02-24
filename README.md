# 🛡️ Linux Authentication IDS (Auth-IDS)

> A real-time Intrusion Detection System that watches your Linux system's authentication logs and alerts you the moment an attack begins — powered by a Random Forest ML model.

---

## 🔍 What Problem Does It Solve?

Linux servers are constantly targeted by attackers — SSH brute force, privilege escalation, port scanning and foreign access attempts happen every day. Most system administrators only find out **after** the damage is done.

**Auth-IDS monitors your system 24/7 and catches attacks as they happen.**

---

## 🚀 What It Does

- 🔴 **SSH Brute Force Detection** — Catches repeated failed login attempts from attackers trying to guess passwords using tools like Hydra
- 🟡 **Privilege Escalation Detection** — Flags unauthorised sudo usage and privilege abuse attempts
- 🟣 **Foreign IP Detection** — Alerts when login attempts come from unexpected geographic locations
- 🟠 **Port Scan Detection** — Identifies reconnaissance scans from tools like nmap before a real attack begins
- 📊 **Live Web Dashboard** — 6-tab interface with real-time threat feed, charts, analytics and world attack map
- 📲 **Instant Slack Alerts** — Notifies your Slack channel the moment a threat is detected with full details
- 📄 **NIST Incident Reports** — Generates professional PDF reports following NIST SP 800-61 Rev 2 standard
- 🌍 **GeoIP World Map** — Visualises attacker locations on an interactive world map in real time

---

## ⚙️ How It Works
```
/var/log/auth.log
       ↓
   monitor.py        watches log file every 3 seconds
       ↓
   parser.py         extracts features from each log line
       ↓
   detector.py       Random Forest ML model classifies the threat
       ↓
   database.py       stores alert in SQLite
       ↓
   slack_notify.py   sends instant Slack notification
       ↓
   dashboard         displays live on web interface
```

---

## 🧠 ML Model

| Property | Detail |
|---|---|
| Algorithm | Random Forest |
| Trees | 100 |
| Features | 39 |
| Training Records | 5,026 balanced samples |
| Test Accuracy | 100% |
| Output | Threat type + confidence score (0-100%) |

The model classifies each authentication event into: `ssh_brute_force`, `sudo_abuse`, `foreign_ip`, `port_scan`, or `authorized`.

---

## 📁 Project Structure
```
Auth_IDS/
├── app.py                  # Flask server & 6 API endpoints
├── monitor.py              # Real-time log watcher (3s polling)
├── parser.py               # Log parser (11 regex patterns)
├── detector.py             # Random Forest ML detection engine
├── database.py             # SQLite alert storage
├── slack_notify.py         # Slack webhook notifications
├── report_generator.py     # NIST SP 800-61 Rev 2 PDF generator
├── linux_auth_model.pkl    # Trained ML model
├── model_columns.pkl       # 39 feature columns
└── dashboard/
    ├── index.html          # 6-tab dashboard UI
    ├── style.css           # Dark theme styling
    └── app.js              # Real-time charts & polling
```

---

## 📦 Installation
```bash
git clone https://github.com/abhisek-bhattarai/SIEM-System.git
cd SIEM-System
python3 -m venv venv
source venv/bin/activate
pip install flask flask-cors pandas scikit-learn requests reportlab
sudo python3 app.py
```

Open browser: **http://localhost:5000**

---

## 🔧 Configuration

Add your Slack webhook in `slack_notify.py`:
```python
WEBHOOK_URL = "https://hooks.slack.com/services/YOUR/WEBHOOK/HERE"
```

Get a free webhook at: https://api.slack.com/apps

---

## 🌐 API Endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Live dashboard UI |
| `GET /api/health` | System health check |
| `GET /api/stats` | Full alert statistics |
| `GET /api/alerts` | Last 100 alerts |
| `GET /api/alerts/live/<id>` | Real-time polling every 4s |
| `GET /api/generate-report` | Download NIST PDF report |

---

## 📊 Live Detection Results

> Captured during live deployment — Ubuntu 24.04 target system, Kali Linux attacker

| Threat Type | Alerts | Share |
|---|---|---|
| 🔴 SSH Brute Force | 4,500 | 58.6% |
| ⚫ Suspicious Activity | 3,072 | 40.0% |
| 🟠 Port Scan | 73 | 0.9% |
| 🟣 Foreign IP | 59 | 0.8% |
| 🟡 Sudo Abuse | 44 | 0.6% |
| **Total** | **7,677** | **100%** |

---

## 🖥️ System Requirements

- Ubuntu 20.04 / 22.04 / 24.04
- Python 3.10+
- Read access to `/var/log/auth.log`
- Minimum 2GB RAM

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, Flask |
| ML | scikit-learn Random Forest |
| Database | SQLite |
| Frontend | JavaScript, Chart.js, Leaflet.js |
| Alerts | Slack Webhooks |
| Reports | ReportLab PDF |
