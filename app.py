from flask      import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
from database   import init_db, get_alerts, get_recent_alerts, save_alert
from monitor    import run_in_background
from slack_notify import send_slack
import sqlite3, os, threading
from datetime import datetime
from collections import defaultdict

DB  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ids.db')
app = Flask(__name__, static_folder='dashboard', static_url_path='')
CORS(app)

# ── nmap HTTP signature detection ────────────────────────────
NMAP_SIGNATURES = [
    'nmaplowercheck', '/sdk', '/evox/about', '/HNAP1',
    '/nice%20ports', '/nmap', '/.git', '/admin.php',
    '/login.php', '/wp-login', '/xmlrpc', '/phpmyadmin',
    'trinity.txt', 'mstshash=nmap', 'options sip'
]


# Track suspicious HTTP requests per IP
http_probe_tracker = defaultdict(list)  # ip -> [timestamps]
http_alerted_ips   = set()

def check_http_portscan(ip, path):
    """Detect nmap/scanner by signatures OR rapid requests."""
    now = datetime.now()

    # Method 1 — signature match (classic nmap HTTP probes)
    is_nmap_probe = any(sig.lower() in path.lower() for sig in NMAP_SIGNATURES)
    if is_nmap_probe:
        http_probe_tracker[ip].append(now)
        http_probe_tracker[ip] = [
            t for t in http_probe_tracker[ip]
            if (now - t).total_seconds() <= 30
        ]

    # Method 2 — track ALL requests from this IP in 10 seconds
    if not hasattr(check_http_portscan, 'all_tracker'):
        check_http_portscan.all_tracker = {}
    tracker = check_http_portscan.all_tracker
    if ip not in tracker:
        tracker[ip] = []
    # Skip normal dashboard traffic — only track suspicious paths
    dashboard_paths = ['/api/alerts', '/api/stats', '/api/health',
                       '/style.css', '/app.js', '/favicon.ico',
                       '/api/generate-report']
    if any(path == p or (p != '/' and path.startswith(p)) for p in dashboard_paths):
        return
    tracker[ip].append(now)
    tracker[ip] = [t for t in tracker[ip] if (now - t).total_seconds() <= 60]

    sig_count = len(http_probe_tracker[ip])
    all_count = len(tracker[ip])
    probe_count = max(sig_count, all_count)

    # Alert if 2+ signature probes OR 6+ any requests in 10 seconds
    if (sig_count >= 1 or all_count >= 2) and ip not in http_alerted_ips:
        http_alerted_ips.add(ip)
        alert = {
            'detected_at': str(now),
            'timestamp'  : str(now),
            'source_ip'  : ip,
            'username'   : 'unknown',
            'service'    : 'http',
            'status'     : 'port_scan',
            'event_type' : 'port_scan_probe',
            'threat_type': 'port_scan',
            'confidence' : round(min(60 + probe_count * 8, 99), 1),
            'raw_log'    : f'HTTP port scan from {ip} — path: {path} ({probe_count} probes in 30s)',
        }
        save_alert(alert)
        threading.Thread(target=send_slack, args=(alert,), daemon=True).start()
        print(f"🔍 HTTP Port scan detected: {ip} | {probe_count} probes | confidence {alert['confidence']}%")

        # Reset after 60 seconds so it can alert again
        def reset_ip():
            import time; time.sleep(60)
            http_alerted_ips.discard(ip)
            http_probe_tracker[ip] = []
        threading.Thread(target=reset_ip, daemon=True).start()


@app.before_request
def detect_scanner():
    """Run on every HTTP request — detect nmap/scanners."""
    ip   = request.remote_addr
    path = request.path
    check_http_portscan(ip, path)


@app.route('/')
def index():
    return send_from_directory('dashboard', 'index.html')

@app.route('/style.css')
def css():
    return send_from_directory('dashboard', 'style.css')

@app.route('/app.js')
def js():
    return send_from_directory('dashboard', 'app.js')

@app.route('/api/alerts')
def api_alerts():
    return jsonify({'alerts': get_alerts(100)})

@app.route('/api/alerts/live/<int:since_id>')
def api_live(since_id):
    return jsonify({'alerts': get_recent_alerts(since_id)})

@app.route('/api/stats')
def api_stats():
    conn = sqlite3.connect(DB)
    c    = conn.cursor()
    c.execute("SELECT COUNT(*) FROM alerts")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM alerts WHERE threat_type='ssh_brute_force'")
    ssh = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM alerts WHERE threat_type='sudo_abuse'")
    sudo = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM alerts WHERE threat_type='foreign_ip'")
    foreign = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM alerts WHERE threat_type='port_scan'")
    port_scan = c.fetchone()[0]
    conn.close()
    return jsonify({
        'total_alerts'   : total,
        'ssh_brute_force': ssh,
        'sudo_abuse'     : sudo,
        'foreign_ip'     : foreign,
        'port_scan'      : port_scan,
    })

@app.route('/api/generate-report')
def generate_report_endpoint():
    """Generate and download a PDF security incident report."""
    import tempfile, os
    from report_generator import generate_report
    from flask import send_file
    ts  = datetime.now().strftime('%Y%m%d_%H%M%S')
    out = os.path.join(tempfile.gettempdir(), f'IDS_Security_Report_{ts}.pdf')
    generate_report(out)
    return send_file(out, as_attachment=True,
                     download_name=f'IDS_Security_Report_{ts}.pdf',
                     mimetype='application/pdf')

@app.route('/api/health')
def api_health():
    return jsonify({'status': 'running', 'monitor': 'active'})

if __name__ == '__main__':
    print("=" * 50)
    print("  Linux Auth IDS — Starting")
    print("=" * 50)
    init_db()
    print("✅ Database ready:", DB)
    run_in_background()
    print("🌐 Dashboard → http://localhost:5000")
    print("📡 API       → http://localhost:5000/api/stats")
    print("🔍 nmap HTTP detection → ACTIVE")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
