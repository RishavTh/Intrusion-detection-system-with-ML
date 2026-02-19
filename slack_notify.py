import urllib.request
import json
from datetime import datetime
SLACK_WEBHOOK  = 'YOUR_SLACK_WEBHOOK_HERE'
NOTIFY_SSH      = True
NOTIFY_SUDO     = True
NOTIFY_FOREIGN  = True
NOTIFY_PORTSCAN = True
NOTIFY_SUSP     = True
NOTIFY_AUTH     = True   # green login alerts
MIN_CONFIDENCE  = 50.0

def should_notify(alert):
    threat = alert.get('threat_type', '')
    conf   = float(alert.get('confidence', 0))
    if conf < MIN_CONFIDENCE:                           return False
    if threat == 'ssh_brute_force' and NOTIFY_SSH:      return True
    if threat == 'sudo_abuse'      and NOTIFY_SUDO:     return True
    if threat == 'foreign_ip'      and NOTIFY_FOREIGN:  return True
    if threat == 'port_scan'       and NOTIFY_PORTSCAN: return True
    if threat == 'suspicious'      and NOTIFY_SUSP:     return True
    if threat == 'authorized'      and NOTIFY_AUTH:     return True
    return False

def build_payload(alert):
    threat  = alert.get('threat_type', 'unknown')
    conf    = float(alert.get('confidence', 0))
    ip      = alert.get('source_ip',   'unknown')
    user    = alert.get('username',    'unknown')
    event   = alert.get('event_type',  'unknown')
    service = alert.get('service',     'unknown')
    ts      = alert.get('detected_at', str(datetime.now()))[:19]
    raw     = str(alert.get('raw_log', 'N/A'))[:200]

    config = {
        'ssh_brute_force': ('#ff3355', '🔴', 'CRITICAL', 'SSH Brute Force Attack'),
        'sudo_abuse'     : ('#ffcc00', '🟡', 'MEDIUM',   'Sudo Privilege Abuse'),
        'foreign_ip'     : ('#aa55ff', '🟣', 'HIGH',     'Foreign IP Access Attempt'),
        'port_scan'      : ('#ff7730', '🟠', 'HIGH',     'Port Scan Detected'),
        'suspicious'     : ('#4a6080', '⚪', 'LOW',      'Suspicious Activity'),
        'authorized'     : ('#00ff88', '✅', 'INFO',     'Authorized Login'),
    }
    color, icon, severity, label = config.get(threat, ('#4a6080', '⚪', 'LOW', 'Unknown'))

    return {
        "text": f"{icon} *IDS ALERT — {severity}* | {label}",
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{icon}  {label}", "emoji": True}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Severity*\n{severity}"},
                        {"type": "mrkdwn", "text": f"*Host*\n`rishav-Vbox`"},
                        {"type": "mrkdwn", "text": f"*Source IP*\n`{ip}`"},
                        {"type": "mrkdwn", "text": f"*Username*\n`{user}`"},
                        {"type": "mrkdwn", "text": f"*Event Type*\n`{event}`"},
                        {"type": "mrkdwn", "text": f"*Service*\n`{service}`"},
                        {"type": "mrkdwn", "text": f"*ML Confidence*\n`{conf}%`"},
                        {"type": "mrkdwn", "text": f"*Detected At*\n`{ts}`"},
                    ]
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Raw Log*\n```{raw}```"}
                },
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn",
                    "text": "🛡 Linux Auth IDS · rishav-Vbox · CS6P05NI Final Year Project"}]
                }
            ]
        }]
    }

def send_slack(alert):
    if not should_notify(alert):
        return
    try:
        data = json.dumps(build_payload(alert)).encode('utf-8')
        req  = urllib.request.Request(
            SLACK_WEBHOOK, data=data,
            headers={'Content-Type': 'application/json'}, method='POST'
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = resp.read().decode()
            if result == 'ok':
                print(f"💬 Slack sent → [{alert.get('threat_type')} | {alert.get('confidence')}%]")
            else:
                print(f"❌ Slack error: {result}")
    except Exception as e:
        print(f"❌ Slack failed: {e}")

if __name__ == '__main__':
    test = {
        'detected_at': str(datetime.now()),
        'source_ip'  : '192.168.16.197',
        'username'   : 'ubuntu',
        'service'    : 'ssh',
        'event_type' : 'port_scan_probe',
        'threat_type': 'port_scan',
        'confidence' : 97.0,
        'raw_log'    : 'Connection closed by invalid user ubuntu 192.168.16.197 port 51154 [preauth]'
    }
    send_slack(test)
