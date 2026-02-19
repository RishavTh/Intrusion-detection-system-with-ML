import os
import time
import threading
from detector     import detect
from database     import save_alert
from slack_notify import send_slack

AUTH_LOG   = '/var/log/auth.log'
NEW_LOGS   = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'new_logs.txt')
BATCH_SIZE = 20
INTERVAL   = 3

_stop_event = threading.Event()

def _write_new_logs(lines):
    with open(NEW_LOGS, 'a') as f:
        for line in lines:
            f.write(line + '\n')

def _notify(alert):
    threading.Thread(target=send_slack, args=(alert,), daemon=True).start()

def _process_batch(lines):
    _write_new_logs(lines)
    alerts = detect(lines)
    if alerts:
        for alert in alerts:
            save_alert(alert)
            _notify(alert)
        print(f"🚨 {len(alerts)} alert(s) → saved + Slack queued")
    else:
        print(f"✅ {len(lines)} lines processed — clean")

def start_monitoring():
    print(f"👁  Monitoring {AUTH_LOG} ...")
    if not os.path.exists(AUTH_LOG):
        print(f"❌ Cannot find {AUTH_LOG} — run with sudo")
        return
    with open(AUTH_LOG, 'r') as f:
        f.seek(0, 2)
        buffer = []
        while not _stop_event.is_set():
            line = f.readline()
            if line:
                line = line.strip()
                if line:
                    buffer.append(line)
                if len(buffer) >= BATCH_SIZE:
                    _process_batch(buffer)
                    buffer = []
            else:
                if buffer:
                    _process_batch(buffer)
                    buffer = []
                time.sleep(INTERVAL)

def stop_monitoring():
    _stop_event.set()

def run_in_background():
    t = threading.Thread(target=start_monitoring, daemon=True)
    t.start()
    print("✅ Monitor running in background thread")
    return t

if __name__ == '__main__':
    start_monitoring()
