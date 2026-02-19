import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ids.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            detected_at TEXT    NOT NULL,
            timestamp   TEXT,
            source_ip   TEXT,
            username    TEXT,
            service     TEXT,
            status      TEXT,
            event_type  TEXT,
            threat_type TEXT,
            confidence  REAL,
            raw_log     TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stats (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            recorded_at     TEXT NOT NULL,
            total_alerts    INTEGER DEFAULT 0,
            ssh_brute_force INTEGER DEFAULT 0,
            sudo_abuse      INTEGER DEFAULT 0,
            foreign_ip      INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()
    print("✅ Database initialised at", DB_PATH)

def save_alert(alert: dict):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (
            detected_at, timestamp, source_ip, username,
            service, status, event_type, threat_type,
            confidence, raw_log
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().isoformat(),
        str(alert.get('timestamp', '')),
        alert.get('source_ip',  'unknown'),
        alert.get('username',   'unknown'),
        alert.get('service',    'unknown'),
        alert.get('status',     'unknown'),
        alert.get('event_type', 'unknown'),
        alert.get('threat_type','unknown'),
        float(alert.get('confidence', 0.0)),
        alert.get('raw_log', '')
    ))
    conn.commit()
    conn.close()

def get_alerts(limit=100):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM alerts ORDER BY detected_at DESC LIMIT ?', (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM alerts')
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE threat_type LIKE '%ssh_brute_force%'")
    ssh = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE threat_type LIKE '%sudo_abuse%'")
    sudo = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE threat_type LIKE '%foreign_ip%'")
    foreign = cursor.fetchone()[0]
    conn.close()
    return {
        'total_alerts'   : total,
        'ssh_brute_force': ssh,
        'sudo_abuse'     : sudo,
        'foreign_ip'     : foreign
    }

def get_recent_alerts(since_id=0):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM alerts WHERE id > ? ORDER BY detected_at ASC',
        (since_id,)
    )
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

if __name__ == '__main__':
    init_db()
    print("✅ database.py working correctly")
