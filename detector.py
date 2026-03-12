import joblib
import numpy as np
import pandas as pd
import os
from datetime import datetime, timedelta
from collections import defaultdict
from parser import parse_lines

MODEL_PATH   = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'linux_auth_model.pkl')
COLUMNS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'model_columns.pkl')

print("Loading ML model...")
model   = joblib.load(MODEL_PATH)
columns = joblib.load(COLUMNS_PATH)
print("✅ ML model loaded successfully")
print(f"   Model expects {len(columns)} features")

PORT_SCAN_THRESHOLD  = 3
PORT_SCAN_WINDOW_SEC  = 30

# ── Password Spray memory (persists between batches) ─────────────────
# Structure: { ip: { username: last_seen_datetime } }
_spray_memory = defaultdict(dict)
SPRAY_USERNAME_THRESHOLD = 3      # 3+ different usernames from same IP
SPRAY_WINDOW_MINUTES     = 5      # within 5 minutes


def detect_password_spray(df):
    """
    Detect password spraying — one IP trying many different usernames.
    Uses persistent memory across batches.
    """
    alerts  = []
    flagged = set()
    if df.empty:
        return alerts, flagged

    # Only look at failed SSH events
    spray_df = df[
        (df['status'] == 'Failed') &
        (df['is_ssh'] == 1) &
        (df['source_ip'] != 'unknown') &
        (df['username'] != 'unknown')
    ].copy()

    if spray_df.empty:
        return alerts, flagged

    now = datetime.now()
    cutoff = now - timedelta(minutes=SPRAY_WINDOW_MINUTES)

    for _, row in spray_df.iterrows():
        ip       = str(row.get('source_ip', 'unknown'))
        username = str(row.get('username',  'unknown'))

        # Add this username attempt to memory
        _spray_memory[ip][username] = now

        # Clean up old entries outside window
        _spray_memory[ip] = {
            u: t for u, t in _spray_memory[ip].items()
            if t >= cutoff
        }

        # Check if threshold reached
        unique_users = len(_spray_memory[ip])
        if unique_users >= SPRAY_USERNAME_THRESHOLD and ip not in flagged:
            conf = round(min(60.0 + unique_users * 5, 95.0), 1)
            alerts.append({
                'timestamp'  : str(row.get('timestamp', '')),
                'source_ip'  : ip,
                'username'   : username,
                'service'    : 'ssh',
                'status'     : 'Failed',
                'event_type' : 'password_spray',
                'threat_type': 'password_spray',
                'confidence' : conf,
                'raw_log'    : str(row.get('raw_log', '')),
            })
            flagged.add(ip)
            print(f"🔫 Password spray detected: {ip} | {unique_users} usernames in {SPRAY_WINDOW_MINUTES}min")

    return alerts, flagged


def detect_port_scans(df):
    alerts  = []
    flagged = set()
    if df.empty:
        return alerts, flagged

    scan_df = df[df['is_portscan'] == True].copy()
    if scan_df.empty:
        return alerts, flagged

    scan_df = scan_df.dropna(subset=['timestamp','source_ip'])
    scan_df = scan_df[scan_df['source_ip'] != 'unknown'].sort_values('timestamp')

    for ip, group in scan_df.groupby('source_ip'):
        group = group.sort_values('timestamp').reset_index(drop=True)
        for i in range(len(group)):
            t0 = group.loc[i,'timestamp']
            try:
                t1 = t0 + pd.Timedelta(seconds=PORT_SCAN_WINDOW_SEC)
            except:
                continue
            window = group[(group['timestamp'] >= t0) & (group['timestamp'] <= t1)]
            unique_ports = window['port'].nunique()
            if unique_ports >= PORT_SCAN_THRESHOLD:
                row  = group.iloc[i]
                conf = round(min(50.0 + unique_ports * 8, 99.0), 1)
                alerts.append({
                    'timestamp'  : str(t0),
                    'source_ip'  : ip,
                    'username'   : str(row.get('username','unknown')),
                    'service'    : 'ssh',
                    'status'     : 'port_scan',
                    'event_type' : 'port_scan_probe',
                    'threat_type': 'port_scan',
                    'confidence' : conf,
                    'raw_log'    : str(row.get('raw_log','')),
                })
                flagged.add(ip)
                break

    return alerts, flagged


def detect_rapid_connections(df):
    """Detect plain nmap SYN scans — rapid connections from same IP."""
    alerts  = []
    flagged = set()
    if df.empty:
        return alerts, flagged
    # Look for any events from same IP in short window
    conn_df = df[df['source_ip'] != 'unknown'].copy()
    if conn_df.empty:
        return alerts, flagged
    conn_df = conn_df.dropna(subset=['timestamp','source_ip'])
    conn_df = conn_df.sort_values('timestamp')
    for ip, group in conn_df.groupby('source_ip'):
        group = group.sort_values('timestamp').reset_index(drop=True)
        for i in range(len(group)):
            t0 = group.loc[i,'timestamp']
            try:
                t1 = t0 + pd.Timedelta(seconds=10)
            except:
                continue
            window = group[(group['timestamp'] >= t0) & (group['timestamp'] <= t1)]
            if len(window) >= 8 and ip not in flagged:
                row  = group.iloc[i]
                conf = round(min(55.0 + len(window) * 3, 92.0), 1)
                alerts.append({
                    'timestamp'  : str(t0),
                    'source_ip'  : ip,
                    'username'   : 'unknown',
                    'service'    : 'ssh',
                    'status'     : 'port_scan',
                    'event_type' : 'port_scan_probe',
                    'threat_type': 'port_scan',
                    'confidence' : conf,
                    'raw_log'    : f'Rapid connection scan from {ip} — {len(window)} events in 10s',
                })
                flagged.add(ip)
                break
    return alerts, flagged

def engineer_features(df):
    if df.empty:
        return pd.DataFrame()

    df = df.copy()

    # Temporal
    if 'timestamp' in df.columns and df['timestamp'].notna().any():
        ts = pd.to_datetime(df['timestamp'], errors='coerce')
        df['hour']        = ts.dt.hour.fillna(0)
        df['day_of_week'] = ts.dt.dayofweek.fillna(0)
        df['is_night']    = df['hour'].apply(lambda h: 1 if (h>=22 or h<=5) else 0)
    else:
        df['hour'] = df['day_of_week'] = df['is_night'] = 0

    # Ensure boolean columns are int BEFORE aggregation
    df['is_ssh']  = df['is_ssh'].astype(int)
    df['is_sudo'] = df['is_sudo'].astype(int)

    # Per-IP aggregation
    ip_grp = df.groupby('source_ip').agg(
        ip_total_events  = ('source_ip','count'),
        ip_fail_count    = ('status',   lambda x:(x=='Failed').sum()),
        ip_success_count = ('status',   lambda x:(x=='Success').sum()),
        ip_avg_attempts  = ('attempts', 'mean'),
    ).reset_index()
    ip_grp['ip_fail_rate'] = ip_grp['ip_fail_count'] / ip_grp['ip_total_events'].replace(0,1)
    df = df.merge(ip_grp, on='source_ip', how='left')

    # Per-user aggregation
    user_grp = df.groupby('username').agg(
        user_total_events = ('username','count'),
        user_fail_count   = ('status',  lambda x:(x=='Failed').sum()),
        user_sudo_count   = ('is_sudo', 'sum'),
        user_ssh_count    = ('is_ssh',  'sum'),
    ).reset_index()
    user_grp['user_fail_rate'] = user_grp['user_fail_count'] / user_grp['user_total_events'].replace(0,1)
    df = df.merge(user_grp, on='username', how='left')

    # Rolling 10-min SSH failures
    df['ssh_fails_10min'] = 0
    if 'timestamp' in df.columns and df['timestamp'].notna().any():
        ssh_df = df[df['is_ssh']==1].copy().sort_values('timestamp')
        for ip, grp in ssh_df.groupby('source_ip'):
            for idx, row in grp.iterrows():
                t = row['timestamp']
                try:
                    w = t - pd.Timedelta(minutes=10)
                    c = grp[(grp['timestamp']>=w) &
                            (grp['timestamp']<=t) &
                            (grp['status']=='Failed')].shape[0]
                    df.loc[idx,'ssh_fails_10min'] = c
                except:
                    pass

    # Sudo fail count per user
    sudo_fails = df[df['is_sudo']==1].groupby('username').agg(
        sudo_fail_count_user=('status', lambda x:(x=='Failed').sum())
    ).reset_index()
    df = df.merge(sudo_fails, on='username', how='left')
    df['sudo_fail_count_user'] = df['sudo_fail_count_user'].fillna(0)

    # Foreign IP flag
    df['is_foreign_ip'] = df['is_foreign'].astype(int)

    # One-hot encoding
    for col, prefix in [('event_type','evt'),('service','svc'),('status','sts')]:
        if col in df.columns:
            dummies = pd.get_dummies(df[col], prefix=prefix)
            df = pd.concat([df, dummies], axis=1)

    # Fill all NaN with 0
    df = df.fillna(0)

    return df


def align_features(features_df):
    """
    Align feature dataframe to EXACTLY match model's expected columns.
    - Add missing columns as 0
    - Drop extra columns
    - Preserve column order
    """
    # Add missing columns with 0
    for col in columns:
        if col not in features_df.columns:
            features_df[col] = 0

    # Select only model columns in correct order
    X = features_df[columns].copy()

    # Ensure all numeric
    X = X.apply(pd.to_numeric, errors='coerce').fillna(0)

    return X


def determine_threat_type(row, flagged_ips):
    event  = str(row.get('event_type',''))
    ip     = str(row.get('source_ip','unknown'))
    is_ssh = int(row.get('is_ssh', 0))
    is_sud = int(row.get('is_sudo',0))
    is_for = bool(row.get('is_foreign',False))

    if event == 'ssh_success':
        return 'authorized'
    if ip in flagged_ips and 'port_scan' in event:
        return 'port_scan'
    if is_for and is_ssh:
        return 'foreign_ip'
    if is_sud:
        return 'sudo_abuse'
    if is_ssh and event in ['ssh_failed','ssh_max_attempts','pam_failure','invalid_user']:
        return 'ssh_brute_force'
    return 'suspicious'


def detect(lines):
    df = parse_lines(lines)
    if df.empty:
        return []

    alerts = []

    # Step 1 — Port scan (rule-based)
    ps_alerts, flagged_ips = detect_port_scans(df)
    rc_alerts, rc_ips = detect_rapid_connections(df)
    for a in rc_alerts:
        if a['source_ip'] not in flagged_ips:
            ps_alerts.append(a)
            flagged_ips.add(a['source_ip'])
    if ps_alerts:
        print(f"🔍 Port scan from: {list(flagged_ips)}")
        alerts.extend(ps_alerts)

    # Step 1b — Password spray (rule-based, uses persistent memory)
    spray_alerts, spray_ips = detect_password_spray(df)
    for a in spray_alerts:
        if a['source_ip'] not in flagged_ips:
            alerts.append(a)
            flagged_ips.add(a['source_ip'])

    # Step 2 — ML for SSH/sudo/foreign (exclude confirmed scan-only rows)
    ml_df = df[~(
        (df['is_portscan'] == True) &
        (df['source_ip'].isin(flagged_ips))
    )].copy()

    if ml_df.empty:
        return alerts

    features = engineer_features(ml_df)
    if features.empty:
        return alerts

    # ── Critical fix: align features to model columns ────────
    try:
        X = align_features(features)
    except Exception as e:
        print(f"⚠ Feature alignment error: {e}")
        return alerts

    try:
        preds = model.predict(X)
        probs = model.predict_proba(X)
        ci    = list(model.classes_).index(1) if 1 in model.classes_ else 1
    except Exception as e:
        print(f"⚠ Model prediction error: {e}")
        return alerts

    for i, (pred, (_, row)) in enumerate(zip(preds, ml_df.iterrows())):
        # Always alert on successful logins (green info alert)
        if str(row.get('event_type','')) == 'ssh_success':
            alerts.append({
                'timestamp'  : str(row.get('timestamp',  '')),
                'source_ip'  : str(row.get('source_ip',  'unknown')),
                'username'   : str(row.get('username',   'unknown')),
                'service'    : 'ssh',
                'status'     : 'Success',
                'event_type' : 'ssh_success',
                'threat_type': 'authorized',
                'confidence' : 100.0,
                'raw_log'    : str(row.get('raw_log',    '')),
            })
            continue
        if pred == 1:
            threat = determine_threat_type(row, flagged_ips)
            alerts.append({
                'timestamp'  : str(row.get('timestamp',  '')),
                'source_ip'  : str(row.get('source_ip',  'unknown')),
                'username'   : str(row.get('username',   'unknown')),
                'service'    : str(row.get('service',    'unknown')),
                'status'     : str(row.get('status',     'unknown')),
                'event_type' : str(row.get('event_type', 'unknown')),
                'threat_type': threat,
                'confidence' : round(float(probs[i][ci] * 100), 1),
                'raw_log'    : str(row.get('raw_log',    '')),
            })

    return alerts


if __name__ == '__main__':
    print("\n=== TEST 1: SSH Brute Force ===")
    r = detect([
        '2026-02-18T12:48:51+05:45 rishav-Vbox sshd[111]: Failed password for invalid user admin from 192.168.16.197 port 45001 ssh2',
        '2026-02-18T12:48:52+05:45 rishav-Vbox sshd[112]: Failed password for invalid user admin from 192.168.16.197 port 45002 ssh2',
        '2026-02-18T12:48:53+05:45 rishav-Vbox sshd[113]: Failed password for invalid user admin from 192.168.16.197 port 45003 ssh2',
        '2026-02-18T12:48:54+05:45 rishav-Vbox sshd[114]: Failed password for invalid user admin from 192.168.16.197 port 45004 ssh2',
        '2026-02-18T12:48:55+05:45 rishav-Vbox sshd[115]: Failed password for invalid user admin from 192.168.16.197 port 45005 ssh2',
    ])
    for a in r: print(f"  ✅ {a['threat_type']} | {a['source_ip']} | {a['confidence']}%")

    print("\n=== TEST 2: Port Scan ===")
    r = detect([
        '2026-02-18T14:42:29.253171+05:45 rishav-Vbox sshd[6492]: Connection closed by invalid user ubuntu 192.168.16.197 port 51154 [preauth]',
        '2026-02-18T14:42:29.256814+05:45 rishav-Vbox sshd[6494]: Connection closed by invalid user ubuntu 192.168.16.197 port 51172 [preauth]',
        '2026-02-18T14:42:29.260486+05:45 rishav-Vbox sshd[6495]: Connection closed by invalid user ubuntu 192.168.16.197 port 51182 [preauth]',
        '2026-02-18T14:42:29.266036+05:45 rishav-Vbox sshd[6496]: Connection closed by invalid user ubuntu 192.168.16.197 port 51190 [preauth]',
        '2026-02-18T14:42:29.270000+05:45 rishav-Vbox sshd[6497]: Connection closed by invalid user ubuntu 192.168.16.197 port 51210 [preauth]',
        '2026-02-18T14:42:29.275000+05:45 rishav-Vbox sshd[6498]: Connection closed by invalid user ubuntu 192.168.16.197 port 51220 [preauth]',
    ])
    for a in r: print(f"  ✅ {a['threat_type']} | {a['source_ip']} | {a['confidence']}%")

    print("\n=== TEST 3: Sudo Abuse ===")
    r = detect([
        '2026-02-18T12:00:00+05:45 rishav-Vbox sudo[200]: rishav : 3 incorrect password attempts ; TTY=pts/0',
        '2026-02-18T12:00:01+05:45 rishav-Vbox sudo[201]: pam_unix(sudo:auth): authentication failure; user=rishav',
    ])
    for a in r: print(f"  ✅ {a['threat_type']} | {a['username']} | {a['confidence']}%")

    print("\n=== TEST 4: Foreign IP ===")
    r = detect([
        '2026-02-18T12:00:00+05:45 rishav-Vbox sshd[300]: Failed password for root from 8.8.8.8 port 54321 ssh2',
        '2026-02-18T12:00:01+05:45 rishav-Vbox sshd[301]: Failed password for root from 8.8.8.8 port 54322 ssh2',
        '2026-02-18T12:00:02+05:45 rishav-Vbox sshd[302]: Failed password for root from 8.8.8.8 port 54323 ssh2',
    ])
    for a in r: print(f"  ✅ {a['threat_type']} | {a['source_ip']} | {a['confidence']}%")
