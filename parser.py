import re
import pandas as pd

NEPAL_RANGES = [
    ('192.168.0.0',   '192.168.255.255'),
    ('10.0.0.0',      '10.255.255.255'),
    ('172.16.0.0',    '172.31.255.255'),
    ('127.0.0.0',     '127.255.255.255'),
    ('202.45.144.0',  '202.45.159.255'),
    ('202.166.192.0', '202.166.255.255'),
    ('103.69.124.0',  '103.69.127.255'),
    ('202.79.32.0',   '202.79.51.255'),
    ('103.1.92.0',    '103.1.95.255'),
    ('27.111.16.0',   '27.111.31.255'),
    ('202.51.192.0',  '202.51.207.255'),
    ('103.82.80.0',   '103.82.87.255'),
    ('100.64.0.0',    '100.127.255.255'),  # CGNAT — college/ISP shared range
]

def ip_to_int(ip):
    try:
        parts = ip.split('.')
        return sum(int(p) << (24 - 8*i) for i, p in enumerate(parts))
    except:
        return 0

def is_nepal_ip(ip):
    if not ip or ip == 'unknown':
        return True
    n = ip_to_int(ip)
    for start, end in NEPAL_RANGES:
        if ip_to_int(start) <= n <= ip_to_int(end):
            return True
    return False

PATTERNS = {
    # ── PRIORITY 1: SSH auth events (must check BEFORE port scan) ──
    'ssh_fail': re.compile(
        r'(?P<ts>\S+)\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
    ),
    'ssh_ok': re.compile(
        r'(?P<ts>\S+)\s+\S+\s+sshd\[\d+\]:\s+Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
    ),
    'ssh_maxauth': re.compile(
        r'(?P<ts>\S+)\s+\S+\s+sshd\[\d+\]:\s+(?:error: maximum authentication attempts exceeded|Disconnecting invalid user \S+).*?from (?P<ip>\S+) port (?P<port>\d+)'
    ),
    'pam_fail': re.compile(
        r'(?P<ts>\S+)\s+\S+\s+sshd\[\d+\]:\s+PAM \d+ more authentication failure.*?rhost=(?P<ip>\S+)'
    ),
    # ── PRIORITY 2: Sudo events ──
    'sudo_fail': re.compile(
        r'(?P<ts>\S+)\s+\S+\s+sudo\[\d+\].*?(?P<user>\S+)\s*:.*?incorrect password attempts'
    ),
    'sudo_wrong': re.compile(
        r'(?P<ts>\S+)\s+\S+\s+sudo.*?authentication failure.*?user=(?P<user>\S+)'
    ),
    'sudo_session': re.compile(
        r'(?P<ts>\S+)\s+\S+\s+sudo\[\d+\]:\s+(?P<user>\S+)\s*:.*?COMMAND=(?P<cmd>\S+)'
    ),
    # ── PRIORITY 3: Port scan probes (after all auth events) ──
    'port_scan_closed': re.compile(
        r'(?P<ts>\S+)\s+\S+\s+sshd\[\d+\]:\s+Connection closed by (?:invalid user \S+ )?(?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+) \[preauth\]'
    ),
    'port_scan_reset': re.compile(
        r'(?P<ts>\S+)\s+\S+\s+sshd\[\d+\]:\s+Connection reset by (?:invalid user \S+ )?(?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+) \[preauth\]'
    ),
    # ── nmap specific patterns ──
    'nmap_probe': re.compile(
        r'(?P<ts>\S+)\s+\S+\s+sshd\[\d+\]:\s+(?:Bad protocol version identification|Did not receive identification string) from (?P<ip>\S+) port (?P<port>\d+)'
    ),
    'nmap_refused': re.compile(
        r'(?P<ts>\S+)\s+\S+\s+sshd\[\d+\]:\s+Unable to negotiate with (?P<ip>\S+) port (?P<port>\d+)'
    ),
}

def parse_line(line):
    result = {
        'timestamp'  : None,
        'source_ip'  : 'unknown',
        'username'   : 'unknown',
        'service'    : 'unknown',
        'status'     : 'unknown',
        'event_type' : 'unknown',
        'port'       : 0,
        'attempts'   : 1,
        'is_sudo'    : False,
        'is_ssh'     : False,
        'is_foreign' : False,
        'is_portscan': False,
        'raw_log'    : line.strip()
    }

    # ── SSH Failed password (HIGHEST PRIORITY) ──────────────
    m = PATTERNS['ssh_fail'].search(line)
    if m:
        result.update({
            'timestamp' : m.group('ts'),
            'source_ip' : m.group('ip'),
            'username'  : m.group('user'),
            'service'   : 'ssh',
            'status'    : 'Failed',
            'event_type': 'ssh_failed',
            'port'      : int(m.group('port')),
            'is_ssh'    : True,
        })
        result['is_foreign'] = not is_nepal_ip(result['source_ip'])
        return result

    # ── SSH Success ──────────────────────────────────────────
    m = PATTERNS['ssh_ok'].search(line)
    if m:
        result.update({
            'timestamp' : m.group('ts'),
            'source_ip' : m.group('ip'),
            'username'  : m.group('user'),
            'service'   : 'ssh',
            'status'    : 'Success',
            'event_type': 'ssh_success',
            'port'      : int(m.group('port')),
            'is_ssh'    : True,
        })
        result['is_foreign'] = not is_nepal_ip(result['source_ip'])
        return result

    # ── SSH Max Auth ─────────────────────────────────────────
    m = PATTERNS['ssh_maxauth'].search(line)
    if m:
        result.update({
            'timestamp' : m.group('ts'),
            'source_ip' : m.group('ip'),
            'service'   : 'ssh',
            'status'    : 'Failed',
            'event_type': 'ssh_max_attempts',
            'is_ssh'    : True,
        })
        result['is_foreign'] = not is_nepal_ip(result['source_ip'])
        return result

    # ── PAM Failure ──────────────────────────────────────────
    m = PATTERNS['pam_fail'].search(line)
    if m:
        result.update({
            'timestamp' : m.group('ts'),
            'source_ip' : m.group('ip'),
            'service'   : 'ssh',
            'status'    : 'Failed',
            'event_type': 'pam_failure',
            'is_ssh'    : True,
        })
        result['is_foreign'] = not is_nepal_ip(result['source_ip'])
        return result

    # ── Sudo Failures ────────────────────────────────────────
    m = PATTERNS['sudo_fail'].search(line)
    if m:
        result.update({
            'timestamp' : m.group('ts'),
            'username'  : m.group('user'),
            'service'   : 'sudo',
            'status'    : 'Failed',
            'event_type': 'sudo_wrong_attempts',
            'is_sudo'   : True,
        })
        return result

    m = PATTERNS['sudo_wrong'].search(line)
    if m:
        result.update({
            'timestamp' : m.group('ts'),
            'username'  : m.group('user'),
            'service'   : 'sudo',
            'status'    : 'Failed',
            'event_type': 'sudo_auth_failure',
            'is_sudo'   : True,
        })
        return result

    m = PATTERNS['sudo_session'].search(line)
    if m:
        result.update({
            'timestamp' : m.group('ts'),
            'username'  : m.group('user'),
            'service'   : 'sudo',
            'status'    : 'Success',
            'event_type': 'sudo_session_open',
            'is_sudo'   : True,
        })
        return result

    # ── nmap specific probes ─────────────────────────────────
    m = PATTERNS['nmap_probe'].search(line)
    if m:
        result.update({
            'timestamp'  : m.group('ts'),
            'source_ip'  : m.group('ip'),
            'service'    : 'ssh',
            'status'     : 'probe',
            'event_type' : 'port_scan_probe',
            'port'       : int(m.group('port')),
            'is_ssh'     : True,
            'is_portscan': True,
        })
        result['is_foreign'] = not is_nepal_ip(result['source_ip'])
        return result

    m = PATTERNS['nmap_refused'].search(line)
    if m:
        result.update({
            'timestamp'  : m.group('ts'),
            'source_ip'  : m.group('ip'),
            'service'    : 'ssh',
            'status'     : 'probe',
            'event_type' : 'port_scan_probe',
            'port'       : int(m.group('port')),
            'is_ssh'     : True,
            'is_portscan': True,
        })
        result['is_foreign'] = not is_nepal_ip(result['source_ip'])
        return result

    # ── Port scan — Connection closed [preauth] (LOWEST PRIORITY) ──
    m = PATTERNS['port_scan_closed'].search(line)
    if m:
        result.update({
            'timestamp'  : m.group('ts'),
            'source_ip'  : m.group('ip'),
            'service'    : 'ssh',
            'status'     : 'closed_preauth',
            'event_type' : 'port_scan_probe',
            'port'       : int(m.group('port')),
            'is_ssh'     : True,
            'is_portscan': True,
        })
        result['is_foreign'] = not is_nepal_ip(result['source_ip'])
        return result

    # ── Port scan — Connection reset [preauth] ───────────────
    m = PATTERNS['port_scan_reset'].search(line)
    if m:
        result.update({
            'timestamp'  : m.group('ts'),
            'source_ip'  : m.group('ip'),
            'service'    : 'ssh',
            'status'     : 'reset_preauth',
            'event_type' : 'port_scan_probe',
            'port'       : int(m.group('port')),
            'is_ssh'     : True,
            'is_portscan': True,
        })
        result['is_foreign'] = not is_nepal_ip(result['source_ip'])
        return result

    return None


def parse_lines(lines):
    records = []
    for line in lines:
        r = parse_line(line)
        if r:
            records.append(r)
    if not records:
        return pd.DataFrame()
    df = pd.DataFrame(records)
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], utc=False, errors='coerce')
        df['timestamp'] = df['timestamp'].apply(
            lambda t: t.tz_localize(None) if t is not pd.NaT and t.tzinfo else t
        )
    return df
