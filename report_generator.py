import sqlite3
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm, cm
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

DB = os.path.join(os.path.dirname(__file__), 'ids.db')

# ── Colour palette ─────────────────────────────────────────
C_DARK   = colors.HexColor('#0a0f1a')
C_NAVY   = colors.HexColor('#1a3a5c')
C_BLUE   = colors.HexColor('#2e75b6')
C_LIGHT  = colors.HexColor('#e2e8f0')
C_DIM    = colors.HexColor('#4a6080')
C_RED    = colors.HexColor('#ff3355')
C_YELLOW = colors.HexColor('#ffcc00')
C_PURPLE = colors.HexColor('#aa55ff')
C_ORANGE = colors.HexColor('#ff7730')
C_GREEN  = colors.HexColor('#00ff88')
C_GREY   = colors.HexColor('#2a3a50')
C_ROW1   = colors.HexColor('#ebf3fb')
C_ROW2   = colors.white
C_HDR    = colors.HexColor('#1a3a5c')

THREAT_COLORS = {
    'ssh_brute_force': C_RED,
    'sudo_abuse':      C_YELLOW,
    'foreign_ip':      C_PURPLE,
    'port_scan':       C_ORANGE,
    'authorized':      C_GREEN,
    'suspicious':      C_DIM,
}

THREAT_LABELS = {
    'ssh_brute_force': 'SSH Brute Force',
    'sudo_abuse':      'Sudo Privilege Abuse',
    'foreign_ip':      'Foreign IP Access',
    'port_scan':       'Port Scan / Reconnaissance',
    'authorized':      'Authorized Login',
    'suspicious':      'Suspicious Activity',
}

SEV_LABELS = {
    'ssh_brute_force': 'CRITICAL',
    'sudo_abuse':      'MEDIUM',
    'foreign_ip':      'HIGH',
    'port_scan':       'HIGH',
    'authorized':      'INFO',
    'suspicious':      'LOW',
}

SEV_COLORS = {
    'CRITICAL': C_RED,
    'HIGH':     C_ORANGE,
    'MEDIUM':   C_YELLOW,
    'LOW':      C_DIM,
    'INFO':     C_GREEN,
}

# ── Styles ─────────────────────────────────────────────────
def make_styles():
    return {
        'cover_title': ParagraphStyle('cover_title', fontName='Helvetica-Bold',
            fontSize=28, textColor=C_NAVY, alignment=TA_CENTER, spaceAfter=6),
        'cover_sub': ParagraphStyle('cover_sub', fontName='Helvetica',
            fontSize=14, textColor=C_BLUE, alignment=TA_CENTER, spaceAfter=4),
        'cover_meta': ParagraphStyle('cover_meta', fontName='Helvetica',
            fontSize=10, textColor=C_DIM, alignment=TA_CENTER, spaceAfter=3),
        'section': ParagraphStyle('section', fontName='Helvetica-Bold',
            fontSize=14, textColor=C_NAVY, spaceBefore=16, spaceAfter=6,
            borderPad=4),
        'subsection': ParagraphStyle('subsection', fontName='Helvetica-Bold',
            fontSize=11, textColor=C_BLUE, spaceBefore=10, spaceAfter=4),
        'body': ParagraphStyle('body', fontName='Helvetica',
            fontSize=9, textColor=colors.HexColor('#333333'),
            spaceBefore=3, spaceAfter=3, leading=14),
        'body_bold': ParagraphStyle('body_bold', fontName='Helvetica-Bold',
            fontSize=9, textColor=colors.HexColor('#333333')),
        'small': ParagraphStyle('small', fontName='Helvetica',
            fontSize=8, textColor=C_DIM),
        'code': ParagraphStyle('code', fontName='Courier',
            fontSize=8, textColor=colors.HexColor('#1a1a1a'),
            backColor=colors.HexColor('#f4f4f4'),
            spaceBefore=2, spaceAfter=2, leftIndent=10),
        'footer': ParagraphStyle('footer', fontName='Helvetica',
            fontSize=8, textColor=C_DIM, alignment=TA_CENTER),
        'tbl_hdr': ParagraphStyle('tbl_hdr', fontName='Helvetica-Bold',
            fontSize=9, textColor=colors.white),
        'tbl_cell': ParagraphStyle('tbl_cell', fontName='Helvetica',
            fontSize=8, textColor=colors.HexColor('#222222')),
        'tbl_code': ParagraphStyle('tbl_code', fontName='Courier',
            fontSize=7, textColor=colors.HexColor('#222222')),
        'finding_title': ParagraphStyle('finding_title', fontName='Helvetica-Bold',
            fontSize=10, textColor=C_NAVY, spaceBefore=8, spaceAfter=2),
        'tag': ParagraphStyle('tag', fontName='Helvetica-Bold',
            fontSize=8, textColor=colors.white, alignment=TA_CENTER),
    }

def hr(color=C_BLUE, thickness=1):
    return HRFlowable(width='100%', thickness=thickness, color=color, spaceAfter=8, spaceBefore=4)

def spacer(h=6):
    return Spacer(1, h * mm)

def sev_tag(sev, styles):
    col = SEV_COLORS.get(sev, C_DIM)
    t = Table([[Paragraph(sev, styles['tag'])]],
              colWidths=[18*mm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), col),
        ('ROUNDEDCORNERS', [3]),
        ('TOPPADDING', (0,0), (-1,-1), 2),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
    ]))
    return t

# ── DB helpers ─────────────────────────────────────────────
def get_stats():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT threat_type, COUNT(*) FROM alerts GROUP BY threat_type")
    counts = dict(c.fetchall())
    c.execute("SELECT COUNT(*) FROM alerts")
    total = c.fetchone()[0]
    c.execute("SELECT MIN(detected_at), MAX(detected_at) FROM alerts")
    period = c.fetchone()
    conn.close()
    return counts, total, period

def get_recent_alerts(limit=20):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""SELECT detected_at, source_ip, username, threat_type,
                        confidence, event_type, raw_log
                 FROM alerts
                 WHERE threat_type != 'authorized'
                 ORDER BY id DESC LIMIT ?""", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def get_top_ips(limit=8):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""SELECT source_ip, COUNT(*) as cnt, threat_type
                 FROM alerts
                 WHERE source_ip != 'unknown'
                   AND threat_type != 'authorized'
                 GROUP BY source_ip
                 ORDER BY cnt DESC LIMIT ?""", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def get_hourly(limit=24):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""SELECT strftime('%H', detected_at) as hr, COUNT(*) as cnt
                 FROM alerts GROUP BY hr ORDER BY cnt DESC LIMIT ?""", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def get_threat_findings():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    findings = {}
    for tt in ['ssh_brute_force','sudo_abuse','foreign_ip','port_scan']:
        c.execute("""SELECT COUNT(*), AVG(confidence), MAX(confidence),
                            MIN(detected_at), MAX(detected_at)
                     FROM alerts WHERE threat_type=?""", (tt,))
        row = c.fetchone()
        if row and row[0]:
            findings[tt] = row
    conn.close()
    return findings

# ── Page template ──────────────────────────────────────────
class ReportTemplate:
    def __init__(self):
        self.page_num = 0

    def on_page(self, canvas, doc):
        self.page_num += 1
        w, h = A4
        canvas.saveState()

        # Top bar
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, h - 14*mm, w, 14*mm, fill=1, stroke=0)
        canvas.setFont('Helvetica-Bold', 9)
        canvas.setFillColor(colors.white)
        canvas.drawString(15*mm, h - 9*mm, 'LINUX AUTHENTICATION IDS')
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor('#8ab4d4'))
        canvas.drawRightString(w - 15*mm, h - 9*mm,
            'Security Incident Report  |  CS6P05NI  |  CONFIDENTIAL')

        # Bottom bar
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, 0, w, 10*mm, fill=1, stroke=0)
        canvas.setFont('Helvetica', 7.5)
        canvas.setFillColor(colors.HexColor('#8ab4d4'))
        canvas.drawString(15*mm, 3.5*mm,
            f'Rishav Kumar Thapa  |  23047504  |  Islington College, Nepal  |  {datetime.now().strftime("%d %B %Y")}')
        canvas.setFillColor(colors.white)
        canvas.setFont('Helvetica-Bold', 8)
        canvas.drawRightString(w - 15*mm, 3.5*mm, f'Page {self.page_num}')

        canvas.restoreState()

    def on_first_page(self, canvas, doc):
        w, h = A4
        canvas.saveState()

        # Full dark cover bg
        canvas.setFillColor(C_DARK)
        canvas.rect(0, 0, w, h, fill=1, stroke=0)

        # Top accent stripe
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, h - 20*mm, w, 20*mm, fill=1, stroke=0)
        canvas.setFillColor(C_BLUE)
        canvas.rect(0, h - 22*mm, w, 2*mm, fill=1, stroke=0)

        # Bottom stripe
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, 0, w, 18*mm, fill=1, stroke=0)
        canvas.setFillColor(C_BLUE)
        canvas.rect(0, 18*mm, w, 1.5*mm, fill=1, stroke=0)

        # Header text
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(colors.HexColor('#8ab4d4'))
        canvas.drawString(15*mm, h - 14*mm,
            'CS6P05NI — Final Year Project  |  Islington College, Nepal')
        canvas.drawRightString(w - 15*mm, h - 14*mm,
            datetime.now().strftime('%d %B %Y — %H:%M'))

        # Classification badge
        canvas.setFillColor(C_RED)
        canvas.roundRect(w/2 - 25*mm, h - 60*mm, 50*mm, 10*mm, 3, fill=1, stroke=0)
        canvas.setFont('Helvetica-Bold', 10)
        canvas.setFillColor(colors.white)
        canvas.drawCentredString(w/2, h - 53.5*mm, 'CONFIDENTIAL')

        # Main title
        canvas.setFont('Helvetica-Bold', 32)
        canvas.setFillColor(colors.white)
        canvas.drawCentredString(w/2, h/2 + 30*mm, 'SECURITY INCIDENT')
        canvas.drawCentredString(w/2, h/2 + 16*mm, 'REPORT')

        # Blue underline
        canvas.setStrokeColor(C_BLUE)
        canvas.setLineWidth(2)
        canvas.line(w/2 - 50*mm, h/2 + 12*mm, w/2 + 50*mm, h/2 + 12*mm)

        # Subtitle
        canvas.setFont('Helvetica', 13)
        canvas.setFillColor(colors.HexColor('#8ab4d4'))
        canvas.drawCentredString(w/2, h/2 + 4*mm,
            'Linux Authentication Intrusion Detection System')
        canvas.drawCentredString(w/2, h/2 - 4*mm,
            'Real-Time Threat Analysis and Detection Summary')

        # Meta box
        canvas.setFillColor(colors.HexColor('#0d1929'))
        canvas.roundRect(w/2 - 55*mm, h/2 - 40*mm, 110*mm, 28*mm, 5, fill=1, stroke=0)
        canvas.setStrokeColor(C_BLUE)
        canvas.setLineWidth(0.8)
        canvas.roundRect(w/2 - 55*mm, h/2 - 40*mm, 110*mm, 28*mm, 5, fill=0, stroke=1)

        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(colors.HexColor('#8ab4d4'))
        canvas.drawCentredString(w/2, h/2 - 15*mm, 'Prepared by: Rishav Kumar Thapa  |  Student ID: 23047504')
        canvas.drawCentredString(w/2, h/2 - 22*mm, 'Module: CS6P05NI Final Year Project  |  Islington College')
        canvas.drawCentredString(w/2, h/2 - 29*mm, f'Report Generated: {datetime.now().strftime("%d %B %Y at %H:%M")}')
        canvas.drawCentredString(w/2, h/2 - 36*mm, 'System Host: rishav-Vbox  |  Ubuntu 24.04 LTS')

        # Footer
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor('#4a6080'))
        canvas.drawCentredString(w/2, 8*mm,
            'This report is auto-generated from live IDS database  |  For academic use only')

        canvas.restoreState()


# ── Main report generator ─────────────────────────────────
def generate_report(output_path):
    styles    = make_styles()
    tmpl      = ReportTemplate()
    story     = []

    counts, total, period = get_stats()
    recent   = get_recent_alerts(20)
    top_ips  = get_top_ips(8)
    hourly   = get_hourly()
    findings = get_threat_findings()

    start_dt = period[0] or 'N/A'
    end_dt   = period[1] or 'N/A'

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm,
        topMargin=22*mm, bottomMargin=16*mm,
    )

    # ── PAGE 1: Cover (handled by on_first_page) ──────────
    story.append(PageBreak())

    # ── PAGE 2: Executive Summary ────────────────────────
    story.append(Paragraph('1. EXECUTIVE SUMMARY', styles['section']))
    story.append(hr())

    ssh   = counts.get('ssh_brute_force', 0)
    sudo  = counts.get('sudo_abuse', 0)
    fip   = counts.get('foreign_ip', 0)
    pscan = counts.get('port_scan', 0)
    susp  = counts.get('suspicious', 0)
    auth  = counts.get('authorized', 0)

    # Threat level
    if ssh > 100 or fip > 5:
        threat_level = 'CRITICAL'
        tl_color     = C_RED
        tl_text      = 'Multiple high-frequency attacks detected. Immediate investigation required.'
    elif ssh > 10 or pscan > 0:
        threat_level = 'HIGH'
        tl_color     = C_ORANGE
        tl_text      = 'Significant attack activity detected. Review recommended within 24 hours.'
    elif sudo > 0:
        threat_level = 'MEDIUM'
        tl_color     = C_YELLOW
        tl_text      = 'Moderate threat activity. Standard monitoring procedures apply.'
    else:
        threat_level = 'LOW'
        tl_color     = C_GREEN
        tl_text      = 'Low threat level. Continue standard monitoring.'

    # Threat level banner
    banner = Table(
        [[Paragraph(f'OVERALL THREAT LEVEL: {threat_level}', styles['tbl_hdr']),
          Paragraph(tl_text, ParagraphStyle('x', fontName='Helvetica', fontSize=9, textColor=colors.white))]],
        colWidths=[50*mm, 120*mm]
    )
    banner.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), tl_color),
        ('TOPPADDING',    (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING',   (0,0), (-1,-1), 10),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
        ('ROUNDEDCORNERS', [4]),
    ]))
    story.append(banner)
    story.append(spacer(4))

    story.append(Paragraph(
        f'The Linux Authentication IDS has been monitoring <b>rishav-Vbox</b> (Ubuntu 24.04 LTS, '
        f'192.168.16.127) and has detected <b>{total:,} security events</b> between '
        f'<b>{start_dt[:16]}</b> and <b>{end_dt[:16]}</b>. '
        f'The system identified <b>{len(findings)} distinct threat categories</b> using a '
        f'Random Forest ML model trained on 900,000+ records with 100% test accuracy.',
        styles['body']))
    story.append(spacer(3))

    # KPI summary table
    kpi_data = [
        [Paragraph('METRIC', styles['tbl_hdr']),
         Paragraph('VALUE', styles['tbl_hdr']),
         Paragraph('METRIC', styles['tbl_hdr']),
         Paragraph('VALUE', styles['tbl_hdr'])],
        [Paragraph('Total Alerts', styles['tbl_cell']),
         Paragraph(f'{total:,}', styles['tbl_cell']),
         Paragraph('SSH Brute Force', styles['tbl_cell']),
         Paragraph(f'{ssh:,}  ({ssh/total*100:.1f}%)', styles['tbl_cell'])],
        [Paragraph('Sudo Abuse', styles['tbl_cell']),
         Paragraph(f'{sudo}  ({sudo/total*100:.1f}%)', styles['tbl_cell']),
         Paragraph('Foreign IP Access', styles['tbl_cell']),
         Paragraph(f'{fip}  ({fip/total*100:.1f}%)', styles['tbl_cell'])],
        [Paragraph('Port Scan', styles['tbl_cell']),
         Paragraph(f'{pscan}  ({pscan/total*100:.1f}%)', styles['tbl_cell']),
         Paragraph('Authorized Logins', styles['tbl_cell']),
         Paragraph(f'{auth}', styles['tbl_cell'])],
        [Paragraph('Monitoring Period Start', styles['tbl_cell']),
         Paragraph(str(start_dt[:16]), styles['tbl_cell']),
         Paragraph('Last Event', styles['tbl_cell']),
         Paragraph(str(end_dt[:16]), styles['tbl_cell'])],
    ]
    kpi_tbl = Table(kpi_data, colWidths=[47*mm, 43*mm, 47*mm, 43*mm])
    kpi_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0),  C_HDR),
        ('BACKGROUND',    (0,1), (-1,1),  C_ROW1),
        ('BACKGROUND',    (0,2), (-1,2),  C_ROW2),
        ('BACKGROUND',    (0,3), (-1,3),  C_ROW1),
        ('BACKGROUND',    (0,4), (-1,4),  C_ROW2),
        ('GRID',          (0,0), (-1,-1), 0.5, colors.HexColor('#CCCCCC')),
        ('TOPPADDING',    (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING',   (0,0), (-1,-1), 8),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(kpi_tbl)
    story.append(spacer(6))

    # ── Threat Findings ───────────────────────────────────
    story.append(Paragraph('2. THREAT FINDINGS', styles['section']))
    story.append(hr())

    finding_num = 1
    for tt, row in findings.items():
        cnt, avg_conf, max_conf, first_seen, last_seen = row
        sev   = SEV_LABELS.get(tt, 'LOW')
        label = THREAT_LABELS.get(tt, tt)
        col   = THREAT_COLORS.get(tt, C_DIM)

        # Finding header row
        hdr = Table(
            [[Paragraph(f'Finding {finding_num}: {label}', ParagraphStyle(
                'fh', fontName='Helvetica-Bold', fontSize=11,
                textColor=colors.white)),
              Paragraph(sev, ParagraphStyle(
                'sv', fontName='Helvetica-Bold', fontSize=10,
                textColor=colors.white, alignment=TA_RIGHT))]],
            colWidths=[140*mm, 40*mm]
        )
        hdr.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,-1), col),
            ('TOPPADDING',    (0,0), (-1,-1), 7),
            ('BOTTOMPADDING', (0,0), (-1,-1), 7),
            ('LEFTPADDING',   (0,0), (-1,-1), 10),
            ('RIGHTPADDING',  (0,0), (-1,-1), 10),
            ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(hdr)

        # Finding detail table
        det = Table([
            [Paragraph('Total Events', styles['tbl_cell']),
             Paragraph(str(cnt), styles['tbl_cell']),
             Paragraph('Avg Confidence', styles['tbl_cell']),
             Paragraph(f'{avg_conf:.1f}%', styles['tbl_cell']),
             Paragraph('Max Confidence', styles['tbl_cell']),
             Paragraph(f'{max_conf:.1f}%', styles['tbl_cell'])],
            [Paragraph('First Detected', styles['tbl_cell']),
             Paragraph(str(first_seen)[:16], styles['tbl_cell']),
             Paragraph('Last Detected', styles['tbl_cell']),
             Paragraph(str(last_seen)[:16], styles['tbl_cell']),
             Paragraph('% of Total', styles['tbl_cell']),
             Paragraph(f'{cnt/total*100:.1f}%', styles['tbl_cell'])],
        ], colWidths=[30*mm, 30*mm, 30*mm, 30*mm, 30*mm, 30*mm])
        det.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0), C_ROW1),
            ('BACKGROUND',    (0,1), (-1,1), C_ROW2),
            ('GRID',          (0,0), (-1,-1), 0.5, colors.HexColor('#CCCCCC')),
            ('TOPPADDING',    (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING',   (0,0), (-1,-1), 6),
            ('FONTNAME',      (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE',      (0,0), (-1,-1), 8),
        ]))
        story.append(det)
        story.append(spacer(4))
        finding_num += 1

    # ── Top Attacker IPs ──────────────────────────────────
    story.append(Paragraph('3. TOP ATTACKER IP ADDRESSES', styles['section']))
    story.append(hr())

    ip_hdr = [
        Paragraph('RANK', styles['tbl_hdr']),
        Paragraph('SOURCE IP', styles['tbl_hdr']),
        Paragraph('ATTACKS', styles['tbl_hdr']),
        Paragraph('PRIMARY THREAT', styles['tbl_hdr']),
        Paragraph('SEVERITY', styles['tbl_hdr']),
    ]
    ip_rows = [ip_hdr]
    for i, (ip, cnt, tt) in enumerate(top_ips):
        sev = SEV_LABELS.get(tt, 'LOW')
        sev_col = SEV_COLORS.get(sev, C_DIM)
        ip_rows.append([
            Paragraph(str(i+1), styles['tbl_cell']),
            Paragraph(ip or 'unknown', styles['tbl_code']),
            Paragraph(str(cnt), styles['tbl_cell']),
            Paragraph(THREAT_LABELS.get(tt, tt), styles['tbl_cell']),
            Paragraph(sev, ParagraphStyle('sv2', fontName='Helvetica-Bold',
                fontSize=8, textColor=sev_col)),
        ])
    ip_tbl = Table(ip_rows, colWidths=[15*mm, 45*mm, 22*mm, 62*mm, 36*mm])
    ip_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0),  C_HDR),
        *[('BACKGROUND', (0,i+1), (-1,i+1),
           C_ROW1 if i%2==0 else C_ROW2) for i in range(len(top_ips))],
        ('GRID',          (0,0), (-1,-1), 0.5, colors.HexColor('#CCCCCC')),
        ('TOPPADDING',    (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING',   (0,0), (-1,-1), 8),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(ip_tbl)
    story.append(spacer(6))

    # ── Recent Alert Log ──────────────────────────────────
    story.append(Paragraph('4. RECENT ALERT LOG (Last 20 Events)', styles['section']))
    story.append(hr())

    log_hdr = [
        Paragraph('TIMESTAMP', styles['tbl_hdr']),
        Paragraph('SOURCE IP', styles['tbl_hdr']),
        Paragraph('USER', styles['tbl_hdr']),
        Paragraph('THREAT', styles['tbl_hdr']),
        Paragraph('CONF%', styles['tbl_hdr']),
        Paragraph('SEV', styles['tbl_hdr']),
    ]
    log_rows = [log_hdr]
    for i, (det_at, src_ip, user, tt, conf, evt, raw) in enumerate(recent):
        sev = SEV_LABELS.get(tt, 'LOW')
        sev_col = SEV_COLORS.get(sev, C_DIM)
        log_rows.append([
            Paragraph(str(det_at)[:16], styles['tbl_code']),
            Paragraph(str(src_ip or '-'), styles['tbl_code']),
            Paragraph(str(user or '-')[:12], styles['tbl_cell']),
            Paragraph(THREAT_LABELS.get(tt, tt), styles['tbl_cell']),
            Paragraph(f'{float(conf or 0):.1f}', styles['tbl_cell']),
            Paragraph(sev, ParagraphStyle('sv3', fontName='Helvetica-Bold',
                fontSize=7, textColor=sev_col)),
        ])
    log_tbl = Table(log_rows, colWidths=[34*mm, 32*mm, 22*mm, 52*mm, 16*mm, 24*mm])
    log_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0),  C_HDR),
        *[('BACKGROUND', (0,i+1), (-1,i+1),
           C_ROW1 if i%2==0 else C_ROW2) for i in range(len(recent))],
        ('GRID',          (0,0), (-1,-1), 0.5, colors.HexColor('#CCCCCC')),
        ('TOPPADDING',    (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING',   (0,0), (-1,-1), 6),
        ('FONTSIZE',      (0,1), (-1,-1), 8),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(log_tbl)
    story.append(spacer(6))

    # ── Attack Hour Pattern ───────────────────────────────
    story.append(Paragraph('5. ATTACK HOUR PATTERN', styles['section']))
    story.append(hr())

    if hourly:
        max_cnt = max(r[1] for r in hourly) if hourly else 1
        hour_data = [[
            Paragraph('HOUR (UTC+5:45)', styles['tbl_hdr']),
            Paragraph('ATTACK COUNT', styles['tbl_hdr']),
            Paragraph('INTENSITY', styles['tbl_hdr']),
        ]]
        for hr_str, cnt in sorted(hourly, key=lambda x: x[0])[:12]:
            bar_len = int((cnt / max_cnt) * 40)
            bar = '|' * bar_len
            hour_data.append([
                Paragraph(f'{hr_str}:00 - {hr_str}:59', styles['tbl_cell']),
                Paragraph(str(cnt), styles['tbl_cell']),
                Paragraph(bar, ParagraphStyle('bar', fontName='Courier',
                    fontSize=8, textColor=C_RED)),
            ])
        hr_tbl = Table(hour_data, colWidths=[45*mm, 35*mm, 100*mm])
        hr_tbl.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0),  C_HDR),
            *[('BACKGROUND', (0,i+1), (-1,i+1),
               C_ROW1 if i%2==0 else C_ROW2) for i in range(len(hourly[:12]))],
            ('GRID',          (0,0), (-1,-1), 0.5, colors.HexColor('#CCCCCC')),
            ('TOPPADDING',    (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING',   (0,0), (-1,-1), 8),
            ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(hr_tbl)
    story.append(spacer(6))

    # ── Recommendations ───────────────────────────────────
    story.append(Paragraph('6. SECURITY RECOMMENDATIONS', styles['section']))
    story.append(hr())

    recs = []
    if ssh > 10:
        recs.append(('CRITICAL', 'SSH Brute Force Mitigation',
            f'{ssh:,} brute force events detected. Immediately: (1) enable SSH key-based authentication '
            f'and disable password auth in /etc/ssh/sshd_config, (2) configure Fail2ban with ban time '
            f'of 1 hour after 3 failures, (3) restrict SSH to specific IP ranges using UFW, '
            f'(4) change SSH port from 22 to a non-standard port above 1024.'))
    if fip > 0:
        recs.append(('HIGH', 'Foreign IP Access Control',
            f'{fip} access attempts from non-Nepal IP addresses detected. Recommend: (1) implement '
            f'geo-blocking at firewall level for countries not expected to access this server, '
            f'(2) review all successful logins from foreign IPs for legitimacy, '
            f'(3) consider VPN-only remote access policy.'))
    if pscan > 0:
        recs.append(('HIGH', 'Port Scan Countermeasures',
            f'{pscan} port scan events detected. Recommend: (1) enable port knocking or '
            f'single-packet authentication, (2) use UFW to close all non-essential ports, '
            f'(3) configure portsentry or similar tool to auto-block scanning IPs, '
            f'(4) ensure only required services are running (systemctl list-units --type=service).'))
    if sudo > 0:
        recs.append(('MEDIUM', 'Sudo Access Review',
            f'{sudo} sudo abuse events detected. Recommend: (1) audit /etc/sudoers for unnecessary '
            f'permissions, (2) implement sudo logging with SYSLOG, (3) use restricted sudo commands '
            f'rather than ALL privileges, (4) review which users are in sudo group.'))

    recs.append(('INFO', 'IDS Enhancement — Convert to IPS',
        'Consider upgrading from IDS to IPS by adding automatic IP blocking: when ML confidence '
        'exceeds 90%, run "sudo ufw deny from <ip>" automatically. This converts detection-only '
        'to active prevention. Implement with caution — test false positive rate thoroughly first.'))

    for sev, title, desc in recs:
        sev_col = SEV_COLORS.get(sev, C_DIM)
        rec_tbl = Table([[
            Paragraph(sev, ParagraphStyle('rs', fontName='Helvetica-Bold',
                fontSize=8, textColor=colors.white, alignment=TA_CENTER)),
            Paragraph(f'<b>{title}</b><br/>{desc}',
                ParagraphStyle('rd', fontName='Helvetica', fontSize=8.5,
                    textColor=colors.HexColor('#222222'), leading=12))
        ]], colWidths=[18*mm, 162*mm])
        rec_tbl.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (0,0),  sev_col),
            ('BACKGROUND',    (1,0), (1,0),  colors.HexColor('#f8f8f8')),
            ('TOPPADDING',    (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LEFTPADDING',   (0,0), (0,0),  6),
            ('LEFTPADDING',   (1,0), (1,0),  10),
            ('RIGHTPADDING',  (0,0), (-1,-1), 8),
            ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
            ('BOX',           (0,0), (-1,-1), 0.5, colors.HexColor('#CCCCCC')),
            ('LINEAFTER',     (0,0), (0,0),   1, sev_col),
        ]))
        story.append(rec_tbl)
        story.append(spacer(3))

    story.append(spacer(4))

    # ── System Info ───────────────────────────────────────
    story.append(Paragraph('7. SYSTEM INFORMATION', styles['section']))
    story.append(hr())

    sys_data = [
        [Paragraph('COMPONENT', styles['tbl_hdr']),
         Paragraph('DETAILS', styles['tbl_hdr']),
         Paragraph('COMPONENT', styles['tbl_hdr']),
         Paragraph('DETAILS', styles['tbl_hdr'])],
        [Paragraph('Host', styles['tbl_cell']),
         Paragraph('rishav-Vbox', styles['tbl_cell']),
         Paragraph('OS', styles['tbl_cell']),
         Paragraph('Ubuntu 24.04 LTS', styles['tbl_cell'])],
        [Paragraph('IDS Version', styles['tbl_cell']),
         Paragraph('1.0 — Production', styles['tbl_cell']),
         Paragraph('ML Model', styles['tbl_cell']),
         Paragraph('Random Forest (100 trees, 39 features)', styles['tbl_cell'])],
        [Paragraph('Monitor IP', styles['tbl_cell']),
         Paragraph('192.168.16.127', styles['tbl_cell']),
         Paragraph('Attack Sim IP', styles['tbl_cell']),
         Paragraph('192.168.16.197 (Kali Linux)', styles['tbl_cell'])],
        [Paragraph('Dashboard', styles['tbl_cell']),
         Paragraph('http://192.168.16.127:5000', styles['tbl_cell']),
         Paragraph('Database', styles['tbl_cell']),
         Paragraph(f'SQLite — {total:,} alerts stored', styles['tbl_cell'])],
        [Paragraph('Report Generated', styles['tbl_cell']),
         Paragraph(datetime.now().strftime('%d %B %Y at %H:%M:%S'), styles['tbl_cell']),
         Paragraph('Prepared By', styles['tbl_cell']),
         Paragraph('Rishav Kumar Thapa — 23047504', styles['tbl_cell'])],
    ]
    sys_tbl = Table(sys_data, colWidths=[35*mm, 57*mm, 35*mm, 57*mm])
    sys_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0), C_HDR),
        *[('BACKGROUND', (0,i+1), (-1,i+1),
           C_ROW1 if i%2==0 else C_ROW2) for i in range(5)],
        ('GRID',          (0,0), (-1,-1), 0.5, colors.HexColor('#CCCCCC')),
        ('TOPPADDING',    (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING',   (0,0), (-1,-1), 8),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(sys_tbl)
    story.append(spacer(4))

    story.append(Paragraph(
        '<i>This report was automatically generated by the Linux Authentication IDS. '
        'All data is sourced directly from the live SQLite database (ids.db) and reflects '
        'real security events captured during system monitoring. '
        'Report classification: CONFIDENTIAL — For academic use only — CS6P05NI Final Year Project.</i>',
        ParagraphStyle('disc', fontName='Helvetica-Oblique', fontSize=8,
            textColor=C_DIM, alignment=TA_CENTER, spaceBefore=8)))

    # ── Build PDF ─────────────────────────────────────────
    doc.build(
        story,
        onFirstPage=tmpl.on_first_page,
        onLaterPages=tmpl.on_page,
    )
    return output_path

if __name__ == '__main__':
    out = f'/tmp/IDS_Report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
    generate_report(out)
    print(f'Report saved: {out}')
