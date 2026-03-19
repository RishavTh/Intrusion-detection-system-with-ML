#!/bin/bash
clear
echo "=================================================="
echo "   AUTH-IDS SYSTEM HEALTH CHECK"
echo "   $(date '+%d %b %Y %H:%M:%S')"
echo "=================================================="

PASS=0
FAIL=0

check() {
    if [ $? -eq 0 ]; then
        echo "  ✅ $1"
        ((PASS++))
    else
        echo "  ❌ $1"
        ((FAIL++))
    fi
}

# ── 1. Python Files ──────────────────────────────────
echo ""
echo "── PYTHON SYNTAX CHECK ─────────────────────────"
cd /home/rishav/Auth_IDS
for f in app.py detector.py database.py monitor.py parser.py slack_notify.py report_generator.py; do
    venv/bin/python3 -m py_compile $f 2>/dev/null
    check "$f"
done

# ── 2. Key Files Exist ───────────────────────────────
echo ""
echo "── KEY FILES ───────────────────────────────────"
for f in ids.db linux_auth_model.pkl model_columns.pkl dashboard/index.html dashboard/app.js dashboard/style.css; do
    test -f /home/rishav/Auth_IDS/$f
    check "$f exists"
done

# ── 3. Flask API ─────────────────────────────────────
echo ""
echo "── FLASK API ───────────────────────────────────"
curl -s http://localhost:5000/api/health > /dev/null 2>&1
check "API health endpoint"
curl -s http://localhost:5000/api/stats > /dev/null 2>&1
check "API stats endpoint"
curl -s http://localhost:5000/api/alerts > /dev/null 2>&1
check "API alerts endpoint"

# ── 4. Database ──────────────────────────────────────
echo ""
echo "── DATABASE ────────────────────────────────────"
test -f /home/rishav/Auth_IDS/ids.db
check "ids.db exists"
COUNT=$(sqlite3 /home/rishav/Auth_IDS/ids.db "SELECT COUNT(*) FROM alerts;" 2>/dev/null)
echo "  📊 Total alerts in DB: $COUNT"
test $COUNT -gt 0
check "Database has alerts"

# ── 5. Threat Types ──────────────────────────────────
echo ""
echo "── THREAT DETECTION COVERAGE ───────────────────"
for threat in ssh_brute_force sudo_abuse foreign_ip port_scan password_spray post_failure_login authorized; do
    C=$(sqlite3 /home/rishav/Auth_IDS/ids.db "SELECT COUNT(*) FROM alerts WHERE threat_type='$threat';" 2>/dev/null)
    echo "  📌 $threat: $C"
done

# ── 6. Auth.log Access ───────────────────────────────
echo ""
echo "── LOG FILE ────────────────────────────────────"
test -f /var/log/auth.log
check "/var/log/auth.log exists"
test -r /var/log/auth.log
check "/var/log/auth.log readable"
LINES=$(wc -l < /var/log/auth.log)
echo "  📄 Total log lines: $LINES"

# ── 7. PDF Report ────────────────────────────────────
echo ""
echo "── PDF REPORT ──────────────────────────────────"
venv/bin/python3 -c "from report_generator import generate_report; generate_report('/tmp/health_check.pdf')" 2>/dev/null
check "PDF generation"
test -f /tmp/health_check.pdf
check "PDF file created"

# ── 8. ML Model ──────────────────────────────────────
echo ""
echo "── ML MODEL ────────────────────────────────────"
venv/bin/python3 -c "import joblib; m=joblib.load('linux_auth_model.pkl'); print('ok')" 2>/dev/null | grep -q ok
check "ML model loads"
venv/bin/python3 -c "import joblib; c=joblib.load('model_columns.pkl'); print(len(c),'features')" 2>/dev/null
check "Model columns load"

# ── 9. GitHub ────────────────────────────────────────
echo ""
echo "── GITHUB ──────────────────────────────────────"
git -C /home/rishav/Auth_IDS status | grep -q "nothing to commit"
check "All changes committed"
git -C /home/rishav/Auth_IDS remote -v | grep -q "siem"
check "SIEM remote configured"

# ── 10. Dashboard Files ──────────────────────────────
echo ""
echo "── DASHBOARD ───────────────────────────────────"
grep -q "toggleTheme" /home/rishav/Auth_IDS/dashboard/app.js
check "Light/dark mode JS"
grep -q "theme-switch-wrap" /home/rishav/Auth_IDS/dashboard/index.html
check "Toggle button in HTML"
grep -q "body.light" /home/rishav/Auth_IDS/dashboard/style.css
check "Light mode CSS"
grep -q "password_spray" /home/rishav/Auth_IDS/dashboard/app.js
check "Password spray in dashboard"
grep -q "post_failure" /home/rishav/Auth_IDS/dashboard/app.js
check "Compromised login in dashboard"

# ── Summary ──────────────────────────────────────────
echo ""
echo "=================================================="
echo "   SUMMARY"
echo "=================================================="
echo "  ✅ PASSED : $PASS"
echo "  ❌ FAILED : $FAIL"
TOTAL=$((PASS + FAIL))
PCT=$((PASS * 100 / TOTAL))
echo "  📊 SCORE  : $PCT%"
echo ""
if [ $FAIL -eq 0 ]; then
    echo "  🎉 ALL SYSTEMS GO — READY FOR VIVA!"
elif [ $FAIL -le 2 ]; then
    echo "  ⚠️  MINOR ISSUES — FIX BEFORE VIVA"
else
    echo "  🚨 ISSUES FOUND — NEEDS ATTENTION"
fi
echo "=================================================="
