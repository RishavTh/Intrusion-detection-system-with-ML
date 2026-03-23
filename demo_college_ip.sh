#!/bin/bash
clear
echo "=================================================="
echo "   COLLEGE IP (CGNAT) DEMO"
echo "   Simulating attack from 100.64.219.54"
echo "=================================================="

COLLEGE_IP="100.64.219.54"

echo ""
echo "── STEP 1: SSH Brute Force from College IP ─────"
for i in 1 2 3; do
    sudo bash -c "echo \"$(date -Iseconds)+05:45 rishav-Vbox sshd[$RANDOM]: Failed password for invalid user admin from $COLLEGE_IP port $RANDOM ssh2\" >> /var/log/auth.log"
    echo "  [$( date '+%H:%M:%S')] Injected failed login $i"
    sleep 2
done

echo ""
echo "── STEP 2: Password Spray from College IP ──────"
for user in admin root ubuntu test; do
    sudo bash -c "echo \"$(date -Iseconds)+05:45 rishav-Vbox sshd[$RANDOM]: Failed password for invalid user $user from $COLLEGE_IP port $RANDOM ssh2\" >> /var/log/auth.log"
    echo "  [$( date '+%H:%M:%S')] Tried username: $user"
    sleep 6
done

echo ""
echo "=================================================="
echo "   CHECK DASHBOARD — Should show:"
echo "   🟣 Foreign IP (before whitelist fix)"
echo "   🔴 SSH Brute Force"
echo "   🔫 Password Spray"
echo "=================================================="
