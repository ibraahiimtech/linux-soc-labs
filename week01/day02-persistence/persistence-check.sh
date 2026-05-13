#!/bin/bash
# ============================================================
# Linux Persistence Detection Script
# Author: Ibrahim
# Purpose: Audit a Linux host for common persistence mechanisms
# Usage:   sudo ./persistence-check.sh
# ============================================================

echo "==========================================="
echo "  PERSISTENCE HUNT - $(hostname) - $(date)"
echo "==========================================="

echo ""
echo "=== 1. CRON JOBS ==="
for user in $(cut -f1 -d: /etc/passwd); do
    cron=$(sudo crontab -u "$user" -l 2>/dev/null)
    if [ -n "$cron" ]; then
        echo "[$user]:"
        echo "$cron"
    fi
done
echo "-- System cron files --"
ls /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null

echo ""
echo "=== 2. SYSTEMD TIMERS ==="
systemctl list-timers --all --no-pager 2>/dev/null | head -20

echo ""
echo "=== 3. CUSTOM SYSTEMD SERVICES ==="
ls -la /etc/systemd/system/*.service 2>/dev/null

echo ""
echo "=== 4. SHELL STARTUP FILES (last 5 lines each) ==="
for f in /etc/profile /etc/bash.bashrc /root/.bashrc /root/.profile; do
    if [ -f "$f" ]; then
        echo "-- $f --"
        sudo tail -5 "$f"
    fi
done
for user_home in /home/*; do
    for f in "$user_home/.bashrc" "$user_home/.profile" "$user_home/.bash_login"; do
        if [ -f "$f" ]; then
            echo "-- $f --"
            tail -5 "$f"
        fi
    done
done

echo ""
echo "=== 5. SSH AUTHORIZED_KEYS ==="
sudo find / -name "authorized_keys" 2>/dev/null

echo ""
echo "=== 6. LD.SO.PRELOAD (should NOT exist) ==="
if [ -f /etc/ld.so.preload ]; then
    echo "ALERT: /etc/ld.so.preload exists!"
    sudo cat /etc/ld.so.preload
else
    echo "OK - file does not exist"
fi

echo ""
echo "=== 7. MOTD SCRIPTS ==="
ls -la /etc/update-motd.d/ 2>/dev/null

echo ""
echo "==========================================="
echo "  HUNT COMPLETE"
echo "==========================================="
