#!/bin/bash
# ============================================================
# Linux Security Audit Script
# Author: Ibrahim [surname]
# Date:   May 2026
# Purpose: Quick SOC-style baseline audit of a Linux host.
#          Checks user accounts, SUID binaries, and login history.
# Usage:  sudo ./linux-audit.sh
#         sudo ./linux-audit.sh > audit-output.txt   (to save output)
# ============================================================

echo "============================================"
echo "  LINUX SECURITY AUDIT"
echo "  Host: $(hostname)"
echo "  Date: $(date)"
echo "============================================"
echo ""

echo "=== 1. SYSTEM INFO ==="
uname -a
echo ""
grep PRETTY_NAME /etc/os-release
echo ""

echo "=== 2. UID 0 ACCOUNTS (should only be 'root') ==="
awk -F: '$3 == 0 {print $1}' /etc/passwd
echo ""

echo "=== 3. USERS WITH LOGIN SHELLS ==="
grep -vE '/(nologin|false|sync|halt|shutdown)$' /etc/passwd | awk -F: '{print $1, "-->", $7}'
echo ""

echo "=== 4. ACCOUNTS WITH EMPTY PASSWORDS ==="
awk -F: '($2 == "") {print $1}' /etc/shadow
echo "(no output above = no empty passwords found)"
echo ""

echo "=== 5. SUID BINARIES (excluding snap duplicates) ==="
find / -type f -perm -4000 -not -path "/snap/*" 2>/dev/null
echo ""
echo "Total SUID binaries (including snap): $(find / -type f -perm -4000 2>/dev/null | wc -l)"
echo ""

echo "=== 6. RECENT SUCCESSFUL LOGINS (last 10, wide format) ==="
last -n 10 -w
echo ""

echo "=== 7. RECENT FAILED LOGINS ==="
lastb -n 10 -w 2>/dev/null
echo ""

echo "=== 8. CURRENTLY LOGGED-IN USERS ==="
who
echo ""

echo "=== 9. RECENT USER MANAGEMENT EVENTS ==="
journalctl 2>/dev/null | grep -iE "useradd|userdel" | tail -10
echo ""

echo "============================================"
echo "  AUDIT COMPLETE"
echo "============================================"
