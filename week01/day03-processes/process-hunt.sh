#!/bin/bash
# ============================================================
# Linux Suspicious Process Detection
# Author: Ibrahim
# Purpose: Identify processes worth investigating
# Usage:   sudo ./process-hunt.sh
# ============================================================

echo "==========================================="
echo "  PROCESS HUNT - $(hostname) - $(date)"
echo "==========================================="

echo ""
echo "=== 1. TOP 10 CPU CONSUMERS ==="
ps aux --sort=-%cpu | head -11

echo ""
echo "=== 2. TOP 10 MEMORY CONSUMERS ==="
ps aux --sort=-%mem | head -11

echo ""
echo "=== 3. PROCESSES RUNNING FROM SUSPICIOUS LOCATIONS ==="
ls -la /proc/*/exe 2>/dev/null | grep -E "/tmp/|/var/tmp/|/dev/shm/"

echo ""
echo "=== 4. PROCESSES WITH DELETED BINARIES (HIGH PRIORITY) ==="
ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"

echo ""
echo "=== 5. LISTENING NETWORK PORTS ==="
ss -tunlp 2>/dev/null

echo ""
echo "=== 6. ESTABLISHED OUTBOUND CONNECTIONS ==="
ss -tunap state established 2>/dev/null | head -20

echo ""
echo "=== 7. NON-STANDARD PROCESS OWNERS ==="
ps -eo user,pid,cmd --no-headers | awk '$1 != "root" && $1 != "systemd+" && $1 != "messagebus" && $1 != "avahi" && $1 != "_apt" && $1 != "syslog" {print}' | head -20

echo ""
echo "==========================================="
echo "  HUNT COMPLETE"
echo "==========================================="
