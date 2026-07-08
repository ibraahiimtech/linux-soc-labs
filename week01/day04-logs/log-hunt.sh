#!/bin/bash
# ============================================================
# SSH Log Analysis Script
# Author: Ibrahim
# Purpose: Summarise SSH brute-force and authentication activity
# Usage:   sudo ./log-hunt.sh [time window, default "1 hour ago"]
# ============================================================

TIME_WINDOW="${1:-1 hour ago}"

echo "==========================================="
echo "  SSH LOG HUNT - $(hostname) - $(date)"
echo "  Window: since $TIME_WINDOW"
echo "==========================================="

echo ""
echo "=== 1. FAILED LOGIN COUNT ==="
COUNT=$(sudo journalctl _COMM=sshd --since "$TIME_WINDOW" --no-pager 2>/dev/null | grep -c "Failed password")
echo "Total failed authentications: $COUNT"

echo ""
echo "=== 2. FAILED LOGINS BY TARGETED USERNAME ==="
sudo journalctl _COMM=sshd --since "$TIME_WINDOW" --no-pager 2>/dev/null \
  | grep "Failed password" \
  | grep -oE "for (invalid user )?[a-zA-Z0-9_-]+" \
  | sed 's/for invalid user //; s/for //' \
  | sort | uniq -c | sort -rn

echo ""
echo "=== 3. FAILED LOGINS BY SOURCE IP ==="
sudo journalctl _COMM=sshd --since "$TIME_WINDOW" --no-pager 2>/dev/null \
  | grep "Failed password" \
  | grep -oE "from [0-9.]+" \
  | sort | uniq -c | sort -rn

echo ""
echo "=== 4. SUCCESSFUL LOGINS (CRITICAL - verify each) ==="
SUCCESS=$(sudo journalctl _COMM=sshd --since "$TIME_WINDOW" --no-pager 2>/dev/null | grep -c "Accepted")
echo "Successful authentications: $SUCCESS"
if [ "$SUCCESS" -gt 0 ]; then
    echo "--- Details ---"
    sudo journalctl _COMM=sshd --since "$TIME_WINDOW" --no-pager 2>/dev/null | grep "Accepted"
fi

echo ""
echo "=== 5. INVALID USERNAME ATTEMPTS (accounts that don't exist) ==="
sudo journalctl _COMM=sshd --since "$TIME_WINDOW" --no-pager 2>/dev/null \
  | grep "Invalid user" \
  | awk '{for(i=1;i<=NF;i++) if($i=="user") print $(i+1)}' \
  | sort | uniq -c | sort -rn | head -10

echo ""
echo "=== 6. SUDO ACTIVITY IN WINDOW ==="
sudo journalctl _COMM=sudo --since "$TIME_WINDOW" --no-pager 2>/dev/null \
  | grep "COMMAND=" \
  | tail -10

echo ""
echo "==========================================="
echo "  HUNT COMPLETE"
echo "==========================================="
