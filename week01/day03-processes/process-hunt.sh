#!/bin/bash
# process-hunt.sh — automated live-process forensics
# Runs the core Day 3 detection techniques in one pass.

echo "======================================"
echo " PROCESS HUNT — $(date)"
echo "======================================"

echo ""
echo "--- [1] Top CPU consumers (miner check) ---"
ps aux --sort=-%cpu | head -5

echo ""
echo "--- [2] Listening ports (backdoor check) ---"
sudo ss -tunap | grep LISTEN

echo ""
echo "--- [3] Processes from suspicious locations ---"
sudo ls -la /proc/*/exe 2>/dev/null | grep -E "/tmp/|/var/tmp/|/dev/shm/"

echo ""
echo "--- [4] Deleted binaries (fileless malware — P1) ---"
sudo ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"

echo ""
echo "======================================"
echo " HUNT COMPLETE"
echo "======================================"
