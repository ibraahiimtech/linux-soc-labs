# SOC Starter Kit — 5 Commands

The five commands I'd reach for first when assessing a Linux host.

## 1. Who has root power?
```bash
awk -F: '$3 == 0 {print $1}' /etc/passwd
```
Lists every account with UID 0. Should only return `root`.
Anything else = backdoor admin account.

## 2. Anything scheduled in cron?
```bash
crontab -l
```
Shows the current user's cron jobs. Look for:
- Scripts in /tmp/, /var/tmp/, /dev/shm/
- Hidden filenames (starting with .)
- Commands like `curl ... | bash`

## 3. Is ld.so.preload present?
```bash
ls -la /etc/ld.so.preload 2>/dev/null
```
This file should NOT exist on a healthy system.
If it does = strong rootkit indicator.

## 4. What's burning CPU?
```bash
ps aux --sort=-%cpu | head -10
```
Top 10 CPU consumers. A sustained 99% CPU process
is the cryptominer signature.

## 5. Anything running from suspicious locations?
```bash
sudo ls -la /proc/*/exe 2>/dev/null | grep -E "/tmp/|/var/tmp/|/dev/shm/|\(deleted\)"
```
Catches two attack patterns at once:
- Processes running from world-writable paths
- Processes whose binary has been deleted (fileless malware)
Empty output = good.

---

## When to use this kit
- New host assessment
- Quick health check before deeper investigation
- "Is anything obviously wrong?" triage

## What it doesn't cover
- Network connections (use `ss -tunap`)
- Persistence in systemd / .bashrc / SSH keys
- Log review (use `journalctl`)
- File integrity / SUID auditing

Treat this as the first 30 seconds, not the whole investigation.
