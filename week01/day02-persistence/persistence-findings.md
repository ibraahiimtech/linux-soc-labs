# Day 2 — Persistence Hunting Lab

**Date:** 13 May 2026
**Host:** cloudsec-lab (Ubuntu 24.04.1 LTS)
**Exercise:** Plant and detect 3 common Linux persistence mechanisms.

## Summary
Planted three persistence mechanisms (cron job, .bashrc backdoor, rogue systemd service) and built a detection script that successfully identified all three. After detection, all plants were cleaned up and confirmed gone.

## Plant 1 — Cron job
**Mechanism:** Added `*/5 * * * * /tmp/.suspicious_script.sh` to user crontab. Script wrote timestamps to /tmp/.pwned every 5 minutes.
**Detection:** `crontab -l` revealed the entry.
**Red flags:** Hidden script path in /tmp/, no comment, world-writable location.

## Plant 2 — .bashrc backdoor
**Mechanism:** Appended two lines to ~/.bashrc — a fake comment and a `touch` command. Triggered on every new shell.
**Detection:** `tail -10 ~/.bashrc` exposed the additions.
**Red flags:** File-creation command in a shell init file has no legitimate use.

## Plant 3 — Rogue systemd service
**Mechanism:** Created /etc/systemd/system/system-update-check.service with ExecStart running a shell command. Enabled to auto-start at boot.
**Detection:** `systemctl list-unit-files --type=service --state=enabled` and `dpkg -S` on the service file. The dpkg check returned "no path found," proving the file did not come from any installed package.
**Red flags:** Vague description, ExecStart running raw shell rather than a binary, not associated with any installed package.

## Lessons learned
- Detection must enumerate every user's crontab, not just root's.
- /tmp is a common attacker staging ground — always check it.
- Comparing systemd unit files against the package database is a fast triage step.
- Attackers deliberately pick boring filenames to evade casual inspection.

## Cleanup
All three plants were removed and verified gone. System is back to baseline.
