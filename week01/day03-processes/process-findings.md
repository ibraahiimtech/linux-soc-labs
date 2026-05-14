# Day 3 — Process Inspection Lab

**Date:** 14 May 2026
**Host:** cloudsec-lab (Ubuntu 24.04.1 LTS)
**Exercise:** Plant 3 suspicious processes; detect and triage each using live-process forensics.

## Summary
Practised live-process inspection by planting a fake cryptominer, a reverse-shell listener, and a process running from a deleted binary. All three were detected using standard Linux tools: ps, ss, /proc/, lsof. Cleanup confirmed system returned to baseline.

## Plant 1 — Cryptominer simulation (kworker-helper)
**Mechanism:** Background bash script at /tmp/.kworker-helper running an infinite CPU-burning loop. Named to mimic legitimate kernel worker threads.

**Detection commands:**
- `ps aux --sort=-%cpu | head -10` — appeared as #1 CPU consumer at 99.7%
- `ls -la /proc/*/exe | grep /tmp/` — exposed binary path
- `ps -eo pid,lstart,cmd` — confirmed start time

**Red flags identified:**
- Sustained 99.7% CPU usage (legitimate kworker threads barely use CPU)
- Binary located in /tmp/ (world-writable, never legitimate)
- Hidden filename (leading dot)
- Name mimics kernel thread naming convention — classic blending technique

## Plant 2 — Reverse-shell listener (nc on 4444)
**Mechanism:** Netcat listening on TCP/4444 — the default Metasploit reverse-shell port.

**Detection commands:**
- `sudo ss -tunap | grep LISTEN` — exposed listener on 0.0.0.0:4444 with PID and program (nc)

**Red flags identified:**
- Port 4444 is not used by any legitimate service
- Netcat (nc) listening on a non-standard port is almost always suspicious
- Binding to 0.0.0.0 means accepting connections from any source

## Plant 3 — Fileless process (deleted binary)
**Mechanism:** Copied /bin/sleep to /tmp/.update-daemon, executed it, then deleted the binary from disk. Process continued running in memory.

**Detection commands:**
- `sudo ls -la /proc/*/exe | grep "(deleted)"` — exposed the deleted-binary process

**Red flags identified:**
- The `(deleted)` flag in /proc/PID/exe is one of the strongest fileless-malware indicators on Linux
- Legitimate software does not delete its own binary while running
- Binary path was in /tmp/ (suspicious location)
- Filename `update-daemon` was designed to look legitimate

## Triage methodology — the 6-step deep dive
For each suspicious PID, applied:
1. `/proc/<pid>/cmdline` — full command line
2. `/proc/<pid>/exe` — binary location
3. `/proc/<pid>/cwd` — working directory
4. `lsof -p <pid> -i` — network connections
5. `/proc/<pid>/status` (PPid field) — parent process
6. `ps -eo lstart` correlation with auth.log / journalctl

## Lessons learned
- Process names alone are unreliable; always verify the binary location via /proc/PID/exe
- Deleted-binary processes are one of the strongest fileless-malware indicators on Linux
- Port 4444 is a Metasploit fingerprint — instantly recognisable on inspection
- Three different attack types required three different detection techniques — no single command catches everything
- Bash has reserved variable names (e.g. PPID); use distinctive names like PARENT_PID to avoid collisions
- /var/log/auth.log can contain binary content; use `grep -a` or `journalctl` instead

## Cleanup
All three plants killed via pkill. Verified processes terminated, port 4444 no longer listening, no deleted-binary processes remaining. Leftover /tmp/ files removed. System confirmed back to baseline.
