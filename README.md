# Linux SOC Labs

Hands-on Linux security investigation work — building toward a junior SOC engineer / cloud security analyst role in the UK.

This repository documents my structured, lab-based practice of the techniques real SOC analysts use to baseline, hunt, and triage on a Linux host. Each lab plants a realistic attacker behaviour, then walks through detecting it using only standard Linux tools.

**Target environment:** Ubuntu 24.04.1 LTS lab VM
**Investigation framework:** MITRE ATT&CK
**Workflow:** enumerate → filter → investigate → document

---

## Featured investigations

### 🔍 Fileless malware detection via deleted binaries
Simulated memory-resident malware by running a binary then deleting it from disk. Detected the running process through the `/proc/<pid>/exe` symlink showing `(deleted)`. One of the strongest fileless-malware indicators on Linux.

→ [week01/day03-processes/](week01/day03-processes/)
**MITRE:** T1620 — Reflective Code Loading

 🔍 Persistence hunting across 7 attacker hiding places
Planted a malicious cron job, a `.bashrc` backdoor, and a rogue systemd service (`system-update-check.service`), then built detection logic to catch each. Verified the systemd service was not package-owned using `dpkg -S`.

→ [week01/day02-persistence/](week01/day02-persistence/)
**MITRE:** T1053.003 (Cron), T1543.002 (systemd), T1546.004 (Shell config)

 🔍 Live process triage workflow
Six-step deep-dive on any suspicious PID using `/proc/`: command line, binary path, working directory, network connections, parent process, start time. Caught a fake cryptominer (sustained 99% CPU), a Metasploit-style listener on port 4444, and the fileless-malware example above.

→ [week01/day03-processes/day03-walkthrough.md](week01/day03-processes/day03-walkthrough.md)
**MITRE:** T1059 (Command-line execution), T1496 (Resource hijacking)

---

 Repository structure

---

 Techniques and tools used

Linux internals
- `/etc/passwd` and `/etc/shadow` analysis for UID 0 audit, empty-password detection, account aging
- SUID binary enumeration with `find / -perm -4000` and GTFOBins lookup
- `/proc/<pid>/` filesystem for live process forensics
- `journalctl` for user-management timeline reconstruction

Persistence detection
- Cron, systemd unit files, shell startup files, SSH `authorized_keys`, PAM, `/etc/ld.so.preload`, MOTD scripts
- Package-database cross-check (`dpkg -S`) to identify manually-placed service files

Process investigation
- `ps aux --sort=-%cpu` for cryptominer signatures
- `ss -tunap` for listener and connection enumeration
- `/proc/*/exe` filtered for `/tmp/`, `/var/tmp/`, `/dev/shm/` paths and `(deleted)` markers
- `lsof -p` and `pstree -p` for relationship mapping

Bash and scripting
- Pipelines combining `grep`, `awk`, `sort`, `uniq` for log analysis
- Reusable detection scripts with clear sections and section markers
- Stream redirection (`> file 2>&1`), background jobs, heredocs

---

 What I learned

- **Most "anomalies" are benign.** The Day 1 `tempadmi` mystery turned out to be a truncated username from a renamed account, resolved by cross-referencing `passwd`, `lastlog`, and `journalctl`. Real SOC work is mostly ruling things out efficiently.
- **No single command catches every attack type.** Three plants in Day 3 needed three different detection techniques. Multi-angle hunting is the whole point.
- **Boring names hide attacks.** "system-update-check.service" is more dangerous than "evil_backdoor.service" because analysts skim past it. Always verify against the package database.
- **Bash has reserved variables.** Hit `PPID: readonly variable` during process-tree work; documented the fix (`PARENT_PID`) so the script is reusable.

---

 Roadmap

This repository is part of a 6-month structured curriculum:

| Phase | Status | Focus |
|---|---|---|
| Month 1 — Linux & Bash | In progress | Audit, persistence, processes, log analysis, hardening |
| Month 2 — Networking | Upcoming | TCP/IP, Wireshark, IDS basics |
| Month 3 — Azure foundations | Upcoming | Entra ID, Defender for Cloud, hardening |
| Month 4 — Sentinel & KQL | Upcoming | Detection rule writing, workbooks, hunting queries |
| Month 5 — Defender XDR | Upcoming | Endpoint detections, Logic Apps automation |
| Month 6 — IR & job prep | Upcoming | Threat modelling, portfolio polish, interviews |

Companion repos:
- [cloud-soc](https://github.com/ibraahiimtech/cloud-soc) — Azure / Sentinel / KQL work
- [networking-fundamentals](https://github.com/ibraahiimtech/networking-fundamentals) — pcap analysis and protocol work

---

 About me

I'm an early-career cyber security learner based in the UK, currently working through a structured hands-on programme alongside formal study. I'm targeting junior SOC engineer and cloud security analyst roles in the Thames Valley / London area.

Open to entry/junior-level conversations: feel free to reach out via my GitHub profile.
