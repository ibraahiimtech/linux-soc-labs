# Day 4 — SSH Log Analysis Lab

**Date:** 8 July 2026
**Host:** cloudsec-lab (Ubuntu 24.04.1 LTS)
**Exercise:** Generate simulated SSH brute-force traffic; detect and characterise using log analysis.

## Summary
Generated 22 failed SSH authentication attempts across 4 different usernames from localhost. Detected 23 events in the journal (matching plus a stray probe). Used journalctl, grep, awk, sed, sort, and uniq to build a full attack picture. Confirmed zero successful authentications; attack contained.

## Simulated attack
- Attacker 1: 5 attempts as `admin`
- Attacker 2: 8 attempts as `root`
- Attacker 3: 3 attempts as `ubuntu`
- Attacker 4: 6 attempts as `test`
- Source: 127.0.0.1
- Method: sshpass loops from localhost

## Detection results
| Metric | Value |
|---|---|
| Total failed authentications | 23 |
| Distinct source IPs | 1 (127.0.0.1) |
| Distinct target usernames | 4 |
| Highest-attempted account | root (9 attempts) |
| Successful authentications | 0 |
| Confirmed breach | No |

## Attack characterisation
- **Automated:** 23 attempts in ~30 minutes suggests scripted tooling, not manual.
- **Prioritised root:** 39% of attempts targeted the root account — classic attacker preference.
- **Mixed targeting:** 4 usernames tried, blending common defaults (ubuntu) with generic names (admin, test).
- **Single source:** All attempts from 127.0.0.1 — trivial to block.

## Detection approach and lessons learned
- **journalctl is the modern way to query system logs** — filter by process (`_COMM=sshd`), time (`--since`), and priority (`-p`).
- **sshd logs two different formats for failed passwords** depending on whether the target account exists — parsers must handle both or misclassify attacks. This is a common SIEM gotcha.
- **The classic SOC pipeline is `get logs → filter → extract field → sort | uniq -c | sort -rn`** — one shape, infinite questions.
- **Never close a brute-force ticket without checking for successful authentications from the same source in the same window.** Silence in that check is the difference between an annoying scan and a breach.

## Triage decision
Lab-generated activity. Attack contained (0 successful logins). On a real production server with this pattern from an external IP the response would be:
1. Block source IP at the firewall
2. Confirm no `Accepted` events from that IP
3. Review sudo activity for suspected user accounts
4. Add source to watchlist
5. Deploy fail2ban or similar rate limiting

## Next steps
- Day 5 hardening lab will add fail2ban, ufw, SSH hardening, and auditd to make this system resilient to the attack pattern demonstrated here.
