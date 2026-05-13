 Linux Security Audit — cloudsec-lab

**Date:** 12 May 2026  
**Auditor:** Ibrahim [surname]  
**System:** cloudsec-lab (Ubuntu 24.04.1 LTS, kernel 6.17.0-23-generic)  
**Audit type:** Routine baseline audit (Week 1 — SOC training lab)

---

 Summary

I ran a baseline security audit on my Ubuntu lab system, covering user 
accounts, SUID binaries, and login history. The system is in good shape 
overall. Two items came up during the login review that looked unusual 
at first glance, but both were tracked down to legitimate past activity 
on the same lab. No real security issues were found. Recommendations 
are listed at the end.

---

 1. User accounts

I checked who can log in, who has admin rights, and whether any accounts 
have weak password settings.


  What I found:
- 2 accounts have real login shells: `root` and `ibraahiimtech` (me).
- Only `root` has UID 0 — no hidden admin accounts.
- No accounts with empty passwords.
- `root` is locked for direct login (uses `!` in `/etc/shadow`), which 
  is the Ubuntu default. Admin tasks go through `sudo`. ✅

  Commands used:
```bash
grep -vE '/(nologin|false|sync|halt|shutdown)$' /etc/passwd
awk -F: '$3 == 0 {print $1}' /etc/passwd
sudo awk -F: '($2 == "" ) {print $1}' /etc/shadow
```

Verdict: Clean. No action needed.

---

 2. SUID binaries

SUID files run with the file owner's privileges, not the user's. 
Misconfigured SUID binaries are a common privilege-escalation path, 
so I wanted to know exactly what's on the system.

What I found:
- 53 SUID files total.
- 18 are real binaries in `/usr/bin`, `/usr/lib`, and `/usr/sbin`.
- 35 are duplicates inside `/snap/core22/` and `/snap/core24/` 
  (snap packages bundle their own copies — expected).
- All identified binaries are standard system tools (`sudo`, `su`, 
  `passwd`, `mount`, `pkexec`, etc.) — nothing custom or out of place.
- `pkexec` was historically vulnerable (CVE-2021-4034, "PwnKit"), 
  patched on this kernel.

Commands used:
```bash
sudo find / -type f -perm -4000 2>/dev/null
sudo find / -type f -perm -4000 -not -path "/snap/*" 2>/dev/null
```

Verdict: Clean. No action needed.

---

 3. Login history

This is where the audit got interesting. I checked recent successful 
and failed logins.

 3.1 An unfamiliar username `tempadmi` in `last` output

`last` showed multiple console sessions on 11 May for a user called 
`tempadmi`. At first this looked suspicious — short, admin-sounding 
usernames are exactly what attackers create.

I investigated:
- `grep -i temp /etc/passwd` → no matching account exists today.
- `lastlog` → no record of any "temp" user ever logging in.
- `sudo grep -i tempadm /var/log/auth.log` → no matches.

**Conclusion:** The `last` command was truncating a longer username to 
8 characters. The records relate to historical activity on this lab 
from before I renamed my primary user from `techsom` to `ibraahiimtech`. 
Not a security event.

**Lesson learned:** Always use `last -w` (wide format) to get full 
usernames and avoid this kind of false alarm.

### 3.2 Failed SSH attempts as `fakeuser` from localhost

14 failed SSH login attempts for user `fakeuser` from 127.0.0.1, 
across 4 separate bursts between 4–7 May.

**Conclusion:** All attempts originated from the lab host itself. 
Consistent with my own past testing of SSH configuration. Not malicious.

### 3.3 User-management activity in the system journal

While reviewing the journal I found a clean trail of accounts created 
and deleted during earlier lab exercises:

| Date         | Event                                           |
|--------------|-------------------------------------------------|
| 29 Apr 09:17 | User `attacker` created                         |
| 29 Apr 10:01 | User `testuser` created and deleted seconds later |
| 7 May 11:01  | User `analyst1` created                         |
| 9 May 10:42  | User `attacker` deleted (`userdel -r`)          |
| Before audit | `analyst1` also deleted (no longer in passwd)   |

All accounts confirmed gone today. No orphaned files left behind 
(verified with `sudo find / -uid 1003`).

**Verdict:** Clean. Documented for the timeline.

---

## 4. Recommendations

1. **Use `last -w` going forward** to avoid truncated-username false alarms.
2. **Rotate `wtmp`** to clear old session data that no longer reflects 
   the current system: `sudo logrotate -f /etc/logrotate.d/wtmp`.
3. **Enable `fail2ban`** to throttle repeated SSH failures automatically.
4. **Switch SSH to key-based authentication only** (disable password 
   login in `/etc/ssh/sshd_config`).
5. **Re-run this audit weekly** as the lab grows in complexity.

---

## 5. What I learned this week

- How `/etc/passwd` and `/etc/shadow` actually work, including the 
  date encoding in `/etc/shadow` field 3 (days since epoch).
- That UID 0 is the only thing that defines "root" — usernames are 
  cosmetic.
- How to read `last`, `lastb`, and `lastlog`, and why each one exists.
- How to investigate a suspicious account from scratch using passwd, 
  shadow, lastlog, and journalctl together.
- The difference between an alert and an incident: most "weird" 
  findings turn out to be benign. The job is to prove it, not assume it.

---

*End of report.*
