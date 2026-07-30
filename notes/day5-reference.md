# Day 5 — Host Hardening

**Lab:** cloudsec-lab (Ubuntu 24.04.1) · **User:** ibraahiimtech
**Focus:** Prevention, not detection — deploy four defensive layers, verify each
end-to-end, and prove the Day 4 attack can no longer succeed.

## The week inverts: Detect -> Prevent

- Day 1: Who's supposed to be here? (Detect)
- Day 2: What runs automatically? (Detect)
- Day 3: What's running now? (Detect)
- Day 4: What happened? (Detect)
- Day 5: How do I make this box harder to attack? (PREVENT)

Core idea: attack surface — every open port, running service, account, and loose
permission is a way in. Hardening = systematically removing surface you don't
need, and protecting what you do.

## The golden rule: NEVER LOCK YOURSELF OUT

Allow your access path FIRST, verify it, THEN tighten everything else. The classic
disaster: enabling default-deny firewall (or disabling password auth) before
confirming your alternative works — on a remote box that's a permanent lockout.
Order matters at every step. A local VM has console fallback — the safe place to
learn the discipline.

## Layer 1 — Firewall (ufw)

    sudo ufw status verbose > ufw-state-before.txt   # snapshot BEFORE
    sudo ufw allow 22/tcp                             # allow SSH FIRST (golden rule)
    sudo ufw default deny incoming                    # THEN default-deny
    sudo ufw default allow outgoing
    sudo ufw status verbose > ufw-state-after.txt     # snapshot AFTER

Target: deny (incoming), allow (outgoing), only 22/tcp ALLOW IN. Even if a backdoor
listener (Day 3, port 4444) were running, ufw refuses inbound to it — the process
can start, but the outside world can't reach it. Watch for CONFIGURATION DRIFT:
unexplained pre-existing rules (baseline, document, reset — don't leave mystery).

## Layer 2 — SSH hardening (drop-in pattern)

Four settings in /etc/ssh/sshd_config.d/99-hardening.conf (never edit main config):
    PermitRootLogin no
    PasswordAuthentication no
    PubkeyAuthentication yes
    MaxAuthTries 3
Verify: sudo sshd -T | grep -iE "permitroot|password|pubkey|maxauth"

CRITICAL ORDER: install AND test the SSH key BEFORE setting PasswordAuthentication
no. Once passwords are off, the key is the ONLY door — prove it works first
(ssh-keygen -lf ~/.ssh/authorized_keys + a real login).

The drop-in .d pattern is the SAME mechanism attackers use for persistence (Day 2).
Neutral tool: main config pristine, changes isolated & findable, rollback = delete
one file. sudo sshd -t tests config before restart (catches a broken file in
seconds vs. a lockout).

## Layer 3 — fail2ban (the "installed != working" layer)

Watches auth log, auto-bans IPs that fail too many times. Config via jail.local
(drop-in — jail.conf stays pristine).

THE TRAP: service active (running) + jail listed does NOT mean it's working.
Verify the OUTCOME:
    sudo fail2ban-client status sshd    # Total failed must climb on real failures
On Ubuntu 24.04 the default filter (even mode = aggressive) does NOT match OpenSSH
9.6+ log format. Modern OpenSSH logs "Invalid user" / "Connection closed by invalid
user", NOT "Failed password" — so the default filter reads every line and matches
nothing. Total failed: 0 after real attacks = broken filter.

THE FIX — custom filter /etc/fail2ban/filter.d/sshd-custom.conf:
    [Definition]
    failregex = ^.*Invalid user .* from <HOST> port \d+
                ^.*Connection closed by invalid user .* <HOST> port \d+
                ^.*Connection closed by authenticating user .* <HOST> port \d+
                ^.*Failed password for .* from <HOST> port \d+
    ignoreregex =

TWO GOTCHAS discovered:
1. Anchor <HOST> with "port \d+" after it — otherwise the greedy .* captures the
   PORT as the IP (log showed bogus "Found 0.0.172.158"). "Counter moved" is NOT
   enough — verify it captured the RIGHT IP (fail2ban.log shows the real address).
2. ignoreself (on by default) ALWAYS ignores the machine's own IPs, separate from
   ignoreip. That's why localhost tests never ban — correct safety, not a bug.

Production-safe jail.local:
    [sshd]
    enabled = true
    filter = sshd-custom
    backend = systemd
    journalmatch = _SYSTEMD_UNIT=ssh.service
    maxretry = 5
    findtime = 600
    bantime = 3600
    ignoreip = 127.0.0.1/8 ::1

## Layer 4 — auditd (the forensic recorder)

Kernel-level audit of security events. Rules via /etc/audit/rules.d/99-hardening.rules
(drop-in). Verify LOADED (not just on disk): sudo auditctl -l

11 rules, each mapping to a week-1 threat:
    -w /etc/passwd -p wa -k account_changes           # Day 1 ghost accounts
    -w /etc/shadow -p wa -k account_changes
    -w /etc/gshadow -p wa -k account_changes
    -w /etc/group -p wa -k account_changes
    -w /etc/ssh/sshd_config -p wa -k ssh_config_changes
    -w /etc/ssh/sshd_config.d/ -p wa -k ssh_config_changes   # watches your own hardening
    -w /etc/sudoers -p wa -k sudo_config_changes
    -w /etc/sudoers.d/ -p wa -k sudo_config_changes
    -a always,exit -F arch=b64 -S init_module,delete_module -k kernel_modules   # rootkit
    -a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_changes
    -a always,exit -F arch=b64 -F euid=0 -S execve -k root_commands
Query by key: sudo ausearch -k ssh_config_changes -ts recent

THE KILLER FEATURE — auid. In an audit record:
- uid=0 / euid=0 = ran as root (what a normal log shows — useless if all admins sudo)
- auid=1000 = who ORIGINALLY logged in, immutable across sudo escalation
auid answers "who ACTUALLY did this?" — the hardest question in IR. sudo can change
your effective identity but can't launder the audit UID. In a multi-admin breach,
auid names the human behind "root".

## Verification against the Day 4 attack
Re-running the Day 4 brute-force against the hardened host: every attempt dies at
"Permission denied (publickey)" — SSH refuses to even offer password auth
(PasswordAuthentication no), so the attacker never reaches the password-guessing
stage. The attack isn't detected — it's IMPOSSIBLE.

## Key takeaways
1. Never lock yourself out — allow+verify your access before you deny.
2. Drop-in .d pattern everywhere — SSH, fail2ban, auditd. Pristine defaults,
   isolated changes, one-file rollback. Same mechanism attackers abuse (Day 2).
3. "Installed" != "working" — verify the OUTCOME, not the service status.
   (fail2ban ran green while catching nothing.)
4. "Counter moved" != "correct" — verify it captured the right DATA (IP, not port).
5. auid captures the human behind root — the answer to "who did this?"
6. Test config before commit (sshd -t) — 30-second fix vs. a rebuild.

MITRE ATT&CK (defensive coverage):
T1078.003 (Local Accounts) -> SSH keys-only + no root · T1110 (Brute Force) -> keys
+ fail2ban · T1098.004 (SSH Authorized Keys) -> auditd watches ~/.ssh · T1547
(Autostart) -> auditd on module loads · T1070.002 (Clear Logs) -> auditd separate
stream · T1562.006 (Indicator Blocking) -> auditd rules loaded
