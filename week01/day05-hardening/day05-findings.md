# Day 5 — Linux Hardening

**Date:** 15–16 July 2026
**Host:** cloudsec-lab (Ubuntu 24.04.1 LTS)
**Exercise:** Apply four layers of defence to a Linux host, verify each layer, and document evidence.

## Objective
Days 1–4 built detection capabilities. Day 5 flips perspective: what defensive controls would stop the attacks in the first place? Deploy the four industry-standard hardening layers and verify each with evidence.

## The 4 layers deployed

### 1. Firewall (ufw)
Default-deny inbound, allow-outbound. Only port 22 (SSH) permitted inbound. Discovered and removed pre-existing rules (port 8000 allow, local subnet deny) whose provenance was unknown — documented as configuration drift.

**Evidence:** `ufw-state-before.txt`, `ufw-state-after.txt`

### 2. SSH hardening
Four settings applied via `/etc/ssh/sshd_config.d/99-hardening.conf` (drop-in override pattern):
- `PermitRootLogin no` — root SSH refused regardless of credentials
- `PasswordAuthentication no` — passwords cannot be used
- `PubkeyAuthentication yes` — keys only
- `MaxAuthTries 3` — three failures then disconnect

Generated ed25519 keypair for the analyst account. Installed public key into authorized_keys. Verified key-based login works before disabling passwords.

**Evidence:** `sshd-hardened-config.txt`

### 3. Fail2ban
Deployed with sshd jail, bantime 3600s, maxretry 5, findtime 600s. Verified running. **Known issue:** the default fail2ban filter does not match the log format produced by OpenSSH 9.6+ on Ubuntu 24.04 (`Connection closed by invalid user` instead of `Failed password`). Aggressive mode also did not resolve this. Documented as follow-up work — this does not affect the primary defence.

**Evidence:** `fail2ban-config.txt`, `fail2ban-status-baseline.txt`, `fail2ban-known-issue.md`

### 4. Auditd
Deployed 11 audit rules covering account changes, SSH config, sudo config, kernel module operations, time changes, and all root-executed commands. Rules use the drop-in pattern at `/etc/audit/rules.d/99-hardening.rules`. Auditd captured configuration events immediately after rule load, confirming end-to-end operation.

**Evidence:** `auditd-rules.txt`, `auditd-runtime-rules.txt`, `auditd-status.txt`, `auditd-sample-events.txt`

## Verification against Day 4 attack

The brute-force pattern from Day 4 (22 SSH attempts across 4 usernames) was re-run against the hardened host. Every attempt was rejected at the SSH protocol level with `Permission denied (publickey)` — the attack cannot proceed to the password-guessing stage. Zero attempts reached the authentication decision.

**Result:** the specific attack detected in Day 4 is now impossible against this host.

## Lessons learned

- **Configuration drift is real.** The unexpected ufw rules (port 8000, subnet deny) had no known source. Real environments accumulate mystery configuration. Baseline, document, reset — don't leave mystery in place.
- **The drop-in override pattern (.d directories) is the professional way.** Applied consistently across SSH (`sshd_config.d`), fail2ban (`jail.local`), and auditd (`rules.d`). Original defaults stay pristine; changes are isolated, findable, and easy to roll back.
- **"Test before commit" prevents lockouts.** `sudo sshd -t` caught a broken sshd_config before restart — restoring from backup was 30 seconds instead of a rebuild.
- **"Installed" is not "working."** Fail2ban was installed, running, and configured correctly, but its default filter didn't match this system's log format. End-to-end testing revealed the gap. Junior engineers assume tools work; senior engineers verify.
- **auditd captures the human, not just the process.** The `auid` field records who originally logged in, even after sudo. This is the answer to "who did this?" in a real forensic investigation.

## MITRE ATT&CK — defensive coverage

| Tactic | Technique | Control |
|---|---|---|
| Initial Access | T1078.003 (Local Accounts) | SSH keys-only + no root SSH |
| Initial Access | T1110 (Brute Force) | SSH keys + fail2ban |
| Persistence | T1098.004 (SSH Authorized Keys) | auditd watches on `.ssh/` files (future) |
| Persistence | T1547 (Boot or Logon Autostart) | auditd on module loads |
| Defense Evasion | T1070.002 (Clear Linux logs) | auditd on separate log stream |
| Defense Evasion | T1562.006 (Indicator Blocking) | auditd rules loaded, immutable when locked |

## Next steps
- Tune fail2ban filter to match OpenSSH 9.6+ log format
- Add `-e 2` to auditd rules to lock the configuration until reboot
- Enable ufw logging and forward to a SIEM (Day 6 or later)
- Deploy unattended-upgrades for automatic security patching
