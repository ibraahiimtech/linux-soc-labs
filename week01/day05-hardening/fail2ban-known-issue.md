# Fail2ban Detection Gap — Ubuntu 24.04 + OpenSSH 9.6+

## Observation
Fail2ban with the default sshd filter (both standard and aggressive modes) did not detect brute-force SSH attempts against a hardened server on Ubuntu 24.04 with OpenSSH 9.6+.

## Symptom
- 10 failed SSH login attempts (as `admin`, non-existent user) generated log entries:
  `Invalid user admin from 127.0.0.1 port 51916`
  `Connection closed by invalid user admin 127.0.0.1 port 51916 [preauth]`
- Fail2ban's `sshd` jail counter remained at `Total failed: 0`
- No ban was triggered

## Root cause (suspected)
On modern OpenSSH, when a login attempt targets an account that does not exist AND password authentication is disabled, sshd short-circuits before it evaluates a password. The resulting log messages (`Invalid user ... Connection closed ... [preauth]`) do not match the default sshd filter regexes shipped with the fail2ban version on Ubuntu 24.04.

## Attempted fixes
1. Standard `[sshd]` jail — no matches (baseline)
2. `mode = aggressive` on the `[sshd]` jail — still no matches

## Workaround
The primary SSH hardening (password authentication disabled, root login disabled, key-only) already rejects these attempts at protocol level. Fail2ban is a defence-in-depth layer, not the primary control. The security posture is not weakened.

## Follow-up
Custom filter regex should be added at `/etc/fail2ban/filter.d/sshd-custom.local` matching the `Connection closed by invalid user .+ \[preauth\]` pattern. This is a Week 2+ task.

## Lesson
"Detection tool installed and running" is not equivalent to "detection tool matching your telemetry." End-to-end testing with the exact log format the environment produces is the only way to verify a detection actually works.
