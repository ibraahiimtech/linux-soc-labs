# Day 2 — Linux Persistence Hunting

**Lab:** cloudsec-lab (Ubuntu 24.04.1) · **User:** ibraahiimtech
**Focus:** Where attackers plant code that survives reboot/login, and how to find it.

## Core principle

Every persistence mechanism answers one question: "What does this machine
execute automatically, and can I get my code into that list?"

Linux auto-executes at four moments:
- Boot: systemd units, ld.so.preload
- Schedule: cron, systemd timers
- Login: shell startup, PAM, MOTD, SSH keys
- Every binary launch: ld.so.preload

User-level persistence is real persistence. A user crontab, a .bashrc line, an
authorized_keys entry — none need root, all survive reboot.

The one instinct that catches everything: don't trust the surface, establish
provenance. Package path vs /etc. Referenced vs merely present. busybox view vs
glibc view. Held private key vs friendly comment. On a clean box, everything
accounts for itself — you hunt the one thing whose origin you can't explain.

## The seven (+1) hiding places

### 1. cron — T1053.003
    sudo ls -la /etc/cron.d/                  # drop-in dir (system format: 6 fields, incl. user)
    cat /etc/crontab                          # master system schedule
    sudo ls -la /etc/cron.{hourly,daily,weekly,monthly}/
    sudo ls -la /var/spool/cron/crontabs/     # REAL per-user location (not crontab -l)
- /etc/cron.d/ needs a user field (6 fields). A 5-field line there = malformed = attacker tell.
- Sweep all users in /var/spool/cron/crontabs/, incl. service accounts (www-data).

### 2. systemd services/timers — T1543.002
    systemctl list-unit-files --state=enabled
    systemctl list-timers --all
    systemctl --user list-unit-files --state=enabled   # user-level, no root needed
- Unit priority: /etc/systemd/system/ (admin+attacker) > /run/ > /lib/ (package).
- A unit in /etc/ shadows the packaged one of the same name.

### 3. systemd drop-in override — T1543.002  (the sneaky one)
    systemctl show <unit> -p DropInPaths      # names the SOURCE file
    sudo find /etc/systemd/system /run/systemd/system -type d -name '*.d'
- Attacker adds /etc/systemd/system/<unit>.service.d/override.conf with e.g.
  ExecStartPre=. The main unit file stays pristine — debsums passes.
- systemctl cat shows the merged result (what runs); DropInPaths shows where each
  piece came from (the finding). Legit drop-ins live under /usr/lib; attacker under /etc.

### 4. Shell startup — T1546.004
    tail -n 20 ~/.bashrc ~/.profile           # check the END (whitespace burial)
    wc -l ~/.bashrc ~/.profile                # baseline counts: 117 / 27
    ls -la /etc/profile.d/                     # drop-in dir, sourced every login
- /etc/profile.d/*.sh is sourced, not executed — no execute bit needed to run.
- Whitespace burial: attacker appends blank lines then payload. tail/wc -l beat it.

### 5. SSH authorized_keys — T1098.004  (quietest backdoor)
    sudo find / -name 'authorized_keys*' -not -path '*/proc/*' 2>/dev/null
    ssh-keygen -lf ~/.ssh/authorized_keys      # fingerprint EACH authorised key
    for k in ~/.ssh/id_*; do ssh-keygen -lf "$k"; done   # keys you actually hold
- Nothing runs — just a line of base64 granting permanent access.
- Detection = the fingerprint, not the comment. Comment is a sticker anyone can
  print; the SHA256 fingerprint is the receipt. A key you can't produce the
  private half of = backdoor.
- Also check command= prefixes and a redirected AuthorizedKeysFile in sshd_config.

### 6. PAM — T1556.003
    grep -rn 'pam_exec\|pam_python\|pam_script' /etc/pam.d/   # the key check
    ls -la /lib/x86_64-linux-gnu/security/
    dpkg -V libpam-modules                     # exit 0 + no output = verified
- pam_exec.so ships legit but runs an arbitrary command on every auth (SSH, sudo,
  su, console). What matters: is it referenced in /etc/pam.d/?

### 7. ld.so.preload — T1574.006  (nastiest — userland rootkit)
    cat /etc/ld.so.preload 2>/dev/null         # file usually absent; existence = suspicious
    busybox cat /etc/ld.so.preload             # static binary, ignores the preload
    busybox ls -la /etc/ | grep ld.so
- A preload lib loads into every dynamically-linked process before libc — can hook
  readdir/open/stat to hide files, incl. itself.
- A glibc tool (cat/ls/find) can be lied to. busybox is statically linked → makes
  syscalls the rootkit can't intercept. Detection = the discrepancy: busybox sees a
  file glibc doesn't → rootkit. Agreement = clean.

### 8 (bonus). MOTD — T1546
    ls -la /etc/update-motd.d/                 # scripts run as ROOT on SSH login

## The thread: Linux is built out of drop-in directories

/etc/cron.d/ · /etc/systemd/system/*.service.d/ · /etc/profile.d/ ·
/etc/update-motd.d/ · /etc/pam.d/

Good design (packages add config without editing each other) — and the single most
consistent persistence surface, because in every case the real file stays pristine
while behaviour changes. When you audit a config file, audit its .d directory. Every time.

## Hunt heuristics that repeated across every spot

1. Timestamp diff — one file much newer than its neighbours in a system directory
   (files dated today among 2023-2024 package files). Caught the cron and profile.d plants.
2. Location provenance — legit systemd drop-ins under /usr/lib; attacker under /etc.
   Same for "referenced vs merely present" (PAM).
3. Cryptographic receipt — SSH keys judged by fingerprint match, never by comment.
4. Tool independence — verify with a tool that can't be subverted (busybox vs hooked glibc).
5. Finding one != done — attackers plant in several spots; sweep every location regardless.
6. Verify cleanup, don't assume it — re-list after every rm; a "cleaned" box and a
   clean box are different claims.

## Field-ownership breadcrumb
A root cron job (/etc/cron.d/ with root in the user field) creates root-owned
artifacts. An unexpected root-owned file in /tmp is itself a forensic lead —
ownership follows the process that created it.

## Lab exercise completed
Planted -> hunted -> cleaned -> verified, one spot at a time, across:
systemd drop-in · cron · /etc/profile.d/ · SSH authorized_keys.
Confirmed the cron plant fired live (5 log entries, every 5 min) before removal.
Full-box re-sweep returned to baseline.

MITRE ATT&CK: T1053 · T1543 · T1546 · T1098 · T1556 · T1574
