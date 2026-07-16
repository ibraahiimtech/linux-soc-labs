 Week 1 Complete Journey — Days 1 to 5
Programme: 6-month career-switch into SOC and Cloud Security
Lab: Ubuntu 24.04.1 LTS VM (cloudsec-lab, user ibraahiimtech) on VMware
Period: May–July 2026
Style: hands-on labs with plant-then-detect exercises, MITRE ATT&CK-aligned writeups, full GitHub portfolio

🎯 The learning arc
Every day answered a specific question about a Linux system:
DayQuestionSkill built1Who's supposed to be here?Baseline auditing2What runs automatically?Persistence hunting3What's running right now?Live-process forensics4What happened, and when?Log analysis5What stops it happening?Defensive hardening
Each day used the same investigation loop: enumerate → filter → investigate → document.

🌅 DAY 1 — Linux Baseline Audit
What we did
Learned how Linux tracks users, privileges, and login activity. Built a mental model of "what does normal look like on this system?" — the prerequisite for spotting anomalies.
Concepts covered

/etc/passwd format and what each field means
/etc/shadow and password hash storage
The date encoding in shadow (days since Unix epoch)
UID 0 is what defines root — usernames are cosmetic
SUID binaries and privilege escalation via GTFOBins
Login history via last, lastb, lastlog
The three-step SOC report pattern: what I did → what I found → verdict

Commands practised
bash# Users with real login shells (not service accounts)
grep -vE '/(nologin|false|sync|halt|shutdown)$' /etc/passwd

# UID 0 accounts — should ONLY return root
awk -F: '$3 == 0 {print $1}' /etc/passwd

# Empty passwords in shadow — should be silent
sudo awk -F: '($2 == "") {print $1}' /etc/shadow

# Password change dates (days since epoch)
sudo awk -F: '{print $1, $3}' /etc/shadow | sort -k2 -n

# Find all SUID binaries excluding snap duplicates
sudo find / -type f -perm -4000 -not -path "/snap/*" 2>/dev/null

# Login history (WIDE format — always use -w to prevent truncation)
last -n 20 -w
sudo lastb -n 20 -w
who
w
Troubleshooting encountered
The "tempadmi" ghost account mystery
Running last -n 20 (without -w), we saw sessions for a user named tempadmi — an admin-sounding truncated name that looked highly suspicious.
Initial investigation:
bashgrep tempadm /etc/passwd    # returned nothing
lastlog | grep -iv "never"  # returned nothing
Root cause found via journalctl timeline:
bashsudo journalctl | grep -iE "useradd|userdel|tempadm"
Revealed the truth: the previous primary user was techsom (before username rename), and multiple test accounts (attacker, testuser, analyst1) had been created and deleted during earlier lab work. The tempadmi in last output was truncated from a longer username since deleted.
Lesson: Always use last -w for full usernames. Truncation creates false alarms.
The sudo and pipes gotcha
Ran grep tempadm /etc/shadow | sudo tee /dev/null — got permission denied. Learned that sudo only elevates the command immediately after it, not the whole pipeline.
The fix: sudo grep tempadm /etc/shadow — put sudo on the command that needs elevation.
The empty command substitution
Ran sudo chage -l $(grep tempadm /etc/passwd | cut -d: -f1) — got chage help text. The inner command returned empty because no matching user existed, so chage -l was called with no argument.
Lesson: Always test command substitution before wrapping it. Check the inner command returns a value first.
Artifacts committed to GitHub
week01/
├── audit-report.md         (SOC-style writeup of findings)
└── linux-audit.sh          (reusable 9-section audit script)
MITRE ATT&CK mapping

T1078.003 — Local Accounts (what we're auditing)
T1548 — Abuse Elevation Control Mechanism (SUID abuse)


🌒 DAY 2 — Persistence Hunting
What we did
Learned the 7 places attackers hide on Linux to maintain access. Played both red team (planting three fake backdoors) and blue team (hunting them down). Built a reusable detection script.
Concepts covered

Persistence = maintaining access after initial compromise (MITRE TA0003)
Attackers hook into anything that runs automatically
The 7 hiding places on Linux:

Cron jobs
Systemd services and timers
Shell startup files (.bashrc, .profile)
SSH authorized_keys
PAM modules
/etc/ld.so.preload (rootkit indicator)
MOTD scripts


The dpkg -S trick to verify systemd services belong to installed packages

The three plants and their detection
Plant 1 — Malicious cron job
bash# Plant
(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.suspicious_script.sh") | crontab -

# Detect
crontab -l  # showed the entry
Plant 2 — .bashrc backdoor
bash# Plant
echo '# system optimization' >> ~/.bashrc
echo 'touch /tmp/.bashrc_hit' >> ~/.bashrc

# Detect
tail -10 ~/.bashrc  # revealed the additions
Plant 3 — Rogue systemd service
bash# Plant
sudo tee /etc/systemd/system/system-update-check.service > /dev/null << 'EOF'
[Unit]
Description=System Update Check
[Service]
ExecStart=/bin/bash -c 'touch /tmp/.systemd_hit'
Type=oneshot
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable system-update-check.service

# Detect
ls -la /etc/systemd/system/*.service       # showed the file
systemctl cat system-update-check.service  # showed the ExecStart
dpkg -S /etc/systemd/system/system-update-check.service  # "no path found" = not from package
Troubleshooting encountered
Multiple folder-not-found errors
Between Day 1 and Day 2, hit a confusing situation where:

Files were being created outside the intended repo
Terminal was in unexpected working directories
day02-persistence sometimes appeared as a file, sometimes a folder, sometimes missing

Root cause: Different terminal sessions were cd-ing to different places, and nano was creating folders/files in whichever directory happened to be current.
The fix — a workflow rule that stuck: Always run pwd before creating any file. Always run ls -la to confirm the environment. Never trust that you're where you think you are.
The sed-based cleanup
Cleaning up the .bashrc plant needed to remove specific lines without disturbing the rest of the file:
bashsed -i '/# system optimization/d' ~/.bashrc
sed -i '/touch \/tmp\/.bashrc_hit/d' ~/.bashrc
Learned that sed -i '/pattern/d' deletes matching lines in place.
Artifacts committed to GitHub
week01/day02-persistence/
├── persistence-check.sh    (7-section detection script)
├── persistence-findings.md (SOC writeup)
└── hunt-output.txt         (proof of detection)
MITRE ATT&CK mapping

T1053.003 — Scheduled Task: Cron
T1543.002 — Create or Modify System Process: systemd Service
T1546.004 — Event Triggered Execution: Unix Shell Configuration Modification


🌓 DAY 3 — Process Inspection
What we did
Learned that malware can live entirely in memory — including malware whose file has been deleted from disk. Built the mental model of /proc/ as a window into every running process. Deployed and detected three attack simulations: a fake cryptominer, a reverse-shell listener, and fileless malware.
Concepts covered

The /proc/ virtual filesystem — every process has a folder
/proc/<pid>/exe symlink shows the binary on disk
/proc/<pid>/cmdline shows the exact command run
/proc/<pid>/status shows user, memory, parent
Fileless malware: process running from a file that's been deleted from disk
The (deleted) marker in /proc/<pid>/exe — one of the strongest fileless malware indicators
Port 4444 as the Metasploit fingerprint
Reserved bash variables like PPID cannot be reassigned

The 6-block deep-dive on any suspicious PID
bashSUSPECT=<pid>

# 1. What command is it running?
sudo cat /proc/$SUSPECT/cmdline | tr '\0' ' '; echo

# 2. Where is the binary?
sudo ls -la /proc/$SUSPECT/exe

# 3. What's the working directory?
sudo ls -la /proc/$SUSPECT/cwd

# 4. Network connections?
sudo lsof -p $SUSPECT -i 2>/dev/null

# 5. Parent process (use PARENT_PID, NOT PPID!)
PARENT_PID=$(awk '/^PPid:/ {print $2}' /proc/$SUSPECT/status)
sudo cat /proc/$PARENT_PID/cmdline | tr '\0' ' '; echo
The three plants and their detection
Plant 1 — Cryptominer simulation (kworker-helper)
bash# Plant — infinite bash loop named to blend in with kernel threads
cat > /tmp/.kworker-helper << 'EOF'
#!/bin/bash
while true; do echo "mining..." > /dev/null; done
EOF
chmod +x /tmp/.kworker-helper
/tmp/.kworker-helper &

# Detect
ps aux --sort=-%cpu | head -10   # showed PID 3592 at 99.7% CPU
Plant 2 — Reverse-shell listener on port 4444
bash# Plant
ncat -lvnp 4444 > /dev/null 2>&1 &

# Detect
sudo ss -tunap | grep LISTEN     # revealed 0.0.0.0:4444
Plant 3 — Fileless process (deleted binary)
bash# Plant
cp /bin/sleep /tmp/.update-daemon
/tmp/.update-daemon 3600 &
PLANT3_PID=$!
rm /tmp/.update-daemon           # delete file while process runs

# Detect
sudo ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"
# Result: /proc/3739/exe -> /tmp/.update-daemon (deleted)
Troubleshooting encountered
The PPID: readonly variable error
During the 6-block deep-dive, ran:
bashPPID=$(awk '/^PPid:/ {print $2}' /proc/$SUSPECT/status)
Got: bash: PPID: readonly variable
Root cause: PPID is a reserved bash variable that always holds the parent PID of the current shell. Cannot be overwritten. The script silently used the shell's parent (gnome-terminal-server, PID 3556) instead.
The fix: Rename to PARENT_PID. Lesson: check whether variable names collide with bash builtins.
The auth.log "binary file matches" issue
Tried to search auth.log:
bashsudo grep -i sudo /var/log/auth.log
Got: grep: /var/log/auth.log: binary file matches
Root cause: Modern Ubuntu sometimes writes binary content into auth.log. Default grep refuses to treat binary as text.
The fixes:

sudo grep -a -i sudo /var/log/auth.log — -a forces text mode
Or use the modern way: sudo journalctl _COMM=sudo --since today (covered in Day 4)

Folder confusion — day02-persistence mystery
Multiple attempts to cd into day03-processes failed with "not a directory" or "no such file" errors. Repeated debugging revealed a mix of:

Stale files from earlier failed attempts
nano sometimes creating a file with the same name as the intended folder
Being in the wrong parent directory

The recovery pattern: Always start with pwd, ls -la, and confirm state. Never trust that a folder exists — check.
Artifacts committed to GitHub
week01/day03-processes/
├── process-hunt.sh         (7-section detection script)
├── process-findings.md     (SOC writeup)
├── day03-walkthrough.md    (full annotated walkthrough)
└── hunt-output.txt         (proof of detection)
MITRE ATT&CK mapping

T1620 — Reflective Code Loading (fileless)
T1496 — Resource Hijacking (cryptominer)
T1059 — Command-line Execution
T1071.001 — Web Protocols (would apply to real C2)


🌔 DAY 4 — SSH Log Analysis
What we did
Learned Linux's two log systems (traditional syslog and the systemd journal). Mastered the 5 essential text-processing tools. Generated 22 fake SSH brute-force attempts, then built a bash pipeline to detect them, characterise the attack, and prove containment.
Concepts covered

Traditional syslog vs systemd journal — how they coexist
journalctl as SQL for system events
The 5 essential tools: grep, awk, sort, uniq, cut
The universal SOC pipeline: get logs → filter → extract field → sort | uniq -c | sort -rn
The two different log formats sshd uses depending on whether the target account exists

The journalctl filter syntax
bash# Last 20 entries
sudo journalctl -n 20

# Logs for a specific process
sudo journalctl _COMM=sshd -n 20

# Time-bounded
sudo journalctl --since "1 hour ago"
sudo journalctl --since "2026-05-15 09:00" --until "2026-05-15 10:00"

# Follow live
sudo journalctl -f

# By priority (err = errors and worse)
sudo journalctl -p err
The simulated attack — 22 attempts
bash# 5 attempts as admin
for i in {1..5}; do
    sshpass -p 'wrongpass' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 admin@localhost 2>/dev/null
done

# 8 attempts as root
for i in {1..8}; do
    sshpass -p 'guess' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 root@localhost 2>/dev/null
done

# 3 attempts as ubuntu, 6 as test — same pattern
The investigation pipeline
bash# Count total failures
sudo journalctl _COMM=sshd --since "30 minutes ago" --no-pager | grep -c "Failed password"
# Result: 23

# Top targeted usernames (handling both log formats)
sudo journalctl _COMM=sshd --since "30 minutes ago" --no-pager \
  | grep "Failed password" \
  | grep -oE "for (invalid user )?[a-zA-Z0-9_-]+" \
  | sed 's/for invalid user //; s/for //' \
  | sort | uniq -c | sort -rn
# Result: 9 root, 6 test, 5 admin, 3 ubuntu

# Source IPs
sudo journalctl _COMM=sshd --since "30 minutes ago" --no-pager \
  | grep "Failed password" \
  | grep -oE "from [0-9.]+" \
  | sort | uniq -c | sort -rn
# Result: 23 from 127.0.0.1

# Did any succeed?
sudo journalctl _COMM=sshd --since "30 minutes ago" --no-pager | grep "Accepted"
# Result: empty = no breach
Troubleshooting encountered
The invalid vs real username log format quirk
First attempt at username extraction gave confusing results:
14 invalid
 9 root
Expected to see admin, test, ubuntu, root — instead saw "invalid" 14 times.
Root cause: sshd writes two different log message formats:

For existing accounts: Failed password for root from 127.0.0.1
For non-existent accounts: Failed password for invalid user admin from 127.0.0.1

The naive awk (print the word after "for") captured invalid for the non-existent accounts.
The fix — the smarter grep + sed pattern:
bashgrep -oE "for (invalid user )?[a-zA-Z0-9_-]+" | sed 's/for invalid user //; s/for //'
Lesson learned: This is a real detection engineering gotcha. Every SIEM engineer has stories about detection rules that seemed correct but missed half the attacks because of a log-format quirk.
The VMware network disconnection
Attempting to install sshpass with sudo apt install -y sshpass failed with:
Err:6 http://gb.archive.ubuntu.com/ubuntu ...
Temporary failure resolving 'gb.archive.ubuntu.com'
Diagnostic sequence:
baship a | grep "inet "        # showed only loopback — no external interface
ping -c 3 8.8.8.8          # failed
ip link show               # showed ens33 in NO-CARRIER state
Root cause: VMware's virtual network adapter was disconnected. Fixed by clicking VM → Removable Devices → Network Adapter → Connect.
Recovery:
bashsudo dhclient ens33
ping -c 3 google.com       # worked
sudo apt update && sudo apt install -y sshpass nmap
Lesson learned: When network commands fail, layer by layer diagnosis works: interface state → routing → DNS → application. That's the pattern for every network debugging job.
The pager > truncation confusion
Ran sudo journalctl -n 20 — output ended with lines truncated at the terminal edge shown by > characters, and finished at (END) waiting for input.
Explanation: journalctl pipes output through less by default. The > symbols mean lines are too wide for the terminal. (END) means the pager is waiting.
The fix: Press q to exit the pager. For scripts, always use --no-pager to disable it.
Artifacts committed to GitHub
week01/day04-logs/
├── log-hunt.sh             (6-section brute-force detection script)
├── log-findings.md         (SOC writeup)
└── hunt-output.txt         (proof of detection)
MITRE ATT&CK mapping

T1110 — Brute Force (SSH)
T1078 — Valid Accounts (if attackers had succeeded)


🛡️ DAY 5 — Linux Hardening
What we did
Deployed 4 defensive layers to make the Day 4 attack impossible. Learned the professional pattern of drop-in overrides (.d/ directories) instead of editing master config files. Verified each layer independently with evidence files.
Concepts covered

Defence in depth — layered controls
ufw (Uncomplicated Firewall) — default-deny inbound
SSH hardening: kill password auth, kill root login
SSH keys: ed25519 as the modern recommended type
The drop-in override pattern (sshd_config.d/, jail.local, rules.d/)
fail2ban — dynamic firewall rules based on log patterns
auditd — kernel-level tamper-resistant audit trail
The critical auid field — records who logged in even after sudo

The 4 layers deployed
Layer 1: ufw firewall
bashsudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw enable
sudo ufw status verbose
Result: only port 22 open, deny inbound default.
Layer 2: SSH hardening
bash# Generate ed25519 keypair
ssh-keygen -t ed25519 -C "ibrahim-cloudsec-lab"

# Install public key
cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Test key-based login BEFORE disabling passwords
ssh -v ibraahiimtech@localhost

# Then apply hardening via drop-in file
sudo tee /etc/ssh/sshd_config.d/99-hardening.conf > /dev/null << 'EOF'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
EOF

# Validate config
sudo sshd -t

# Reload
sudo systemctl reload ssh
Layer 3: fail2ban
bashsudo tee /etc/fail2ban/jail.local > /dev/null << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8 ::1
backend = systemd
[sshd]
enabled = true
port = ssh
EOF

sudo systemctl restart fail2ban
Layer 4: auditd
bashsudo tee /etc/audit/rules.d/99-hardening.rules > /dev/null << 'EOF'
# Account file changes
-w /etc/passwd -p wa -k account_changes
-w /etc/shadow -p wa -k account_changes
-w /etc/gshadow -p wa -k account_changes
-w /etc/group -p wa -k account_changes

# SSH config changes
-w /etc/ssh/sshd_config -p wa -k ssh_config_changes
-w /etc/ssh/sshd_config.d/ -p wa -k ssh_config_changes

# Sudo config changes
-w /etc/sudoers -p wa -k sudo_config_changes
-w /etc/sudoers.d/ -p wa -k sudo_config_changes

# Kernel modules (rootkit indicator)
-a always,exit -F arch=b64 -S init_module,delete_module -k kernel_modules

# Time changes (forensic anti-tampering)
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_changes

# All commands run by root
-a always,exit -F arch=b64 -F euid=0 -S execve -k root_commands
EOF

sudo augenrules --load
Troubleshooting encountered
Discovered mystery ufw rules
Initial state check revealed:
Status: active
22/tcp                     ALLOW       Anywhere
8000                       ALLOW       Anywhere
Anywhere                   DENY        192.168.17.0/24
Neither we nor you remembered configuring these. The DENY rule against the local subnet was actively harmful — it blocked the VM's own network.
Root cause: Unknown — likely accumulated during earlier lab work or default from Ubuntu Desktop.
The fix (configuration drift response):
bashsudo ufw status numbered > ufw-state-before.txt  # snapshot for the record
sudo ufw disable
sudo ufw reset                                    # wipe all rules
# Then rebuild deliberately
Lesson learned: Real environments accumulate mystery configuration. Real engineers baseline, document, and reset — they don't leave mystery in place.
The sshd_config nano disaster
Editing sshd_config manually somehow removed the # characters from comment lines. Testing revealed:
/etc/ssh/sshd_config: line 2: Bad configuration option: This
/etc/ssh/sshd_config: line 3: Bad configuration option: sshd_config(5)
sshd was trying to interpret English sentences as configuration.
The safety net that saved us:
bashsudo sshd -t    # tested before restart, caught the errors
Because we hadn't restarted SSH yet, the broken config was only on disk. SSH was still running with the previous (working) config.
The recovery:
bashsudo cp /etc/ssh/sshd_config.backup-20260715 /etc/ssh/sshd_config
sudo sshd -t   # silent = valid config
Then the improved approach — use sshd_config.d/:
bashsudo tee /etc/ssh/sshd_config.d/99-hardening.conf > /dev/null << 'EOF'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
EOF
Lesson learned: The drop-in override pattern (.d/ directories) is the professional way. Original config stays pristine, changes are isolated, rollback is trivial.
The SSH key generation false start
Ran ssh-keygen -t ed25519 -C "..." twice. Both times prompts appeared but no key files were created. Investigation showed:
bashls -la ~/.ssh/
# no id_ed25519 files
Suspected cause: Ctrl+C or Ctrl+D pressed at one of the passphrase prompts silently cancelled the generation.
The fix: Ran it again, deliberately pressed Enter three times (accepting defaults).
Lesson learned: ssh-keygen fails silently on interrupted input. Verify with ls -la ~/.ssh/ after every generation.
The fail2ban filter mismatch
After deploying fail2ban and running the Day 4 brute force again, expected to see bans applied — got zero:
bashsudo fail2ban-client status sshd
# Currently failed: 0
# Currently banned: 0
Investigation of actual log messages:
bashsudo journalctl _COMM=sshd --since "10 minutes ago"
# "Invalid user admin from 127.0.0.1"
# "Connection closed by invalid user admin 127.0.0.1 port 51916 [preauth]"
Root cause: Modern OpenSSH 9.6+ on Ubuntu 24.04 short-circuits authentication for non-existent users. The resulting log format doesn't match fail2ban's default sshd filter regex.
Attempted fix: Setting mode = aggressive in [sshd] jail — did not resolve.
Decision: Documented as fail2ban-known-issue.md, moved on. The primary defence (SSH hardening) already blocks these attacks at protocol level — fail2ban is a defence-in-depth layer, not the primary control.
Lesson learned: "Detection tool installed and running" is not equivalent to "detection tool matching your telemetry." End-to-end testing is the only way to verify a detection actually works. This is real detection engineering.
The sshd -T privilege separation error
Later diagnostic checks failed with:
Missing privilege separation directory: /run/sshd
Root cause: /run/sshd is created by systemd on boot. On a fresh system where SSH hadn't started via its usual path, the directory was missing.
The fixes:
bash# Option A — create the directory
sudo mkdir -p /run/sshd

# Option B — check config directly instead
sudo grep -iE "(permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries)" \
    /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
The wrong-folder file-not-found errors
Ran cat auditd-status.txt from home directory:
cat: auditd-status.txt: No such file or directory
Root cause: Files were in ~/linux-soc-labs/week01/day05-hardening/, but the prompt showed ~$ — we were in the wrong folder.
The fix: Always cd to the correct folder first. Always check pwd.
Lesson learned: "File not found" usually means one of two things: the file genuinely doesn't exist, or you're standing in the wrong folder. Check where you're standing first.
Artifacts committed to GitHub
week01/day05-hardening/
├── day05-findings.md              (SOC writeup)
├── fail2ban-known-issue.md        (honest documentation of what didn't work)
├── ufw-state-before.txt           (before state)
├── ufw-state-after.txt            (after state)
├── sshd-hardened-config.txt       (SSH override config)
├── fail2ban-config.txt            (jail.local content)
├── fail2ban-status-baseline.txt   (jail status)
├── auditd-rules.txt               (rules file)
├── auditd-runtime-rules.txt       (loaded rules)
├── auditd-status.txt              (daemon state)
└── auditd-sample-events.txt       (captured events)
MITRE ATT&CK — defensive coverage
TacticTechniqueControlInitial AccessT1078.003SSH keys-only + no root SSHInitial AccessT1110SSH keys + fail2banPersistenceT1547auditd on module loadsDefense EvasionT1070.002auditd on separate log streamDefense EvasionT1562.006auditd immutable mode available

🧭 Cross-cutting lessons from Week 1
These aren't tied to any single day — they emerged repeatedly:
The investigation loop
Every day, same 4 steps:

Enumerate — gather everything in a category
Filter — drop the known-good
Investigate — triage what's left
Document — write findings clearly

The "check first" habit
Before every operation:

Run pwd to know where you are
Run ls -la to confirm the environment
Run git status before commits

This alone prevents 50% of "why is this broken?" moments.
Configuration files are fragile
One character wrong and services refuse to start. Universal truth. Always:

Back up before editing
Test with tools like sshd -t before applying
Use drop-in .d/ overrides instead of editing master files
Keep backup files with a date suffix

"Installed" is not "working"
Every detection tool needs end-to-end testing against your actual telemetry. Fail2ban taught this brutally — installed, running, correctly configured, and still not matching our log format.
Silence is a signal
In Unix:

grep returning no output = pattern not found
sshd -t printing nothing = config is valid
sudo awk ... /etc/shadow printing nothing on empty password check = no accounts have empty passwords

Silence is data. Get comfortable reading it.
Trust the terminal
The terminal doesn't lie. If it says "no such file", the file doesn't exist. If it says "connection refused", the connection was refused. Debug from what the terminal tells you, not from what you expect.

🎯 The bigger picture
You now have working, verified, portfolio-documented capability across:

Auditing Linux systems for compromise indicators
Hunting persistence across 7 different attack vectors
Investigating live processes including fileless malware
Analysing logs at scale with bash pipelines
Hardening hosts with 4-layer defence in depth

Each Day is one focused artifact. Each artifact is portfolio evidence. Each troubleshooting story is interview material.
Total artifacts: 20+ files across 5 days, all committed to github.com/ibraahiimtech/linux-soc-labs.
That's a real Week 1.

💾 How to save this
If you want this in your repo as a permanent record:
bashcd ~/linux-soc-labs
mkdir -p notes
nano notes/week01-complete-journey.md
# paste this whole document, save (Ctrl+O, Enter, Ctrl+X)

git add notes/week01-complete-journey.md
git commit -m "Add complete Week 1 journey document"
git push
Then you'll always have it — on GitHub, from your phone, from any computer.
Take your time deciding on the consolidation-vs-forward-progress question. Whichever you choose, this document is your baseline.
Claude is AI and can make mistakes. Please double-check responses.
