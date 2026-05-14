 Day 3 — Process Inspection: Catching Attackers in the Act

Finding things alive in memory — three days into SOC training.

The big picture
Three days, three different questions about a Linux system:
DayQuestion we askDay 1Who is supposed to be here? (users, SUID files)Day 2What's set up to run automatically? (cron, systemd, .bashrc)Day 3What's running RIGHT NOW that shouldn't be? (live processes)
Today was about catching attackers in the act — finding malware alive in memory, even when it's deleted from disk.

PART 1 — Setting up the workspace
Why: Always start in a clean, dedicated folder. A SOC analyst's habit: one investigation = one folder.
Commands used:
bashcd ~/linux-soc-labs/week01
mkdir -p day03-processes
cd day03-processes
pwd
What we did: Navigated into the repo, created a new folder for Day 3, moved inside it, verified location.
Finding: Working directory confirmed at /home/ibraahiimtech/linux-soc-labs/week01/day03-processes ✅

PART 2 — The 3 fake attackers (planting evidence)
🎯 Plant 1 — The CPU thief (/tmp/.kworker-helper)
Why: Simulates a cryptominer. Real cryptominers steal CPU cycles to mine cryptocurrency for the attacker. They name themselves like legitimate kernel threads (e.g. kworker/...) to blend in.
Commands used:
bashcat > /tmp/.kworker-helper << 'EOF'
#!/bin/bash
# Pretend cryptominer — just burns CPU
while true; do
    echo "mining..." > /dev/null
done
EOF

chmod +x /tmp/.kworker-helper
/tmp/.kworker-helper &
echo "Plant #1 PID: $!"
What we did:

cat > file << 'EOF' ... EOF — wrote the script content using a heredoc
chmod +x — made the file executable
& — ran it in the background
$! — bash's "PID of last backgrounded process" variable

🚨 Finding: Plant #1 PID 3592 — a process pretending to be a kernel thread is now running on the system.

🎯 Plant 2 — The hidden back door (nc on port 4444)
Why: Simulates a reverse-shell listener. Port 4444 is the default Metasploit reverse-shell port — instantly recognised by any security analyst.
Commands used:
bash# First attempt
nc -lvnp 4444 > /dev/null 2>&1 &
echo "Plant #2 PID: $!"

# When ncat wasn't installed:
sudo apt install -y ncat
ncat -lvnp 4444 > /dev/null 2>&1 &
Flag breakdown for nc -lvnp 4444:

-l listen mode
-v verbose
-n no DNS resolution
-p 4444 on port 4444

🚨 Finding: Plant #2 PID 3594 — a listener is now open on port 4444 awaiting an inbound connection.

🎯 Plant 3 — The ghost in memory (deleted-binary process)
Why: Simulates fileless malware. The attacker runs a binary, then deletes the file from disk — but the process keeps running in memory. Most antivirus scans disk only, so this is invisible to traditional defences.
Commands used:
bashcp /bin/sleep /tmp/.update-daemon
/tmp/.update-daemon 3600 &
PLANT3_PID=$!
echo "Plant #3 PID: $PLANT3_PID"
rm /tmp/.update-daemon
What we did:

Copied a real Linux binary (sleep) to a suspicious location
Started it running (sleep for 3600 seconds = 1 hour of doing nothing)
Captured its PID into a variable
Deleted the binary from disk while the process kept running

🚨 Finding: Plant #3 PID 3739 — process exists in memory but its file on disk is gone. The classic fileless persistence technique.

Confirm all 3 are running
Commands used:
bashjobs
ps aux | grep -E "kworker-helper|nc|update-daemon" | grep -v grep
What we did: Verified the background jobs with jobs, then searched the live process list for our three plants by name.
🚨 Finding: All 3 plants confirmed active:

ibraahi+ 3592 99.7%CPU ... /tmp/.kworker-helper
ibraahi+ 3594 ... nc -lvnp 4444
ibraahi+ 3739 ... /tmp/.update-daemon 3600


PART 3 — The 7 hunting techniques
🔍 Technique 1 — High-CPU hunting
Why: Cryptominers can't hide CPU usage. Whatever they name themselves, they always show at the top of a CPU-sorted process list.
Command used:
bashps aux --sort=-%cpu | head -10
Flag breakdown:

aux — all processes, user-oriented format, including those without a TTY
--sort=-%cpu — sort descending by CPU
| head -10 — first 10 lines only

🚨 Finding: PID 3592 (/tmp/.kworker-helper) at 99.8% CPU. The next legitimate process (gnome-shell) at just 1.3%. The gap is the smoking gun.

🔍 Technique 2 — Listening port enumeration
Why: Any port not used by a legitimate service warrants investigation. Reverse-shell listeners, C2 beacons, and unauthorised services all create open ports.
Command used:
bashsudo ss -tunap | grep LISTEN
Flag breakdown:

-t TCP
-u UDP
-n numeric (no name resolution)
-a all states
-p show process

🚨 Finding:
tcp LISTEN 0 1 0.0.0.0:4444 0.0.0.0:* users:(("nc",pid=3594,fd=3))
Port 4444, run by nc, listening on every interface (0.0.0.0). Metasploit fingerprint, completely out of place beside the legitimate listeners (DNS, SSH, CUPS).

🔍 Technique 3 — Processes running from suspicious locations
Why: Legitimate software lives in /usr/bin/, /usr/sbin/, /usr/lib/, /opt/. Nothing legitimate runs from /tmp/, /var/tmp/, or /dev/shm/ — these are world-writable directories used as attacker staging grounds.
Command used:
bashsudo ls -la /proc/*/exe 2>/dev/null | grep -E "/tmp/|/var/tmp/|/dev/shm/"
What it does: Every running process has a folder in /proc/<pid>/. The exe symlink inside points to the actual binary on disk. This command lists all of them and filters for suspicious paths.
🚨 Finding:
/proc/3739/exe -> /tmp/.update-daemon (deleted)
One line — two red flags: suspicious location AND deleted binary.

🔍 Technique 4 — Deleted binaries (HIGH PRIORITY)
Why: This is the strongest fileless-malware indicator on Linux. Legitimate software essentially never deletes itself while running. If a SOC analyst sees this on production, it's a P1 incident.
Command used:
bashsudo ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"
🚨 Finding:
/proc/3739/exe -> /tmp/.update-daemon (deleted)
PID 3739 — process alive, file gone. Escalate immediately in a real environment.

🔍 Technique 5 — The process family tree
Why: Attack patterns are recognisable by lineage. sshd → bash → wget → bash tells the story: SSH login → shell → downloader → second shell. Anomalous parent-child relationships expose attacks that look fine in isolation.
Command used:
bashpstree -p | head -30
Flag breakdown:

-p show PIDs alongside names

Finding: Standard hierarchy — systemd(1) at the top fathering everything else legitimately. No anomalous parent-child relationships on this clean lab system. ✅

🔍 Technique 6 — The 6-block deep dive on a suspect PID
Why: When you find a suspicious PID, you need its full identity card. This 6-step sequence gives you everything: command, binary, working directory, network connections, parent, start time.
Commands used (with SUSPECT_PID=534 as the demo target):
bashSUSPECT_PID=534

# Block 1: What command is it running?
sudo cat /proc/$SUSPECT_PID/cmdline | tr '\0' ' '; echo

# Block 2: Where is its binary?
sudo ls -la /proc/$SUSPECT_PID/exe

# Block 3: What's its working directory?
sudo ls -la /proc/$SUSPECT_PID/cwd

# Block 4: What network connections does it hold?
sudo lsof -p $SUSPECT_PID -i 2>/dev/null

# Block 5: Who's the parent?
PPID=$(awk '/^PPid:/ {print $2}' /proc/$SUSPECT_PID/status)
echo "Parent PID: $PPID"
sudo cat /proc/$PPID/cmdline | tr '\0' ' '; echo
Findings on PID 534 (systemd-resolved):

✅ Command: /usr/lib/systemd/systemd-resolved
✅ Binary: /usr/lib/systemd/systemd-resolved (legitimate path, not deleted)
✅ Working dir: / (normal for a daemon)
✅ Network: listening on DNS port 53 (exactly what systemd-resolved should do)
✅ Run by systemd-resolve user (proper service account)

🚨 BUT — important lesson: bash: PPID: readonly variable. The variable PPID is a reserved bash variable holding the parent PID of the current shell. You can't overwrite it. Result: instead of showing systemd-resolved's parent, the script showed your shell's parent (gnome-terminal-server, PID 3556).
Fix: Use a different variable name:
bashPARENT_PID=$(awk '/^PPid:/ {print $2}' /proc/$SUSPECT_PID/status)
echo "Parent PID: $PARENT_PID"
sudo cat /proc/$PARENT_PID/cmdline | tr '\0' ' '; echo

🔍 Technique 7 — Timeline correlation
Why: Time is the linchpin of every investigation. "Three suspicious processes started within 7 minutes — what else happened in that window?"
Commands used:
bashps -eo pid,lstart,cmd | grep -E "kworker|nc|update-daemon" | grep -v grep
sudo grep -i sudo /var/log/auth.log | tail -20
Flag breakdown for ps -eo:

-e every process
-o pid,lstart,cmd custom columns: PID, full start timestamp, command

🚨 Finding: Attack timeline reconstructed:

11:27:53 — kworker-helper started (Plant 1)
11:28:52 — nc on 4444 started (Plant 2)
11:34:34 — update-daemon started (Plant 3)

A 7-minute window of three suspicious processes — exactly what an incident timeline looks like.
🚨 Bonus finding:
sudo grep -i sudo /var/log/auth.log
grep: /var/log/auth.log: binary file matches
Modern Ubuntu sometimes writes binary content to auth.log. Fix for tomorrow:

sudo grep -ai sudo /var/log/auth.log (-a forces text mode)
sudo journalctl _COMM=sudo --since today (the modern systemd way — covered in Day 4)


PART 4 — The detection script
Why: Manual hunting works but doesn't scale. A reusable script can hunt across a fleet of servers in seconds.
Commands used:
bashnano process-hunt.sh
# [paste script content — 7 sections of checks]
# Ctrl+O, Enter, Ctrl+X

ls -la process-hunt.sh
head -5 process-hunt.sh

chmod +x process-hunt.sh
ls -la process-hunt.sh

sudo ./process-hunt.sh
sudo ./process-hunt.sh > hunt-output.txt 2>&1
What we did:

Created the file in nano, saved
Verified the content
Made it executable
Ran it interactively to verify it works
Re-ran with > hunt-output.txt 2>&1 to capture output to a file

Stream redirection breakdown:

> hunt-output.txt — send standard output to the file
2>&1 — also send errors (stream 2) to wherever stream 1 is going

🚨 Findings (all 3 plants caught in a single run):

Section 1 — CPU: PID 3592 99.6% /tmp/.kworker-helper ✅
Section 3 — Suspicious locations: /tmp/.update-daemon (deleted) ✅
Section 4 — Deleted binaries: /tmp/.update-daemon (deleted) ✅
Section 5 — Listening ports: 0.0.0.0:4444 nc pid=3594 ✅


PART 5 — Cleanup and verification
Why: SOC discipline. Never assume cleanup worked. Verify with the same tools you used for detection.
Commands used:
bash# Kill the three plants
pkill -f kworker-helper
pkill -f "nc -lvnp 4444"
pkill -f "/tmp/.update-daemon"

# Verify each is dead
ps aux | grep -E "kworker-helper|nc -lvnp 4444|update-daemon" | grep -v grep
sudo ss -tunlp | grep 4444
sudo ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"

# Remove leftover files
rm /tmp/.kworker-helper 2>/dev/null
rm /tmp/.update-daemon 2>/dev/null

# Sanity check
ls -la /tmp/ | grep -E "kworker|update-daemon"
pkill -f flag: matches the full command line, not just the process name. Critical for catching things like /tmp/.update-daemon 3600 where the path is part of the command.
🚨 Findings — clean verified three ways:

Process check: empty ✅
Port check: empty ✅
Deleted-binary check: empty ✅
Filesystem check: empty ✅

System verified back to baseline.

What you can demonstrate after today
You can credibly say in an interview:

"I can investigate a potentially compromised Linux host using live-memory forensics. My approach: enumerate top CPU consumers, listening ports, processes running from non-standard locations, and processes with deleted binaries. For each suspect PID I perform a six-step deep dive — command line, binary location, working directory, network connections, parent process, start time — and correlate timestamps with auth logs. I've built and tested a detection script that catches simulated cryptominers, reverse-shell listeners, and fileless malware. The script and writeups are in my GitHub portfolio."

That paragraph alone outperforms 50% of entry-level SOC candidates.

Key takeaways

Three different attacks needed three different detection techniques. No single command catches everything.
/proc/<pid>/exe is your forensic superpower. It exposes the binary identity of any running process, including deleted ones.
Port 4444 is a Metasploit fingerprint. Memorise common attacker ports — they're instant escalation triggers.
(deleted) in /proc/<pid>/exe is the strongest fileless-malware indicator on Linux. P1 in production.
Bash has reserved variable names like PPID. Use distinctive names (e.g. PARENT_PID) in your scripts.
Always verify cleanup with multiple checks, not just one.


End of Day 3 walkthrough.
