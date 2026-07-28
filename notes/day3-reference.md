# Day 3 — Process Inspection: Catching Attackers in the Act

**Lab:** cloudsec-lab (Ubuntu 24.04.1) · **User:** ibraahiimtech
**Focus:** Live-memory forensics — finding processes that shouldn't be running,
including malware deleted from disk but still alive in RAM.

## The three-day arc

- Day 1: Who is supposed to be here? (users, SUID files)
- Day 2: What's set up to run automatically? (cron, systemd, .bashrc)
- Day 3: What's running RIGHT NOW that shouldn't be? (live processes)

Days 1-2 examine the disk (static config). Day 3 examines memory (what's
executing). This catches attackers the first two can't — most notably fileless
malware: a binary deleted from disk while its process keeps running. Disk scans
(incl. most antivirus) miss it entirely.

## The forensic superpower: /proc/PID/

Every running process has a directory at /proc/<PID>/ exposing its true identity,
regardless of what it named itself or whether its file still exists.

- /proc/PID/exe      -> symlink to the REAL binary (truth, even if the name lies)
- /proc/PID/cmdline  -> full launch command line (null-separated)
- /proc/PID/cwd      -> working directory (often the attacker's staging area)
- /proc/PID/status   -> parent PID (PPid:), UID, memory

/proc/PID/exe is the crown jewel. A process calling itself kworker-helper is
exposed the moment exe points at /tmp/. When the binary is deleted, the symlink
reads "-> /path (deleted)" — the strongest fileless-malware signal on Linux.

## The three attackers (why no single command catches all)

| Attacker | Simulates | Caught by | Invisible to |
|---|---|---|---|
| /tmp/.kworker-helper (99% CPU loop) | Cryptominer | CPU hunt | — |
| nc -lvnp 4444 | Reverse-shell listener | Port enum | CPU hunt |
| /tmp/.update-daemon (deleted sleep) | Fileless malware | /proc deleted-binary | CPU hunt, port enum |

Thesis: each attacker is invisible to the techniques that catch the others.
Process forensics is a sweep of independent checks, never one command.

## The 7 hunting techniques

### 1. High-CPU hunting (catches the miner)
    ps aux --sort=-%cpu | head -10
A miner hides its name, never its CPU. The tell is the GAP — one process at 99%
while everything else is <2%. (Your own ps command briefly shows at the top too —
mentally skip your own tools.)

### 2. Listening-port enumeration (catches the listener)
    sudo ss -tunap | grep LISTEN
-t TCP -u UDP -n numeric -a all -p process. Red flags: high port like 4444
(Metasploit fingerprint), bound to 0.0.0.0 (all interfaces), owned by a
non-service process like nc. Legit listeners are named daemons (sshd, cupsd,
systemd-resolve), usually on 127.0.0.1 if local-only.

### 3. Processes from suspicious locations
    sudo ls -la /proc/*/exe 2>/dev/null | grep -E "/tmp/|/var/tmp/|/dev/shm/"
Nothing legitimate runs from world-writable dirs. Location alone = suspicious.

### 4. Deleted binaries — HIGH PRIORITY (catches the ghost)
    sudo ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"
(deleted) = process alive, file gone. Deliberate anti-forensics — the only reason
to delete a running binary is to hide from disk scans. P1 in production; escalate
immediately. The kernel still holds the code in RAM, so the binary can even be
recovered from /proc/PID/exe for analysis.

### 5. Process family tree
    pstree -p | head -30
Lineage tells the story. sshd -> bash -> wget -> bash = remote login -> shell ->
download -> second shell. Anomalous parent-child relationships expose attacks that
look fine in isolation.

### 6. The 6-block deep dive on a suspect PID
    SUSPECT_PID=<pid>
    sudo cat /proc/$SUSPECT_PID/cmdline | tr '\0' ' '; echo   # 1. command
    sudo ls -la /proc/$SUSPECT_PID/exe                        # 2. binary (watch for deleted)
    sudo ls -la /proc/$SUSPECT_PID/cwd                        # 3. working dir
    sudo lsof -p $SUSPECT_PID -i 2>/dev/null                  # 4. network connections
    PARENT_PID=$(awk '/^PPid:/ {print $2}' /proc/$SUSPECT_PID/status)  # 5. parent
    echo "Parent PID: $PARENT_PID"
    sudo cat /proc/$PARENT_PID/cmdline | tr '\0' ' '; echo
TRAP: never name the parent variable PPID — it's a reserved bash variable (the
shell's own parent) and is read-only. Using it silently returns the wrong process.
Use a distinctive name like PARENT_PID.

### 7. Timeline correlation
    ps -eo pid,lstart,cmd | grep -E "\.kworker-helper|nc -lvnp|\.update-daemon" | grep -v grep
Individual suspects are findings; suspects clustered in time are an incident.
Bracket the window, then pivot to everything else in it (auth logs, file changes,
network). Time is the connective tissue.
Pattern lesson: keep grep patterns specific. Matching bare "kworker" drowns your
plant in dozens of real [kworker/...] kernel threads — use \.kworker-helper.

## Cleanup discipline
    pkill -f kworker-helper
    pkill -f "nc -lvnp 4444"
    pkill -f "/tmp/.update-daemon"      # -f matches full cmdline; needed when path is an arg
    # verify three independent ways + filesystem
    ps aux | grep -E "kworker-helper|nc -lvnp 4444|update-daemon" | grep -v grep
    sudo ss -tunlp | grep 4444
    sudo ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"
    rm /tmp/.kworker-helper 2>/dev/null
    ls -la /tmp/ | grep -E "kworker|update-daemon"
Verify with the same tools you detected with. Never assume the kill worked.

## Key takeaways
1. Three attacks, three techniques — no single command catches everything.
2. /proc/PID/exe is the forensic superpower — exposes any process's real binary,
   including deleted ones.
3. Port 4444 is a Metasploit fingerprint — memorise common attacker ports.
4. (deleted) in /proc/PID/exe is the strongest fileless-malware signal — P1.
5. Bash reserves variable names (e.g. PPID) — use distinctive names in scripts.
6. False positives: broad grep patterns catch real kernel threads and substring
   matches (nc inside "launcher"). Tighten patterns; eyeball and discard.
7. Always verify cleanup with multiple checks, not one.

## Interview line earned
"I can investigate a potentially compromised Linux host using live-memory
forensics: enumerate top CPU consumers, listening ports, processes from
non-standard locations, and deleted-binary processes. For each suspect PID I run
a six-step deep dive — command, binary, working dir, network, parent, start time —
and correlate timestamps with logs. I've built and tested a detection script
catching simulated cryptominers, reverse-shell listeners, and fileless malware."

MITRE ATT&CK: T1496 (Resource Hijacking) · T1571 (Non-Standard Port) ·
T1059 (Command & Scripting Interpreter) · T1070.004 (File Deletion) ·
T1055 (Process Injection / in-memory) · T1057 (Process Discovery)
