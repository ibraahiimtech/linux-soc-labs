# Day 4 — Log Analysis at Scale

**Lab:** cloudsec-lab (Ubuntu 24.04.1) · **User:** ibraahiimtech
**Focus:** Reconstructing what happened from logs — turning thousands of noisy
lines into a single ranked finding.

## The four-day arc

- Day 1: Who's supposed to be here? (users, SUID) -> /etc/passwd
- Day 2: What runs automatically? (cron, systemd)
- Day 3: What's running now? (live memory, /proc)
- Day 4: What happened? (logs)

Processes die; logs persist. When an attacker's process is long gone, logs are
often the only evidence left.

## The two logging worlds (modern Ubuntu)

1. Traditional text logs — plain files in /var/log/
   - /var/log/auth.log   — logins, sudo, SSH (security-critical)
   - /var/log/syslog     — general system messages
   - Read with grep, awk, tail, less

2. The systemd journal — a BINARY database, not a text file
   - Cannot be grep-ed directly — it's structured binary
   - Every entry has fields: _COMM, _PID, _UID, priority, timestamp
   - Read with journalctl and its filters

Use both: text logs are fast and grep-friendly; the journal is structured and
precise (filter by field, severity, time).

## The "binary file matches" fix (Day 3 loose end)

grep on auth.log sometimes returns "binary file matches" — the log has occasional
binary bytes, so grep refuses to treat it as text.

- Stay in text:   grep -a          (force grep to treat file as text)
- Switch to journal: journalctl _COMM=sudo

Habit: use grep -a on logs by default. Harmless on clean files, saves you on dirty
ones — and you can't predict which you'll get.

## journalctl essentials

    journalctl _COMM=sudo --no-pager             # all entries from the sudo command
    journalctl _COMM=sudo -p warning --no-pager  # only warning-level and above
    journalctl --since "1 hour ago" -p warning   # time + severity filter
    journalctl --since "2026-07-29 13:00" --until "2026-07-29 13:10"  # bounded window
    journalctl -u ssh --no-pager                 # everything from the ssh service

- _COMM=<name>  filter by the command that logged it
- -p warning    priority (emerg=0 ... debug=7); warning = warnings + worse
- --since/--until  time windows (the journal's superpower for timelines)
- -u <unit>     filter by systemd service
- --no-pager    print straight to terminal instead of opening less

The journal understands severity and time as structured fields — things the text
log can't slice on easily.

## The count-and-rank pipeline (the heart of "at scale")

A brute-force attack leaves thousands of near-identical lines. You can't read them;
you count and rank them.

    sudo grep -a "incorrect password attempt" /var/log/auth.log \
      | awk '{print $4}' \
      | sort \
      | uniq -c \
      | sort -rn

Stage by stage:
- grep -a "..."      find the failure lines
- awk '{print $4}'   extract the field to count (here the username)
- sort               group identical values together
- uniq -c            collapse duplicates and COUNT each
- sort -rn           sort counts reverse (highest first), numeric (10 > 9)

Result: thousands of lines -> "4823 10.0.0.5" at the top = worst attacker, instantly.
On a real SSH log, extract the IP (rhost=) instead of the user.

### CRITICAL RULE: sort MUST come before uniq -c

uniq only collapses ADJACENT duplicate lines — it compares each line to the one
directly above it, not the whole file.

    WITHOUT sort:  alice bob alice bob alice -> 1 alice / 1 bob / 1 alice ...  (WRONG)
    WITH sort:     alice alice alice bob bob -> 3 alice / 2 bob               (RIGHT)

The bug hides when data happens to be pre-grouped, then silently corrupts counts
when it isn't. Always sort first — never rely on luck.

## Finding the WHO vs the WHEN (same pipeline, different field)

WHO — count by username/IP:
    sudo grep -a "incorrect password attempt" /var/log/auth.log \
      | awk '{print $4}' | sort | uniq -c | sort -rn

WHEN — count by hour (find the attack window):
    sudo grep -a "incorrect password attempt" /var/log/auth.log \
      | awk '{print substr($1,1,13)}' | sort | uniq -c

substr($1,1,13) grabs the first 13 chars of the timestamp (2026-07-29T13) =
date+hour. A spike in one hour tells you WHEN the attack clustered.

## awk field lesson
Don't memorise field numbers — look at the line, count the whitespace-separated
fields, pick the one you want, verify the output, adjust. Every log format differs.
Example auth.log failure line:
    $1=timestamp  $2=hostname  $3=sudo:  $4=username  $5=:  $6=1  $7=incorrect ...

## Saving findings (SOC discipline)
    sudo grep -a "incorrect password attempt" /var/log/auth.log \
      | awk '{print $4}' | sort | uniq -c | sort -rn > failed-auth-summary.txt
> redirects output to a file — an investigation produces a dated artifact.

## Key takeaways
1. Two log worlds — text (grep -a) and journal (journalctl). Use both.
2. grep -a by default on logs — immune to the "binary file matches" trap.
3. The journal filters on structured fields — _COMM, -p severity, --since time.
4. Count-and-rank is the workhorse — flood of lines -> one ranked finding.
5. sort before uniq -c, always — or counts are silently wrong.
6. Same pipeline finds WHO and WHEN — change the extracted field.
7. Tight, evenly-spaced, incrementing timestamps/PIDs = automated attack signature.

MITRE ATT&CK: T1110 (Brute Force) · T1078 (Valid Accounts) ·
T1070.002 (Clear Linux Logs) · T1562.008 (Impair Defenses: Disable Cloud Logs)
