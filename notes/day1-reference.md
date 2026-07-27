# Day 1 — Baseline Audit (Reference Card)

## The one-line summary

*Before you can spot what's wrong on a Linux system, you have to know what normal looks like.*

## The 3 things you check

### 1. Users — "Who has access?"

The account list lives in `/etc/passwd`. The password hashes live in `/etc/shadow`.

- **Real login shells only** — filter out service accounts
- **UID 0 = root** — the name is cosmetic; anyone with UID 0 has root power
- **Empty passwords = instant compromise** — should never happen

Key commands:

```bash
# real users (login shells)
grep -vE '/(nologin|false|sync|halt|shutdown)$' /etc/passwd

# UID 0 check (should only return root)
awk -F: '$3 == 0 {print $1}' /etc/passwd

# empty password check (should be silent)
sudo awk -F: '($2 == "") {print $1}' /etc/shadow
```

### 2. SUID binaries — "What has dangerous power?"

A SUID file runs with the **owner's** privileges, not the runner's. If root owns a SUID file, anyone who executes it briefly becomes root — no password needed.

- Legitimate uses exist: `passwd`, `sudo`, `mount`
- Attackers plant SUID root binaries as backdoors
- ~17–18 SUID files is normal on Ubuntu Desktop; establish your baseline

Key command:

```bash
sudo find / -type f -perm -4000 -not -path "/snap/*" 2>/dev/null
```

**Red flag:** SUID files in `/tmp/`, `/home/`, or unfamiliar paths.

### 3. Login history — "Who's been here?"

Three tools, three questions:

| Command | Answers |
|---|---|
| `last -w` | Who logged in successfully? |
| `sudo lastb -w` | Who tried and failed? |
| `lastlog` | When did each user last log in? |

Always use `-w` — otherwise usernames truncate at 8 characters and create false alarms.

## The Day 1 mental model

Three questions, three sections, one goal:

> **Establish a known-good baseline you can compare against next week.**

## The lessons that stick

- **Silence is data.** Empty output on `/etc/shadow` empty-password check = good news.
- **UID 0 is the definition of root.** Usernames are lies.
- **SUID ≠ sudo.** SUID is automatic file-level power. Sudo is asked-for user-level power.
- **`last -w` prevents fake "tempadmi" ghost accounts** caused by username truncation.

## The one command sequence to remember

If someone dropped you on a Linux box and said "audit it," you'd run these 5, in this order:

```bash
grep -vE '/(nologin|false|sync|halt|shutdown)$' /etc/passwd
awk -F: '$3 == 0 {print $1}' /etc/passwd
sudo awk -F: '($2 == "") {print $1}' /etc/shadow
sudo find / -type f -perm -4000 -not -path "/snap/*" 2>/dev/null
last -w
```

That's Day 1. Everything else you'll figure out from `man` pages or context.

## Verified baseline (17 Jul 2026, cloudsec-lab)

- 2 accounts with login shells: root + ibraahiimtech
- Only root has UID 0
- No empty password fields
- 18 SUID binaries — all in standard system paths, all package-owned
- Recent login history consistent with declared analyst activity
