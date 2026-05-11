
  Linux SOC Lab

   Overview
This repository documents my Linux security investigation labs as part of my SOC and Cloud Security training.

   Skills Practiced
- Linux filesystem navigation
- User and group investigation
- File permissions
- sudo log analysis
- Failed SSH login investigation
- Active session investigation
- Bash commands

   Labs

| Lab | Topic |
|---|---|
| Day 1 | Linux basics |
| Day 2 | Users, groups, permissions |
| Day 3 | Log analysis |
| Day 4 | DNS and tcpdump |
| Day 5 | Network troubleshooting |
| Day 6 | SOC investigation practice |

   Commands Used

```bash
whoami
id
pwd
ls -la
cat /etc/passwd
sudo grep "sudo" /var/log/auth.log
sudo grep "Failed password" /var/log/auth.log
who
last
