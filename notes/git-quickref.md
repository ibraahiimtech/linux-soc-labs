# Git Quick Reference Card

## 1. Git initialisation — turning a folder into a git repo

**What it does:** Creates a hidden `.git/` subfolder in your current directory. That folder is what makes git "see" the folder as a repository.

**When to use it:** When you have files locally that you want to start tracking, but no GitHub repo yet — or you created a GitHub repo and want to push existing local work up.

**Commands:**
\`\`\`bash
cd ~/my-project
git init
git add .
git commit -m "Initial commit"
\`\`\`

**Key rule:** Git only works inside a folder that has `.git/` (or whose parent has it). Run `ls -la` and look for `.git/` to confirm.

---

## 2. Repo cloning — downloading a GitHub repo to your machine

**What it does:** Copies a GitHub repo down to your local machine, including its full history and the `.git/` folder. The cloned folder is automatically connected to GitHub — no extra setup needed.

**When to use it:** When the repo already exists on GitHub and you want a local copy to work on.

**Commands:**
\`\`\`bash
cd ~
git clone https://github.com/username/repo-name.git
cd repo-name
\`\`\`

**Key rule:** Clone is for existing GitHub repos. Init is for new local work. Don't run `git init` inside a cloned repo — it already has `.git/`.

---

## 3. Author identity config — who's making the commits

**What it does:** Tells git what name and email to stamp on every commit you make. GitHub uses the email to attribute commits to your profile.

**When to use it:** Once per machine, before your first commit ever.

**Commands:**
\`\`\`bash
git config --global user.name "Your Name"
git config --global user.email "your-github-email@example.com"
git config --global --list | grep user
\`\`\`

**Key rules:**
- Use the email tied to your GitHub account, or your GitHub noreply email
- `--global` = applies to every repo on this machine
- Without `--global` = only applies to the current repo

---

## 4. Personal Access Token (PAT) auth — pushing to GitHub from the CLI

**What it does:** Replaces password authentication for git operations over HTTPS.

**Steps to create:**
1. GitHub → profile → Settings → Developer settings
2. Personal access tokens → Tokens (classic) → Generate new token (classic)
3. Name it, set expiration (90 days), tick `repo` scope only
4. Copy the token immediately — shown only once

**Cache it:**
\`\`\`bash
git config --global credential.helper store
git push
\`\`\`

**Security rules:**
- Treat the token like a password — never share, never commit
- Always set an expiration date
- Tick only the scopes you need
- Rotate or revoke from GitHub if compromised

---

## The 5-command daily workflow

\`\`\`bash
cd ~/my-repo
git pull
git status
git add .
git commit -m "message"
git push
\`\`\`

---

## Troubleshooting cheat sheet

| Error | Likely cause | Fix |
|---|---|---|
| `not a git repository` | You're not inside a repo folder | `cd` into the repo or clone first |
| `Author identity unknown` | No name/email set | Run the two `git config` commands |
| `Authentication failed` | Using password instead of PAT | Generate and use a PAT |
| `Updates were rejected` | Remote has commits you don't | `git pull` first, then push |
| `nothing to commit` | No staged changes | Use `git add` before `git commit` |
