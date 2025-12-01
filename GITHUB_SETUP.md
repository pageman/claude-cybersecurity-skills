# How to Push to GitHub

Follow these steps to upload this project to github.com/pageman

## Step 1: Create Repository on GitHub

1. Go to https://github.com/new
2. Repository name: `claude-cybersecurity-skills`
3. Description: "Comprehensive cybersecurity skills collection for Claude Code"
4. Set to **Public** (or Private if you prefer)
5. **Do NOT** initialize with README, .gitignore, or license (we already have these)
6. Click "Create repository"

## Step 2: Configure Git (if not already done)

```bash
# Set your name and email (if not already configured)
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

## Step 3: Add and Commit Files

```bash
# Navigate to project directory
cd /Users/paulamerigojr.iipajo/claude-scientific-test/claude-cybersecurity-skills

# Stage all files
git add .

# Commit with descriptive message
git commit -m "Initial commit: Claude Cybersecurity Skills prototype

- Authorization framework with scope validation
- Subdomain enumeration skill
- Nmap scanning integration
- CVE lookup via NVD API
- Sigma rule creation
- Example workflows and documentation"
```

## Step 4: Link to GitHub Repository

Replace `pageman` with your actual GitHub username:

```bash
# Add GitHub as remote origin
git remote add origin https://github.com/pageman/claude-cybersecurity-skills.git

# Verify remote was added
git remote -v
```

## Step 5: Push to GitHub

```bash
# Push to main branch
git branch -M main
git push -u origin main
```

## Step 6: Verify Upload

Visit: https://github.com/pageman/claude-cybersecurity-skills

You should see all files uploaded!

## Optional: Add Repository Topics

On GitHub, add these topics to make the repo discoverable:
- `cybersecurity`
- `claude-code`
- `security-tools`
- `penetration-testing`
- `threat-detection`
- `sigma-rules`
- `claude-ai`
- `security-automation`

## Optional: Add License

If you want to make this open source:

1. On GitHub, click "Add file" → "Create new file"
2. Name it `LICENSE`
3. GitHub will offer license templates - MIT is recommended for maximum adoption
4. Commit the license

Then pull it locally:
```bash
git pull origin main
```

## Troubleshooting

### Authentication Issues

If you get authentication errors, you may need to:

1. **Use Personal Access Token** (recommended):
   - Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
   - Generate new token with `repo` scope
   - Use token as password when pushing

2. **Or use SSH**:
   ```bash
   # Generate SSH key (if you don't have one)
   ssh-keygen -t ed25519 -C "your.email@example.com"

   # Add to ssh-agent
   eval "$(ssh-agent -s)"
   ssh-add ~/.ssh/id_ed25519

   # Copy public key and add to GitHub
   cat ~/.ssh/id_ed25519.pub

   # Change remote to SSH
   git remote set-url origin git@github.com:pageman/claude-cybersecurity-skills.git
   ```

### Push Rejected

If push is rejected:
```bash
# Pull first, then push
git pull origin main --rebase
git push -u origin main
```

## Next Steps After Upload

1. **Edit README on GitHub** to add badges:
   ```markdown
   # Claude Cybersecurity Skills

   [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
   [![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
   ```

2. **Enable GitHub Issues** for community feedback

3. **Add GitHub Actions** for automated testing (future)

4. **Create releases** as you add more skills

5. **Share on social media** and security forums
