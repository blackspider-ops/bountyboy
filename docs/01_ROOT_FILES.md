# 📁 Root Directory Files

This document explains every file in the root `bountyboy/` directory.

---

## 📄 setup.sh - Installation Script

**Purpose:** One-command setup for macOS. Installs all dependencies.

```bash
#!/bin/bash
# Bug Bounty Automation - macOS Setup Script
# Run this once to set up everything

set -e  # Exit immediately if any command fails
        # WHY: We don't want partial installs - either everything works or nothing
```

### Line-by-Line Breakdown:

```bash
# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
```
- `command -v brew` checks if `brew` command exists
- `&> /dev/null` redirects both stdout and stderr to null (silent check)
- `!` negates - so "if brew NOT found"
- **WHY Homebrew?** It's the standard macOS package manager. Makes installing Go, nmap easy.

```bash
# Install Go
if ! command -v go &> /dev/null; then
    brew install go
```
- **WHY Go?** Most modern security tools (subfinder, httpx, nuclei) are written in Go
- They're fast, single-binary, no dependencies

```bash
# Setup Go PATH
GOPATH=$(go env GOPATH)
if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
    echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.zshrc
```
- Go installs binaries to `~/go/bin/`
- We need this in PATH so we can run `subfinder`, `httpx`, etc.
- **WHY ~/.zshrc?** macOS uses zsh by default since Catalina
- The pattern `*":$GOPATH/bin:"*` checks if already in PATH (avoid duplicates)

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null
```
- `go install` downloads, compiles, and installs the tool
- `-v` verbose output
- `@latest` gets the newest version
- `2>/dev/null` hides error messages (cleaner output)
- **WHY these specific tools?**
  - `subfinder` - Fast subdomain enumeration, uses many sources
  - `httpx` - Fast HTTP probing, checks if hosts are alive
  - `nuclei` - Vulnerability scanner with templates
  - `assetfinder` - Another subdomain tool (different sources)
  - `amass` - Most thorough subdomain tool (but slow)

```bash
python3 -m venv venv
```
- Creates isolated Python environment
- **WHY venv?** 
  - Keeps dependencies separate from system Python
  - Reproducible environment
  - Easy cleanup (just delete venv folder)

```bash
pip install -r requirements.txt > /dev/null
```
- Installs Python packages listed in requirements.txt
- `> /dev/null` hides verbose pip output

---

## 📄 requirements.txt - Python Dependencies

**Purpose:** Lists all Python packages needed.

```
requests>=2.28.0
```
- HTTP library for making web requests
- **WHY requests?** Industry standard, simple API, handles cookies/sessions
- `>=2.28.0` means "version 2.28.0 or higher"

```
pyyaml>=6.0
```
- YAML parser for config files
- **WHY YAML over JSON?** 
  - Supports comments (JSON doesn't)
  - More readable for config files
  - Easier to edit by hand

```
python-nmap>=0.7.1
```
- Python wrapper for nmap
- **WHY?** Lets us call nmap from Python and parse results

```
rich>=13.0.0
```
- Beautiful terminal output (colors, tables, progress bars)
- **WHY rich?** 
  - Makes output readable
  - Professional looking
  - Easy to use

```
click>=8.1.0
```
- Command-line argument parsing
- **WHY click over argparse?**
  - Cleaner syntax with decorators
  - Better help text generation
  - Easier to add subcommands

```
schedule>=1.2.0
```
- Job scheduling for monitoring mode
- **WHY?** Run scans automatically every X hours

```
python-dotenv>=1.0.0
```
- Load environment variables from .env file
- **WHY?** Keep secrets out of config files

```
aiohttp>=3.8.0
```
- Async HTTP client
- **WHY aiohttp over requests?**
  - Async = can make 100s of requests simultaneously
  - 10-100x faster for scanning many hosts
  - requests is synchronous (one at a time)

```
dnspython>=2.4.0
```
- DNS queries from Python
- **WHY?** DNS analysis, zone transfers, record enumeration

```
mmh3>=4.0.0
```
- MurmurHash3 implementation
- **WHY?** Favicon hashing for technology identification

---

## 📄 .gitignore - Git Ignore Rules

**Purpose:** Tells Git which files NOT to track.

```gitignore
# Virtual Environment
venv/
```
- **WHY ignore?** 
  - venv is 100+ MB
  - Can be recreated with `pip install -r requirements.txt`
  - Different on each machine

```gitignore
# Scan Results & Data (contains sensitive target info)
data/
logs/
```
- **WHY ignore?**
  - Contains target-specific data
  - Could expose what you're scanning
  - Different for each user

```gitignore
# Config with secrets
config.yaml
.env
```
- **WHY ignore?**
  - Contains API keys (Shodan, etc.)
  - Contains webhook URLs
  - NEVER commit secrets to Git

```gitignore
# Keep example config
!config.example.yaml
```
- `!` means "DON'T ignore this"
- **WHY?** Example config should be in repo so users know the format

---

## 📄 config.example.yaml - Configuration Template

**Purpose:** Template for user configuration. Copy to `config.yaml` and customize.

```yaml
targets:
  - example.com
```
- List of domains to scan
- **WHY list?** Can monitor multiple targets

```yaml
notifications:
  discord_webhook: ""
  slack_webhook: ""
```
- **WHY Discord/Slack?**
  - Real-time alerts when vulns found
  - Most bug bounty hunters use these
  - Easy to set up (just paste webhook URL)

```yaml
subdomain_discovery:
  tools:
    subfinder: true
    amass: false  # Disabled by default - slow
```
- **WHY amass disabled?**
  - Amass is VERY thorough but takes 10-30 minutes
  - For quick scans, subfinder + assetfinder is enough
  - Enable for deep recon on important targets

```yaml
scanning:
  nmap:
    interesting_ports:
      - 8080
      - 8443
      - 9000
```
- **WHY these ports?**
  - 8080: Common for dev servers, Tomcat
  - 8443: HTTPS on non-standard port
  - 9000: PHP-FPM, SonarQube
  - 3000: Node.js, React dev server
  - 5000: Flask default
  - If found, we do deeper scan on that host

```yaml
nuclei:
  severity:
    - critical
    - high
    - medium
```
- **WHY not low/info?**
  - Low/info generate too much noise
  - Focus on actionable findings
  - Can enable for thorough scans

---

## 📄 DISCLAIMER.md - Legal Protection

**Purpose:** Legal disclaimer to protect you.

**WHY needed?**
- Security tools can be misused
- Makes clear this is for authorized testing only
- Standard practice for security tools
- Protects against liability

---

## 📄 LICENSE - MIT License

**Purpose:** Defines how others can use the code.

**WHY MIT?**
- Most permissive open source license
- Anyone can use, modify, distribute
- Only requirement: include the license
- Standard for security tools

---

## 📄 README.md - Project Documentation

**Purpose:** First thing users see on GitHub.

**Key sections:**
- Features list (what it does)
- Installation instructions
- Usage examples
- Module documentation

**WHY detailed README?**
- Users need to know how to use it
- Shows professionalism
- Helps with GitHub discoverability
