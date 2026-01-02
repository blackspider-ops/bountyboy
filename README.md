# 🎯 BountyBoy

**The Ultimate Bug Bounty Automation Toolkit**

Automate your recon. Find bugs faster. Get paid.

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║   ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗                      ║
║   ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝                      ║
║   ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝                       ║
║   ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝                        ║
║   ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║                         ║
║   ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝                         ║
║                                                                               ║
║   ██████╗  ██████╗ ██╗   ██╗                                                  ║
║   ██╔══██╗██╔═══██╗╚██╗ ██╔╝                                                  ║
║   ██████╔╝██║   ██║ ╚████╔╝                                                   ║
║   ██╔══██╗██║   ██║  ╚██╔╝                                                    ║
║   ██████╔╝╚██████╔╝   ██║                                                     ║
║   ╚═════╝  ╚═════╝    ╚═╝                                                     ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

## ⚠️ Disclaimer

**This tool is for authorized security testing only.** See [DISCLAIMER.md](DISCLAIMER.md) for full details.

Only use on:
- Bug bounty programs where you're authorized
- Your own systems
- Systems where you have written permission

---

## 🚀 Features

BountyBoy runs 25+ security modules in parallel, automating hours of manual recon into minutes.

### 📡 Reconnaissance
| Module | Description |
|--------|-------------|
| Subdomain Discovery | Subfinder, Assetfinder, Amass, crt.sh (parallel) |
| Port Scanning | httpx alive check + nmap + nuclei |
| Visual Recon | Screenshots + tech stack detection |
| Wayback Machine | Historical URLs, parameters, endpoints |
| Shodan Recon | Service enumeration, CVE detection |
| Email Harvesting | Find employee emails for social engineering scope |
| Cloud Enumeration | S3, Azure Blob, GCP bucket discovery |

### 🔍 Vulnerability Scanning
| Module | Description | Severity |
|--------|-------------|----------|
| **SSRF Scanner** | Cloud metadata, internal network access | 🔴 Critical |
| **IDOR Scanner** | Broken access control, ID manipulation | 🔴 Critical |
| **JWT Analyzer** | None algorithm, weak secrets, token manipulation | 🔴 Critical |
| SQLi Scanner | Error-based SQL injection detection | 🔴 Critical |
| XSS Scanner | Reflected XSS with DOM analysis | 🟠 High |
| Subdomain Takeover | Dangling DNS, unclaimed services | 🟠 High |
| CORS Checker | Misconfigured cross-origin policies | 🟠 High |
| Open Redirect | URL redirect vulnerabilities | 🟡 Medium |
| SSL/TLS Analyzer | Weak ciphers, expired certs, misconfigs | 🟡 Medium |
| Security Headers | Missing CSP, HSTS, X-Frame-Options | 🟡 Medium |

### 🛠️ Analysis Tools
| Module | Description |
|--------|-------------|
| JavaScript Analyzer | Secrets, API keys, endpoints in JS files |
| Path Fuzzer | Admin panels, backup files, sensitive paths |
| API Fuzzer | REST/GraphQL endpoint discovery, Swagger docs |
| Parameter Miner | Hidden parameters, reflection testing |
| Favicon Hash | Technology identification via Shodan |
| Google Dorking | Generate Google dorks for target |
| GitHub Dorking | Find leaked secrets in repos |
| DNS Analyzer | Zone transfer, DNSSEC, SPF/DMARC |

---

## 📦 Installation

### Prerequisites
- macOS or Linux
- Python 3.9+
- Go 1.19+ (for some tools)

### Quick Setup

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/bountyboy.git
cd bountyboy

# Run setup script (installs everything)
chmod +x setup.sh
./setup.sh

# Activate virtual environment
source venv/bin/activate

# Copy and configure
cp config.example.yaml config.yaml
# Edit config.yaml with your API keys (optional but recommended)
```

### Manual Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/assetfinder@latest

# Add Go bin to PATH
export PATH=$PATH:~/go/bin
```

---

## 🎮 Usage

### Scan Modes

```bash
# Quick scan - Subdomain discovery only (~30 seconds)
python ultimate.py -t example.com --quick

# Standard scan - Discovery + scanning + analysis (~10 minutes)
python ultimate.py -t example.com --standard

# Full scan - Everything including vuln checks (~20 minutes)
python ultimate.py -t example.com --full

# Insane mode - Absolutely everything (~30+ minutes)
python ultimate.py -t example.com --insane
```

### Options

```bash
python ultimate.py -t TARGET [OPTIONS]

Options:
  -t, --target    Target domain (required)
  --quick         Subdomain discovery only
  --standard      Discovery + scanning + analysis
  --full          + vulnerability checks
  --insane        + cloud enum + email harvest + everything
  --learn         Enable learning mode (explains each step)
  --notify        Send Discord/Slack notifications
  --report        Generate HTML/Markdown reports
  -c, --config    Config file (default: config.yaml)
```

### Examples

```bash
# Learn mode - great for beginners
python ultimate.py -t example.com --standard --learn

# Full scan with notifications and reports
python ultimate.py -t example.com --full --notify --report

# Quick recon on multiple targets
for target in target1.com target2.com; do
  python ultimate.py -t $target --quick
done
```

---

## ⚙️ Configuration

Edit `config.yaml` to customize:

```yaml
# API Keys (optional but recommended)
shodan:
  api_key: "your_shodan_key"

hunter:
  api_key: "your_hunter_key"

# Notifications
notifications:
  discord_webhook: "https://discord.com/api/webhooks/..."
  slack_webhook: "https://hooks.slack.com/..."

# Module settings
subdomain_discovery:
  tools:
    subfinder: true
    amass: false  # Slow but thorough
    assetfinder: true
    crtsh: true
```

---

## 📊 Output

Results are saved to `./data/TARGET/`:

```
data/
└── example.com/
    ├── subdomains/
    │   ├── all_subdomains.txt
    │   └── new_subdomains.txt
    ├── scans/
    │   ├── alive_hosts.txt
    │   ├── nmap_results.xml
    │   ├── nuclei_findings.json
    │   ├── ssrf_critical.txt
    │   ├── idor_vulnerabilities.txt
    │   └── ...
    ├── screenshots/
    │   └── *.png
    └── reports/
        ├── report_20260102_120000.html
        ├── report_20260102_120000.md
        └── results_20260102_120000.json
```

---

## 🎬 Sample Workflow

Here's a real-world workflow for hunting on a new target:

### Step 1: Quick Recon (Get the lay of the land)

```bash
# Activate environment
source venv/bin/activate

# Quick subdomain discovery
python ultimate.py -t target.com --quick

# Check output
cat data/target.com/subdomains/all_subdomains.txt
```

**Output:**
```
[+] Running Subfinder...
[+] Running Assetfinder...
[+] Running crt.sh...
[✓] Found 247 unique subdomains
[✓] 12 NEW subdomains detected!
```

### Step 2: Standard Scan (Find attack surface)

```bash
# Run standard scan with learning mode
python ultimate.py -t target.com --standard --learn
```

**What happens:**
1. Checks which subdomains are alive (httpx)
2. Scans ports on alive hosts (nmap)
3. Runs nuclei for known vulns
4. Analyzes JavaScript files for secrets
5. Pulls Wayback Machine URLs
6. Fuzzes for hidden paths

### Step 3: Full Vulnerability Scan

```bash
# Full scan with reports
python ultimate.py -t target.com --full --report
```

**What happens (in addition to standard):**
1. Subdomain takeover checks
2. CORS misconfiguration testing
3. SSL/TLS analysis
4. **SSRF scanning** (cloud metadata!)
5. **JWT token analysis**
6. **IDOR/access control testing**
7. SQLi & XSS quick checks
8. API endpoint fuzzing

### Step 4: Review Findings

```bash
# Check for critical findings
cat data/target.com/scans/ssrf_critical.txt
cat data/target.com/scans/idor_vulnerabilities.txt
cat data/target.com/scans/jwt_test_tokens.txt

# Open HTML report
open data/target.com/reports/report_*.html
```

### Step 5: Manual Verification

**⚠️ IMPORTANT:** Always verify findings manually before reporting!

```bash
# Example: Test a potential IDOR
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "https://api.target.com/users/123"  # Your ID

curl -H "Authorization: Bearer YOUR_TOKEN" \
  "https://api.target.com/users/124"  # Someone else's ID

# If you get different user data = IDOR confirmed!
```

### Sample Output

```
══════════════════════════════════════════════════════════════════════
  SCAN COMPLETE - FINAL SUMMARY
══════════════════════════════════════════════════════════════════════

📊 Results
┌──────────────────┬───────┬────────┐
│ Category         │ Count │ Status │
├──────────────────┼───────┼────────┤
│ Subdomains       │   247 │   ✓    │
│ NEW Subdomains   │    12 │   ✓    │
│ Alive Hosts      │    89 │   ✓    │
│ Nuclei Findings  │     3 │   🚨   │
│ JS Secrets       │     7 │   🚨   │
│ SSRF Vulns       │     1 │   🚨   │
│ IDOR Vulns       │     2 │   🚨   │
│ JWT Weak Secrets │     1 │   🚨   │
│ XSS Vulns        │     4 │   🚨   │
│ Open Redirects   │     2 │   🚨   │
└──────────────────┴───────┴────────┘

⚠️ Action Required
┌─────────────────────────────────────────────────────────────────┐
│ 🚨 20 FINDINGS REQUIRE MANUAL VERIFICATION                      │
│                                                                 │
│ Review the output files and verify before reporting.            │
└─────────────────────────────────────────────────────────────────┘

Completed in 847.3 seconds
```

---

## 🔄 Continuous Monitoring

Set up a cron job to monitor for new subdomains:

```bash
# Edit crontab
crontab -e

# Add this line (runs daily at 2 AM)
0 2 * * * cd /path/to/bountyboy && source venv/bin/activate && python ultimate.py -t target.com --quick --notify
```

You'll get Discord/Slack notifications when new subdomains appear!

---

## 🏆 Bug Bounty Tips

1. **Start with `--quick`** to get subdomains fast
2. **Use `--learn`** to understand what each module does
3. **Focus on new subdomains** - they're often untested
4. **Check SSRF, IDOR, JWT first** - highest payouts
5. **Verify findings manually** before reporting
6. **Read program rules** - stay in scope

### High-Value Targets
- Staging/dev environments
- API endpoints
- Admin panels
- File upload functionality
- Authentication flows

---

## 📚 What Each Module Does

Use `--learn` flag to get explanations during scans. Here's a quick reference:

### Reconnaissance Modules

| Module | What It Does | Why It Matters |
|--------|--------------|----------------|
| **Subfinder** | Queries DNS databases, APIs for subdomains | Fast, reliable subdomain enumeration |
| **Assetfinder** | Finds domains from various sources | Catches subdomains others miss |
| **crt.sh** | Searches Certificate Transparency logs | Finds subdomains from SSL certs |
| **httpx** | Checks if hosts are alive, gets status codes | No point scanning dead hosts |
| **nmap** | Port scanning, service detection | Find open services to attack |
| **nuclei** | Runs vulnerability templates | Automated CVE/misconfig detection |

### Vulnerability Modules

| Module | What It Does | Typical Bounty |
|--------|--------------|----------------|
| **SSRF Scanner** | Tests for server-side request forgery | $5,000 - $25,000 |
| **IDOR Scanner** | Tests for broken access control | $500 - $10,000 |
| **JWT Analyzer** | Tests JWT token security | $1,000 - $15,000 |
| **SQLi Scanner** | Tests for SQL injection | $1,000 - $20,000 |
| **XSS Scanner** | Tests for cross-site scripting | $100 - $5,000 |
| **Subdomain Takeover** | Finds unclaimed subdomains | $200 - $2,000 |
| **CORS Checker** | Tests cross-origin policies | $200 - $3,000 |
| **Open Redirect** | Tests URL redirect vulns | $100 - $1,000 |

### Analysis Modules

| Module | What It Does | What To Look For |
|--------|--------------|------------------|
| **JS Analyzer** | Extracts secrets from JavaScript | API keys, tokens, endpoints |
| **Wayback** | Gets historical URLs | Old endpoints, parameters |
| **Path Fuzzer** | Finds hidden paths | Admin panels, backups |
| **API Fuzzer** | Discovers API endpoints | Swagger docs, GraphQL |
| **Param Miner** | Finds hidden parameters | Reflected params for XSS/SQLi |
| **Favicon Hash** | Identifies tech by favicon | Know what you're attacking |

---

## 🧪 Local Vulnerable Lab

Practice your skills safely with our Docker-based vulnerable lab. Test BountyBoy against intentionally vulnerable applications before going after real targets.

### Quick Start

```bash
# Start the lab (requires Docker)
cd lab
docker-compose up -d

# Wait ~30 seconds for containers to initialize
```

### Available Targets

| Application | URL | Description |
|-------------|-----|-------------|
| **DVWA** | http://localhost:8080 | Damn Vulnerable Web App - SQLi, XSS, Command Injection, LFI |
| **Juice Shop** | http://localhost:3000 | OWASP Juice Shop - Modern web app vulnerabilities |

### Testing DVWA

DVWA has 4 security levels: Low, Medium, High, Impossible. Test your bypass techniques!

```bash
# 1. Setup DVWA (first time only)
#    Go to http://localhost:8080/setup.php
#    Click "Create / Reset Database"

# 2. Login: admin / password

# 3. Run the DVWA tester
source venv/bin/activate
python test_dvwa.py

# 4. Enter your PHPSESSID cookie (from browser DevTools)
# 5. Choose security level (1-4)
```

**Sample Output (High Security):**
```
═══ Testing SQL Injection ═══
○ Basic SQLi                    # Blocked
🚨 Comment bypass SQLi          # Bypassed!

═══ Testing Command Injection ═══
○ Semicolon injection           # Blocked  
🚨 Newline injection            # Bypassed!

═══ Testing Local File Inclusion ═══
○ Basic LFI                     # Blocked
🚨 File protocol                # Bypassed!
```

### Testing Juice Shop

```bash
# Run full scan against Juice Shop
source venv/bin/activate
python test_lab.py

# Or use ultimate.py
python ultimate.py -t localhost:3000 --standard
```

### What You'll Find

| Target | Vulnerability Types |
|--------|---------------------|
| **DVWA** | SQLi, XSS, Command Injection, LFI, CSRF, File Upload, Brute Force |
| **Juice Shop** | SQLi, XSS, IDOR, JWT flaws, XXE, SSRF, Broken Auth, and 100+ challenges |

### Stop the Lab

```bash
cd lab
docker-compose down
```

### Why Use the Lab?

1. **Safe Practice** - No legal issues, it's your own system
2. **Test Bypasses** - Try different security levels
3. **Validate Tools** - Confirm BountyBoy detects real vulns
4. **Learn Techniques** - Understand how vulnerabilities work
5. **Develop Payloads** - Build your payload library

---

## 🤝 Contributing

PRs welcome! Areas to contribute:
- New vulnerability modules
- Bug fixes
- Documentation
- Nuclei templates

---

## 📜 License

MIT License - see [LICENSE](LICENSE)

---

## 🙏 Credits

Built with:
- [ProjectDiscovery](https://projectdiscovery.io/) tools (subfinder, httpx, nuclei)
- [tomnomnom](https://github.com/tomnomnom) tools (assetfinder)
- Python async magic

---

**Happy Hunting! 🎯💰**
