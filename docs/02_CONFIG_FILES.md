# ⚙️ Configuration Files

Deep dive into configuration structure and options.

---

## 📄 config.example.yaml - Complete Breakdown

### Targets Section

```yaml
targets:
  - example.com
  # - another-target.com
```

**What it does:** Defines which domains to scan.

**Design decisions:**
- **List format** - Can scan multiple targets in one config
- **Commented examples** - Shows users how to add more
- **Domain only** - No protocol (http/https), we check both

---

### Notifications Section

```yaml
notifications:
  enabled: true
  discord_webhook: ""
  slack_webhook: ""
```

**What it does:** Configures real-time alerts.

**Why Discord/Slack webhooks?**
1. **Instant alerts** - Know immediately when vuln found
2. **No server needed** - Webhooks are push-based
3. **Free** - Both services offer free webhooks
4. **Mobile** - Get alerts on phone

**How webhooks work:**
```
Your Script → HTTP POST → Discord/Slack Server → Your Channel
```

**Why not email?**
- Email requires SMTP server setup
- Often goes to spam
- Slower delivery
- More complex configuration

```yaml
email:
  enabled: false
  smtp_server: ""
  smtp_port: 587
```
- **Port 587** - Standard SMTP submission port with TLS
- **Why disabled by default?** Most users prefer Discord/Slack

---

### Subdomain Discovery Section

```yaml
subdomain_discovery:
  tools:
    subfinder: true
    amass: false
    assetfinder: true
    crtsh: true
  timeout: 120
```

**Tool selection rationale:**

| Tool | Speed | Coverage | Default |
|------|-------|----------|---------|
| subfinder | Fast (30s) | Good | ✅ ON |
| assetfinder | Fast (20s) | Medium | ✅ ON |
| crt.sh | Fast (10s) | SSL certs only | ✅ ON |
| amass | Slow (10-30min) | Excellent | ❌ OFF |

**Why multiple tools?**
- Each tool uses different data sources
- Combined results = better coverage
- Example: subfinder might find `api.example.com`, assetfinder finds `dev.example.com`

**Why amass disabled?**
```yaml
amass: false  # Disabled by default - slow but thorough
```
- Amass does active DNS brute-forcing
- Takes 10-30 minutes per target
- For quick recon, it's overkill
- Enable for important targets where you need EVERY subdomain

**Timeout setting:**
```yaml
timeout: 120  # 2 minutes per tool
```
- Prevents hanging on slow networks
- 120 seconds is enough for most tools
- Increase for slow connections

---

### Scanning Section

```yaml
scanning:
  httpx_alive_check: true
```

**Why alive check first?**
- Subdomain might exist in DNS but server is down
- No point scanning dead hosts
- Saves 90% of scan time on large targets

```yaml
nmap:
  quick_scan_ports: "1000"
```
- **Top 1000 ports** covers 99% of common services
- Full scan (65535 ports) takes 10-15 min per host
- Quick scan takes 30 seconds

```yaml
interesting_ports:
  - 8080   # Tomcat, dev servers
  - 8443   # HTTPS alternate
  - 9000   # PHP-FPM, SonarQube
  - 3000   # Node.js, React
  - 5000   # Flask
  - 8000   # Django, Python HTTP
```

**Why these specific ports?**
- **8080**: Most common alternate HTTP port. Tomcat default. Often has admin panels.
- **8443**: HTTPS on non-standard port. Sometimes less secured.
- **9000**: PHP-FPM (can be exploited), SonarQube (code analysis)
- **3000**: Node.js apps, React dev servers (often debug mode)
- **5000**: Flask default (often debug mode enabled)
- **8000**: Django dev server, Python SimpleHTTPServer

**Logic:** If we find these ports, the host is "interesting" and worth a deeper scan.

```yaml
rate_limit: 1000
```
- Packets per second for nmap
- **Why 1000?** Fast but not aggressive enough to trigger IDS
- Lower for stealth, higher for speed

---

### Nuclei Section

```yaml
nuclei:
  enabled: true
  severity:
    - critical
    - high
    - medium
  tags:
    - cve
    - exposure
    - misconfig
```

**Severity levels explained:**

| Severity | What it means | Example |
|----------|---------------|---------|
| critical | RCE, auth bypass | Log4j, Spring4Shell |
| high | Data exposure, SQLi | Exposed .git, SQLi |
| medium | Info disclosure | Version disclosure |
| low | Minor issues | Missing headers |
| info | Informational | Tech detection |

**Why exclude low/info?**
- Generate hundreds of findings
- Most are not actionable
- Noise drowns out real issues

**Tags explained:**
- `cve` - Known CVEs (Log4j, etc.)
- `exposure` - Exposed files (.git, .env, backups)
- `misconfig` - Misconfigurations (default creds, debug mode)

---

### Visual Recon Section

```yaml
visual_recon:
  screenshots: true
  tech_detection: true
  timeout: 30
```

**Why screenshots?**
- Quick visual overview of all hosts
- Spot login pages, admin panels
- Identify similar-looking hosts (same template)

**Why tech detection?**
- Know what you're attacking
- WordPress? Look for WP vulns
- React? Look for client-side issues

**Timeout 30s:**
- Some pages load slowly
- Don't wait forever
- 30s is reasonable for most pages

---

### JavaScript Analysis Section

```yaml
js_analysis:
  enabled: true
  max_files_per_host: 20
  max_hosts: 50
```

**Why analyze JavaScript?**
- JS files often contain:
  - API endpoints
  - API keys (accidentally committed)
  - Internal URLs
  - Debug code
  - Comments with sensitive info

**Why limits?**
- Large sites have 100s of JS files
- Analyzing all takes forever
- 20 files per host catches main app code
- 50 hosts max prevents runaway scans

---

### Wayback Section

```yaml
wayback:
  enabled: true
  max_urls: 10000
```

**Why Wayback Machine?**
- Historical snapshots of websites
- Find:
  - Old endpoints that still work
  - Removed but not deleted files
  - Old parameters
  - Debug pages

**Why 10000 limit?**
- Large sites have millions of archived URLs
- 10000 is enough to find interesting stuff
- More takes too long to process

---

### Fuzzing Section

```yaml
fuzzing:
  enabled: true
  categories:
    - critical
    - admin
    - api
    - backup
  max_hosts: 30
  concurrency: 20
```

**Categories explained:**

| Category | What it finds | Examples |
|----------|---------------|----------|
| critical | Sensitive files | .git, .env, .htaccess |
| admin | Admin panels | /admin, /wp-admin, /manager |
| api | API endpoints | /api, /graphql, /swagger |
| backup | Backup files | .bak, .old, .zip |
| dev | Dev files | /debug, /test, /phpinfo |
| files | Common files | robots.txt, sitemap.xml |

**Why not all categories?**
- Full fuzzing = 1000s of requests per host
- Takes too long
- Focus on high-value paths

**Concurrency 20:**
- 20 simultaneous requests per host
- Fast but not aggressive
- Higher = faster but might trigger WAF

---

### Monitoring Section

```yaml
monitoring:
  interval_hours: 24
  history_days: 30
```

**Why 24 hours?**
- Daily scans catch new subdomains quickly
- Not so frequent that it's annoying
- Balance between coverage and resources

**Why 30 days history?**
- Track changes over time
- See when subdomains appeared/disappeared
- Identify patterns

---

### Output Section

```yaml
output:
  data_dir: "./data"
  html_reports: true
```

**Directory structure created:**
```
data/
└── targets/
    └── example_com/
        ├── subdomains/
        │   ├── current.txt
        │   └── history/
        ├── scans/
        ├── screenshots/
        └── reports/
```

**Why this structure?**
- Organized by target
- Easy to find results
- History preserved
- Reports separate from raw data
