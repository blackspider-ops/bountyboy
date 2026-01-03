# 📊 Reporting & Notifications

Deep dive into Report Generator and Notifier modules.

---

## 📄 src/report_generator.py - Report Generator

### Overview

```python
"""
Report Generator Module

Generates comprehensive HTML and Markdown reports:
- Executive summary
- Detailed findings
- Severity breakdown
- Recommendations
- Evidence/screenshots

WHY REPORTS?
Good reports = faster payouts:
- Clear, professional presentation
- Easy for triagers to understand
- All evidence in one place
- Severity justification
"""
```

**Professional reports get paid faster.** Triagers review hundreds of reports. A clean, well-organized report stands out and gets processed quickly.

---

### HTML Report Structure

```python
def generate_html(self, results: dict, output_dir: str) -> str:
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Bug Bounty Report - {target}</title>
    <style>
        :root {{
            --bg-dark: #1a1a2e;
            --bg-card: #16213e;
            --accent: #0f3460;
            --highlight: #e94560;
            --text: #eee;
            --success: #00d26a;
            --warning: #ffc107;
            --danger: #dc3545;
        }}
        ...
    </style>
</head>
```

**Why dark theme?**
- Easier on the eyes for long reading sessions
- Professional, modern look
- Matches most security tools' aesthetics
- Color-coded severity stands out

---

### CSS Design Decisions

```css
.summary-card {{
    background: var(--bg-card);
    padding: 20px;
    border-radius: 10px;
    text-align: center;
    border-left: 4px solid var(--accent);
}}

.summary-card.critical {{
    border-left-color: var(--danger);  /* Red */
}}

.summary-card.high {{
    border-left-color: #ff6b6b;  /* Orange-red */
}}

.summary-card.medium {{
    border-left-color: var(--warning);  /* Yellow */
}}

.summary-card.low {{
    border-left-color: var(--info);  /* Blue */
}}
```

**Why colored borders?**
- Instant visual severity indication
- Triagers can scan quickly
- Critical findings jump out
- Consistent with industry standards

---

### Summary Grid

```python
        <div class="summary-grid">
            <div class="summary-card">
                <div class="number">{len(results.get('subdomains', []))}</div>
                <div class="label">Subdomains</div>
            </div>
            <div class="summary-card critical">
                <div class="number">{len(results.get('vulnerabilities', []))}</div>
                <div class="label">Nuclei Findings</div>
            </div>
            ...
        </div>
```

**Why summary cards?**
- Executive summary at a glance
- Numbers are big and bold
- Triagers see impact immediately
- No need to scroll for overview

---

### Finding Cards

```python
for vuln in vulns:
    severity = vuln.get('info', {}).get('severity', 'info')
    name = vuln.get('info', {}).get('name', 'Unknown')
    host = vuln.get('host', '')
    html += f"""
        <div class="finding {severity}">
            <span class="severity-badge {severity}">{severity}</span>
            <h3>{name}</h3>
            <p class="url">{host}</p>
        </div>
"""
```

**Finding card structure:**
1. Severity badge (colored pill)
2. Vulnerability name (bold heading)
3. Affected URL (clickable)

**Why this order?**
- Severity first = instant triage
- Name explains the issue
- URL shows where to verify

---

### Markdown Report

```python
def generate_markdown(self, results: dict, output_dir: str) -> str:
    md = f"""# Bug Bounty Report: {target}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Executive Summary

| Metric | Count |
|--------|-------|
| Subdomains | {len(results.get('subdomains', []))} |
| Alive Hosts | {len(results.get('alive_hosts', []))} |
| Nuclei Findings | {len(results.get('vulnerabilities', []))} |
...
```

**Why Markdown too?**
- Works in GitHub, GitLab, Jira
- Easy to copy/paste into reports
- Version control friendly
- Can be converted to PDF

---

### Report Generation Flow

```python
def generate(self, results: dict, output_dir: str) -> dict:
    html_path = self.generate_html(results, output_dir)
    md_path = self.generate_markdown(results, output_dir)
    
    return {
        'html': html_path,
        'markdown': md_path
    }
```

**Both formats generated:**
- HTML for visual review
- Markdown for documentation
- Same data, different presentations

---

## 📄 src/notifier.py - Notification Module

### Overview

```python
"""
Notification Module

Send alerts when interesting things are found:
- New subdomains discovered
- Vulnerabilities detected
- Interesting ports found

WHY NOTIFICATIONS?
Your automation runs 24/7. You can't watch it constantly.
Notifications let you know immediately when something interesting happens.
"""
```

**Real-time alerts = faster response.** New subdomain at 3am? You get pinged. Critical vuln found? Instant alert. Don't miss opportunities.

---

### Initialization

```python
class Notifier:
    def __init__(self, config: dict):
        self.config = config['notifications']
        self.enabled = self.config.get('enabled', False)
```

**Why `enabled` flag?**
- Can disable all notifications easily
- Useful for testing (no spam)
- Config-driven behavior

---

### Discord Notifications

```python
def _send_discord(self, title: str, message: str, severity: str):
    colors = {
        'critical': 0xFF0000,  # Red
        'high': 0xFF6600,      # Orange
        'medium': 0xFFFF00,    # Yellow
        'info': 0x00FF00,      # Green
        'new': 0x00FFFF        # Cyan
    }
    
    payload = {
        "embeds": [{
            "title": f"🎯 {title}",
            "description": message,
            "color": colors.get(severity, 0x00FF00)
        }]
    }
    
    resp = requests.post(
        self.config['discord_webhook'],
        json=payload,
        timeout=10
    )
```

**Why embeds?**
- Rich formatting (colors, titles)
- Stands out in Discord channel
- Can include multiple fields
- Professional appearance

**Color coding:**
| Severity | Color | Hex |
|----------|-------|-----|
| Critical | Red | `0xFF0000` |
| High | Orange | `0xFF6600` |
| Medium | Yellow | `0xFFFF00` |
| Info | Green | `0x00FF00` |
| New | Cyan | `0x00FFFF` |

---

### Slack Notifications

```python
def _send_slack(self, title: str, message: str, severity: str):
    emoji = {
        'critical': '🚨',
        'high': '⚠️',
        'medium': '📢',
        'info': 'ℹ️',
        'new': '🆕'
    }
    
    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji.get(severity, 'ℹ️')} {title}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": message
                }
            }
        ]
    }
```

**Why Block Kit?**
- Modern Slack formatting
- Headers stand out
- Markdown support
- Better than plain text

**Emoji mapping:**
| Severity | Emoji | Meaning |
|----------|-------|---------|
| Critical | 🚨 | Alarm - urgent! |
| High | ⚠️ | Warning |
| Medium | 📢 | Announcement |
| Info | ℹ️ | Information |
| New | 🆕 | New discovery |

---

### Notification Types

#### New Subdomains

```python
def notify_new_subdomains(self, target: str, subdomains: list):
    if not subdomains:
        return
    
    message = f"**Target:** {target}\n"
    message += f"**Count:** {len(subdomains)} new subdomains\n\n"
    message += "**New subdomains:**\n"
    for sub in subdomains[:10]:  # Limit to 10
        message += f"• {sub}\n"
    if len(subdomains) > 10:
        message += f"... and {len(subdomains) - 10} more"
    
    self.send("New Subdomains Found!", message, "new")
```

**Why limit to 10?**
- Discord/Slack have message limits
- Too many = notification ignored
- Shows sample, mentions total count

---

#### Vulnerability Found

```python
def notify_vulnerability(self, finding: dict):
    severity = finding.get('info', {}).get('severity', 'unknown')
    name = finding.get('info', {}).get('name', 'Unknown Vulnerability')
    host = finding.get('host', 'Unknown host')
    
    message = f"**Vulnerability:** {name}\n"
    message += f"**Severity:** {severity.upper()}\n"
    message += f"**Host:** {host}\n"
    
    if finding.get('matched-at'):
        message += f"**URL:** {finding['matched-at']}\n"
    
    self.send(f"Vulnerability Found: {name}", message, severity)
```

**Key information included:**
1. Vulnerability name
2. Severity (for prioritization)
3. Affected host
4. Exact URL (if available)

---

#### Scan Complete

```python
def notify_scan_complete(self, target: str, summary: dict):
    message = f"**Target:** {target}\n"
    message += f"**Subdomains:** {summary.get('total_subdomains', 0)}\n"
    message += f"**New subdomains:** {summary.get('new_subdomains', 0)}\n"
    message += f"**Alive hosts:** {summary.get('alive_hosts', 0)}\n"
    message += f"**Vulnerabilities:** {summary.get('vulnerabilities', 0)}\n"
    
    self.send("Scan Complete", message, "info")
```

**Why scan complete notification?**
- Know when to check results
- Summary of what was found
- Can schedule follow-up work

---

## 🔧 Configuration

### config.yaml

```yaml
notifications:
  enabled: true
  discord_webhook: "https://discord.com/api/webhooks/..."
  slack_webhook: "https://hooks.slack.com/services/..."
```

**Getting webhooks:**

**Discord:**
1. Server Settings → Integrations → Webhooks
2. New Webhook → Copy URL

**Slack:**
1. Apps → Incoming Webhooks
2. Add to Slack → Copy URL

---

## 🎯 Best Practices

### Report Writing

1. **Executive summary first** - Triagers are busy
2. **Severity badges visible** - Quick triage
3. **Evidence included** - URLs, screenshots
4. **Recommendations** - How to fix

### Notifications

1. **Don't spam** - Only important findings
2. **Include context** - Target, severity, URL
3. **Limit length** - 10 items max
4. **Color code** - Visual severity

---

## ⚠️ Important Notes

1. **Webhook URLs are secrets** - Don't commit to git!
2. **Rate limits exist** - Discord: 30/min, Slack: 1/sec
3. **Test notifications** - Verify webhooks work before long scans
4. **Reports are evidence** - Keep them for reference

