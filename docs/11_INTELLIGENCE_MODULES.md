# 🕵️ Intelligence Gathering Modules

Deep dive into Cloud Enumeration, Email Harvesting, Shodan Recon, GitHub Dorking, and Favicon Hashing.

---

## 📄 src/cloud_enum.py - Cloud Storage Enumeration

### Overview

```python
"""
Cloud Storage Enumeration Module

Finds exposed cloud storage buckets and blobs:
- AWS S3 buckets
- Azure Blob Storage
- Google Cloud Storage
- DigitalOcean Spaces

WHY CLOUD ENUMERATION?
Companies often misconfigure cloud storage:
- Public buckets with sensitive data
- Backup files exposed
- Database dumps
- Source code
- Customer data
"""
```

**Public cloud buckets = data breaches.** Companies misconfigure S3 buckets all the time. One public bucket with customer data = CRITICAL severity.

---

### Bucket Name Generation

```python
self.patterns = [
    '{target}',
    '{target}-backup',
    '{target}-backups',
    '{target}-data',
    '{target}-files',
    '{target}-assets',
    '{target}-static',
    '{target}-uploads',
    '{target}-dev',
    '{target}-staging',
    '{target}-prod',
    '{target}-logs',
    '{target}-db',
    '{target}-private',
    'backup-{target}',
    '{keyword}-{target}',
]

self.keywords = ['backup', 'data', 'dev', 'prod', 'staging', 'test', 'logs', 'db']
```

**Why these patterns?**
- Companies use predictable naming: `companyname-backup`, `companyname-prod`
- Developers are lazy: `dev`, `test`, `staging` are common
- Backups are gold: `backup`, `db`, `logs`

---

### S3 Bucket Checking

```python
async def check_s3_bucket(self, session, bucket):
    urls = [
        f"https://{bucket}.s3.amazonaws.com",      # Virtual-hosted style
        f"https://s3.amazonaws.com/{bucket}",       # Path style
    ]
    
    for url in urls:
        async with session.get(url, ...) as resp:
            if resp.status == 200:
                return {'status': 'PUBLIC', 'severity': 'HIGH'}
            elif resp.status == 403:
                return {'status': 'EXISTS (Access Denied)', 'severity': 'INFO'}
            elif resp.status == 404:
                text = await resp.text()
                if 'NoSuchBucket' not in text:
                    return {'status': 'EXISTS (Empty)', 'severity': 'LOW'}
```

**Status meanings:**
| Status | Meaning | Severity |
|--------|---------|----------|
| 200 | Public! Anyone can read | HIGH |
| 403 | Exists but private | INFO |
| 404 + NoSuchBucket | Doesn't exist | - |
| 404 + other | Exists but empty | LOW |

---

### Multi-Provider Support

```python
# AWS S3
await self.check_s3_bucket(session, name)

# Azure Blob
url = f"https://{container}.blob.core.windows.net/?comp=list"

# Google Cloud Storage
url = f"https://storage.googleapis.com/{bucket}"

# DigitalOcean Spaces
regions = ['nyc3', 'sfo2', 'sfo3', 'ams3', 'sgp1', 'fra1']
url = f"https://{space}.{region}.digitaloceanspaces.com"
```

**Why all providers?**
- Companies use multiple clouds
- Each has different URL patterns
- One might be misconfigured

---

## 📄 src/email_harvester.py - Email Harvester

### Overview

```python
"""
Email Harvester Module

Finds email addresses associated with a target:
- Employee emails for phishing scope
- Contact emails
- Email patterns (first.last@, f.last@, etc.)

Sources:
- Hunter.io API
- Website scraping
- Google dorking
"""
```

**Emails reveal organization structure.** Finding the email pattern lets you guess any employee's email.

---

### Hunter.io Integration

```python
async def search_hunter(self, session, domain):
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={self.hunter_api_key}"
    
    async with session.get(url, ...) as resp:
        data = await resp.json()
        for email_data in data.get('data', {}).get('emails', []):
            emails.append({
                'email': email_data.get('value'),
                'type': email_data.get('type'),
                'confidence': email_data.get('confidence'),
                'first_name': email_data.get('first_name'),
                'last_name': email_data.get('last_name'),
                'position': email_data.get('position'),
            })
```

**Hunter.io provides:**
- Verified emails
- Names and positions
- Confidence scores
- Email patterns

---

### Email Pattern Detection

```python
def detect_email_pattern(self, emails, domain):
    patterns = {
        'first.last': 0,    # john.doe@
        'f.last': 0,        # j.doe@
        'first_last': 0,    # john_doe@
        'firstlast': 0,     # johndoe@
        'flast': 0,         # jdoe@
        'lastf': 0,         # doej@
    }
    
    for email_data in emails:
        local = email.split('@')[0].lower()
        first = email_data.get('first_name', '').lower()
        last = email_data.get('last_name', '').lower()
        
        if local == f"{first}.{last}":
            patterns['first.last'] += 1
        elif local == f"{first[0]}.{last}":
            patterns['f.last'] += 1
        # ... etc
```

**Why detect patterns?**
- Know pattern = guess any email
- `first.last@company.com` → `ceo.name@company.com`
- Useful for social engineering scope

---

## 📄 src/shodan_recon.py - Shodan Reconnaissance

### Overview

```python
"""
Shodan Reconnaissance Module

Queries Shodan for exposed services and vulnerabilities:
- Open ports and services
- Known vulnerabilities (CVEs)
- SSL certificate info
- Technology detection
- Exposed databases, admin panels

WHY SHODAN?
Shodan scans the entire internet and indexes everything.
Instead of scanning yourself (slow, might get blocked),
query Shodan's database for instant results.
"""
```

**Shodan = Google for hackers.** It indexes every internet-connected device. Query instead of scan.

---

### Shodan Dorks

```python
def generate_dorks(self, target):
    return [
        f'hostname:"{target}"',                    # All hosts
        f'ssl.cert.subject.cn:"{target}"',         # SSL certs
        f'org:"{target}"',                         # Organization
        f'hostname:"{target}" port:22',            # SSH
        f'hostname:"{target}" "MongoDB"',          # MongoDB
        f'hostname:"{target}" "Elasticsearch"',    # Elasticsearch
        f'hostname:"{target}" vuln:',              # Known CVEs
        f'hostname:"{target}" http.title:"Admin"', # Admin panels
    ]
```

**Dork meanings:**
| Dork | Finds |
|------|-------|
| `hostname:` | All hosts for domain |
| `ssl.cert.subject.cn:` | SSL certificates |
| `port:22` | SSH servers |
| `"MongoDB"` | MongoDB instances |
| `vuln:` | Hosts with known CVEs |
| `http.title:"Admin"` | Admin panels |

---

### Vulnerability Extraction

```python
for host in results['hosts']:
    vulns = host.get('vulns', [])
    if vulns:
        for vuln in vulns:
            results['vulnerabilities'].append({
                'ip': host.get('ip_str'),
                'port': host.get('port'),
                'cve': vuln
            })
```

**Shodan tracks CVEs!** If a service has known vulnerabilities, Shodan tells you. Instant CVE list.

---

## 📄 src/github_dorker.py - GitHub Dorking

### Overview

```python
"""
GitHub Dorking Module

Searches GitHub for leaked secrets related to a target:
- API keys accidentally committed
- Passwords in config files
- Internal URLs and endpoints
- AWS credentials
- Database connection strings

WHY GITHUB DORKING?
Developers make mistakes. They commit .env files, hardcode API keys,
push config files with passwords. GitHub indexes everything.
"""
```

**GitHub = treasure trove of secrets.** Developers commit credentials by accident. Search for them.

---

### Dork Categories

```python
self.dorks = {
    'passwords': [
        '"{target}" password',
        '"{target}" secret',
        '"{target}" credentials',
    ],
    'api_keys': [
        '"{target}" api_key',
        '"{target}" access_token',
    ],
    'aws': [
        '"{target}" AWS_ACCESS_KEY_ID',
        '"{target}" AWS_SECRET_ACCESS_KEY',
    ],
    'config_files': [
        '"{target}" filename:.env',
        '"{target}" filename:config.php',
        '"{target}" filename:settings.py',
    ],
    'private_keys': [
        '"{target}" BEGIN RSA PRIVATE KEY',
        '"{target}" BEGIN OPENSSH PRIVATE KEY',
    ],
}
```

**What each category finds:**
| Category | Finds | Severity |
|----------|-------|----------|
| passwords | Hardcoded passwords | CRITICAL |
| api_keys | API keys in code | CRITICAL |
| aws | AWS credentials | CRITICAL |
| config_files | .env, config.php | HIGH |
| private_keys | SSH/PGP keys | CRITICAL |

---

## 📄 src/favicon_hash.py - Favicon Hash Lookup

### Overview

```python
"""
Favicon Hash Lookup Module

Identifies technologies by favicon hash:
- Calculate favicon hash (MMH3)
- Search Shodan for matching hashes
- Identify frameworks, products, services

WHY FAVICON HASHING?
Every web application has a favicon. Default favicons reveal:
- What software is running (Jenkins, Grafana, etc.)
- Framework versions
- Hidden admin panels
"""
```

**Favicons are fingerprints.** Default Jenkins favicon = Jenkins server. Default Grafana favicon = Grafana dashboard.

---

### Known Hashes Database

```python
self.known_hashes = {
    # Development/CI
    '-1293291467': ('Jenkins', 'Jenkins CI/CD Server'),
    '-1090637934': ('Grafana', 'Grafana Dashboard'),
    '-1073467418': ('Kibana', 'Kibana Dashboard'),
    
    # Databases/Admin
    '-1840324437': ('phpMyAdmin', 'phpMyAdmin Database Admin'),
    '-1193933858': ('MongoDB', 'MongoDB'),
    '-1023673190': ('Elasticsearch', 'Elasticsearch'),
    
    # Web Servers
    '-1137684790': ('Apache', 'Apache Default'),
    '116323821': ('Nginx', 'Nginx Default'),
    '-380651196': ('Tomcat', 'Apache Tomcat'),
}
```

**Why these products?**
- Jenkins = CI/CD, often has secrets
- Grafana/Kibana = dashboards with data
- phpMyAdmin = database access
- Default pages = misconfiguration

---

### Hash Calculation

```python
def mmh3_hash(self, data: bytes) -> int:
    import mmh3
    return mmh3.hash(codecs.encode(base64.b64encode(data), 'utf-8'))
```

**Why MMH3?**
- MurmurHash3 is what Shodan uses
- Same hash = same favicon
- Can search Shodan: `http.favicon.hash:-1293291467`

---

### Shodan Query Generation

```python
result['shodan_query'] = f"http.favicon.hash:{result['hash']}"
result['shodan_url'] = f"https://www.shodan.io/search?query={result['shodan_query']}"
```

**Why generate Shodan queries?**
- Find ALL instances of same technology
- Unknown hash? Search Shodan to identify
- Find other targets running same software

---

## 🎯 Module Comparison

| Module | Finds | API Required | Speed |
|--------|-------|--------------|-------|
| Cloud Enum | Public buckets | No | Medium |
| Email Harvest | Employee emails | Hunter.io (optional) | Fast |
| Shodan Recon | Services, CVEs | Shodan (optional) | Fast |
| GitHub Dorking | Leaked secrets | No | Manual |
| Favicon Hash | Technologies | No | Fast |

**When to use each:**
1. **Cloud Enum** - Always, public buckets are common
2. **Email Harvest** - If social engineering in scope
3. **Shodan** - Always, instant service enumeration
4. **GitHub Dorking** - Always, secrets are everywhere
5. **Favicon Hash** - To identify unknown services

---

## ⚠️ Important Notes

1. **API keys enhance results** - Shodan and Hunter.io free tiers available
2. **GitHub rate limits** - Use generated URLs manually
3. **Cloud buckets are sensitive** - Don't download data, just report
4. **Emails are PII** - Handle responsibly

