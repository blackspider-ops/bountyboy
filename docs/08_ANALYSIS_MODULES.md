# 🔬 Analysis Modules

Deep dive into CORS Checker, Header Analyzer, SSL Analyzer, and Parameter Miner.

---

## 📄 src/cors_checker.py - CORS Misconfiguration Checker

### Overview

```python
"""
CORS Misconfiguration Checker

WHY CORS MATTERS?
CORS controls which websites can make requests to your API.
Misconfigured CORS = attacker's website can steal user data.

Example attack:
1. User visits attacker.com while logged into target.com
2. attacker.com makes request to target.com/api/user
3. If CORS is misconfigured, attacker gets user's data!
"""
```

**CORS = Cross-Origin Resource Sharing.** It's a browser security feature that prevents website A from reading data from website B. But if misconfigured, attackers can bypass it.

---

### Test Origins

```python
self.test_origins = [
    'https://evil.com',              # Random attacker domain
    'https://attacker.com',          # Another attacker domain
    'null',                          # Null origin (sandboxed iframes)
    'https://{target}.evil.com',     # Subdomain of attacker
    'https://evil{target}',          # Prefix bypass
    'https://{target}evil.com',      # Suffix bypass
]
```

**Why these specific origins?**

| Origin | Tests For |
|--------|-----------|
| `evil.com` | Basic misconfiguration - trusts any origin |
| `null` | Null origin allowed - exploitable via iframes |
| `{target}.evil.com` | Subdomain bypass - regex like `*.target.com` |
| `evil{target}` | Prefix bypass - regex like `target.com*` |
| `{target}evil.com` | Suffix bypass - regex like `*target.com` |

**Real-world bypass example:**
If server checks `if origin.endswith('target.com')`:
- `evil.com` ❌ blocked
- `attackertarget.com` ✅ bypassed!

---

### CORS Check Logic

```python
async def check_cors(self, session, url, origin):
    headers = {
        'Origin': origin,  # We send our "evil" origin
    }
    
    async with session.get(url, headers=headers, ...) as resp:
        # Check response headers
        acao = resp.headers.get('Access-Control-Allow-Origin', '')
        acac = resp.headers.get('Access-Control-Allow-Credentials', '')
        
        if not acao:
            return None  # No CORS headers = not vulnerable
```

**Key headers:**
- `Access-Control-Allow-Origin` (ACAO) - Which origins can read response
- `Access-Control-Allow-Credentials` (ACAC) - Can include cookies?

---

### Vulnerability Detection

```python
        # Check for vulnerabilities
        if acao == '*':
            vulnerability = 'Wildcard Origin'
            severity = 'LOW' if acac.lower() != 'true' else 'HIGH'
        
        elif acao == origin:
            vulnerability = 'Origin Reflection'
            severity = 'MEDIUM' if acac.lower() != 'true' else 'HIGH'
        
        elif acao == 'null':
            vulnerability = 'Null Origin Allowed'
            severity = 'MEDIUM' if acac.lower() != 'true' else 'HIGH'
```

**Vulnerability types:**

| Type | What It Means | Severity |
|------|---------------|----------|
| Wildcard (`*`) | Any website can read | LOW (no creds) / HIGH (with creds) |
| Origin Reflection | Server echoes any origin | MEDIUM / HIGH |
| Null Origin | Sandboxed iframes can read | MEDIUM / HIGH |

**Why credentials matter?**
- Without credentials: Attacker reads public data only
- With credentials: Attacker reads user's private data!

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true  ← THIS IS CRITICAL!
```

---

### Endpoints to Test

```python
endpoints = [
    '/',
    '/api',
    '/api/v1',
    '/api/user',    # User data!
    '/api/me',      # Current user!
    '/graphql',     # GraphQL often has CORS issues
]
```

**Why these endpoints?**
- `/api/user`, `/api/me` - Contain sensitive user data
- `/graphql` - Often misconfigured, can query anything
- `/api/v1` - API endpoints are the target

---

### Severity Calculation

```python
severity = 'LOW' if acac.lower() != 'true' else 'HIGH'
```

**Severity matrix:**

| ACAO | ACAC | Severity | Why |
|------|------|----------|-----|
| `*` | `false` | LOW | Can't steal user data |
| `*` | `true` | HIGH | Can steal user data! |
| Reflected | `false` | MEDIUM | Potential issue |
| Reflected | `true` | HIGH | Can steal user data! |

---

## 📄 src/header_analyzer.py - Security Headers Analyzer

### Overview

```python
"""
Security Headers Analyzer

WHY SECURITY HEADERS?
Missing headers = easier attacks:
- No CSP = easier XSS exploitation
- No X-Frame-Options = clickjacking possible
- No HSTS = downgrade attacks possible

These are usually LOW-MEDIUM severity but easy to find and report.
"""
```

**Security headers tell browsers how to behave securely.** Missing headers = browser doesn't know to protect user.

---

### Headers to Check

```python
self.security_headers = {
    'Strict-Transport-Security': {
        'description': 'HSTS - Forces HTTPS connections',
        'severity': 'MEDIUM',
        'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
    },
    'Content-Security-Policy': {
        'description': 'CSP - Prevents XSS and injection attacks',
        'severity': 'MEDIUM',
        'recommendation': 'Implement a strict CSP policy'
    },
    'X-Frame-Options': {
        'description': 'Prevents clickjacking attacks',
        'severity': 'LOW',
        'recommendation': 'Add: X-Frame-Options: DENY or SAMEORIGIN'
    },
    'X-Content-Type-Options': {
        'description': 'Prevents MIME type sniffing',
        'severity': 'LOW',
        'recommendation': 'Add: X-Content-Type-Options: nosniff'
    },
    ...
}
```

**Header importance:**

| Header | Missing = | Severity |
|--------|-----------|----------|
| HSTS | MITM attacks possible | MEDIUM |
| CSP | XSS easier to exploit | MEDIUM |
| X-Frame-Options | Clickjacking possible | LOW |
| X-Content-Type-Options | MIME sniffing attacks | LOW |

---

### Dangerous Headers

```python
self.dangerous_headers = {
    'Server': {
        'description': 'Reveals server software version',
        'severity': 'INFO',
        'recommendation': 'Remove or obfuscate Server header'
    },
    'X-Powered-By': {
        'description': 'Reveals technology stack',
        'severity': 'INFO',
        'recommendation': 'Remove X-Powered-By header'
    },
    'X-AspNet-Version': {
        'description': 'Reveals ASP.NET version',
        'severity': 'LOW',
    },
}
```

**Why dangerous?**
- `Server: Apache/2.4.29` → Attacker knows exact version → Searches for CVEs
- `X-Powered-By: PHP/7.2` → Attacker knows PHP version → Targets PHP vulns

---

### Analysis Logic

```python
async def analyze_host(self, session, host):
    async with session.get(url, ...) as resp:
        headers = resp.headers
        
        # Check for missing security headers
        for header, info in self.security_headers.items():
            if header in headers or header.lower() in [h.lower() for h in headers]:
                result['present_headers'].append({...})
                result['score'] += 1
            else:
                result['missing_headers'].append({
                    'header': header,
                    'severity': info['severity'],
                    'recommendation': info['recommendation']
                })
        
        # Check for dangerous headers
        for header, info in self.dangerous_headers.items():
            value = headers.get(header, '')
            if value:
                result['dangerous_headers'].append({
                    'header': header,
                    'value': value,  # Shows actual version!
                    ...
                })
```

**Why case-insensitive check?**
HTTP headers are case-insensitive. `Content-Type` = `content-type` = `CONTENT-TYPE`.

---

## 📄 src/ssl_analyzer.py - SSL/TLS Analyzer

### Overview

```python
"""
SSL/TLS Certificate Analyzer

WHY SSL ANALYSIS?
SSL issues are easy to find and report:
- Expired cert = immediate security issue
- Weak ciphers = potential MITM attacks
- Self-signed = trust issues

Usually LOW-MEDIUM severity but quick wins.
"""
```

---

### Weak Ciphers

```python
self.weak_ciphers = [
    'RC4',      # Broken, many attacks
    'DES',      # 56-bit key, easily cracked
    '3DES',     # Slow, vulnerable to Sweet32
    'MD5',      # Broken hash function
    'NULL',     # No encryption at all!
    'EXPORT',   # Intentionally weak (40-bit)
    'anon'      # No authentication
]
```

**Why these are weak:**

| Cipher | Problem |
|--------|---------|
| RC4 | Multiple attacks, banned by RFC 7465 |
| DES | 56-bit key cracked in hours |
| 3DES | Sweet32 attack, slow |
| MD5 | Collision attacks |
| NULL | Literally no encryption |
| EXPORT | 40-bit = cracked in seconds |
| anon | No server authentication |

---

### Certificate Analysis

```python
async def analyze_host(self, host, port=443):
    # Create SSL context that accepts anything
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Accept invalid certs
    
    with context.wrap_socket(sock, server_hostname=host) as ssock:
        cert = ssock.getpeercert(binary_form=False)
        cipher = ssock.cipher()
        version = ssock.version()
```

**Why `CERT_NONE`?**
We want to analyze ALL certificates, including:
- Expired certs
- Self-signed certs
- Invalid certs

If we verified, we couldn't analyze broken certs!

---

### Issue Detection

```python
# Check expiration
expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
days_left = (expiry - datetime.now()).days

if days_left < 0:
    result['issues'].append({
        'severity': 'HIGH',
        'issue': 'Certificate EXPIRED',
        'details': f'Expired {abs(days_left)} days ago'
    })
elif days_left < 30:
    result['issues'].append({
        'severity': 'MEDIUM',
        'issue': 'Certificate expiring soon',
        'details': f'Expires in {days_left} days'
    })
```

**Expiration severity:**
- Expired = HIGH (browsers show scary warning)
- < 30 days = MEDIUM (will expire soon)
- > 30 days = OK

```python
# Check if self-signed
subject = result['certificate'].get('subject', {})
issuer = result['certificate'].get('issuer', {})
if subject == issuer:
    result['issues'].append({
        'severity': 'MEDIUM',
        'issue': 'Self-signed certificate',
    })
```

**Why self-signed is bad:**
- Not trusted by browsers
- Users see security warning
- Could be attacker's cert

```python
# Check TLS version
if 'TLSv1.0' in version or 'TLSv1.1' in version or 'SSLv' in version:
    result['issues'].append({
        'severity': 'MEDIUM',
        'issue': 'Outdated TLS version',
        'details': f'Using {version}, should use TLS 1.2 or higher'
    })
```

**TLS version issues:**
- SSLv2/v3 = BROKEN, many attacks
- TLS 1.0 = POODLE, BEAST attacks
- TLS 1.1 = Deprecated
- TLS 1.2+ = OK

---

## 📄 src/param_miner.py - Parameter Miner

### Overview

```python
"""
Parameter Mining Module

WHY PARAMETER MINING?
Hidden parameters can lead to:
- SQL injection
- XSS
- IDOR
- Privilege escalation
- Debug modes

Developers often leave debug parameters like:
?debug=true, ?admin=1, ?test=1
"""
```

**Hidden parameters = hidden functionality.** Developers add `?debug=1` during development and forget to remove it.

---

### Common Parameters

```python
self.common_params = [
    # Debug/Test
    'debug', 'test', 'testing', 'dev', 'development', 'staging',
    'verbose', 'log', 'trace', 'profile', 'benchmark',
    
    # Admin/Auth
    'admin', 'administrator', 'root', 'superuser', 'su',
    'auth', 'authenticated', 'login', 'logged_in', 'session',
    'token', 'api_key', 'apikey', 'key', 'secret',
    'role', 'roles', 'permission', 'permissions', 'access',
    
    # User/Account
    'user', 'userid', 'user_id', 'uid', 'username',
    'account', 'accountid', 'account_id', 'aid',
    
    # File/Path
    'file', 'filename', 'path', 'filepath', 'dir', 'directory',
    'url', 'uri', 'link', 'href', 'src', 'source',
    'include', 'require', 'load', 'read', 'fetch',
    
    # Redirect/Navigation
    'redirect', 'redir', 'return', 'returnurl', 'return_url',
    'next', 'prev', 'back', 'goto', 'continue', 'destination',
    ...
]
```

**Why these categories?**

| Category | Potential Vuln |
|----------|----------------|
| Debug | Verbose errors, stack traces |
| Admin | Privilege escalation |
| User | IDOR (change user_id) |
| File | LFI/RFI (include=../../etc/passwd) |
| Redirect | Open redirect |

---

### Extracting Params from JS

```python
def extract_params_from_js(self, js_content):
    params = set()
    
    # Match URL query parameters
    url_param_pattern = r'[\?&]([a-zA-Z_][a-zA-Z0-9_]*)[=\'\"]'
    params.update(re.findall(url_param_pattern, js_content))
    
    # Match object keys that look like params
    obj_key_pattern = r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']:\s*["\']?'
    params.update(re.findall(obj_key_pattern, js_content))
    
    # Match form field names
    form_pattern = r'name=["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']'
    params.update(re.findall(form_pattern, js_content))
```

**Pattern explanations:**

| Pattern | Catches | Example |
|---------|---------|---------|
| `[\?&]param=` | URL params | `?debug=1` |
| `"param":` | Object keys | `{"admin": true}` |
| `name="param"` | Form fields | `<input name="secret">` |

---

### Reflection Testing

```python
async def check_param_reflection(self, session, url, param):
    test_value = f"PARAMTEST{param}123"  # Unique marker
    
    # Build URL with parameter
    test_url = f"{url}?{param}={test_value}"
    
    # Get baseline (without param)
    baseline_resp = await session.get(url)
    baseline_length = len(await baseline_resp.text())
    
    # Get response with param
    test_resp = await session.get(test_url)
    test_text = await test_resp.text()
    
    # Check for reflection
    if test_value in test_text:
        return {
            'param': param,
            'type': 'REFLECTED',
            'severity': 'MEDIUM',
            'note': 'Parameter value is reflected in response (potential XSS)'
        }
    
    # Check for behavior change
    length_diff = abs(len(test_text) - baseline_length)
    if length_diff > 100:
        return {
            'param': param,
            'type': 'BEHAVIOR_CHANGE',
            'note': f'Response changed by {length_diff} bytes'
        }
```

**Why test reflection?**
- Reflected param = potential XSS
- Behavior change = param is processed (might be vuln)

**Why unique marker?**
`PARAMTEST{param}123` is unlikely to appear naturally. If we see it in response, we KNOW it's our input being reflected.

---

## 🎯 Module Comparison

| Module | Finds | Severity | Speed |
|--------|-------|----------|-------|
| CORS | Cross-origin issues | MEDIUM-HIGH | Fast |
| Headers | Missing security headers | LOW-MEDIUM | Fast |
| SSL | Certificate issues | LOW-HIGH | Medium |
| Param Miner | Hidden parameters | LOW-MEDIUM | Slow |

**When to use each:**
1. **CORS** - Always check APIs, especially `/api/user`
2. **Headers** - Quick wins, easy to report
3. **SSL** - Check all HTTPS hosts
4. **Param Miner** - After finding interesting endpoints

---

## ⚠️ Important Notes

1. **CORS + Credentials = HIGH** - Always note if credentials are allowed
2. **Headers are easy wins** - Low severity but quick to find
3. **SSL issues are common** - Many sites have expired certs
4. **Param mining is slow** - Test top params on key endpoints only

