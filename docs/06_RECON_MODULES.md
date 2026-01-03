# 🔍 Reconnaissance Modules

Deep dive into Wayback Machine, JavaScript Analysis, Visual Recon, and Path Fuzzing.

---

## 📄 src/wayback.py - Wayback Machine Analyzer

### Overview

```python
"""
Wayback Machine Module

Queries the Wayback Machine (web.archive.org) to find:
- Old URLs that might still work
- Forgotten endpoints
- Historical parameters
- Removed but still accessible pages

WHY WAYBACK?
Companies remove pages but forget to actually delete them from the server.
The Wayback Machine remembers everything. Old admin panels, old API versions,
debug endpoints that were "removed" - they might still be there.
"""
```

**The Wayback Machine archives the ENTIRE web.** Every page, every version. If a company had a `/debug` endpoint in 2019 and "removed" it, Wayback remembers. And often, the endpoint still works - they just removed the link.

---

### Class Initialization

```python
class WaybackAnalyzer:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        self.cdx_api = "https://web.archive.org/cdx/search/cdx"
```

**Line-by-line:**
- `self.cdx_api` - The CDX API is Wayback's search interface. It returns structured data about archived URLs, not the actual pages.

**Why CDX API instead of browsing Wayback?**
- Returns JSON/CSV data we can parse
- Can search with wildcards (`*.example.com/*`)
- Much faster than scraping the web interface
- Can filter by status code, date, etc.

---

### Fetching Historical URLs

```python
async def fetch_wayback_urls(self, session: aiohttp.ClientSession, 
                              domain: str, limit: int = 10000) -> list:
    params = {
        'url': f'*.{domain}/*',      # Wildcard: all subdomains, all paths
        'output': 'json',             # Return JSON format
        'fl': 'original,timestamp,statuscode,mimetype',  # Fields to return
        'filter': 'statuscode:200',   # Only successful responses
        'collapse': 'urlkey',         # Deduplicate similar URLs
        'limit': limit                # Max results
    }
```

**Parameter breakdown:**

| Parameter | Value | Why |
|-----------|-------|-----|
| `url` | `*.example.com/*` | Wildcard matches ALL subdomains and paths |
| `output` | `json` | Easy to parse programmatically |
| `fl` | `original,timestamp,...` | Only get fields we need (faster) |
| `filter` | `statuscode:200` | Skip 404s, errors - we want pages that existed |
| `collapse` | `urlkey` | Dedupe URLs that differ only by query params |
| `limit` | `10000` | Don't overwhelm with millions of results |

**Why `collapse=urlkey`?**
Without it, you'd get:
```
/page?id=1
/page?id=2
/page?id=3
... (thousands of times)
```
With collapse, you get one `/page` entry. We extract parameters separately.

---

### Extracting Parameters

```python
def extract_parameters(self, urls: list) -> dict:
    params_by_path = defaultdict(set)
    
    for url_data in urls:
        url = url_data[0] if isinstance(url_data, list) else url_data
        parsed = urlparse(url)
        
        if parsed.query:
            params = parse_qs(parsed.query)
            path = parsed.path
            for param in params.keys():
                params_by_path[path].add(param)
    
    return {path: list(params) for path, params in params_by_path.items()}
```

**Why extract parameters?**
Historical parameters reveal hidden functionality:
- `/search?q=` - obvious
- `/search?debug=1` - not obvious, might still work!
- `/api/users?include_deleted=true` - hidden feature

**Output example:**
```python
{
    '/search': ['q', 'page', 'debug', 'format'],
    '/api/users': ['id', 'include_deleted', 'admin'],
    '/export': ['format', 'all', 'secret_key']  # Jackpot!
}
```

---

### URL Categorization

```python
def categorize_urls(self, urls: list) -> dict:
    categories = {
        'admin': [],      # Admin panels
        'api': [],        # API endpoints
        'backup': [],     # Backup files
        'config': [],     # Config files
        'debug': [],      # Debug endpoints
        'upload': [],     # Upload functionality
        'auth': [],       # Authentication
        'interesting': [], # URLs with parameters
        'all': []
    }
    
    patterns = {
        'admin': ['admin', 'dashboard', 'manage', 'control', 'panel'],
        'api': ['api', '/v1/', '/v2/', '/v3/', 'graphql', 'rest'],
        'backup': ['backup', '.bak', '.old', '.save', 'copy'],
        'config': ['config', 'settings', 'setup', '.env', '.ini', '.conf'],
        'debug': ['debug', 'test', 'dev', 'staging', 'sandbox'],
        ...
    }
```

**Why categorize?**
10,000 URLs is overwhelming. Categorization lets you focus:
1. Check `backup` first - might have credentials
2. Check `debug` - might have verbose errors
3. Check `admin` - might have weak auth
4. Check `api` - might have undocumented endpoints

**Priority order for bug hunting:**
1. `config` - credentials, API keys
2. `backup` - old code with vulns
3. `debug` - verbose errors, stack traces
4. `admin` - auth bypass potential
5. `api` - hidden endpoints

---

### Checking If URLs Are Still Alive

```python
async def check_url_alive(self, session: aiohttp.ClientSession, url: str) -> bool:
    try:
        async with session.head(url, timeout=aiohttp.ClientTimeout(total=5),
                                ssl=False, allow_redirects=True) as resp:
            return resp.status == 200
    except:
        return False
```

**Why HEAD request?**
- Faster than GET (no body downloaded)
- Just checks if URL exists
- Less suspicious in logs

**Why `ssl=False`?**
- Many old URLs have expired/invalid certs
- We just want to know if it's alive
- Security doesn't matter for this check

---

### Main Analysis Flow

```python
async def analyze_domain(self, domain: str, output_dir: str) -> dict:
    # 1. Fetch all historical URLs
    urls = await self.fetch_wayback_urls(session, domain)
    
    # 2. Categorize them
    results['categories'] = self.categorize_urls(urls)
    
    # 3. Extract parameters
    results['parameters'] = self.extract_parameters(urls)
    
    # 4. Check if interesting URLs are still alive
    interesting_urls = (
        results['categories'].get('admin', [])[:10] +
        results['categories'].get('backup', [])[:10] +
        results['categories'].get('config', [])[:10] +
        results['categories'].get('debug', [])[:10]
    )
    
    # 5. Parallel alive check with semaphore
    semaphore = asyncio.Semaphore(20)
    async def check_with_limit(url):
        async with semaphore:
            if await self.check_url_alive(session, url):
                return url
            return None
```

**Why semaphore of 20?**
- Don't overwhelm target with 1000 simultaneous requests
- 20 concurrent requests is aggressive but not abusive
- Balances speed vs. not getting blocked

---

## 📄 src/js_analyzer.py - JavaScript Analyzer

### Overview

```python
"""
JavaScript File Analyzer

Extracts and analyzes JavaScript files from targets to find:
- API endpoints (fetch calls, axios, XMLHttpRequest)
- Hardcoded secrets (API keys, tokens, passwords)
- Hidden functionality
- Internal URLs and paths

WHY JS ANALYSIS?
Modern web apps are JavaScript heavy. The JS files contain:
- API routes the app uses (some might be undocumented)
- Sometimes hardcoded credentials (devs make mistakes)
- Business logic that reveals how the app works
- Internal endpoints not meant to be public
"""
```

**JS files are GOLD.** Developers bundle everything into JS - including things they shouldn't. API keys, internal URLs, debug flags. This module extracts it all.

---

### Pattern Definitions

```python
self.patterns = {
    'api_endpoints': [
        r'["\']/(api|v1|v2|v3)/[^"\']+["\']',           # "/api/users"
        r'fetch\s*\(\s*["\'][^"\']+["\']',               # fetch("/api/data")
        r'axios\.(get|post|put|delete|patch)\s*\(\s*["\'][^"\']+["\']',  # axios.get("/api")
        r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\'][^"\']+["\']',  # $.ajax({url: "/api"})
        r'XMLHttpRequest[^;]*open\s*\([^,]+,\s*["\'][^"\']+["\']',  # xhr.open("GET", "/api")
    ],
```

**Why these specific patterns?**

| Pattern | Catches | Example |
|---------|---------|---------|
| `/api/...` | Direct API paths | `"/api/v1/users"` |
| `fetch(...)` | Modern JS fetch API | `fetch("/api/data")` |
| `axios.*` | Popular HTTP library | `axios.get("/secret")` |
| `$.ajax` | jQuery AJAX calls | `$.ajax({url: "/admin"})` |
| `XMLHttpRequest` | Legacy XHR | `xhr.open("GET", "/api")` |

```python
    'secrets': [
        r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][^"\']{10,}["\']',
        r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\'][^"\']{10,}["\']',
        r'["\']?access[_-]?token["\']?\s*[:=]\s*["\'][^"\']{10,}["\']',
        r'Bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',  # JWT
        r'["\']?aws[_-]?access["\']?\s*[:=]\s*["\'][A-Z0-9]{16,}["\']',
    ],
```

**Secret patterns explained:**

| Pattern | Catches | Why 10+ chars? |
|---------|---------|----------------|
| `api_key` | API keys | Short values are likely placeholders |
| `secret_key` | Secret keys | `"secret_key": "changeme"` = false positive |
| `access_token` | OAuth tokens | Real tokens are long |
| `Bearer ...` | JWT tokens | JWTs have specific format |
| `aws_access` | AWS keys | AWS keys are 16+ chars |

```python
    'cloud_urls': [
        r's3\.amazonaws\.com/[a-zA-Z0-9\-]+',
        r'[a-zA-Z0-9\-]+\.s3\.amazonaws\.com',
        r'storage\.googleapis\.com/[a-zA-Z0-9\-]+',
        r'[a-zA-Z0-9\-]+\.blob\.core\.windows\.net',
    ]
```

**Why cloud URLs matter:**
- S3 buckets might be public
- GCS buckets might have sensitive data
- Azure blobs might be misconfigured
- Finding these = potential data exposure

---

### Extracting JS URLs from Pages

```python
async def extract_js_urls(self, session: aiohttp.ClientSession, url: str) -> list:
    content = await self.fetch_page(session, url)
    js_urls = []
    
    # Find script tags
    script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
    for match in re.finditer(script_pattern, content, re.IGNORECASE):
        src = match.group(1)
        if src.endswith('.js') or '.js?' in src:
            full_url = urljoin(url, src)
            js_urls.append(full_url)
    
    # Find ES6 imports
    import_pattern = r'import\s+.*from\s+["\']([^"\']+\.js)["\']'
    for match in re.finditer(import_pattern, content):
        src = match.group(1)
        full_url = urljoin(url, src)
        js_urls.append(full_url)
```

**Two extraction methods:**

1. **Script tags:** `<script src="app.js">` - traditional
2. **ES6 imports:** `import x from './module.js'` - modern

**Why `urljoin`?**
JS sources can be:
- Absolute: `https://cdn.example.com/app.js`
- Relative: `./js/app.js`
- Protocol-relative: `//cdn.example.com/app.js`

`urljoin` handles all cases correctly.

---

### Analyzing JS Content

```python
def analyze_js_content(self, content: str, source_url: str) -> dict:
    findings = {
        'source': source_url,
        'api_endpoints': [],
        'secrets': [],
        'urls': [],
        'sensitive_paths': [],
        'cloud_urls': []
    }
    
    for category, patterns in self.patterns.items():
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                value = match.group(0)
                if value not in findings[category]:
                    findings[category].append(value)
    
    return findings
```

**Why deduplicate?**
Same API endpoint might appear 100 times in minified JS. We only need it once.

**Why `re.IGNORECASE`?**
- `API_KEY` and `api_key` should both match
- `Fetch` and `fetch` should both match
- Developers are inconsistent

---

### Parallel Host Analysis

```python
async def analyze_async(self, hosts: list, output_dir: str) -> dict:
    # Limit concurrency to avoid overwhelming targets
    semaphore = asyncio.Semaphore(10)
    
    async def analyze_with_limit(host):
        async with semaphore:
            return await self.analyze_host(host)
    
    tasks = [analyze_with_limit(host) for host in hosts]
    results = await asyncio.gather(*tasks, return_exceptions=True)
```

**Why semaphore of 10?**
- JS analysis is heavier than simple requests
- Each host might have 20+ JS files
- 10 hosts × 20 files = 200 concurrent requests max
- Prevents overwhelming targets

---

## 📄 src/visual_recon.py - Visual Reconnaissance

### Overview

```python
"""
Visual Recon Module

Screenshots and tech stack identification:
- EyeWitness - Screenshots all web servers
- Tech detection - Identify frameworks, CMS, etc.

WHY VISUAL RECON?
Port scan tells you "port 443 is open". Screenshot tells you "it's an admin panel".
Tech detection tells you "it's running WordPress 5.2". Now you know exactly
what to attack and how.
"""
```

**Visual recon is underrated.** You can browse 500 subdomains in 5 minutes by looking at screenshots. Your eyes catch things automated tools miss.

---

### Screenshot Taking

```python
def take_screenshots(self, hosts: list, output_dir: str) -> str:
    # Write URLs to file
    input_file = Path(output_dir) / "screenshot_targets.txt"
    with open(input_file, 'w') as f:
        for host in hosts:
            f.write(f"https://{host}\n")
            f.write(f"http://{host}\n")  # Try both protocols
    
    success_flag, output = run_tool(
        ["eyewitness", "-f", str(input_file), "-d", str(report_dir), 
         "--no-prompt", "--timeout", str(self.recon_config['timeout'])],
        timeout=len(hosts) * self.recon_config['timeout'] + 60
    )
```

**Why both HTTP and HTTPS?**
- Some servers only respond on HTTP
- Some only on HTTPS
- Some redirect HTTP→HTTPS
- Capture all possibilities

**Why EyeWitness?**
- Generates HTML report with thumbnails
- Categorizes by response type
- Detects default pages, login forms
- Industry standard tool

---

### Tech Stack Detection

```python
def _detect_single_host(self, host: str) -> list:
    technologies = []
    
    # Check headers
    if 'Server' in headers:
        server = headers['Server']
        technologies.append(f"Server: {server}")
        if 'nginx' in server.lower():
            technologies.append("nginx")
        elif 'apache' in server.lower():
            technologies.append("Apache")
    
    if 'X-Powered-By' in headers:
        powered = headers['X-Powered-By']
        if 'php' in powered.lower():
            technologies.append("PHP")
        elif 'express' in powered.lower():
            technologies.append("Express.js")
```

**Headers reveal tech:**

| Header | Reveals |
|--------|---------|
| `Server: nginx/1.18` | Web server + version |
| `X-Powered-By: PHP/7.4` | Backend language |
| `X-AspNet-Version` | ASP.NET version |

```python
    # Check response body for patterns
    body = resp.text.lower()
    
    if 'wp-content' in body or 'wordpress' in body:
        technologies.append("WordPress")
    if 'react' in body or 'reactdom' in body:
        technologies.append("React")
    if 'csrfmiddlewaretoken' in body:
        technologies.append("Django")
```

**Body patterns:**

| Pattern | Technology |
|---------|------------|
| `wp-content` | WordPress |
| `reactdom` | React |
| `csrfmiddlewaretoken` | Django |
| `_next` | Next.js |
| `ng-` | Angular |

---

### Checking Common Files

```python
def _check_common_files(self, host: str, protocol: str, technologies: list):
    checks = [
        ('/robots.txt', 'robots.txt'),
        ('/wp-login.php', 'WordPress'),
        ('/.git/config', 'Git Exposed'),      # CRITICAL!
        ('/.env', 'Env File Exposed'),         # CRITICAL!
        ('/phpinfo.php', 'PHPInfo Exposed'),   # CRITICAL!
        ('/graphql', 'GraphQL'),
    ]
    
    for path, tech in checks:
        resp = requests.get(f"{protocol}://{host}{path}", ...)
        if resp.status_code == 200:
            technologies.append(tech)
            if tech in ['Git Exposed', 'Env File Exposed', 'PHPInfo Exposed']:
                warning(f"  ⚠️  INTERESTING: {tech} found at {path}")
```

**Why these files?**

| File | Why Critical |
|------|--------------|
| `/.git/config` | Source code exposure! |
| `/.env` | Credentials, API keys! |
| `/phpinfo.php` | Server config, paths! |
| `/graphql` | API introspection! |

---

## 📄 src/fuzzer.py - Path Fuzzer

### Overview

```python
"""
Directory and Path Fuzzer

Discovers hidden paths and files on web servers:
- Admin panels (/admin, /administrator, /wp-admin)
- Backup files (.bak, .old, .backup)
- Config files (.env, config.php, web.config)
- Git repositories (.git/config)
- Development files (test.php, debug.log)

WHY FUZZING?
Robots.txt and sitemaps only show what companies WANT you to see.
Fuzzing finds what they forgot to hide.
"""
```

**Fuzzing = trying paths until something works.** Companies hide admin panels, forget to delete backups, leave debug endpoints. Fuzzing finds them.

---

### Path Categories

```python
self.paths = {
    'critical': [
        '/.git/config',        # Source code!
        '/.git/HEAD',          # Git repo exists
        '/.env',               # Credentials!
        '/.env.local',         # Local overrides
        '/.env.production',    # Prod credentials!
        '/config.php',         # PHP config
        '/wp-config.php',      # WordPress DB creds
        '/web.config',         # IIS config
        '/backup.sql',         # Database dump!
        '/dump.sql',           # Database dump!
    ],
```

**Why these are CRITICAL:**

| Path | Contains |
|------|----------|
| `/.git/config` | Git remote URLs, sometimes tokens |
| `/.env` | DB passwords, API keys, secrets |
| `/wp-config.php` | WordPress DB credentials |
| `/backup.sql` | Entire database! |

```python
    'admin': [
        '/admin',
        '/admin/',
        '/administrator',
        '/wp-admin',
        '/dashboard',
        '/panel',
        '/cpanel',
        '/manage',
    ],
```

**Admin panels = auth bypass potential:**
- Default credentials
- Weak passwords
- Auth bypass vulns
- Privilege escalation

```python
    'api': [
        '/api',
        '/api/v1',
        '/api/v2',
        '/graphql',
        '/graphiql',           # GraphQL playground!
        '/swagger',
        '/swagger-ui',
        '/swagger.json',       # API documentation!
        '/openapi.json',
        '/api-docs',
    ],
```

**API endpoints = hidden functionality:**
- Undocumented endpoints
- Debug endpoints
- Internal APIs
- GraphQL introspection

```python
    'backup': [
        '/backup',
        '/backups',
        '/bak',
        '/old',
        '/archive',
        '/site.zip',           # Entire site!
        '/backup.zip',
        '/www.zip',
    ],
```

**Backups = old code with vulns:**
- Unpatched vulnerabilities
- Hardcoded credentials
- Debug code left in
- Source code exposure

---

### Path Checking Logic

```python
async def check_path(self, session: aiohttp.ClientSession, 
                     base_url: str, path: str) -> dict | None:
    url = f"{base_url.rstrip('/')}{path}"
    
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                           ssl=False, allow_redirects=False) as resp:
        
        if resp.status == 200:
            content = await resp.text()
            # Skip generic error pages
            if len(content) < 100 and ('not found' in content.lower() or 
                                        'error' in content.lower()):
                return None
            
            return {
                'url': url,
                'path': path,
                'status': 200,
                'content_length': content_length,
            }
        
        elif resp.status == 403:
            # Forbidden = EXISTS but protected
            return {
                'url': url,
                'path': path,
                'status': 403,
                'note': 'Forbidden - exists but protected'
            }
```

**Why check content length?**
Some servers return 200 for everything but with "Not Found" in body. We filter these false positives.

**Why 403 is interesting?**
- 404 = doesn't exist
- 403 = EXISTS but you can't access
- 403 on `/admin` = admin panel exists, try to bypass!

**Why `allow_redirects=False`?**
- We want to know if path exists, not where it redirects
- `/admin` → `/login` tells us admin exists
- Following redirect would hide this info

---

### Parallel Fuzzing

```python
async def fuzz_host(self, host: str, categories: list = None) -> dict:
    # Try HTTPS first, then HTTP
    for protocol in ['https', 'http']:
        base_url = f"{protocol}://{host}"
        
        # Check if host is alive first
        try:
            async with session.get(base_url, timeout=5, ssl=False) as resp:
                if resp.status >= 400:
                    continue
        except:
            continue
        
        # Fuzz with concurrency limit
        semaphore = asyncio.Semaphore(20)
        
        async def check_with_limit(path):
            async with semaphore:
                return await self.check_path(session, base_url, path)
        
        tasks = [check_with_limit(path) for path in paths_to_check]
        findings = await asyncio.gather(*tasks)
```

**Why check if alive first?**
- Don't waste time fuzzing dead hosts
- Quick HEAD request confirms host responds
- Skip to next protocol if this one fails

**Why semaphore of 20?**
- 20 concurrent requests per host
- Fast but not abusive
- Won't trigger rate limiting on most servers

---

## 🎯 Module Comparison

| Module | Finds | Speed | Noise Level |
|--------|-------|-------|-------------|
| Wayback | Historical URLs, params | Fast | None (passive) |
| JS Analyzer | Secrets, endpoints | Medium | Low |
| Visual Recon | Tech stack, screenshots | Slow | Low |
| Path Fuzzer | Hidden paths | Medium | Medium |

**When to use each:**

1. **Wayback** - Always first. Passive, fast, reveals history.
2. **JS Analyzer** - After finding alive hosts. Secrets are gold.
3. **Visual Recon** - When you have many subdomains. Quick visual scan.
4. **Path Fuzzer** - On interesting hosts. Find hidden functionality.

---

## ⚠️ Important Notes

1. **Wayback is passive** - No requests to target, just archive.org
2. **JS analysis is noisy** - Downloads many files, might be logged
3. **Fuzzing is detectable** - Many 404s in logs = obvious scanning
4. **Rate limit everything** - Semaphores prevent abuse

