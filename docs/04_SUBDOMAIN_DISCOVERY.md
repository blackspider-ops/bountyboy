# 🔍 Subdomain Discovery Modules

Two implementations: synchronous and async (parallel).

---

## 📄 src/subdomain_discovery.py - Synchronous Version

### Overview

```python
"""
Subdomain Discovery Module

Chains multiple tools to find all subdomains:
- Subfinder: Fast passive subdomain enumeration
- Amass: Comprehensive subdomain discovery
- Assetfinder: Quick asset discovery
- crt.sh: Certificate transparency logs

WHY MULTIPLE TOOLS?
Each tool uses different data sources. Subfinder might find subdomains from
VirusTotal that Amass misses. Amass might find subdomains from DNS brute
forcing that Subfinder doesn't do. Combining them gives complete coverage.
"""
```

**Key insight:** No single tool finds everything. Each has different data sources:

| Tool | Data Sources |
|------|--------------|
| Subfinder | VirusTotal, SecurityTrails, Shodan, Censys, etc. |
| Assetfinder | crt.sh, Facebook, Wayback, etc. |
| Amass | All of above + DNS brute forcing |
| crt.sh | Certificate Transparency logs |

---

### Class Initialization

```python
class SubdomainDiscovery:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        self.timeout = config['subdomain_discovery']['timeout']
```

**Why store config?**
- Need to check which tools are enabled
- Need timeout settings
- Avoid passing config to every method

**Why learn_mode?**
- Educational explanations when enabled
- Silent when disabled (cleaner output)

---

### run_subfinder()

```python
def run_subfinder(self, target: str) -> set:
    """Run subfinder for passive subdomain enumeration."""
    learn("Subfinder", 
          "Subfinder queries passive sources like VirusTotal, SecurityTrails, "
          "Shodan, etc. It doesn't touch the target directly - just collects "
          "subdomains that have been indexed by these services. Fast and stealthy.",
          self.learn_mode)
```

**Why "passive"?**
- Subfinder doesn't send requests to target
- Queries third-party databases
- Target doesn't know you're scanning
- Stealthy reconnaissance

```python
    if not check_tool_installed("subfinder"):
        error("subfinder not installed - skipping")
        return set()
```

**Why check first?**
- Graceful degradation
- Don't crash if tool missing
- Continue with other tools

```python
    success_flag, output = run_tool(
        ["subfinder", "-d", target, "-silent"],
        timeout=self.timeout
    )
```

**Command breakdown:**
- `subfinder` - the tool
- `-d target` - domain to enumerate
- `-silent` - only output subdomains (no banner, no stats)

**Why `-silent`?**
- Easier to parse output
- Just one subdomain per line
- No need to filter out noise

```python
    if success_flag:
        subs = set(line.strip() for line in output.split('\n') if line.strip())
        success(f"Subfinder found {len(subs)} subdomains")
        return subs
```

**Why set?**
- Automatic deduplication
- O(1) lookup for combining results
- No duplicate subdomains

**Why `line.strip()`?**
- Remove whitespace
- Handle Windows line endings (\r\n)
- Skip empty lines

---

### run_amass()

```python
def run_amass(self, target: str) -> set:
    success_flag, output = run_tool(
        ["amass", "enum", "-passive", "-d", target],
        timeout=self.timeout
    )
```

**Command breakdown:**
- `amass enum` - enumeration mode
- `-passive` - only passive sources (no DNS brute forcing)
- `-d target` - domain

**Why `-passive`?**
- Active mode does DNS brute forcing
- Takes 10-30 minutes
- Generates lots of DNS queries (noisy)
- Passive is faster and stealthier

**When to use active?**
- Deep recon on important target
- When you have time
- When stealth doesn't matter

---

### run_assetfinder()

```python
def run_assetfinder(self, target: str) -> set:
    success_flag, output = run_tool(
        ["assetfinder", "--subs-only", target],
        timeout=self.timeout
    )
```

**Command breakdown:**
- `assetfinder` - the tool
- `--subs-only` - only subdomains (not related domains)
- `target` - domain (no flag needed)

**Why `--subs-only`?**
- Without it, assetfinder returns related domains too
- Example: `example.com` might return `example.net`
- We only want subdomains of our target

---

### run_crtsh()

```python
def run_crtsh(self, target: str) -> set:
    """Query crt.sh certificate transparency logs."""
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{target}&output=json",
            timeout=30
        )
```

**URL breakdown:**
- `https://crt.sh/` - Certificate Transparency search engine
- `?q=%.{target}` - search for `*.example.com` (% is wildcard)
- `&output=json` - return JSON instead of HTML

**Why Certificate Transparency?**
- When company gets SSL cert, it's logged publicly
- Even internal subdomains get certs
- `staging.internal.example.com` might have a cert
- Great for finding "hidden" subdomains

```python
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for entry in data:
                name = entry.get('name_value', '')
                for sub in name.split('\n'):
                    sub = sub.strip().lower()
                    if sub and '*' not in sub:
                        subs.add(sub)
```

**Why split by newline?**
- One cert can cover multiple domains
- `name_value` might be `www.example.com\napi.example.com`

**Why filter `*`?**
- Wildcard certs: `*.example.com`
- Not actual subdomains
- Can't scan a wildcard

**Why `.lower()`?**
- DNS is case-insensitive
- `WWW.Example.COM` = `www.example.com`
- Normalize for deduplication

---

### discover() - Main Method

```python
def discover(self, target: str, output_dir: str) -> tuple[set, list]:
    all_subs = set()
    tools_config = self.config['subdomain_discovery']['tools']
    
    if tools_config.get('subfinder'):
        all_subs.update(self.run_subfinder(target))
    
    if tools_config.get('amass'):
        all_subs.update(self.run_amass(target))
```

**Why check config?**
- User can enable/disable tools
- Amass disabled by default (slow)
- Flexible configuration

```python
    # Filter to only include subdomains of target
    all_subs = {s for s in all_subs if s.endswith(target)}
```

**Why filter?**
- Some tools return related domains
- `example.com` might return `example.net`
- Only want actual subdomains

**Why `endswith(target)`?**
- `api.example.com`.endswith(`example.com`) = True
- `example.net`.endswith(`example.com`) = False

```python
    # Check for new subdomains
    new_subs = []
    if current_file.exists():
        with open(current_file, 'r') as f:
            old_subs = set(line.strip() for line in f if line.strip())
        new_subs = list(all_subs - old_subs)
```

**Why track new subdomains?**
- New subdomains = new attack surface
- Often untested, unpatched
- Competitive advantage in bug bounty
- Alert user to investigate

```python
    # Save current results
    with open(current_file, 'w') as f:
        f.write('\n'.join(sorted(all_subs)))
    
    # Save to history
    with open(history_file, 'w') as f:
        f.write('\n'.join(sorted(all_subs)))
```

**Why two files?**
- `current.txt` - latest results (for comparison)
- `history/TIMESTAMP.txt` - historical record

**Why sorted?**
- Consistent ordering
- Easy to diff manually
- Alphabetical = logical grouping

---

## 📄 src/async_discovery.py - Parallel Version

### Why Async?

```python
"""
Async Subdomain Discovery Module

Runs ALL discovery tools simultaneously using asyncio.
Instead of: Subfinder (30s) → Assetfinder (20s) → crt.sh (10s) = 60s total
We get:     All three at once = ~30s total (speed of slowest tool)
"""
```

**Visual comparison:**

Sequential:
```
|--Subfinder (30s)--|--Assetfinder (20s)--|--crt.sh (10s)--|
Total: 60 seconds
```

Parallel:
```
|--Subfinder (30s)--|
|--Assetfinder (20s)--|
|--crt.sh (10s)--|
Total: 30 seconds (limited by slowest)
```

---

### ThreadPoolExecutor

```python
class AsyncSubdomainDiscovery:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.executor = ThreadPoolExecutor(max_workers=5)
```

**Why ThreadPoolExecutor?**
- External tools (subfinder, etc.) are blocking
- Can't use pure async (they're not async)
- ThreadPool runs them in separate threads
- `max_workers=5` - up to 5 tools simultaneously

---

### run_tool_async()

```python
async def run_tool_async(self, cmd: list, tool_name: str) -> set:
    """Run a tool asynchronously using thread pool."""
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(
            self.executor,
            lambda: subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        )
```

**How it works:**
1. `asyncio.get_event_loop()` - get current async event loop
2. `run_in_executor()` - run blocking code in thread pool
3. `await` - wait for result without blocking other tasks
4. `lambda:` - wrap subprocess call in callable

**Why lambda?**
- `run_in_executor` needs a callable
- `subprocess.run(...)` is a call, not a callable
- `lambda: subprocess.run(...)` is a callable that calls subprocess

---

### run_crtsh() - True Async

```python
async def run_crtsh(self, target: str) -> set:
    """Query crt.sh asynchronously."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://crt.sh/?q=%.{target}&output=json",
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
```

**Why aiohttp instead of requests?**
- `requests` is synchronous (blocking)
- `aiohttp` is truly async
- Doesn't need thread pool
- More efficient for HTTP requests

**`async with` explained:**
- Creates session, automatically closes when done
- Same as `with` but for async code
- Proper resource cleanup

---

### discover_async() - Parallel Execution

```python
async def discover_async(self, target: str, output_dir: str) -> tuple[set, list]:
    tasks = []
    
    if tools_config.get('subfinder'):
        tasks.append(self.run_subfinder(target))
    if tools_config.get('assetfinder'):
        tasks.append(self.run_assetfinder(target))
```

**Building task list:**
- Each enabled tool becomes a task
- Tasks are coroutines (not yet running)

```python
    # Run all tasks simultaneously
    results = await asyncio.gather(*tasks, return_exceptions=True)
```

**`asyncio.gather()` explained:**
- Takes multiple coroutines
- Runs them ALL simultaneously
- Returns when ALL complete
- `*tasks` unpacks list into arguments
- `return_exceptions=True` - don't crash if one fails

**Why `return_exceptions=True`?**
- If one tool fails, others continue
- Failed tool returns exception object
- We can check and handle individually

```python
    # Combine results
    all_subs = set()
    for result in results:
        if isinstance(result, set):
            all_subs.update(result)
```

**Why check `isinstance`?**
- With `return_exceptions=True`, failed tasks return Exception
- Only add successful results (sets)
- Skip exceptions

---

### Synchronous Wrapper

```python
def discover(self, target: str, output_dir: str) -> tuple[set, list]:
    """Synchronous wrapper for async discovery."""
    return asyncio.run(self.discover_async(target, output_dir))
```

**Why wrapper?**
- Calling code might not be async
- `asyncio.run()` runs async code from sync context
- Clean API - caller doesn't need to know it's async

---

## 🆚 When to Use Which?

| Scenario | Use |
|----------|-----|
| Quick scan, time matters | async_discovery.py |
| Debugging, need to see order | subdomain_discovery.py |
| Default in ultimate.py | async_discovery.py |

**BountyBoy uses async by default** because speed matters in bug bounty.
