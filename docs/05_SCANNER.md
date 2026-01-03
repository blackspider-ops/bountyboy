# 🔬 Scanner Module (src/scanner.py)

Port scanning and vulnerability detection pipeline.

---

## 📄 Overview

```python
"""
Scanning Pipeline Module

Smart scanning workflow:
1. httpx - Check which hosts are actually alive
2. Nmap - Port scan (quick first, full on interesting targets)
3. Nuclei - Check for known vulnerabilities

WHY THIS ORDER?
No point scanning dead hosts. httpx filters them out fast.
Quick Nmap scan finds obvious stuff. Full scan only on interesting targets.
Nuclei runs last because it needs to know what services are running.
"""
```

**Pipeline visualization:**
```
Subdomains (247)
      ↓
   httpx (alive check)
      ↓
Alive Hosts (89)
      ↓
   nmap quick (top 100 ports)
      ↓
Interesting? ──Yes──→ nmap full (top 1000 or all 65535)
      ↓
   nuclei (vulnerability templates)
      ↓
   Results
```

---

## 🏗️ Class Initialization

```python
class Scanner:
    def __init__(self, config: dict, learn_mode: bool = False, deep_ports: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        self.deep_ports = deep_ports
        self.scan_config = config['scanning']
        # Aggressive timeouts for speed
        self.quick_timeout = 60  # 1 min per host max
        self.full_timeout = 180 if deep_ports else 120  # 3 min for deep, 2 min normal
        self.max_parallel = 10   # Scan 10 hosts at once
```

**Parameters explained:**

| Parameter | Purpose |
|-----------|---------|
| `config` | Full config dict |
| `learn_mode` | Show educational explanations |
| `deep_ports` | Scan all 65535 ports (slow) |

**Timeouts:**
- `quick_timeout = 60` - 1 minute max for quick scan
- `full_timeout = 120/180` - 2-3 minutes for full scan
- **WHY aggressive?** Prevent hanging on slow/filtered hosts

**Parallelism:**
- `max_parallel = 10` - Scan 10 hosts simultaneously
- **WHY 10?** Balance between speed and not overwhelming network

---

## 🔍 check_alive()

```python
def check_alive(self, subdomains: set, output_dir: str) -> list:
    """Use httpx to find alive hosts."""
```

**Why check alive first?**
- Subdomain exists in DNS ≠ server is running
- Example: `old.example.com` has DNS record but server is down
- Scanning dead hosts wastes time
- httpx checks in seconds

```python
    # Write subdomains to temp file
    input_file = Path(output_dir) / "subdomains_input.txt"
    with open(input_file, 'w') as f:
        f.write('\n'.join(subdomains))
```

**Why write to file?**
- httpx reads from file with `-l` flag
- More reliable than piping for large lists
- Can inspect file for debugging

```python
    success_flag, output = run_tool(
        ["httpx", "-l", str(input_file), "-silent", "-no-color", "-timeout", "5"],
        timeout=120  # 2 min max for all hosts
    )
```

**httpx flags:**
- `-l file` - read targets from file
- `-silent` - only output alive hosts
- `-no-color` - no ANSI colors (easier to parse)
- `-timeout 5` - 5 second timeout per host

**Why 5 second timeout?**
- Most servers respond in <1 second
- 5 seconds catches slow servers
- Longer = waiting for dead hosts

```python
    # Extract just the hostname from URLs
    alive_hosts = []
    for url in alive:
        host = url.replace('https://', '').replace('http://', '').split('/')[0]
        alive_hosts.append(host)
```

**Why extract hostname?**
- httpx returns full URLs: `https://www.example.com`
- We need just: `www.example.com`
- For nmap and other tools

---

## ⚡ quick_scan()

```python
def quick_scan(self, host: str) -> dict:
    """Quick Nmap scan - top 100 ports only for speed."""
    success_flag, output = run_tool(
        ["nmap", "-sV", "--top-ports", "100", "-T4", "--max-retries", "1", 
         "--host-timeout", "30s", "-oG", "-", host],
        timeout=self.quick_timeout
    )
```

**nmap flags explained:**

| Flag | Meaning | Why |
|------|---------|-----|
| `-sV` | Version detection | Know what's running (Apache 2.4, nginx, etc.) |
| `--top-ports 100` | Scan top 100 ports | Covers 90% of services, fast |
| `-T4` | Aggressive timing | Faster scanning |
| `--max-retries 1` | Only retry once | Don't waste time on filtered ports |
| `--host-timeout 30s` | 30 second max per host | Prevent hanging |
| `-oG -` | Grepable output to stdout | Easy to parse |

**Why top 100 instead of 1000?**
- Top 100 covers: 80, 443, 22, 21, 8080, 3306, etc.
- 10x faster than top 1000
- If we find interesting ports, we do full scan anyway

**Why `-T4`?**
```
-T0: Paranoid (very slow, IDS evasion)
-T1: Sneaky
-T2: Polite
-T3: Normal (default)
-T4: Aggressive (fast)
-T5: Insane (may miss ports)
```
- T4 is fast but still accurate
- T5 can miss ports due to timeouts

---

## 🔎 full_scan()

```python
def full_scan(self, host: str) -> dict:
    """Extended scan - top 1000 ports or all 65535 if deep_ports enabled."""
    
    if self.deep_ports:
        # Full 65535 port scan - SLOW but thorough
        success_flag, output = run_tool(
            ["nmap", "-sV", "-p-", "-T4", "--max-retries", "2",
             "--host-timeout", "10m", "-oG", "-", host],
            timeout=900  # 15 min max for full scan
        )
```

**Deep ports mode (`-p-`):**
- Scans ALL 65535 ports
- Takes 10-15 minutes per host
- Finds hidden services on weird ports
- Use when thoroughness > speed

```python
    else:
        # Top 1000 instead of all ports - still thorough but 60x faster
        success_flag, output = run_tool(
            ["nmap", "-sV", "--top-ports", "1000", "-T4", "--max-retries", "1",
             "--host-timeout", "60s", "-oG", "-", host],
            timeout=self.full_timeout
        )
```

**Normal mode (top 1000):**
- Covers 99% of common services
- Takes ~1 minute per host
- Good balance of speed and coverage

**Port coverage comparison:**

| Mode | Ports | Time | Coverage |
|------|-------|------|----------|
| Quick | 100 | 10s | 90% |
| Full | 1000 | 60s | 99% |
| Deep | 65535 | 10-15min | 100% |

---

## 📊 _parse_nmap_output()

```python
def _parse_nmap_output(self, output: str, host: str) -> dict:
    """Parse nmap grepable output."""
    result = {'host': host, 'ports': []}
    for line in output.split('\n'):
        if 'Ports:' in line:
            ports_section = line.split('Ports:')[1].split('Ignored')[0]
```

**Grepable output format:**
```
Host: 93.184.216.34 ()  Ports: 80/open/tcp//http//nginx/, 443/open/tcp//https//nginx/  Ignored State: filtered (998)
```

**Parsing logic:**
1. Find line with `Ports:`
2. Extract section between `Ports:` and `Ignored`
3. Split by comma for each port
4. Parse each port entry

```python
            for port_info in ports_section.split(','):
                port_info = port_info.strip()
                if '/' in port_info:
                    parts = port_info.split('/')
                    if len(parts) >= 5:
                        port_num = parts[0].strip()
                        state = parts[1].strip()
                        service = parts[4].strip() if len(parts) > 4 else 'unknown'
                        if state == 'open':
                            result['ports'].append({
                                'port': port_num,
                                'service': service
                            })
```

**Port entry format:** `80/open/tcp//http//nginx/`
- parts[0] = `80` (port number)
- parts[1] = `open` (state)
- parts[2] = `tcp` (protocol)
- parts[3] = `` (empty)
- parts[4] = `http` (service)
- parts[5] = `nginx` (version)

**Why only `open` ports?**
- `filtered` = firewall blocking, can't connect
- `closed` = port exists but nothing listening
- `open` = service running, can interact

---

## 🎯 has_interesting_ports()

```python
def has_interesting_ports(self, scan_result: dict) -> bool:
    """Check if scan found interesting ports worth full scanning."""
    interesting = set(str(p) for p in self.scan_config['nmap']['interesting_ports'])
    found_ports = set(p['port'] for p in scan_result.get('ports', []))
    return bool(interesting & found_ports)
```

**Logic:**
1. Get list of "interesting" ports from config
2. Get ports found in scan
3. Check if any overlap (set intersection `&`)

**Why these ports are interesting:**
```yaml
interesting_ports:
  - 8080   # Dev servers, Tomcat
  - 8443   # HTTPS alternate
  - 9000   # PHP-FPM, debug
  - 3000   # Node.js
  - 5000   # Flask
  - 8000   # Django
```

**If interesting port found:**
- Host likely has dev/debug services
- Worth doing deeper scan
- Might find more hidden ports

---

## 🔄 _scan_host() - Parallel Scanning

```python
def _scan_host(self, host: str) -> dict:
    """Scan a single host (for parallel execution)."""
    info(f"  Scanning {host}...")
    scan_result = self.quick_scan(host)
    
    if scan_result.get('ports'):
        success(f"  Found {len(scan_result['ports'])} open ports on {host}")
        
        # Full scan if interesting ports found
        if self.has_interesting_ports(scan_result):
            info(f"  Interesting ports found - running full scan...")
            scan_result = self.full_scan(host)
    
    return scan_result
```

**Scanning strategy:**
1. Quick scan (top 100 ports)
2. If interesting ports found → full scan
3. If not interesting → keep quick scan results

**Why this approach?**
- Most hosts only have 80/443
- No need for full scan on boring hosts
- Save time for interesting targets

---

## 🦠 run_nuclei()

```python
def run_nuclei(self, hosts: list, output_dir: str) -> list:
    """Run nuclei vulnerability scanner."""
```

**What is Nuclei?**
- Template-based vulnerability scanner
- 5000+ templates for known vulns
- Checks for: CVEs, misconfigs, exposures

```python
    # Write hosts to file
    input_file = Path(output_dir) / "nuclei_targets.txt"
    with open(input_file, 'w') as f:
        for host in hosts[:30]:  # Limit to 30 hosts for speed
            f.write(f"https://{host}\n")
            f.write(f"http://{host}\n")
```

**Why both http and https?**
- Some hosts only have HTTP
- Some only have HTTPS
- Some have both with different content
- Check both to be thorough

**Why limit to 30?**
- Nuclei is thorough but slow
- 30 hosts × 5000 templates = lots of requests
- Prevent scan from taking hours

```python
    success_flag, output = run_tool(
        ["nuclei", "-l", str(input_file), "-severity", severity, 
         "-tags", tags, "-json", "-o", str(output_file),
         "-timeout", "5", "-retries", "1", "-c", "50"],  # Fast settings
        timeout=300  # 5 min max
    )
```

**Nuclei flags:**
- `-l file` - targets file
- `-severity critical,high,medium` - only important findings
- `-tags cve,exposure,misconfig` - template categories
- `-json` - JSON output for parsing
- `-o file` - output file
- `-timeout 5` - 5 second timeout per request
- `-retries 1` - only retry once
- `-c 50` - 50 concurrent requests

**Why these settings?**
- Fast but still catches important stuff
- Skip low/info (too noisy)
- Focus on actionable findings

---

## 🔧 scan() - Main Pipeline

```python
def scan(self, subdomains: set, output_dir: str) -> dict:
    """Run full scanning pipeline with parallel execution."""
    
    results = {
        'alive_hosts': [],
        'scan_results': [],
        'nuclei_findings': []
    }
```

**Results structure:**
- `alive_hosts` - hosts that responded
- `scan_results` - port scan results per host
- `nuclei_findings` - vulnerabilities found

```python
    # Step 2: Parallel scan all alive hosts
    with ThreadPoolExecutor(max_workers=self.max_parallel) as executor:
        future_to_host = {executor.submit(self._scan_host, host): host for host in alive[:30]}
        
        for future in as_completed(future_to_host):
            try:
                scan_result = future.result(timeout=self.full_timeout)
                if scan_result:
                    results['scan_results'].append(scan_result)
            except Exception as e:
                host = future_to_host[future]
                warning(f"  Scan failed for {host}: {e}")
```

**Parallel execution explained:**

1. `ThreadPoolExecutor(max_workers=10)` - pool of 10 threads
2. `executor.submit()` - submit task to pool
3. `future_to_host` - map future to host (for error reporting)
4. `as_completed()` - yield futures as they complete
5. `future.result()` - get result (or exception)

**Why ThreadPoolExecutor?**
- nmap is blocking (not async)
- Threads allow parallel execution
- 10 threads = 10 hosts scanned simultaneously

**Why `as_completed()`?**
- Process results as they come
- Don't wait for slowest host
- Show progress to user

---

## 📈 Performance Summary

| Optimization | Impact |
|--------------|--------|
| Alive check first | Skip 50-90% of hosts |
| Quick scan (100 ports) | 10x faster than 1000 |
| Parallel scanning | 10x faster (10 threads) |
| Aggressive timeouts | No hanging on slow hosts |
| Limit to 30 hosts | Prevent runaway scans |

**Before optimizations:** 4-5 hours
**After optimizations:** 15-20 minutes
