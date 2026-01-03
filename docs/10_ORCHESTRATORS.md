# 🎯 Orchestrators

Deep dive into ultimate.py and the orchestration logic.

---

## 📄 ultimate.py - The Main Orchestrator

### Overview

```python
"""
BountyBoy - The Ultimate Bug Bounty Automation Toolkit

THE COMPLETE ARSENAL - Everything runs in parallel where possible.

MODULES INCLUDED:
├── Subdomain Discovery (parallel)
├── Scanning Pipeline
├── Deep Analysis (parallel)
├── Vulnerability Checks (parallel)
├── Intelligence Gathering (parallel)
└── Reporting
"""
```

**ultimate.py is the brain.** It coordinates all modules, manages execution order, handles parallelization, and generates reports.

---

### Imports Organization

```python
# Core Python
import asyncio
import click
import urllib3
import json
from pathlib import Path
from datetime import datetime

# Rich for pretty output
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

# Our utilities
from src.utils import load_config, ensure_dirs, learn, success, error, info, warning, timestamp

# Discovery modules
from src.async_discovery import AsyncSubdomainDiscovery
from src.scanner import Scanner

# Analysis modules
from src.visual_recon import VisualRecon
from src.js_analyzer import JSAnalyzer
from src.wayback import WaybackAnalyzer
from src.fuzzer import PathFuzzer

# Vulnerability modules
from src.subdomain_takeover import SubdomainTakeoverChecker
from src.cors_checker import CORSChecker
from src.header_analyzer import HeaderAnalyzer
from src.ssl_analyzer import SSLAnalyzer

# Extended vulnerability modules
from src.sqli_scanner import SQLiScanner
from src.xss_scanner import XSSScanner
from src.ssrf_scanner import SSRFScanner
from src.jwt_analyzer import JWTAnalyzer
from src.idor_scanner import IDORScanner

# Intelligence modules
from src.shodan_recon import ShodanRecon
from src.email_harvester import EmailHarvester
from src.cloud_enum import CloudEnumerator
from src.param_miner import ParamMiner

# Reporting
from src.report_generator import ReportGenerator
from src.notifier import Notifier
```

**Why this organization?**
- Grouped by functionality
- Easy to find what you need
- Clear dependencies
- Logical import order

---

### CLI Options

```python
@click.command()
@click.option('--target', '-t', required=True, help='Target domain')
@click.option('--learn', 'learn_mode', is_flag=True, help='Enable learning mode')
@click.option('--config', '-c', default='config.yaml', help='Config file')
@click.option('--quick', is_flag=True, help='Quick: subdomain discovery only')
@click.option('--standard', is_flag=True, help='Standard: discovery + scanning + analysis')
@click.option('--full', is_flag=True, help='Full: everything including all vuln checks')
@click.option('--insane', is_flag=True, help='Insane: absolutely everything, takes longest')
@click.option('--turbo', is_flag=True, help='Turbo: fast parallel scan (~5-10 min)')
@click.option('--deep-ports', is_flag=True, help='Scan all 65535 ports')
@click.option('--notify', is_flag=True, help='Send notifications')
@click.option('--report', is_flag=True, help='Generate HTML/MD reports')
```

**Why Click?**
- Clean CLI interface
- Automatic help generation
- Type validation
- Easy to extend

**Scan modes explained:**

| Mode | Time | What It Does |
|------|------|--------------|
| `--quick` | ~30s | Subdomain discovery only |
| `--standard` | ~10min | + scanning + analysis |
| `--full` | ~15-20min | + all vuln checks |
| `--turbo` | ~5-10min | Fast parallel, aggressive timeouts |
| `--insane` | ~30+min | + cloud enum + email harvest |

---

### Mode Determination

```python
def main(target, learn_mode, config, quick, standard, full, insane, turbo, deep_ports, notify, report):
    # Determine mode
    if quick:
        mode = 'quick'
    elif standard:
        mode = 'standard'
    elif full:
        mode = 'full'
    elif insane:
        mode = 'insane'
    elif turbo:
        mode = 'turbo'
    else:
        mode = 'standard'  # Default
```

**Why explicit mode selection?**
- Clear user intent
- No ambiguity
- Easy to add new modes
- Default is safe (standard)

---

### Module Initialization

```python
def initialize_modules(cfg: dict, learn_mode: bool, notify: bool, deep_ports: bool = False) -> dict:
    return {
        # Discovery
        'discovery': AsyncSubdomainDiscovery(cfg, learn_mode),
        'scanner': Scanner(cfg, learn_mode, deep_ports),
        
        # Analysis
        'visual': VisualRecon(cfg, learn_mode),
        'js': JSAnalyzer(cfg, learn_mode),
        'wayback': WaybackAnalyzer(cfg, learn_mode),
        'fuzzer': PathFuzzer(cfg, learn_mode),
        
        # Vulnerability
        'takeover': SubdomainTakeoverChecker(cfg, learn_mode),
        'cors': CORSChecker(cfg, learn_mode),
        'headers': HeaderAnalyzer(cfg, learn_mode),
        'ssl': SSLAnalyzer(cfg, learn_mode),
        
        # Extended vulnerability
        'sqli': SQLiScanner(cfg, learn_mode),
        'xss': XSSScanner(cfg, learn_mode),
        'ssrf': SSRFScanner(cfg, learn_mode),
        'jwt': JWTAnalyzer(cfg, learn_mode),
        'idor': IDORScanner(cfg, learn_mode),
        
        # Intelligence
        'shodan': ShodanRecon(cfg, learn_mode),
        'email': EmailHarvester(cfg, learn_mode),
        'cloud': CloudEnumerator(cfg, learn_mode),
        'params': ParamMiner(cfg, learn_mode),
        
        # Reporting
        'report': ReportGenerator(cfg),
        'notifier': Notifier(cfg) if notify else None,
    }
```

**Why dictionary of modules?**
- Easy to access: `modules['scanner'].scan(...)`
- Can pass around as single object
- Easy to add/remove modules
- Conditional initialization (notifier)

---

### Results Container

```python
def initialize_results(target: str, mode: str) -> dict:
    return {
        'target': target,
        'mode': mode,
        'start_time': datetime.now().isoformat(),
        
        # Discovery results
        'subdomains': set(),
        'new_subdomains': [],
        'alive_hosts': [],
        
        # Scan results
        'vulnerabilities': [],
        'js_secrets': [],
        'js_endpoints': [],
        
        # Wayback results
        'wayback_urls': 0,
        'wayback_alive': [],
        'wayback_params': [],
        
        # Vulnerability results
        'takeover_vulns': [],
        'cors_vulns': [],
        'ssl_issues': [],
        'sqli_vulns': [],
        'xss_vulns': [],
        'ssrf_vulns': [],
        'jwt_vulns': [],
        'idor_vulns': [],
        
        # Intelligence results
        'emails': [],
        'cloud_buckets': [],
        ...
    }
```

**Why centralized results?**
- Single source of truth
- Easy to serialize to JSON
- All modules contribute to same structure
- Report generator reads from here

---

### Phase 1: Subdomain Discovery

```python
# ═══════════════════════════════════════════════════════════════
# PHASE 1: SUBDOMAIN DISCOVERY
# ═══════════════════════════════════════════════════════════════
print_phase("PHASE 1: SUBDOMAIN DISCOVERY")

results['subdomains'], results['new_subdomains'] = modules['discovery'].discover(
    target, dirs['subdomains']
)

if not results['subdomains']:
    warning("No subdomains found. Exiting.")
    return

notify_new_subdomains(modules['notifier'], target, results['new_subdomains'])

if mode == 'quick':
    finalize(results, start_time, dirs, modules, report)
    return
```

**Why discovery first?**
- Everything else depends on subdomains
- No subdomains = nothing to scan
- Quick mode exits here

**Early exit pattern:**
- Check if we have data to work with
- Exit gracefully if not
- Don't waste time on empty results

---

### Phase 2: Scanning Pipeline

```python
# ═══════════════════════════════════════════════════════════════
# PHASE 2: SCANNING PIPELINE
# ═══════════════════════════════════════════════════════════════
print_phase("PHASE 2: SCANNING PIPELINE")

scan_results = modules['scanner'].scan(results['subdomains'], dirs['scans'])
results['alive_hosts'] = scan_results['alive_hosts']
results['vulnerabilities'] = scan_results['nuclei_findings']

notify_vulnerabilities(modules['notifier'], results['vulnerabilities'])

if not results['alive_hosts']:
    warning("No alive hosts found.")
    finalize(results, start_time, dirs, modules, report)
    return
```

**Scanning order:**
1. httpx - Find alive hosts
2. nmap - Port scan alive hosts
3. nuclei - Vulnerability scan

**Why this order?**
- Don't scan dead hosts (waste of time)
- Port scan reveals services
- Nuclei needs to know what services exist

---

### Phase 3: Deep Analysis

```python
# ═══════════════════════════════════════════════════════════════
# PHASE 3: DEEP ANALYSIS
# ═══════════════════════════════════════════════════════════════
print_phase("PHASE 3: DEEP ANALYSIS")

hosts = results['alive_hosts'][:50]  # Limit to 50 hosts

# JavaScript Analysis
console.print("[cyan]▶ JavaScript Analysis[/cyan]")
js_results = modules['js'].analyze(hosts, dirs['scans'])
results['js_secrets'] = js_results.get('secrets', [])
results['js_endpoints'] = js_results.get('api_endpoints', [])

# Wayback Machine
console.print("\n[cyan]▶ Wayback Machine[/cyan]")
wb_results = modules['wayback'].analyze(target, dirs['scans'])
results['wayback_urls'] = wb_results.get('total_urls', 0)
results['wayback_params'] = list(set(
    p for params in wb_results.get('parameters', {}).values() for p in params
))

# Path Fuzzing
console.print("\n[cyan]▶ Path Fuzzing[/cyan]")
fuzz_results = modules['fuzzer'].fuzz(hosts[:20], dirs['scans'])
results['fuzz_findings'] = fuzz_results.get('critical_findings', [])
```

**Why limit hosts?**
- `hosts[:50]` - Don't analyze 1000 hosts
- `hosts[:20]` for fuzzing - Even more limited
- Balances thoroughness vs. time

**Analysis modules:**
1. JS Analysis - Find secrets in JavaScript
2. Wayback - Historical URLs and params
3. Visual Recon - Screenshots and tech detection
4. Path Fuzzing - Hidden paths

---

### Phase 4: Vulnerability Checks

```python
# ═══════════════════════════════════════════════════════════════
# PHASE 4: VULNERABILITY CHECKS
# ═══════════════════════════════════════════════════════════════
print_phase("PHASE 4: VULNERABILITY CHECKS")

# Subdomain Takeover
takeover_results = modules['takeover'].check(list(results['subdomains']), dirs['scans'])
results['takeover_vulns'] = takeover_results.get('vulnerable', [])

# CORS Check
cors_results = modules['cors'].check(hosts[:30], target, dirs['scans'])
results['cors_vulns'] = cors_results.get('vulnerable_endpoints', [])

# Security Headers
header_results = modules['headers'].analyze(hosts[:30], dirs['scans'])
results['header_issues'] = header_results.get('common_missing', {})

# SSL/TLS Analysis
ssl_results = modules['ssl'].analyze(hosts[:30], dirs['scans'])
results['ssl_issues'] = ssl_results.get('issues_found', [])
```

**Vulnerability checks:**
1. Subdomain Takeover - Dangling DNS
2. CORS - Cross-origin issues
3. Headers - Missing security headers
4. SSL - Certificate issues

---

### Phase 4.5: Extended Vulnerability Checks

```python
# ═══════════════════════════════════════════════════════════════
# PHASE 4.5: EXTENDED VULNERABILITY CHECKS
# ═══════════════════════════════════════════════════════════════

# SQLi Quick Check
sqli_urls = [f"http://{h}" for h in hosts[:15]]
if results.get('wayback_params'):
    sqli_urls.extend(results['wayback_params'][:20])
sqli_results = modules['sqli'].scan(sqli_urls, dirs['scans'])
results['sqli_vulns'] = sqli_results.get('vulnerable', [])

# XSS Quick Check
xss_urls = [f"http://{h}" for h in hosts[:15]]
if results.get('wayback_params'):
    xss_urls.extend(results['wayback_params'][:20])
xss_results = modules['xss'].scan(xss_urls, dirs['scans'])
results['xss_vulns'] = xss_results.get('vulnerable', [])
```

**Why combine hosts + wayback params?**
- Hosts give us base URLs
- Wayback params give us URLs with parameters
- SQLi/XSS need parameters to test
- More comprehensive coverage

---

### Phase 4.6: High-Value Vulnerability Checks

```python
# ═══════════════════════════════════════════════════════════════
# PHASE 4.6: HIGH-VALUE VULNERABILITY CHECKS
# ═══════════════════════════════════════════════════════════════

# SSRF Scanner (Cloud metadata = big bounties)
ssrf_results = modules['ssrf'].scan(hosts[:15], dirs['scans'])
results['ssrf_vulns'] = ssrf_results.get('critical_findings', []) + ssrf_results.get('high_findings', [])

# JWT Analysis (Auth bypass potential)
jwt_results = modules['jwt'].analyze(hosts[:20], dirs['scans'])
results['jwt_vulns'] = jwt_results.get('critical_findings', [])
results['jwt_weak_secrets'] = jwt_results.get('weak_secrets_found', [])

# IDOR / Broken Access Control
discovered_urls = results.get('wayback_alive', []) + [ep.get('url', '') for ep in results.get('api_endpoints', []) if isinstance(ep, dict)]
idor_results = modules['idor'].scan(hosts[:15], discovered_urls[:30], dirs['scans'])
results['idor_vulns'] = idor_results.get('critical_findings', []) + idor_results.get('high_findings', [])
```

**Why "high-value"?**
- SSRF with cloud metadata = $10k+ bounties
- JWT auth bypass = $5k-$20k bounties
- IDOR = Most common high-paying vuln

**Why limited hosts?**
- These scans are slower
- More thorough per host
- Quality over quantity

---

### Turbo Mode

```python
def run_turbo_scan(target, results, modules, dirs, generate_report, start_time):
    """
    TURBO MODE - Fast parallel scanning with aggressive timeouts.
    Target: Complete in 5-10 minutes.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    hosts = list(results['subdomains'])[:20]  # Limit to 20 hosts
    results['alive_hosts'] = hosts  # Skip alive check for speed
    
    # Phase 1: Quick parallel tasks
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {}
        
        futures['wayback'] = executor.submit(modules['wayback'].analyze, target, dirs['scans'])
        futures['headers'] = executor.submit(modules['headers'].analyze, hosts[:10], dirs['scans'])
        futures['js'] = executor.submit(modules['js'].analyze, hosts[:10], dirs['scans'])
        futures['fuzzer'] = executor.submit(modules['fuzzer'].fuzz, hosts[:10], dirs['scans'])
        futures['takeover'] = executor.submit(modules['takeover'].check, hosts, dirs['scans'])
        futures['cors'] = executor.submit(modules['cors'].check, hosts[:10], target, dirs['scans'])
        
        for name, future in futures.items():
            try:
                result = future.result(timeout=120)  # 2 min max per task
                # Process result...
            except Exception as e:
                warning(f"  ✗ {name} failed/timeout: {str(e)[:50]}")
```

**Turbo mode optimizations:**
1. Skip alive check (assume all alive)
2. Limit to 20 hosts
3. Run 6 tasks in parallel
4. 2 minute timeout per task
5. Continue even if tasks fail

**Why ThreadPoolExecutor?**
- True parallelism (not just async)
- Each module runs in separate thread
- Timeouts prevent hanging
- Failures don't stop other tasks

---

### Finalization

```python
def finalize(results, start_time, dirs, modules, generate_report):
    duration = datetime.now() - start_time
    results['end_time'] = datetime.now().isoformat()
    results['duration_seconds'] = duration.total_seconds()
    
    # Convert sets to lists for JSON
    results['subdomains'] = list(results.get('subdomains', set()))
    
    # Print summary
    print_summary(results, duration)
    
    # Generate reports
    if generate_report:
        report_paths = modules['report'].generate(results, dirs['reports'])
        success(f"HTML Report: {report_paths['html']}")
        success(f"Markdown Report: {report_paths['markdown']}")
    
    # Save JSON results
    json_path = Path(dirs['reports']) / f"results_{timestamp()}.json"
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    # Notify completion
    if modules['notifier']:
        modules['notifier'].notify_scan_complete(results['target'], {...})
```

**Finalization steps:**
1. Calculate duration
2. Convert sets to lists (JSON can't serialize sets)
3. Print summary table
4. Generate HTML/MD reports
5. Save raw JSON
6. Send completion notification

---

### Summary Printing

```python
def print_summary(results, duration):
    table = Table(title="📊 Results", show_header=True, header_style="bold cyan")
    table.add_column("Category", style="dim")
    table.add_column("Count", justify="right")
    table.add_column("Status", justify="center")
    
    def add_row(label, count, critical=False):
        if critical and count > 0:
            status = "🚨"
        elif count > 0:
            status = "✓"
        else:
            status = "○"
        table.add_row(label, str(count), status)
    
    add_row("Subdomains", len(results.get('subdomains', [])))
    add_row("Nuclei Findings", len(results.get('vulnerabilities', [])), True)
    add_row("JS Secrets", len(results.get('js_secrets', [])), True)
    add_row("SSRF Vulns", len(results.get('ssrf_vulns', [])), True)
    add_row("IDOR Vulns", len(results.get('idor_vulns', [])), True)
    ...
    
    console.print(table)
```

**Why Rich tables?**
- Clean, formatted output
- Color-coded status
- Easy to scan visually
- Professional appearance

---

## 🎯 Execution Flow

```
main()
  │
  ├── Load config
  ├── Setup directories
  ├── Initialize modules
  ├── Initialize results
  │
  ├── PHASE 1: Subdomain Discovery
  │   └── Exit if --quick
  │
  ├── TURBO MODE (if --turbo)
  │   └── Parallel execution, exit
  │
  ├── PHASE 2: Scanning Pipeline
  │   └── Exit if no alive hosts
  │
  ├── PHASE 3: Deep Analysis
  │   └── Exit if --standard
  │
  ├── PHASE 4: Vulnerability Checks
  ├── PHASE 4.5: Extended Vuln Checks
  ├── PHASE 4.6: High-Value Vuln Checks
  │   └── Exit if --full
  │
  ├── PHASE 5: Intelligence Gathering (--insane only)
  │
  └── finalize()
      ├── Print summary
      ├── Generate reports
      ├── Save JSON
      └── Send notifications
```

---

## ⚠️ Important Notes

1. **Mode determines depth** - Quick is fast, Insane is thorough
2. **Early exits save time** - No subdomains? Exit. No alive hosts? Exit.
3. **Parallelization is key** - Turbo mode runs 6 tasks simultaneously
4. **Limits prevent abuse** - hosts[:50], hosts[:20], etc.
5. **Results are cumulative** - Each phase adds to results dict

