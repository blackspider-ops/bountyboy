# 📚 BountyBoy Complete Documentation

This folder contains **line-by-line explanations** for every file in BountyBoy.

## 📁 Documentation Structure

```
docs/
├── README.md                    # This file - overview
├── 01_ROOT_FILES.md            # Root directory files (setup.sh, requirements.txt)
├── 02_CONFIG_FILES.md          # Configuration files (config.yaml)
├── 03_UTILS.md                 # Utility functions (src/utils.py)
├── 04_SUBDOMAIN_DISCOVERY.md   # Subdomain enumeration modules
├── 05_SCANNER.md               # Port scanning & nuclei
├── 06_RECON_MODULES.md         # Reconnaissance modules
├── 07_VULN_SCANNERS.md         # SQLi, XSS, SSRF scanners
├── 08_ANALYSIS_MODULES.md      # CORS, headers, SSL, params
├── 09_REPORTING.md             # Reports & notifications
├── 10_ORCHESTRATORS.md         # Main orchestrator files
├── 11_INTELLIGENCE_MODULES.md  # Cloud enum, email harvest, Shodan
├── 12_LAB_TESTING.md           # DVWA, Juice Shop testing
├── 13_ADDITIONAL_SCANNERS.md   # Open redirect, DNS, API, JWT, IDOR
└── 14_UTILITIES.md             # learn.py, monitor.py, tools_check.py
```

## 🎯 Quick Navigation

| I want to understand... | Read this |
|------------------------|-----------|
| How to set up BountyBoy | [01_ROOT_FILES.md](01_ROOT_FILES.md) |
| How to configure it | [02_CONFIG_FILES.md](02_CONFIG_FILES.md) |
| How subdomain discovery works | [04_SUBDOMAIN_DISCOVERY.md](04_SUBDOMAIN_DISCOVERY.md) |
| How port scanning works | [05_SCANNER.md](05_SCANNER.md) |
| How SQLi/XSS/SSRF scanning works | [07_VULN_SCANNERS.md](07_VULN_SCANNERS.md) |
| How JWT/IDOR/API scanning works | [13_ADDITIONAL_SCANNERS.md](13_ADDITIONAL_SCANNERS.md) |
| How to test against DVWA | [12_LAB_TESTING.md](12_LAB_TESTING.md) |
| How the orchestrator works | [10_ORCHESTRATORS.md](10_ORCHESTRATORS.md) |
| How to learn bug bounty | [14_UTILITIES.md](14_UTILITIES.md) |

## 📂 File Coverage

### Root Files
- `setup.sh` - Installation script → [01_ROOT_FILES.md](01_ROOT_FILES.md)
- `requirements.txt` - Python dependencies → [01_ROOT_FILES.md](01_ROOT_FILES.md)
- `config.yaml` - Configuration → [02_CONFIG_FILES.md](02_CONFIG_FILES.md)

### Orchestrators
- `ultimate.py` - Main scanner → [10_ORCHESTRATORS.md](10_ORCHESTRATORS.md)
- `orchestrator.py` - Basic version → [10_ORCHESTRATORS.md](10_ORCHESTRATORS.md)
- `orchestrator_v2.py` - With notifications → [10_ORCHESTRATORS.md](10_ORCHESTRATORS.md)
- `orchestrator_v3.py` - Async version → [10_ORCHESTRATORS.md](10_ORCHESTRATORS.md)

### Source Modules (src/)
- `utils.py` → [03_UTILS.md](03_UTILS.md)
- `subdomain_discovery.py` → [04_SUBDOMAIN_DISCOVERY.md](04_SUBDOMAIN_DISCOVERY.md)
- `async_discovery.py` → [04_SUBDOMAIN_DISCOVERY.md](04_SUBDOMAIN_DISCOVERY.md)
- `scanner.py` → [05_SCANNER.md](05_SCANNER.md)
- `wayback.py`, `js_analyzer.py`, `visual_recon.py`, `fuzzer.py` → [06_RECON_MODULES.md](06_RECON_MODULES.md)
- `sqli_scanner.py`, `xss_scanner.py`, `ssrf_scanner.py` → [07_VULN_SCANNERS.md](07_VULN_SCANNERS.md)
- `cors_checker.py`, `header_analyzer.py`, `ssl_analyzer.py`, `param_miner.py` → [08_ANALYSIS_MODULES.md](08_ANALYSIS_MODULES.md)
- `report_generator.py`, `notifier.py` → [09_REPORTING.md](09_REPORTING.md)
- `cloud_enum.py`, `email_harvester.py`, `shodan_recon.py`, `github_dorker.py`, `favicon_hash.py` → [11_INTELLIGENCE_MODULES.md](11_INTELLIGENCE_MODULES.md)
- `open_redirect.py`, `dns_analyzer.py`, `google_dorker.py` → [13_ADDITIONAL_SCANNERS.md](13_ADDITIONAL_SCANNERS.md)
- `api_fuzzer.py`, `jwt_analyzer.py`, `idor_scanner.py` → [13_ADDITIONAL_SCANNERS.md](13_ADDITIONAL_SCANNERS.md)
- `subdomain_takeover.py` → [13_ADDITIONAL_SCANNERS.md](13_ADDITIONAL_SCANNERS.md)

### Test Files
- `test_dvwa.py` → [12_LAB_TESTING.md](12_LAB_TESTING.md)
- `test_lab.py` → [12_LAB_TESTING.md](12_LAB_TESTING.md)
- `test_local.py` → [12_LAB_TESTING.md](12_LAB_TESTING.md)

### Utility Scripts
- `learn.py` → [14_UTILITIES.md](14_UTILITIES.md)
- `monitor.py` → [14_UTILITIES.md](14_UTILITIES.md)
- `tools_check.py` → [14_UTILITIES.md](14_UTILITIES.md)

## 🔑 Key Concepts

### Why Python?
- Async support for parallel operations
- Rich ecosystem (aiohttp, requests, etc.)
- Easy to read and modify
- Good for rapid prototyping

### Why Async?
- Bug bounty = scanning MANY hosts
- Sequential = slow (wait for each request)
- Async = fast (send all requests, process as they return)
- 10x-100x speed improvement

### Why Modular Design?
- Each module does ONE thing well
- Easy to add/remove modules
- Easy to test individually
- Easy to understand

## 🚀 Quick Start Reading Order

1. **Setup:** [01_ROOT_FILES.md](01_ROOT_FILES.md) - How to install
2. **Config:** [02_CONFIG_FILES.md](02_CONFIG_FILES.md) - How to configure
3. **Orchestrator:** [10_ORCHESTRATORS.md](10_ORCHESTRATORS.md) - How it all fits together
4. **Subdomain:** [04_SUBDOMAIN_DISCOVERY.md](04_SUBDOMAIN_DISCOVERY.md) - First phase
5. **Scanning:** [05_SCANNER.md](05_SCANNER.md) - Port scanning
6. **Vulns:** [07_VULN_SCANNERS.md](07_VULN_SCANNERS.md) - Finding bugs
7. **Advanced:** [13_ADDITIONAL_SCANNERS.md](13_ADDITIONAL_SCANNERS.md) - JWT, IDOR, API

---

**Every file. Every line. Explained.**
