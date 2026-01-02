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

This is GOLD for bug hunters. Many critical bugs come from JS analysis.
"""
import re
import asyncio
import aiohttp
from pathlib import Path
from urllib.parse import urljoin, urlparse
from src.utils import learn, success, error, info, warning, timestamp

class JSAnalyzer:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        
        # Patterns to find in JS files
        self.patterns = {
            'api_endpoints': [
                r'["\']/(api|v1|v2|v3)/[^"\']+["\']',
                r'fetch\s*\(\s*["\'][^"\']+["\']',
                r'axios\.(get|post|put|delete|patch)\s*\(\s*["\'][^"\']+["\']',
                r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\'][^"\']+["\']',
                r'XMLHttpRequest[^;]*open\s*\([^,]+,\s*["\'][^"\']+["\']',
            ],
            'secrets': [
                r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][^"\']{10,}["\']',
                r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\'][^"\']{10,}["\']',
                r'["\']?access[_-]?token["\']?\s*[:=]\s*["\'][^"\']{10,}["\']',
                r'["\']?auth[_-]?token["\']?\s*[:=]\s*["\'][^"\']{10,}["\']',
                r'["\']?password["\']?\s*[:=]\s*["\'][^"\']{6,}["\']',
                r'["\']?aws[_-]?access["\']?\s*[:=]\s*["\'][A-Z0-9]{16,}["\']',
                r'Bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',  # JWT
                r'["\']?private[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']',
            ],
            'urls': [
                r'https?://[^\s"\'<>]+',
                r'["\']//[a-zA-Z0-9][^\s"\'<>]+["\']',
            ],
            'sensitive_paths': [
                r'["\']/(admin|dashboard|internal|private|debug|test|staging)[^"\']*["\']',
                r'["\']/(backup|config|settings|setup)[^"\']*["\']',
                r'["\']\.env["\']',
                r'["\'][^"\']*\.(sql|bak|old|backup|log)["\']',
            ],
            'cloud_urls': [
                r's3\.amazonaws\.com/[a-zA-Z0-9\-]+',
                r'[a-zA-Z0-9\-]+\.s3\.amazonaws\.com',
                r'storage\.googleapis\.com/[a-zA-Z0-9\-]+',
                r'[a-zA-Z0-9\-]+\.blob\.core\.windows\.net',
            ]
        }
    
    async def fetch_page(self, session: aiohttp.ClientSession, url: str) -> str:
        """Fetch a page and return its content."""
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), 
                                   ssl=False) as resp:
                if resp.status == 200:
                    return await resp.text()
        except Exception:
            pass
        return ""
    
    async def extract_js_urls(self, session: aiohttp.ClientSession, url: str) -> list:
        """Extract JavaScript file URLs from a page."""
        content = await self.fetch_page(session, url)
        if not content:
            return []
        
        js_urls = []
        
        # Find script tags
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        for match in re.finditer(script_pattern, content, re.IGNORECASE):
            src = match.group(1)
            if src.endswith('.js') or '.js?' in src:
                full_url = urljoin(url, src)
                js_urls.append(full_url)
        
        # Find inline JS imports
        import_pattern = r'import\s+.*from\s+["\']([^"\']+\.js)["\']'
        for match in re.finditer(import_pattern, content):
            src = match.group(1)
            full_url = urljoin(url, src)
            js_urls.append(full_url)
        
        return list(set(js_urls))
    
    def analyze_js_content(self, content: str, source_url: str) -> dict:
        """Analyze JavaScript content for interesting patterns."""
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
    
    async def analyze_host(self, host: str) -> dict:
        """Analyze all JS files from a host."""
        results = {
            'host': host,
            'js_files_analyzed': 0,
            'findings': []
        }
        
        async with aiohttp.ClientSession() as session:
            # Try both HTTP and HTTPS
            for protocol in ['https', 'http']:
                url = f"{protocol}://{host}"
                
                # Get JS URLs from main page
                js_urls = await self.extract_js_urls(session, url)
                
                if js_urls:
                    info(f"  Found {len(js_urls)} JS files on {host}")
                    
                    # Analyze each JS file
                    for js_url in js_urls[:20]:  # Limit to 20 files per host
                        content = await self.fetch_page(session, js_url)
                        if content:
                            findings = self.analyze_js_content(content, js_url)
                            if any(findings[k] for k in findings if k != 'source'):
                                results['findings'].append(findings)
                            results['js_files_analyzed'] += 1
                    
                    break  # Found JS files, no need to try other protocol
        
        return results
    
    async def analyze_async(self, hosts: list, output_dir: str) -> dict:
        """Analyze JS files from multiple hosts in parallel."""
        learn("JavaScript Analysis",
              "We're scanning JavaScript files for secrets and endpoints. "
              "Developers often leave API keys, internal URLs, and debug endpoints "
              "in JS files. This is how many critical bugs are found - not by "
              "scanning, but by reading the code the app sends to your browser.",
              self.learn_mode)
        
        info(f"Analyzing JavaScript files from {len(hosts)} hosts...")
        
        # Analyze hosts in parallel (but limit concurrency)
        semaphore = asyncio.Semaphore(10)
        
        async def analyze_with_limit(host):
            async with semaphore:
                return await self.analyze_host(host)
        
        tasks = [analyze_with_limit(host) for host in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Compile findings
        all_findings = {
            'total_hosts': len(hosts),
            'total_js_files': 0,
            'api_endpoints': set(),
            'secrets': [],
            'sensitive_paths': set(),
            'cloud_urls': set(),
            'by_host': []
        }
        
        for result in results:
            if isinstance(result, dict):
                all_findings['total_js_files'] += result['js_files_analyzed']
                all_findings['by_host'].append(result)
                
                for finding in result['findings']:
                    all_findings['api_endpoints'].update(finding['api_endpoints'])
                    all_findings['secrets'].extend(finding['secrets'])
                    all_findings['sensitive_paths'].update(finding['sensitive_paths'])
                    all_findings['cloud_urls'].update(finding['cloud_urls'])
        
        # Convert sets to lists for JSON serialization
        all_findings['api_endpoints'] = list(all_findings['api_endpoints'])
        all_findings['sensitive_paths'] = list(all_findings['sensitive_paths'])
        all_findings['cloud_urls'] = list(all_findings['cloud_urls'])
        
        # Report findings
        success(f"Analyzed {all_findings['total_js_files']} JS files")
        
        if all_findings['secrets']:
            warning(f"🚨 Found {len(all_findings['secrets'])} potential SECRETS!")
            for secret in all_findings['secrets'][:5]:
                warning(f"  {secret[:50]}...")
        
        if all_findings['api_endpoints']:
            info(f"Found {len(all_findings['api_endpoints'])} API endpoints")
        
        if all_findings['cloud_urls']:
            info(f"Found {len(all_findings['cloud_urls'])} cloud storage URLs")
        
        # Save results
        import json
        output_file = Path(output_dir) / f"js_analysis_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(all_findings, f, indent=2, default=list)
        
        return all_findings
    
    def analyze(self, hosts: list, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.analyze_async(hosts, output_dir))
