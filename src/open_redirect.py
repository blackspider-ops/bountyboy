"""
Open Redirect Finder Module

Finds open redirect vulnerabilities:
- URL parameter-based redirects
- Header-based redirects
- JavaScript-based redirects
- Meta refresh redirects

WHY OPEN REDIRECTS?
Open redirects allow attackers to:
- Phishing (victim sees trusted domain in URL)
- OAuth token theft
- SSRF chain attacks
- Bypass security filters

Usually MEDIUM severity, but can be HIGH if chained with other vulns.
"""
import asyncio
import aiohttp
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from pathlib import Path
from src.utils import learn, success, error, info, warning, timestamp

class OpenRedirectFinder:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        
        # Common redirect parameters
        self.redirect_params = [
            'url', 'redirect', 'redirect_url', 'redirect_uri', 'redirectUrl',
            'return', 'return_url', 'returnUrl', 'return_to', 'returnTo',
            'next', 'next_url', 'nextUrl', 'goto', 'go', 'to',
            'dest', 'destination', 'target', 'link', 'linkurl',
            'redir', 'rurl', 'r', 'u', 'uri', 'path',
            'continue', 'continueTo', 'forward', 'forwardTo',
            'out', 'outurl', 'checkout_url', 'checkout',
            'image_url', 'img_url', 'load_url', 'file_url',
            'page', 'page_url', 'file', 'reference', 'ref',
            'site', 'html', 'data', 'domain', 'callback',
            'feed', 'host', 'port', 'logout', 'login',
            'view', 'show', 'open', 'window', 'location',
        ]
        
        # Payloads to test
        self.payloads = [
            'https://evil.com',
            '//evil.com',
            '/\\evil.com',
            'https:evil.com',
            '////evil.com',
            'https://evil.com/',
            '//evil.com/%2f..',
            '///evil.com',
            '\\\\evil.com',
            '/\\/evil.com',
            'https://evil.com#',
            'https://evil.com?',
            '//evil%00.com',
            '//evil%0d%0a.com',
            'https://evil.com%00',
            'https://evil.com%0d%0a',
            '//google.com%2f@evil.com',
            '//evil.com\\@google.com',
            'https://expected.com@evil.com',
            'https://evil.com#expected.com',
            'https://evil.com?expected.com',
            '//evil.com/expected.com',
        ]
    
    async def check_redirect(self, session: aiohttp.ClientSession, 
                             url: str, param: str, payload: str) -> dict | None:
        """Check if a URL is vulnerable to open redirect."""
        # Parse URL and add/modify parameter
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        query_params[param] = [payload]
        
        new_query = urlencode(query_params, doseq=True)
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        
        try:
            async with session.get(
                test_url, 
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
                allow_redirects=False  # Don't follow redirects
            ) as resp:
                
                # Check for redirect status codes
                if resp.status in [301, 302, 303, 307, 308]:
                    location = resp.headers.get('Location', '')
                    
                    # Check if redirect goes to our payload
                    if 'evil.com' in location.lower():
                        return {
                            'url': url,
                            'test_url': test_url,
                            'param': param,
                            'payload': payload,
                            'redirect_to': location,
                            'status': resp.status,
                            'type': 'header_redirect',
                            'severity': 'MEDIUM'
                        }
                
                # Check response body for JS/meta redirects
                if resp.status == 200:
                    try:
                        body = await resp.text()
                        body_lower = body.lower()
                        
                        # Check for meta refresh
                        if 'evil.com' in body_lower and 'meta' in body_lower and 'refresh' in body_lower:
                            return {
                                'url': url,
                                'test_url': test_url,
                                'param': param,
                                'payload': payload,
                                'type': 'meta_refresh',
                                'severity': 'MEDIUM'
                            }
                        
                        # Check for JS redirect
                        if 'evil.com' in body_lower and ('window.location' in body_lower or 
                                                          'document.location' in body_lower):
                            return {
                                'url': url,
                                'test_url': test_url,
                                'param': param,
                                'payload': payload,
                                'type': 'javascript_redirect',
                                'severity': 'MEDIUM'
                            }
                    except:
                        pass
        
        except Exception:
            pass
        
        return None
    
    async def find_redirect_endpoints(self, session: aiohttp.ClientSession, 
                                       host: str) -> list:
        """Find potential redirect endpoints on a host."""
        endpoints = []
        
        # Common redirect paths
        paths = [
            '/redirect',
            '/redirect.php',
            '/redir',
            '/out',
            '/outbound',
            '/go',
            '/goto',
            '/link',
            '/url',
            '/return',
            '/logout',
            '/login',
            '/signin',
            '/signout',
            '/external',
            '/leave',
            '/away',
            '/jump',
            '/track',
            '/click',
        ]
        
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{host}"
            
            for path in paths:
                url = f"{base_url}{path}"
                try:
                    async with session.head(url, timeout=aiohttp.ClientTimeout(total=5),
                                           ssl=False, allow_redirects=False) as resp:
                        if resp.status < 500:
                            endpoints.append(url)
                except:
                    pass
            
            # Also test base URL with redirect params
            endpoints.append(base_url)
            
            if endpoints:
                break
        
        return endpoints
    
    async def scan_host(self, session: aiohttp.ClientSession, host: str) -> list:
        """Scan a host for open redirect vulnerabilities."""
        findings = []
        
        # Find potential endpoints
        endpoints = await self.find_redirect_endpoints(session, host)
        
        # Test each endpoint with each param and payload
        for endpoint in endpoints[:5]:  # Limit endpoints per host
            for param in self.redirect_params[:15]:  # Limit params
                for payload in self.payloads[:5]:  # Limit payloads
                    result = await self.check_redirect(session, endpoint, param, payload)
                    if result:
                        findings.append(result)
                        # Found vuln with this param, try next param
                        break
        
        return findings
    
    async def scan_async(self, hosts: list, output_dir: str) -> dict:
        """Scan multiple hosts for open redirect vulnerabilities."""
        learn("Open Redirect",
              "Open redirects let attackers redirect users to malicious sites "
              "while the URL shows a trusted domain. We test:\n\n"
              "• URL parameters (redirect=, url=, next=, etc.)\n"
              "• Various bypass payloads (//evil.com, /\\evil.com)\n"
              "• Header-based redirects (Location header)\n"
              "• JavaScript/meta refresh redirects\n\n"
              "Impact: Phishing, OAuth token theft, SSRF chains.",
              self.learn_mode)
        
        info(f"Scanning {len(hosts)} hosts for open redirects...")
        
        results = {
            'total_hosts': len(hosts),
            'vulnerable': [],
            'by_type': {
                'header_redirect': [],
                'meta_refresh': [],
                'javascript_redirect': []
            }
        }
        
        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(5)  # Limit concurrency
            
            async def scan_with_limit(host):
                async with semaphore:
                    return await self.scan_host(session, host)
            
            tasks = [scan_with_limit(host) for host in hosts[:30]]  # Limit hosts
            all_findings = await asyncio.gather(*tasks, return_exceptions=True)
            
            for findings in all_findings:
                if isinstance(findings, list):
                    for finding in findings:
                        results['vulnerable'].append(finding)
                        rtype = finding.get('type', 'unknown')
                        if rtype in results['by_type']:
                            results['by_type'][rtype].append(finding)
        
        # Report findings
        if results['vulnerable']:
            warning(f"🚨 Found {len(results['vulnerable'])} open redirect vulnerabilities!")
            
            # Deduplicate by URL
            seen = set()
            for vuln in results['vulnerable']:
                key = f"{vuln['url']}:{vuln['param']}"
                if key not in seen:
                    seen.add(key)
                    warning(f"  [{vuln['severity']}] {vuln['url']}")
                    warning(f"      Param: {vuln['param']}, Type: {vuln['type']}")
        else:
            info("No open redirect vulnerabilities found")
        
        # Save results
        import json
        output_file = Path(output_dir) / f"open_redirect_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def scan(self, hosts: list, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.scan_async(hosts, output_dir))
