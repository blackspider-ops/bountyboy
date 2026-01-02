"""
XSS (Cross-Site Scripting) Scanner Module

Basic XSS detection through reflection testing:
- Reflected XSS detection
- DOM-based XSS indicators
- Context-aware payload testing

WHY XSS SCANNING?
XSS allows attackers to:
- Steal session cookies
- Perform actions as the victim
- Redirect users to malicious sites
- Deface websites

This is a BASIC scanner for finding obvious XSS.
For thorough testing, manual verification is required.
"""
import asyncio
import aiohttp
import re
import html
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, quote
from pathlib import Path
from src.utils import learn, success, error, info, warning, timestamp

class XSSScanner:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        
        # Unique identifier for our payloads
        self.canary = "XSS7331"
        
        # Basic XSS payloads
        self.payloads = [
            # Basic script tags
            f'<script>alert("{self.canary}")</script>',
            f'<script>alert(\'{self.canary}\')</script>',
            f'<ScRiPt>alert("{self.canary}")</ScRiPt>',
            
            # Event handlers
            f'<img src=x onerror=alert("{self.canary}")>',
            f'<svg onload=alert("{self.canary}")>',
            f'<body onload=alert("{self.canary}")>',
            f'<input onfocus=alert("{self.canary}") autofocus>',
            f'<marquee onstart=alert("{self.canary}")>',
            f'<video><source onerror=alert("{self.canary}")>',
            f'<details open ontoggle=alert("{self.canary}")>',
            
            # Without quotes
            f'<img src=x onerror=alert({self.canary})>',
            f'<svg/onload=alert({self.canary})>',
            
            # Encoded
            f'<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
            
            # Breaking out of attributes
            f'"><script>alert("{self.canary}")</script>',
            f"'><script>alert('{self.canary}')</script>",
            f'"><img src=x onerror=alert("{self.canary}")>',
            f"'><img src=x onerror=alert('{self.canary}')>",
            
            # Breaking out of JS strings
            f"';alert('{self.canary}');//",
            f'";alert("{self.canary}");//',
            f"'-alert('{self.canary}')-'",
            f'"-alert("{self.canary}")-"',
            
            # Template literals
            f'${{alert("{self.canary}")}}',
            
            # HTML entities bypass
            f'&lt;script&gt;alert("{self.canary}")&lt;/script&gt;',
        ]
        
        # Simpler payloads for reflection testing
        self.reflection_tests = [
            f'{self.canary}',
            f'<{self.canary}>',
            f'"{self.canary}"',
            f"'{self.canary}'",
            f'</{self.canary}>',
        ]
        
        # Patterns indicating XSS
        self.xss_patterns = [
            rf'<script[^>]*>.*?{self.canary}.*?</script>',
            rf'onerror\s*=\s*["\']?[^"\']*{self.canary}',
            rf'onload\s*=\s*["\']?[^"\']*{self.canary}',
            rf'onclick\s*=\s*["\']?[^"\']*{self.canary}',
            rf'<img[^>]*{self.canary}[^>]*>',
            rf'<svg[^>]*{self.canary}[^>]*>',
        ]
        
        self.compiled_patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.xss_patterns]
    
    def analyze_reflection(self, response_text: str, payload: str) -> dict:
        """Analyze how a payload is reflected in the response."""
        result = {
            'reflected': False,
            'encoded': False,
            'context': None,
            'dangerous': False
        }
        
        # Check if canary is in response
        if self.canary not in response_text:
            return result
        
        result['reflected'] = True
        
        # Check if HTML encoded
        if html.escape(self.canary) in response_text and self.canary not in response_text.replace(html.escape(self.canary), ''):
            result['encoded'] = True
            return result
        
        # Check context
        response_lower = response_text.lower()
        canary_pos = response_lower.find(self.canary.lower())
        
        if canary_pos > 0:
            # Get surrounding context
            start = max(0, canary_pos - 50)
            end = min(len(response_text), canary_pos + len(self.canary) + 50)
            context = response_text[start:end]
            
            # Determine context
            if '<script' in context.lower():
                result['context'] = 'javascript'
                result['dangerous'] = True
            elif 'href=' in context.lower() or 'src=' in context.lower():
                result['context'] = 'attribute'
                result['dangerous'] = True
            elif '<' in context and '>' in context:
                result['context'] = 'html'
                result['dangerous'] = True
            else:
                result['context'] = 'text'
        
        # Check for XSS patterns
        for pattern in self.compiled_patterns:
            if pattern.search(response_text):
                result['dangerous'] = True
                break
        
        return result
    
    async def test_parameter(self, session: aiohttp.ClientSession,
                             url: str, param: str, original_value: str) -> dict | None:
        """Test a parameter for XSS."""
        parsed = urlparse(url)
        
        # First, test simple reflection
        for test in self.reflection_tests:
            query_params = parse_qs(parsed.query)
            query_params[param] = [test]
            
            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            try:
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as resp:
                    text = await resp.text()
                    
                    analysis = self.analyze_reflection(text, test)
                    
                    if analysis['reflected'] and not analysis['encoded']:
                        # Reflection found, now test actual payloads
                        for payload in self.payloads[:10]:
                            query_params[param] = [payload]
                            new_query = urlencode(query_params, doseq=True)
                            payload_url = urlunparse((
                                parsed.scheme, parsed.netloc, parsed.path,
                                parsed.params, new_query, parsed.fragment
                            ))
                            
                            try:
                                async with session.get(
                                    payload_url,
                                    timeout=aiohttp.ClientTimeout(total=10),
                                    ssl=False
                                ) as payload_resp:
                                    payload_text = await payload_resp.text()
                                    
                                    # Check if payload is reflected unencoded
                                    if self.canary in payload_text:
                                        # Check for dangerous patterns
                                        for pattern in self.compiled_patterns:
                                            if pattern.search(payload_text):
                                                return {
                                                    'url': url,
                                                    'test_url': payload_url,
                                                    'param': param,
                                                    'payload': payload,
                                                    'context': analysis['context'],
                                                    'type': 'reflected_xss',
                                                    'severity': 'HIGH' if analysis['dangerous'] else 'MEDIUM'
                                                }
                            except:
                                pass
                        
                        # Even if no dangerous pattern, report reflection
                        if analysis['dangerous']:
                            return {
                                'url': url,
                                'param': param,
                                'context': analysis['context'],
                                'type': 'potential_xss',
                                'severity': 'MEDIUM',
                                'note': 'Input reflected without encoding - manual verification needed'
                            }
            
            except Exception:
                pass
        
        return None
    
    async def scan_url(self, session: aiohttp.ClientSession, url: str) -> list:
        """Scan a URL for XSS vulnerabilities."""
        findings = []
        
        parsed = urlparse(url)
        if not parsed.query:
            return findings
        
        query_params = parse_qs(parsed.query)
        
        for param, values in query_params.items():
            original_value = values[0] if values else ''
            
            result = await self.test_parameter(session, url, param, original_value)
            if result:
                findings.append(result)
        
        return findings
    
    async def scan_async(self, urls: list, output_dir: str) -> dict:
        """Scan multiple URLs for XSS vulnerabilities."""
        learn("XSS Scanning",
              "We're testing for Cross-Site Scripting (XSS):\n\n"
              "• Reflected XSS: Input reflected in response\n"
              "• Context detection: HTML, JS, attribute contexts\n"
              "• Encoding bypass: Check if input is sanitized\n\n"
              "What we're looking for:\n"
              "• Unencoded reflection of our payloads\n"
              "• Script tags or event handlers in response\n\n"
              "⚠️ This is basic scanning. Manual verification required.",
              self.learn_mode)
        
        info(f"Scanning {len(urls)} URLs for XSS...")
        
        results = {
            'total_urls': len(urls),
            'vulnerable': [],
            'by_severity': {
                'HIGH': [],
                'MEDIUM': [],
                'LOW': []
            }
        }
        
        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(5)
            
            async def scan_with_limit(url):
                async with semaphore:
                    return await self.scan_url(session, url)
            
            tasks = [scan_with_limit(url) for url in urls[:100]]
            all_findings = await asyncio.gather(*tasks, return_exceptions=True)
            
            for findings in all_findings:
                if isinstance(findings, list):
                    for finding in findings:
                        results['vulnerable'].append(finding)
                        severity = finding.get('severity', 'MEDIUM')
                        if severity in results['by_severity']:
                            results['by_severity'][severity].append(finding)
        
        # Report findings
        if results['vulnerable']:
            warning(f"🚨 Found {len(results['vulnerable'])} potential XSS vulnerabilities!")
            
            for vuln in results['vulnerable'][:10]:
                warning(f"  [{vuln['severity']}] {vuln['type']}")
                warning(f"      URL: {vuln['url']}")
                warning(f"      Param: {vuln['param']}")
                if vuln.get('context'):
                    warning(f"      Context: {vuln['context']}")
        else:
            info("No XSS vulnerabilities found")
        
        # Save results
        import json
        output_file = Path(output_dir) / f"xss_scan_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def scan(self, urls: list, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.scan_async(urls, output_dir))
