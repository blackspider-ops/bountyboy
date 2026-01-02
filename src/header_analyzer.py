"""
Security Headers Analyzer

Checks for missing or misconfigured security headers:
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security (HSTS)
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy

WHY SECURITY HEADERS?
Missing headers = easier attacks:
- No CSP = easier XSS exploitation
- No X-Frame-Options = clickjacking possible
- No HSTS = downgrade attacks possible

These are usually LOW-MEDIUM severity but easy to find and report.
Good for building reputation on bug bounty platforms.
"""
import asyncio
import aiohttp
from pathlib import Path
from src.utils import learn, success, error, info, warning, timestamp

class HeaderAnalyzer:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        
        # Security headers to check
        self.security_headers = {
            'Strict-Transport-Security': {
                'description': 'HSTS - Forces HTTPS connections',
                'severity': 'MEDIUM',
                'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
            },
            'Content-Security-Policy': {
                'description': 'CSP - Prevents XSS and injection attacks',
                'severity': 'MEDIUM',
                'recommendation': 'Implement a strict CSP policy'
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking attacks',
                'severity': 'LOW',
                'recommendation': 'Add: X-Frame-Options: DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME type sniffing',
                'severity': 'LOW',
                'recommendation': 'Add: X-Content-Type-Options: nosniff'
            },
            'X-XSS-Protection': {
                'description': 'Legacy XSS filter (deprecated but still useful)',
                'severity': 'INFO',
                'recommendation': 'Add: X-XSS-Protection: 1; mode=block'
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information leakage',
                'severity': 'LOW',
                'recommendation': 'Add: Referrer-Policy: strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'description': 'Controls browser features (camera, mic, etc.)',
                'severity': 'INFO',
                'recommendation': 'Implement Permissions-Policy to restrict features'
            }
        }
        
        # Dangerous headers that shouldn't be present
        self.dangerous_headers = {
            'Server': {
                'description': 'Reveals server software version',
                'severity': 'INFO',
                'recommendation': 'Remove or obfuscate Server header'
            },
            'X-Powered-By': {
                'description': 'Reveals technology stack',
                'severity': 'INFO',
                'recommendation': 'Remove X-Powered-By header'
            },
            'X-AspNet-Version': {
                'description': 'Reveals ASP.NET version',
                'severity': 'LOW',
                'recommendation': 'Remove X-AspNet-Version header'
            },
            'X-AspNetMvc-Version': {
                'description': 'Reveals ASP.NET MVC version',
                'severity': 'LOW',
                'recommendation': 'Remove X-AspNetMvc-Version header'
            }
        }
    
    async def analyze_host(self, session: aiohttp.ClientSession, host: str) -> dict:
        """Analyze security headers for a host."""
        result = {
            'host': host,
            'missing_headers': [],
            'present_headers': [],
            'dangerous_headers': [],
            'score': 0,
            'max_score': len(self.security_headers)
        }
        
        for protocol in ['https', 'http']:
            url = f"{protocol}://{host}"
            
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                       ssl=False, allow_redirects=True) as resp:
                    
                    headers = resp.headers
                    
                    # Check for missing security headers
                    for header, info in self.security_headers.items():
                        if header in headers or header.lower() in [h.lower() for h in headers]:
                            result['present_headers'].append({
                                'header': header,
                                'value': headers.get(header, headers.get(header.lower(), '')),
                                'description': info['description']
                            })
                            result['score'] += 1
                        else:
                            result['missing_headers'].append({
                                'header': header,
                                'severity': info['severity'],
                                'description': info['description'],
                                'recommendation': info['recommendation']
                            })
                    
                    # Check for dangerous headers
                    for header, info in self.dangerous_headers.items():
                        value = headers.get(header, headers.get(header.lower(), ''))
                        if value:
                            result['dangerous_headers'].append({
                                'header': header,
                                'value': value,
                                'severity': info['severity'],
                                'description': info['description'],
                                'recommendation': info['recommendation']
                            })
                    
                    break  # Success, no need to try other protocol
                    
            except Exception:
                continue
        
        return result
    
    async def analyze_async(self, hosts: list, output_dir: str) -> dict:
        """Analyze security headers for multiple hosts."""
        learn("Security Headers",
              "HTTP security headers tell browsers how to behave securely. "
              "Missing headers make attacks easier:\n\n"
              "• No CSP → XSS attacks are easier\n"
              "• No X-Frame-Options → Clickjacking possible\n"
              "• No HSTS → Man-in-the-middle attacks\n"
              "• Server header → Reveals software versions\n\n"
              "These are usually LOW-MEDIUM severity but easy wins. "
              "Good for building reputation on platforms.",
              self.learn_mode)
        
        info(f"Analyzing security headers for {len(hosts)} hosts...")
        
        results = {
            'total_hosts': len(hosts),
            'hosts_analyzed': 0,
            'average_score': 0,
            'common_missing': {},
            'by_host': []
        }
        
        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(20)
            
            async def analyze_with_limit(host):
                async with semaphore:
                    return await self.analyze_host(session, host)
            
            tasks = [analyze_with_limit(host) for host in hosts]
            host_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            total_score = 0
            for result in host_results:
                if isinstance(result, dict) and result.get('score') is not None:
                    results['by_host'].append(result)
                    results['hosts_analyzed'] += 1
                    total_score += result['score']
                    
                    # Track common missing headers
                    for missing in result['missing_headers']:
                        header = missing['header']
                        results['common_missing'][header] = results['common_missing'].get(header, 0) + 1
            
            if results['hosts_analyzed'] > 0:
                results['average_score'] = total_score / results['hosts_analyzed']
        
        # Report findings
        success(f"Analyzed {results['hosts_analyzed']} hosts")
        info(f"Average security score: {results['average_score']:.1f}/{len(self.security_headers)}")
        
        if results['common_missing']:
            warning("Most commonly missing headers:")
            sorted_missing = sorted(results['common_missing'].items(), key=lambda x: -x[1])
            for header, count in sorted_missing[:5]:
                pct = (count / results['hosts_analyzed']) * 100
                warning(f"  {header}: missing on {count} hosts ({pct:.0f}%)")
        
        # Save results
        import json
        output_file = Path(output_dir) / f"headers_analysis_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def analyze(self, hosts: list, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.analyze_async(hosts, output_dir))
