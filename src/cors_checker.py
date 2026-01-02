"""
CORS Misconfiguration Checker

Checks for Cross-Origin Resource Sharing misconfigurations:
- Wildcard origins (Access-Control-Allow-Origin: *)
- Origin reflection (server reflects any origin)
- Null origin allowed
- Credentials with wildcard

WHY CORS MATTERS?
CORS controls which websites can make requests to your API.
Misconfigured CORS = attacker's website can steal user data.

Example attack:
1. User visits attacker.com while logged into target.com
2. attacker.com makes request to target.com/api/user
3. If CORS is misconfigured, attacker gets user's data!

This is usually MEDIUM-HIGH severity depending on what data is exposed.
"""
import asyncio
import aiohttp
from pathlib import Path
from src.utils import learn, success, error, info, warning, timestamp

class CORSChecker:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        
        # Test origins to check
        self.test_origins = [
            'https://evil.com',
            'https://attacker.com',
            'null',
            'https://{target}.evil.com',  # Subdomain bypass attempt
            'https://evil{target}',        # Prefix bypass attempt
            'https://{target}evil.com',    # Suffix bypass attempt
        ]
    
    async def check_cors(self, session: aiohttp.ClientSession, 
                         url: str, origin: str) -> dict | None:
        """Check CORS configuration for a URL with specific origin."""
        headers = {
            'Origin': origin,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            async with session.get(url, headers=headers, 
                                   timeout=aiohttp.ClientTimeout(total=10),
                                   ssl=False, allow_redirects=True) as resp:
                
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                
                if not acao:
                    return None
                
                vulnerability = None
                severity = None
                
                # Check for vulnerabilities
                if acao == '*':
                    vulnerability = 'Wildcard Origin'
                    severity = 'LOW' if acac.lower() != 'true' else 'HIGH'
                
                elif acao == origin:
                    vulnerability = 'Origin Reflection'
                    severity = 'MEDIUM' if acac.lower() != 'true' else 'HIGH'
                
                elif acao == 'null':
                    vulnerability = 'Null Origin Allowed'
                    severity = 'MEDIUM' if acac.lower() != 'true' else 'HIGH'
                
                if vulnerability:
                    return {
                        'url': url,
                        'origin_tested': origin,
                        'acao': acao,
                        'acac': acac,
                        'vulnerability': vulnerability,
                        'severity': severity,
                        'credentials_allowed': acac.lower() == 'true'
                    }
        
        except Exception:
            pass
        
        return None
    
    async def check_host(self, session: aiohttp.ClientSession, 
                         host: str, target: str) -> list:
        """Check a host for CORS misconfigurations."""
        findings = []
        
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{host}"
            
            # Test common API endpoints
            endpoints = [
                '/',
                '/api',
                '/api/v1',
                '/api/user',
                '/api/me',
                '/graphql',
            ]
            
            for endpoint in endpoints:
                url = f"{base_url}{endpoint}"
                
                for origin_template in self.test_origins:
                    origin = origin_template.replace('{target}', target)
                    
                    finding = await self.check_cors(session, url, origin)
                    if finding:
                        findings.append(finding)
                        # Found vuln, no need to test more origins for this endpoint
                        break
        
        return findings
    
    async def check_async(self, hosts: list, target: str, output_dir: str) -> dict:
        """Check multiple hosts for CORS misconfigurations."""
        learn("CORS Misconfiguration",
              "CORS (Cross-Origin Resource Sharing) controls which websites can "
              "make requests to an API. We're testing for:\n\n"
              "• Wildcard (*) - Any website can make requests\n"
              "• Origin Reflection - Server trusts any origin we send\n"
              "• Null Origin - Can be exploited via sandboxed iframes\n"
              "• Credentials + Wildcard - Most dangerous combination\n\n"
              "If misconfigured, an attacker's website can steal user data "
              "when victims visit it while logged into the target.",
              self.learn_mode)
        
        info(f"Checking {len(hosts)} hosts for CORS misconfigurations...")
        
        results = {
            'total_hosts': len(hosts),
            'vulnerable_endpoints': [],
            'by_severity': {'HIGH': [], 'MEDIUM': [], 'LOW': []}
        }
        
        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(10)
            
            async def check_with_limit(host):
                async with semaphore:
                    return await self.check_host(session, host, target)
            
            tasks = [check_with_limit(host) for host in hosts]
            all_findings = await asyncio.gather(*tasks, return_exceptions=True)
            
            for findings in all_findings:
                if isinstance(findings, list):
                    for finding in findings:
                        results['vulnerable_endpoints'].append(finding)
                        severity = finding['severity']
                        results['by_severity'][severity].append(finding)
        
        # Report findings
        total_vulns = len(results['vulnerable_endpoints'])
        if total_vulns > 0:
            warning(f"🚨 Found {total_vulns} CORS misconfigurations!")
            
            for severity in ['HIGH', 'MEDIUM', 'LOW']:
                vulns = results['by_severity'][severity]
                if vulns:
                    warning(f"\n  [{severity}] {len(vulns)} endpoints:")
                    for v in vulns[:3]:  # Show first 3
                        warning(f"    {v['url']} - {v['vulnerability']}")
                    if len(vulns) > 3:
                        warning(f"    ... and {len(vulns) - 3} more")
        else:
            info("No CORS misconfigurations found")
        
        # Save results
        import json
        output_file = Path(output_dir) / f"cors_check_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def check(self, hosts: list, target: str, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.check_async(hosts, target, output_dir))
