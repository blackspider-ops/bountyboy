"""
Subdomain Takeover Checker

Checks if subdomains are vulnerable to takeover:
- Dangling DNS records pointing to deprovisioned services
- Unclaimed S3 buckets, Azure blobs, GitHub pages
- Expired Heroku apps, Shopify stores, etc.

WHY SUBDOMAIN TAKEOVER?
Company sets up blog.target.com → Heroku
Company cancels Heroku but forgets to remove DNS record
Attacker claims the Heroku app name
Now attacker controls blog.target.com!

This is usually HIGH/CRITICAL severity. Easy to find, easy to exploit.
"""
import asyncio
import aiohttp
import dns.resolver
from pathlib import Path
from src.utils import learn, success, error, info, warning, timestamp

class SubdomainTakeoverChecker:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        
        # Fingerprints for vulnerable services
        # Format: (cname_pattern, response_fingerprint, service_name)
        self.fingerprints = {
            # Cloud Providers
            's3': {
                'cnames': ['.s3.amazonaws.com', '.s3-website'],
                'fingerprints': ['NoSuchBucket', 'The specified bucket does not exist'],
                'service': 'AWS S3'
            },
            'azure': {
                'cnames': ['.azurewebsites.net', '.cloudapp.azure.com', '.azure-api.net', 
                          '.azurecontainer.io', '.blob.core.windows.net'],
                'fingerprints': ['404 Web Site not found', 'The resource you are looking for has been removed'],
                'service': 'Microsoft Azure'
            },
            'gcp': {
                'cnames': ['.storage.googleapis.com', '.appspot.com'],
                'fingerprints': ['The requested URL was not found on this server'],
                'service': 'Google Cloud'
            },
            
            # Hosting/PaaS
            'heroku': {
                'cnames': ['.herokuapp.com', '.herokudns.com'],
                'fingerprints': ['No such app', "There's nothing here, yet", 'herokucdn.com/error-pages'],
                'service': 'Heroku'
            },
            'github': {
                'cnames': ['.github.io', '.githubusercontent.com'],
                'fingerprints': ["There isn't a GitHub Pages site here", '404 - File not found'],
                'service': 'GitHub Pages'
            },
            'netlify': {
                'cnames': ['.netlify.app', '.netlify.com'],
                'fingerprints': ['Not Found - Request ID'],
                'service': 'Netlify'
            },
            'vercel': {
                'cnames': ['.vercel.app', '.now.sh'],
                'fingerprints': ['The deployment could not be found'],
                'service': 'Vercel'
            },
            'surge': {
                'cnames': ['.surge.sh'],
                'fingerprints': ['project not found'],
                'service': 'Surge.sh'
            },
            
            # E-commerce/CMS
            'shopify': {
                'cnames': ['.myshopify.com'],
                'fingerprints': ['Sorry, this shop is currently unavailable', 'Only one step left'],
                'service': 'Shopify'
            },
            'tumblr': {
                'cnames': ['.tumblr.com'],
                'fingerprints': ["There's nothing here", "Whatever you were looking for doesn't currently exist"],
                'service': 'Tumblr'
            },
            'wordpress': {
                'cnames': ['.wordpress.com'],
                'fingerprints': ["doesn't exist"],
                'service': 'WordPress.com'
            },
            
            # Other Services
            'zendesk': {
                'cnames': ['.zendesk.com'],
                'fingerprints': ['Help Center Closed', 'this help center no longer exists'],
                'service': 'Zendesk'
            },
            'freshdesk': {
                'cnames': ['.freshdesk.com'],
                'fingerprints': ['We could not find what you were looking for'],
                'service': 'Freshdesk'
            },
            'unbounce': {
                'cnames': ['.unbounce.com'],
                'fingerprints': ['The requested URL was not found on this server'],
                'service': 'Unbounce'
            },
            'fastly': {
                'cnames': ['.fastly.net'],
                'fingerprints': ['Fastly error: unknown domain'],
                'service': 'Fastly'
            },
            'pantheon': {
                'cnames': ['.pantheonsite.io'],
                'fingerprints': ['The gods are wise', '404 error unknown site'],
                'service': 'Pantheon'
            },
            'cargo': {
                'cnames': ['.cargocollective.com'],
                'fingerprints': ['404 Not Found'],
                'service': 'Cargo'
            },
            'feedpress': {
                'cnames': ['.redirect.feedpress.me'],
                'fingerprints': ['The feed has not been found'],
                'service': 'FeedPress'
            },
            'ghost': {
                'cnames': ['.ghost.io'],
                'fingerprints': ['The thing you were looking for is no longer here'],
                'service': 'Ghost'
            },
            'helpjuice': {
                'cnames': ['.helpjuice.com'],
                'fingerprints': ['We could not find what you were looking for'],
                'service': 'Helpjuice'
            },
            'helpscout': {
                'cnames': ['.helpscoutdocs.com'],
                'fingerprints': ['No settings were found for this company'],
                'service': 'HelpScout'
            },
            'intercom': {
                'cnames': ['.custom.intercom.help'],
                'fingerprints': ['This page is reserved for artistic dogs', "Uh oh. That page doesn't exist"],
                'service': 'Intercom'
            },
            'landingi': {
                'cnames': ['.landingi.com'],
                'fingerprints': ['It looks like you'],
                'service': 'Landingi'
            },
            'ngrok': {
                'cnames': ['.ngrok.io'],
                'fingerprints': ['ngrok.io not found', 'Tunnel .*.ngrok.io not found'],
                'service': 'ngrok'
            },
            'pingdom': {
                'cnames': ['.stats.pingdom.com'],
                'fingerprints': ['This public report page has not been activated by the user'],
                'service': 'Pingdom'
            },
            'readme': {
                'cnames': ['.readme.io'],
                'fingerprints': ['Project doesnt exist'],
                'service': 'Readme.io'
            },
            'statuspage': {
                'cnames': ['.statuspage.io'],
                'fingerprints': ['You are being redirected', 'Status page pushed a b]'],
                'service': 'Statuspage'
            },
            'tilda': {
                'cnames': ['.tilda.ws'],
                'fingerprints': ['Please renew your subscription'],
                'service': 'Tilda'
            },
            'uservoice': {
                'cnames': ['.uservoice.com'],
                'fingerprints': ['This UserVoice subdomain is currently available'],
                'service': 'UserVoice'
            },
            'webflow': {
                'cnames': ['.webflow.io'],
                'fingerprints': ["The page you are looking for doesn't exist or has been moved"],
                'service': 'Webflow'
            },
        }
    
    async def get_cname(self, subdomain: str) -> str | None:
        """Get CNAME record for a subdomain."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            answers = resolver.resolve(subdomain, 'CNAME')
            for rdata in answers:
                return str(rdata.target).rstrip('.')
        except:
            pass
        return None
    
    async def check_response(self, session: aiohttp.ClientSession, 
                             url: str, fingerprints: list) -> bool:
        """Check if response contains vulnerability fingerprint."""
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                   ssl=False, allow_redirects=True) as resp:
                text = await resp.text()
                for fp in fingerprints:
                    if fp.lower() in text.lower():
                        return True
        except:
            pass
        return False
    
    async def check_subdomain(self, session: aiohttp.ClientSession, 
                              subdomain: str) -> dict | None:
        """Check a single subdomain for takeover vulnerability."""
        cname = await self.get_cname(subdomain)
        
        if not cname:
            return None
        
        # Check against fingerprints
        for service_id, service_info in self.fingerprints.items():
            for cname_pattern in service_info['cnames']:
                if cname_pattern in cname.lower():
                    # Found matching CNAME, check response
                    for protocol in ['https', 'http']:
                        url = f"{protocol}://{subdomain}"
                        if await self.check_response(session, url, service_info['fingerprints']):
                            return {
                                'subdomain': subdomain,
                                'cname': cname,
                                'service': service_info['service'],
                                'vulnerable': True,
                                'severity': 'HIGH'
                            }
                    
                    # CNAME matches but no fingerprint - might still be interesting
                    return {
                        'subdomain': subdomain,
                        'cname': cname,
                        'service': service_info['service'],
                        'vulnerable': False,
                        'note': 'CNAME points to service but no vulnerability fingerprint found'
                    }
        
        return None
    
    async def check_async(self, subdomains: list, output_dir: str) -> dict:
        """Check multiple subdomains for takeover vulnerabilities."""
        learn("Subdomain Takeover",
              "We're checking if any subdomains point to services that can be claimed. "
              "How it works:\n"
              "1. Company creates blog.target.com → points to Heroku\n"
              "2. Company stops using Heroku but forgets DNS record\n"
              "3. Attacker claims the Heroku app name\n"
              "4. Attacker now controls blog.target.com!\n\n"
              "This is usually HIGH/CRITICAL severity. We check CNAME records "
              "and look for 'dangling' pointers to unclaimed services.",
              self.learn_mode)
        
        info(f"Checking {len(subdomains)} subdomains for takeover vulnerabilities...")
        
        results = {
            'total_checked': len(subdomains),
            'vulnerable': [],
            'interesting': [],
            'services_found': {}
        }
        
        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(20)
            
            async def check_with_limit(subdomain):
                async with semaphore:
                    return await self.check_subdomain(session, subdomain)
            
            tasks = [check_with_limit(sub) for sub in subdomains]
            findings = await asyncio.gather(*tasks, return_exceptions=True)
            
            for finding in findings:
                if isinstance(finding, dict):
                    service = finding['service']
                    results['services_found'][service] = results['services_found'].get(service, 0) + 1
                    
                    if finding.get('vulnerable'):
                        results['vulnerable'].append(finding)
                    else:
                        results['interesting'].append(finding)
        
        # Report findings
        if results['vulnerable']:
            warning(f"🚨 Found {len(results['vulnerable'])} VULNERABLE subdomains!")
            for vuln in results['vulnerable']:
                warning(f"  [{vuln['severity']}] {vuln['subdomain']} → {vuln['service']}")
        else:
            info("No vulnerable subdomains found")
        
        if results['services_found']:
            info("Services detected:")
            for service, count in results['services_found'].items():
                info(f"  {service}: {count}")
        
        # Save results
        import json
        output_file = Path(output_dir) / f"takeover_check_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def check(self, subdomains: list, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.check_async(subdomains, output_dir))
