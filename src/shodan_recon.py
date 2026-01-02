"""
Shodan Reconnaissance Module

Queries Shodan for exposed services and vulnerabilities:
- Open ports and services
- Known vulnerabilities (CVEs)
- SSL certificate info
- Technology detection
- Exposed databases, admin panels

WHY SHODAN?
Shodan scans the entire internet and indexes everything.
Instead of scanning yourself (slow, might get blocked),
query Shodan's database for instant results.

Finds things like:
- MongoDB without auth
- Elasticsearch exposed
- Jenkins/Kibana dashboards
- Old Apache/nginx versions with CVEs
"""
import asyncio
import aiohttp
from pathlib import Path
from src.utils import learn, success, error, info, warning, timestamp

class ShodanRecon:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        self.api_key = config.get('shodan', {}).get('api_key', '')
        self.base_url = "https://api.shodan.io"
    
    async def search_host(self, session: aiohttp.ClientSession, ip: str) -> dict | None:
        """Query Shodan for a specific IP."""
        if not self.api_key:
            return None
        
        try:
            url = f"{self.base_url}/shodan/host/{ip}?key={self.api_key}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception:
            pass
        return None
    
    async def search_domain(self, session: aiohttp.ClientSession, domain: str) -> dict | None:
        """Query Shodan for domain info."""
        if not self.api_key:
            return None
        
        try:
            url = f"{self.base_url}/dns/domain/{domain}?key={self.api_key}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception:
            pass
        return None
    
    async def search_query(self, session: aiohttp.ClientSession, query: str) -> dict | None:
        """Run a Shodan search query."""
        if not self.api_key:
            return None
        
        try:
            url = f"{self.base_url}/shodan/host/search?key={self.api_key}&query={query}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception:
            pass
        return None
    
    def generate_dorks(self, target: str) -> list:
        """Generate Shodan dork queries for a target."""
        return [
            f'hostname:"{target}"',
            f'ssl.cert.subject.cn:"{target}"',
            f'org:"{target}"',
            f'hostname:"{target}" port:22',
            f'hostname:"{target}" port:3389',
            f'hostname:"{target}" port:21',
            f'hostname:"{target}" "MongoDB"',
            f'hostname:"{target}" "Elasticsearch"',
            f'hostname:"{target}" product:"Apache"',
            f'hostname:"{target}" product:"nginx"',
            f'hostname:"{target}" vuln:',
            f'hostname:"{target}" http.title:"Dashboard"',
            f'hostname:"{target}" http.title:"Admin"',
            f'hostname:"{target}" http.title:"Login"',
        ]
    
    async def recon_async(self, target: str, output_dir: str) -> dict:
        """Run Shodan reconnaissance."""
        learn("Shodan Reconnaissance",
              "Shodan is a search engine for internet-connected devices. "
              "It continuously scans the internet and indexes:\n"
              "• Open ports and services\n"
              "• Software versions\n"
              "• Known vulnerabilities (CVEs)\n"
              "• SSL certificates\n"
              "• Banners and responses\n\n"
              "Instead of scanning (slow, detectable), we query Shodan's database.",
              self.learn_mode)
        
        results = {
            'target': target,
            'has_api_key': bool(self.api_key),
            'domain_info': None,
            'hosts': [],
            'vulnerabilities': [],
            'interesting_services': [],
            'dork_urls': []
        }
        
        if not self.api_key:
            warning("No Shodan API key configured")
            info("Get free API key at: https://shodan.io")
            info("Add to config.yaml: shodan.api_key")
            
            # Generate dork URLs for manual search
            dorks = self.generate_dorks(target)
            for dork in dorks:
                results['dork_urls'].append({
                    'query': dork,
                    'url': f"https://www.shodan.io/search?query={dork.replace(' ', '+')}"
                })
            
            info(f"Generated {len(dorks)} Shodan dork URLs for manual search")
            
            # Save dorks
            output_file = Path(output_dir) / f"shodan_dorks_{timestamp()}.txt"
            with open(output_file, 'w') as f:
                f.write(f"# Shodan Dorks for {target}\n\n")
                for dork in results['dork_urls']:
                    f.write(f"Query: {dork['query']}\n")
                    f.write(f"URL: {dork['url']}\n\n")
            
            return results
        
        info(f"Querying Shodan for {target}...")
        
        async with aiohttp.ClientSession() as session:
            # Get domain info
            domain_info = await self.search_domain(session, target)
            if domain_info:
                results['domain_info'] = domain_info
                success(f"Found {len(domain_info.get('subdomains', []))} subdomains in Shodan")
            
            # Search for hosts
            search_result = await self.search_query(session, f'hostname:"{target}"')
            if search_result:
                results['hosts'] = search_result.get('matches', [])
                success(f"Found {len(results['hosts'])} hosts")
                
                # Extract vulnerabilities and interesting services
                for host in results['hosts']:
                    # Check for vulns
                    vulns = host.get('vulns', [])
                    if vulns:
                        for vuln in vulns:
                            results['vulnerabilities'].append({
                                'ip': host.get('ip_str'),
                                'port': host.get('port'),
                                'cve': vuln
                            })
                    
                    # Check for interesting services
                    product = host.get('product', '')
                    port = host.get('port')
                    
                    interesting_ports = [21, 22, 23, 25, 3306, 5432, 27017, 6379, 9200, 11211]
                    interesting_products = ['mongodb', 'elasticsearch', 'redis', 'memcached', 
                                           'jenkins', 'kibana', 'grafana', 'phpmyadmin']
                    
                    if port in interesting_ports or any(p in product.lower() for p in interesting_products):
                        results['interesting_services'].append({
                            'ip': host.get('ip_str'),
                            'port': port,
                            'product': product,
                            'version': host.get('version', '')
                        })
        
        # Report findings
        if results['vulnerabilities']:
            warning(f"🚨 Found {len(results['vulnerabilities'])} CVEs!")
            for vuln in results['vulnerabilities'][:5]:
                warning(f"  {vuln['ip']}:{vuln['port']} - {vuln['cve']}")
        
        if results['interesting_services']:
            info(f"Found {len(results['interesting_services'])} interesting services")
            for svc in results['interesting_services'][:5]:
                info(f"  {svc['ip']}:{svc['port']} - {svc['product']} {svc['version']}")
        
        # Save results
        import json
        output_file = Path(output_dir) / f"shodan_recon_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def recon(self, target: str, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.recon_async(target, output_dir))
