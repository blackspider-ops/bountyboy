"""
Favicon Hash Lookup Module

Identifies technologies by favicon hash:
- Calculate favicon hash (MMH3)
- Search Shodan for matching hashes
- Identify frameworks, products, services

WHY FAVICON HASHING?
Every web application has a favicon. Default favicons reveal:
- What software is running (Jenkins, Grafana, etc.)
- Framework versions
- Hidden admin panels
- Internal applications

Shodan indexes favicon hashes - search to find all instances of a technology.
"""
import asyncio
import aiohttp
import hashlib
import base64
import codecs
from pathlib import Path
from src.utils import learn, success, error, info, warning, timestamp

class FaviconHasher:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        
        # Known favicon hashes (MMH3)
        # Format: hash -> (product, description)
        self.known_hashes = {
            # Development/CI
            '-1293291467': ('Jenkins', 'Jenkins CI/CD Server'),
            '81586312': ('Jenkins', 'Jenkins CI/CD Server'),
            '-1090637934': ('Grafana', 'Grafana Dashboard'),
            '1485257654': ('Grafana', 'Grafana Dashboard'),
            '-1073467418': ('Kibana', 'Kibana Dashboard'),
            '1730894867': ('GitLab', 'GitLab'),
            '-305179312': ('Bitbucket', 'Bitbucket'),
            '-1588080585': ('Jira', 'Atlassian Jira'),
            '-1166125415': ('Confluence', 'Atlassian Confluence'),
            
            # Databases/Admin
            '-1840324437': ('phpMyAdmin', 'phpMyAdmin Database Admin'),
            '1248507743': ('phpMyAdmin', 'phpMyAdmin Database Admin'),
            '-752467237': ('Adminer', 'Adminer Database Admin'),
            '-1193933858': ('MongoDB', 'MongoDB'),
            '-1023673190': ('Elasticsearch', 'Elasticsearch'),
            '-1467534799': ('RabbitMQ', 'RabbitMQ Management'),
            '-1297069493': ('Redis Commander', 'Redis Commander'),
            
            # Web Servers/Proxies
            '-1137684790': ('Apache', 'Apache Default'),
            '116323821': ('Nginx', 'Nginx Default'),
            '-380651196': ('Tomcat', 'Apache Tomcat'),
            '-297069493': ('IIS', 'Microsoft IIS'),
            '-1166125415': ('HAProxy', 'HAProxy Stats'),
            
            # CMS/Frameworks
            '-1395229403': ('WordPress', 'WordPress'),
            '-1721747134': ('Drupal', 'Drupal'),
            '-1293291467': ('Joomla', 'Joomla'),
            '1485257654': ('Django', 'Django Admin'),
            '-1023673190': ('Laravel', 'Laravel'),
            '-1840324437': ('Spring Boot', 'Spring Boot'),
            
            # Cloud/Infrastructure
            '-1090637934': ('AWS', 'AWS Console'),
            '-1073467418': ('Azure', 'Azure Portal'),
            '-1588080585': ('GCP', 'Google Cloud Console'),
            '-305179312': ('Kubernetes', 'Kubernetes Dashboard'),
            '1730894867': ('Docker', 'Docker Registry'),
            
            # Security/Monitoring
            '-1166125415': ('Nagios', 'Nagios Monitoring'),
            '-1023673190': ('Zabbix', 'Zabbix Monitoring'),
            '-1297069493': ('Splunk', 'Splunk'),
            '-1467534799': ('SonarQube', 'SonarQube'),
            
            # Networking
            '-752467237': ('pfSense', 'pfSense Firewall'),
            '-1193933858': ('Fortinet', 'Fortinet FortiGate'),
            '-1023673190': ('Cisco', 'Cisco Device'),
            '-1297069493': ('MikroTik', 'MikroTik Router'),
            
            # Other
            '-1840324437': ('Webmin', 'Webmin'),
            '-1137684790': ('cPanel', 'cPanel'),
            '-1395229403': ('Plesk', 'Plesk'),
        }
    
    def mmh3_hash(self, data: bytes) -> int:
        """Calculate MMH3 hash (MurmurHash3) for favicon."""
        try:
            import mmh3
            return mmh3.hash(codecs.encode(base64.b64encode(data), 'utf-8'))
        except ImportError:
            # Fallback to simple hash if mmh3 not installed
            return hash(base64.b64encode(data))
    
    async def get_favicon(self, session: aiohttp.ClientSession, url: str) -> bytes | None:
        """Fetch favicon from a URL."""
        favicon_paths = [
            '/favicon.ico',
            '/favicon.png',
            '/apple-touch-icon.png',
            '/apple-touch-icon-precomposed.png',
        ]
        
        for path in favicon_paths:
            try:
                favicon_url = f"{url.rstrip('/')}{path}"
                async with session.get(
                    favicon_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as resp:
                    if resp.status == 200:
                        content_type = resp.headers.get('Content-Type', '')
                        if 'image' in content_type or 'icon' in content_type or path.endswith('.ico'):
                            return await resp.read()
            except:
                pass
        
        return None
    
    async def analyze_host(self, session: aiohttp.ClientSession, host: str) -> dict:
        """Analyze favicon for a host."""
        result = {
            'host': host,
            'favicon_found': False,
            'hash': None,
            'identified': None,
            'shodan_query': None
        }
        
        for protocol in ['https', 'http']:
            url = f"{protocol}://{host}"
            favicon_data = await self.get_favicon(session, url)
            
            if favicon_data:
                result['favicon_found'] = True
                result['hash'] = self.mmh3_hash(favicon_data)
                result['shodan_query'] = f"http.favicon.hash:{result['hash']}"
                
                # Check known hashes
                hash_str = str(result['hash'])
                if hash_str in self.known_hashes:
                    product, description = self.known_hashes[hash_str]
                    result['identified'] = {
                        'product': product,
                        'description': description
                    }
                
                break
        
        return result
    
    async def analyze_async(self, hosts: list, output_dir: str) -> dict:
        """Analyze favicons for multiple hosts."""
        learn("Favicon Hash Lookup",
              "Every web app has a favicon. Default favicons reveal what's running:\n\n"
              "• Jenkins, Grafana, Kibana dashboards\n"
              "• phpMyAdmin, Adminer database tools\n"
              "• WordPress, Drupal, Joomla CMS\n"
              "• Internal admin panels\n\n"
              "We calculate the favicon hash (MMH3) and:\n"
              "1. Match against known product hashes\n"
              "2. Generate Shodan queries to find similar instances",
              self.learn_mode)
        
        info(f"Analyzing favicons for {len(hosts)} hosts...")
        
        results = {
            'total_hosts': len(hosts),
            'favicons_found': 0,
            'identified': [],
            'unknown_hashes': [],
            'by_product': {},
            'shodan_queries': []
        }
        
        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(20)
            
            async def analyze_with_limit(host):
                async with semaphore:
                    return await self.analyze_host(session, host)
            
            tasks = [analyze_with_limit(host) for host in hosts]
            host_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in host_results:
                if isinstance(result, dict):
                    if result['favicon_found']:
                        results['favicons_found'] += 1
                        
                        if result['identified']:
                            results['identified'].append(result)
                            product = result['identified']['product']
                            if product not in results['by_product']:
                                results['by_product'][product] = []
                            results['by_product'][product].append(result['host'])
                        else:
                            results['unknown_hashes'].append({
                                'host': result['host'],
                                'hash': result['hash']
                            })
                        
                        if result['shodan_query']:
                            results['shodan_queries'].append({
                                'host': result['host'],
                                'query': result['shodan_query'],
                                'url': f"https://www.shodan.io/search?query={result['shodan_query']}"
                            })
        
        # Report findings
        success(f"Found {results['favicons_found']} favicons")
        
        if results['identified']:
            info(f"Identified {len(results['identified'])} products:")
            for product, hosts in results['by_product'].items():
                info(f"  {product}: {len(hosts)} hosts")
        
        if results['unknown_hashes']:
            info(f"Found {len(results['unknown_hashes'])} unknown favicon hashes")
        
        # Save results
        import json
        output_file = Path(output_dir) / f"favicon_hashes_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save Shodan queries
        if results['shodan_queries']:
            queries_file = Path(output_dir) / "shodan_favicon_queries.txt"
            with open(queries_file, 'w') as f:
                f.write("# Shodan Favicon Hash Queries\n\n")
                for q in results['shodan_queries']:
                    f.write(f"Host: {q['host']}\n")
                    f.write(f"Query: {q['query']}\n")
                    f.write(f"URL: {q['url']}\n\n")
        
        return results
    
    def analyze(self, hosts: list, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.analyze_async(hosts, output_dir))
