"""
Wayback Machine Module

Queries the Wayback Machine (web.archive.org) to find:
- Old URLs that might still work
- Forgotten endpoints
- Historical parameters
- Removed but still accessible pages

WHY WAYBACK?
Companies remove pages but forget to actually delete them from the server.
The Wayback Machine remembers everything. Old admin panels, old API versions,
debug endpoints that were "removed" - they might still be there.

Also finds URL parameters that were used historically. These parameters
might still be processed by the server even if not shown in the current UI.
"""
import asyncio
import aiohttp
import json
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode
from collections import defaultdict
from src.utils import learn, success, error, info, warning, timestamp

class WaybackAnalyzer:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        self.cdx_api = "https://web.archive.org/cdx/search/cdx"
    
    async def fetch_wayback_urls(self, session: aiohttp.ClientSession, 
                                  domain: str, limit: int = 10000) -> list:
        """Fetch URLs from Wayback Machine CDX API."""
        params = {
            'url': f'*.{domain}/*',
            'output': 'json',
            'fl': 'original,timestamp,statuscode,mimetype',
            'filter': 'statuscode:200',
            'collapse': 'urlkey',
            'limit': limit
        }
        
        try:
            async with session.get(self.cdx_api, params=params,
                                   timeout=aiohttp.ClientTimeout(total=60)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data and len(data) > 1:
                        # First row is headers
                        return data[1:]
        except Exception as e:
            error(f"Wayback fetch failed: {e}")
        return []
    
    def extract_parameters(self, urls: list) -> dict:
        """Extract unique parameters from URLs."""
        params_by_path = defaultdict(set)
        
        for url_data in urls:
            url = url_data[0] if isinstance(url_data, list) else url_data
            parsed = urlparse(url)
            
            if parsed.query:
                params = parse_qs(parsed.query)
                path = parsed.path
                for param in params.keys():
                    params_by_path[path].add(param)
        
        return {path: list(params) for path, params in params_by_path.items()}
    
    def categorize_urls(self, urls: list) -> dict:
        """Categorize URLs by type/interest level."""
        categories = {
            'admin': [],
            'api': [],
            'backup': [],
            'config': [],
            'debug': [],
            'upload': [],
            'auth': [],
            'interesting': [],
            'all': []
        }
        
        patterns = {
            'admin': ['admin', 'dashboard', 'manage', 'control', 'panel'],
            'api': ['api', '/v1/', '/v2/', '/v3/', 'graphql', 'rest'],
            'backup': ['backup', '.bak', '.old', '.save', 'copy'],
            'config': ['config', 'settings', 'setup', '.env', '.ini', '.conf'],
            'debug': ['debug', 'test', 'dev', 'staging', 'sandbox'],
            'upload': ['upload', 'file', 'attach', 'import'],
            'auth': ['login', 'auth', 'signin', 'register', 'password', 'token']
        }
        
        seen = set()
        for url_data in urls:
            url = url_data[0] if isinstance(url_data, list) else url_data
            
            # Skip duplicates
            parsed = urlparse(url)
            url_key = f"{parsed.netloc}{parsed.path}"
            if url_key in seen:
                continue
            seen.add(url_key)
            
            url_lower = url.lower()
            categorized = False
            
            for category, keywords in patterns.items():
                if any(kw in url_lower for kw in keywords):
                    categories[category].append(url)
                    categorized = True
                    break
            
            if not categorized and '?' in url:
                # URLs with parameters are interesting
                categories['interesting'].append(url)
            
            categories['all'].append(url)
        
        return categories
    
    async def check_url_alive(self, session: aiohttp.ClientSession, url: str) -> bool:
        """Check if a historical URL is still accessible."""
        try:
            async with session.head(url, timeout=aiohttp.ClientTimeout(total=5),
                                    ssl=False, allow_redirects=True) as resp:
                return resp.status == 200
        except:
            return False
    
    async def analyze_domain(self, domain: str, output_dir: str) -> dict:
        """Analyze a domain using Wayback Machine."""
        learn("Wayback Machine Analysis",
              "The Wayback Machine archives the entire web. We're searching for "
              "old URLs from this target. Why? Because:\n"
              "1. Old admin panels might still exist\n"
              "2. 'Removed' debug endpoints might still work\n"
              "3. Historical parameters reveal hidden functionality\n"
              "4. Old API versions might have vulnerabilities patched in new ones",
              self.learn_mode)
        
        info(f"Querying Wayback Machine for {domain}...")
        
        results = {
            'domain': domain,
            'total_urls': 0,
            'categories': {},
            'parameters': {},
            'alive_interesting': []
        }
        
        async with aiohttp.ClientSession() as session:
            # Fetch historical URLs
            urls = await self.fetch_wayback_urls(session, domain)
            results['total_urls'] = len(urls)
            
            if not urls:
                warning(f"No Wayback data found for {domain}")
                return results
            
            success(f"Found {len(urls)} historical URLs")
            
            # Categorize URLs
            results['categories'] = self.categorize_urls(urls)
            
            # Extract parameters
            results['parameters'] = self.extract_parameters(urls)
            
            # Report interesting findings
            for category in ['admin', 'api', 'backup', 'config', 'debug']:
                count = len(results['categories'].get(category, []))
                if count > 0:
                    info(f"  {category.upper()}: {count} URLs")
            
            # Check if interesting URLs are still alive
            interesting_urls = (
                results['categories'].get('admin', [])[:10] +
                results['categories'].get('backup', [])[:10] +
                results['categories'].get('config', [])[:10] +
                results['categories'].get('debug', [])[:10]
            )
            
            if interesting_urls:
                info("Checking if interesting URLs are still alive...")
                
                semaphore = asyncio.Semaphore(20)
                async def check_with_limit(url):
                    async with semaphore:
                        if await self.check_url_alive(session, url):
                            return url
                        return None
                
                tasks = [check_with_limit(url) for url in interesting_urls[:50]]
                alive_results = await asyncio.gather(*tasks)
                results['alive_interesting'] = [u for u in alive_results if u]
                
                if results['alive_interesting']:
                    warning(f"🎯 {len(results['alive_interesting'])} interesting URLs still ALIVE!")
                    for url in results['alive_interesting'][:5]:
                        warning(f"  {url}")
        
        # Save results
        output_file = Path(output_dir) / f"wayback_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save parameters separately (useful for fuzzing)
        params_file = Path(output_dir) / "parameters.txt"
        all_params = set()
        for params in results['parameters'].values():
            all_params.update(params)
        with open(params_file, 'w') as f:
            f.write('\n'.join(sorted(all_params)))
        
        info(f"Found {len(all_params)} unique parameters")
        
        return results
    
    def analyze(self, domain: str, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.analyze_domain(domain, output_dir))
