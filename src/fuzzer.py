"""
Directory and Path Fuzzer

Discovers hidden paths and files on web servers:
- Admin panels (/admin, /administrator, /wp-admin)
- Backup files (.bak, .old, .backup)
- Config files (.env, config.php, web.config)
- Git repositories (.git/config)
- Development files (test.php, debug.log)

WHY FUZZING?
Robots.txt and sitemaps only show what companies WANT you to see.
Fuzzing finds what they forgot to hide. Backup files with credentials,
exposed git repos with source code, admin panels with default passwords.

This is different from port scanning - we're looking for hidden PATHS
on web servers we already know about.
"""
import asyncio
import aiohttp
from pathlib import Path
from src.utils import learn, success, error, info, warning, timestamp

class PathFuzzer:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        
        # Common paths to check (curated list - not too aggressive)
        self.paths = {
            'critical': [
                '/.git/config',
                '/.git/HEAD',
                '/.env',
                '/.env.local',
                '/.env.production',
                '/config.php',
                '/wp-config.php',
                '/web.config',
                '/config.yml',
                '/config.yaml',
                '/database.yml',
                '/settings.py',
                '/.htpasswd',
                '/.htaccess',
                '/server-status',
                '/phpinfo.php',
                '/info.php',
                '/test.php',
                '/debug.php',
                '/backup.sql',
                '/dump.sql',
                '/database.sql',
                '/db.sql',
            ],
            'admin': [
                '/admin',
                '/admin/',
                '/administrator',
                '/administrator/',
                '/wp-admin',
                '/wp-admin/',
                '/admin.php',
                '/login',
                '/login/',
                '/signin',
                '/dashboard',
                '/dashboard/',
                '/panel',
                '/cpanel',
                '/manage',
                '/management',
            ],
            'api': [
                '/api',
                '/api/',
                '/api/v1',
                '/api/v2',
                '/api/v3',
                '/graphql',
                '/graphiql',
                '/swagger',
                '/swagger-ui',
                '/swagger.json',
                '/openapi.json',
                '/api-docs',
                '/docs',
                '/redoc',
            ],
            'backup': [
                '/backup',
                '/backup/',
                '/backups',
                '/bak',
                '/old',
                '/archive',
                '/temp',
                '/tmp',
                '/cache',
                '/.backup',
                '/site.zip',
                '/backup.zip',
                '/www.zip',
                '/html.zip',
            ],
            'dev': [
                '/dev',
                '/development',
                '/staging',
                '/test',
                '/testing',
                '/debug',
                '/demo',
                '/sandbox',
                '/.vscode',
                '/.idea',
                '/node_modules',
                '/vendor',
            ],
            'files': [
                '/robots.txt',
                '/sitemap.xml',
                '/crossdomain.xml',
                '/clientaccesspolicy.xml',
                '/security.txt',
                '/.well-known/security.txt',
                '/humans.txt',
                '/readme.txt',
                '/README.md',
                '/CHANGELOG.md',
                '/LICENSE',
                '/package.json',
                '/composer.json',
            ]
        }
    
    async def check_path(self, session: aiohttp.ClientSession, 
                         base_url: str, path: str) -> dict | None:
        """Check if a path exists and return info."""
        url = f"{base_url.rstrip('/')}{path}"
        
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                   ssl=False, allow_redirects=False) as resp:
                
                # Interesting status codes
                if resp.status == 200:
                    content_length = resp.headers.get('Content-Length', 'unknown')
                    content_type = resp.headers.get('Content-Type', 'unknown')
                    
                    # Read a bit of content to check if it's a real page
                    try:
                        content = await resp.text()
                        # Skip generic error pages
                        if len(content) < 100 and ('not found' in content.lower() or 
                                                    'error' in content.lower()):
                            return None
                    except:
                        pass
                    
                    return {
                        'url': url,
                        'path': path,
                        'status': 200,
                        'content_length': content_length,
                        'content_type': content_type
                    }
                
                elif resp.status in [301, 302, 307, 308]:
                    location = resp.headers.get('Location', '')
                    return {
                        'url': url,
                        'path': path,
                        'status': resp.status,
                        'redirect': location
                    }
                
                elif resp.status == 403:
                    # Forbidden means it exists but we can't access
                    return {
                        'url': url,
                        'path': path,
                        'status': 403,
                        'note': 'Forbidden - exists but protected'
                    }
        
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
        
        return None
    
    async def fuzz_host(self, host: str, categories: list = None) -> dict:
        """Fuzz a single host for hidden paths."""
        results = {
            'host': host,
            'found': [],
            'critical': [],
            'forbidden': []
        }
        
        if categories is None:
            categories = list(self.paths.keys())
        
        # Collect all paths to check
        paths_to_check = []
        for cat in categories:
            paths_to_check.extend(self.paths.get(cat, []))
        
        async with aiohttp.ClientSession() as session:
            # Try HTTPS first, then HTTP
            for protocol in ['https', 'http']:
                base_url = f"{protocol}://{host}"
                
                # Check if host is alive
                try:
                    async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=5),
                                          ssl=False) as resp:
                        if resp.status >= 400:
                            continue
                except:
                    continue
                
                # Fuzz paths with concurrency limit
                semaphore = asyncio.Semaphore(20)
                
                async def check_with_limit(path):
                    async with semaphore:
                        return await self.check_path(session, base_url, path)
                
                tasks = [check_with_limit(path) for path in paths_to_check]
                findings = await asyncio.gather(*tasks)
                
                for finding in findings:
                    if finding:
                        results['found'].append(finding)
                        
                        if finding['status'] == 403:
                            results['forbidden'].append(finding)
                        elif finding['path'] in self.paths['critical']:
                            results['critical'].append(finding)
                
                break  # Found working protocol
        
        return results
    
    async def fuzz_async(self, hosts: list, output_dir: str, 
                         categories: list = None) -> dict:
        """Fuzz multiple hosts in parallel."""
        learn("Path Fuzzing",
              "We're checking common paths on each web server. Looking for:\n"
              "• Exposed .git folders (source code leak!)\n"
              "• .env files (credentials!)\n"
              "• Admin panels (auth bypass potential)\n"
              "• Backup files (old code with vulns)\n"
              "• API documentation (hidden endpoints)\n\n"
              "This is passive - we're just checking if paths exist, not exploiting.",
              self.learn_mode)
        
        info(f"Fuzzing {len(hosts)} hosts for hidden paths...")
        
        all_results = {
            'total_hosts': len(hosts),
            'total_found': 0,
            'critical_findings': [],
            'by_host': []
        }
        
        # Fuzz hosts with limited concurrency
        semaphore = asyncio.Semaphore(5)
        
        async def fuzz_with_limit(host):
            async with semaphore:
                return await self.fuzz_host(host, categories)
        
        tasks = [fuzz_with_limit(host) for host in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, dict):
                all_results['by_host'].append(result)
                all_results['total_found'] += len(result['found'])
                all_results['critical_findings'].extend(result['critical'])
        
        # Report findings
        success(f"Found {all_results['total_found']} accessible paths")
        
        if all_results['critical_findings']:
            warning(f"🚨 {len(all_results['critical_findings'])} CRITICAL findings!")
            for finding in all_results['critical_findings']:
                warning(f"  {finding['url']}")
        
        # Save results
        import json
        output_file = Path(output_dir) / f"fuzzing_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(all_results, f, indent=2)
        
        return all_results
    
    def fuzz(self, hosts: list, output_dir: str, categories: list = None) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.fuzz_async(hosts, output_dir, categories))
