"""
Parameter Mining Module

Discovers hidden URL parameters:
- From Wayback Machine
- From JavaScript files
- Common parameter wordlist
- Parameter pollution testing

WHY PARAMETER MINING?
Hidden parameters can lead to:
- SQL injection
- XSS
- IDOR
- Privilege escalation
- Debug modes

Developers often leave debug parameters like:
?debug=true, ?admin=1, ?test=1
"""
import asyncio
import aiohttp
import re
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode
from src.utils import learn, success, error, info, warning, timestamp

class ParamMiner:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        
        # Common hidden parameters
        self.common_params = [
            # Debug/Test
            'debug', 'test', 'testing', 'dev', 'development', 'staging',
            'verbose', 'log', 'trace', 'profile', 'benchmark',
            
            # Admin/Auth
            'admin', 'administrator', 'root', 'superuser', 'su',
            'auth', 'authenticated', 'login', 'logged_in', 'session',
            'token', 'api_key', 'apikey', 'key', 'secret',
            'role', 'roles', 'permission', 'permissions', 'access',
            
            # User/Account
            'user', 'userid', 'user_id', 'uid', 'username',
            'account', 'accountid', 'account_id', 'aid',
            'email', 'mail', 'phone', 'mobile',
            
            # Data/Content
            'id', 'ID', 'Id', 'ids', 'item', 'itemid', 'item_id',
            'page', 'p', 'pg', 'offset', 'limit', 'count', 'size',
            'sort', 'order', 'orderby', 'order_by', 'dir', 'direction',
            'filter', 'filters', 'search', 'q', 'query', 'keyword',
            'category', 'cat', 'type', 'kind', 'class',
            
            # File/Path
            'file', 'filename', 'path', 'filepath', 'dir', 'directory',
            'url', 'uri', 'link', 'href', 'src', 'source',
            'include', 'require', 'load', 'read', 'fetch',
            'template', 'tpl', 'view', 'layout', 'theme',
            
            # Format/Output
            'format', 'fmt', 'output', 'out', 'type', 'content_type',
            'callback', 'jsonp', 'cb', 'json', 'xml', 'html', 'raw',
            'download', 'export', 'print', 'pdf',
            
            # Action/Method
            'action', 'act', 'do', 'cmd', 'command', 'op', 'operation',
            'method', 'mode', 'func', 'function', 'handler',
            'submit', 'save', 'update', 'delete', 'remove', 'create',
            
            # Redirect/Navigation
            'redirect', 'redir', 'return', 'returnurl', 'return_url',
            'next', 'prev', 'back', 'goto', 'continue', 'destination',
            'ref', 'referer', 'referrer', 'from', 'to',
            
            # Version/API
            'version', 'ver', 'v', 'api', 'api_version',
            'lang', 'language', 'locale', 'l', 'i18n',
            
            # Cache/Performance
            'cache', 'nocache', 'no_cache', 'refresh', 'reload',
            'timestamp', 'ts', 't', 'time', 'date',
            
            # Security
            'csrf', 'csrf_token', 'xsrf', 'nonce', 'hash',
            'signature', 'sig', 'sign', 'hmac',
        ]
        
        # Test values for parameter discovery
        self.test_values = ['1', 'true', 'admin', 'test', '../../etc/passwd']
    
    def extract_params_from_url(self, url: str) -> set:
        """Extract parameters from a URL."""
        params = set()
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            params.update(query_params.keys())
        except:
            pass
        return params
    
    def extract_params_from_js(self, js_content: str) -> set:
        """Extract potential parameters from JavaScript code."""
        params = set()
        
        # Match URL query parameters
        url_param_pattern = r'[\?&]([a-zA-Z_][a-zA-Z0-9_]*)[=\'\"]'
        params.update(re.findall(url_param_pattern, js_content))
        
        # Match object keys that look like params
        obj_key_pattern = r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']:\s*["\']?'
        params.update(re.findall(obj_key_pattern, js_content))
        
        # Match form field names
        form_pattern = r'name=["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']'
        params.update(re.findall(form_pattern, js_content))
        
        return params
    
    async def check_param_reflection(self, session: aiohttp.ClientSession, 
                                     url: str, param: str) -> dict | None:
        """Check if a parameter is reflected or causes different behavior."""
        test_value = f"PARAMTEST{param}123"
        
        # Build URL with parameter
        separator = '&' if '?' in url else '?'
        test_url = f"{url}{separator}{param}={test_value}"
        
        try:
            # Get baseline response
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                   ssl=False) as baseline_resp:
                baseline_length = len(await baseline_resp.text())
                baseline_status = baseline_resp.status
            
            # Get response with parameter
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10),
                                   ssl=False) as test_resp:
                test_text = await test_resp.text()
                test_length = len(test_text)
                test_status = test_resp.status
                
                # Check for reflection
                if test_value in test_text:
                    return {
                        'param': param,
                        'url': url,
                        'type': 'REFLECTED',
                        'severity': 'MEDIUM',
                        'note': 'Parameter value is reflected in response (potential XSS)'
                    }
                
                # Check for significant response difference
                length_diff = abs(test_length - baseline_length)
                if length_diff > 100 or test_status != baseline_status:
                    return {
                        'param': param,
                        'url': url,
                        'type': 'BEHAVIOR_CHANGE',
                        'severity': 'LOW',
                        'note': f'Response changed (length diff: {length_diff}, status: {baseline_status} -> {test_status})'
                    }
        
        except Exception:
            pass
        
        return None
    
    async def mine_async(self, hosts: list, wayback_params: list, 
                         js_content: str, output_dir: str) -> dict:
        """Mine parameters from multiple sources."""
        learn("Parameter Mining",
              "We're discovering hidden URL parameters that might be vulnerable:\n"
              "• From Wayback Machine - historical parameters\n"
              "• From JavaScript - params used in code\n"
              "• Common wordlist - debug, admin, test params\n\n"
              "Hidden parameters can lead to:\n"
              "• SQL injection\n"
              "• XSS (if reflected)\n"
              "• IDOR (if user IDs)\n"
              "• Debug mode access",
              self.learn_mode)
        
        info("Mining parameters from multiple sources...")
        
        results = {
            'total_params': 0,
            'unique_params': set(),
            'reflected_params': [],
            'behavior_change_params': [],
            'by_source': {
                'wayback': set(),
                'javascript': set(),
                'common': set(self.common_params)
            }
        }
        
        # Collect params from Wayback
        for param in wayback_params:
            results['by_source']['wayback'].add(param)
            results['unique_params'].add(param)
        
        # Collect params from JS
        if js_content:
            js_params = self.extract_params_from_js(js_content)
            results['by_source']['javascript'] = js_params
            results['unique_params'].update(js_params)
        
        # Add common params
        results['unique_params'].update(self.common_params)
        
        results['total_params'] = len(results['unique_params'])
        info(f"Collected {results['total_params']} unique parameters")
        info(f"  From Wayback: {len(results['by_source']['wayback'])}")
        info(f"  From JavaScript: {len(results['by_source']['javascript'])}")
        info(f"  Common wordlist: {len(results['by_source']['common'])}")
        
        # Test parameter reflection on hosts
        if hosts:
            info("Testing parameter reflection...")
            
            async with aiohttp.ClientSession() as session:
                semaphore = asyncio.Semaphore(10)
                
                async def test_param(host, param):
                    async with semaphore:
                        url = f"https://{host}"
                        return await self.check_param_reflection(session, url, param)
                
                # Test top params on first few hosts
                test_hosts = hosts[:5]
                test_params = list(results['unique_params'])[:50]
                
                tasks = []
                for host in test_hosts:
                    for param in test_params:
                        tasks.append(test_param(host, param))
                
                findings = await asyncio.gather(*tasks, return_exceptions=True)
                
                for finding in findings:
                    if isinstance(finding, dict):
                        if finding['type'] == 'REFLECTED':
                            results['reflected_params'].append(finding)
                        else:
                            results['behavior_change_params'].append(finding)
        
        # Report findings
        if results['reflected_params']:
            warning(f"🚨 Found {len(results['reflected_params'])} REFLECTED parameters!")
            for p in results['reflected_params'][:5]:
                warning(f"  {p['param']} on {p['url']}")
        
        if results['behavior_change_params']:
            info(f"Found {len(results['behavior_change_params'])} params that change behavior")
        
        # Convert sets to lists for JSON
        results['unique_params'] = list(results['unique_params'])
        results['by_source'] = {k: list(v) for k, v in results['by_source'].items()}
        
        # Save results
        import json
        output_file = Path(output_dir) / f"params_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save param wordlist
        params_file = Path(output_dir) / "params_wordlist.txt"
        with open(params_file, 'w') as f:
            f.write('\n'.join(sorted(results['unique_params'])))
        
        return results
    
    def mine(self, hosts: list, wayback_params: list, 
             js_content: str, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.mine_async(hosts, wayback_params, js_content, output_dir))
