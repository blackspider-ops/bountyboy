"""
API Endpoint Fuzzer Module

Discovers and tests API endpoints:
- Common API path fuzzing
- REST/GraphQL endpoint discovery
- API version enumeration
- Authentication bypass attempts
- Rate limiting detection

WHY API FUZZING?
APIs are often less protected than web interfaces:
- Undocumented endpoints with sensitive data
- Debug/admin endpoints left exposed
- Version mismatches with different security
- Missing authentication on internal APIs
"""
import asyncio
import aiohttp
import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse
from src.utils import learn, success, error, info, warning, timestamp


class APIFuzzer:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        self.timeout = aiohttp.ClientTimeout(total=10)
        
        # API path wordlists
        self.api_paths = {
            'common': [
                '/api', '/api/v1', '/api/v2', '/api/v3',
                '/v1', '/v2', '/v3',
                '/rest', '/rest/v1', '/rest/v2',
                '/graphql', '/graphiql', '/playground',
                '/swagger', '/swagger-ui', '/swagger.json', '/swagger.yaml',
                '/openapi', '/openapi.json', '/openapi.yaml',
                '/api-docs', '/docs', '/redoc',
                '/health', '/healthz', '/health/live', '/health/ready',
                '/status', '/ping', '/version', '/info',
                '/metrics', '/prometheus',
            ],
            'auth': [
                '/api/auth', '/api/login', '/api/logout', '/api/register',
                '/api/token', '/api/refresh', '/api/oauth',
                '/auth/login', '/auth/token', '/oauth/token',
                '/api/users/me', '/api/profile', '/api/account',
                '/api/password/reset', '/api/password/forgot',
            ],
            'admin': [
                '/api/admin', '/admin/api', '/api/internal',
                '/api/debug', '/api/test', '/api/dev',
                '/api/config', '/api/settings', '/api/system',
                '/api/logs', '/api/audit', '/api/events',
                '/internal/api', '/private/api',
            ],
            'data': [
                '/api/users', '/api/user', '/api/customers',
                '/api/orders', '/api/products', '/api/items',
                '/api/data', '/api/export', '/api/import',
                '/api/backup', '/api/dump', '/api/download',
                '/api/files', '/api/uploads', '/api/attachments',
                '/api/search', '/api/query',
            ],
            'graphql': [
                '/graphql',
                '/graphiql',
                '/playground',
                '/api/graphql',
                '/v1/graphql',
                '/query',
                '/gql',
            ]
        }
        
        # Interesting response indicators
        self.interesting_patterns = {
            'api_info': [
                r'"version":', r'"api_version":', r'"swagger":',
                r'"openapi":', r'"info":', r'"paths":',
            ],
            'auth_bypass': [
                r'"authenticated":\s*true', r'"admin":\s*true',
                r'"role":\s*"admin"', r'"isAdmin":\s*true',
            ],
            'data_leak': [
                r'"email":', r'"password":', r'"token":',
                r'"secret":', r'"api_key":', r'"private_key":',
                r'"ssn":', r'"credit_card":', r'"phone":',
            ],
            'debug_info': [
                r'"debug":', r'"stack_trace":', r'"error":',
                r'"exception":', r'"traceback":',
            ],
            'graphql': [
                r'"__schema"', r'"__type"', r'"queryType":',
                r'"mutationType":', r'"subscriptionType":',
            ]
        }
        
        # GraphQL introspection query
        self.graphql_introspection = '''
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                types { name kind description }
            }
        }
        '''
    
    async def check_endpoint(self, session: aiohttp.ClientSession, url: str, method: str = 'GET') -> dict | None:
        """Check if an API endpoint exists and analyze response."""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; APIFuzzer/1.0)',
                'Accept': 'application/json, */*',
                'Content-Type': 'application/json',
            }
            
            async with session.request(
                method, url, headers=headers, timeout=self.timeout, ssl=False
            ) as resp:
                if resp.status in [200, 201, 204, 301, 302, 401, 403]:
                    content = ''
                    try:
                        content = await resp.text()
                    except:
                        pass
                    
                    return {
                        'url': url,
                        'status': resp.status,
                        'content_type': resp.headers.get('Content-Type', ''),
                        'content_length': len(content),
                        'content_preview': content[:500] if content else '',
                        'findings': self.analyze_response(content, resp.status)
                    }
        except:
            pass
        return None
    
    def analyze_response(self, content: str, status: int) -> list:
        """Analyze response for interesting patterns."""
        findings = []
        
        for category, patterns in self.interesting_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append({
                        'category': category,
                        'pattern': pattern,
                        'severity': self.get_severity(category, status)
                    })
                    break
        
        return findings
    
    def get_severity(self, category: str, status: int) -> str:
        """Determine severity based on category and status."""
        if category == 'data_leak':
            return 'critical'
        elif category == 'auth_bypass' and status == 200:
            return 'high'
        elif category == 'debug_info':
            return 'medium'
        elif category == 'api_info':
            return 'info'
        return 'low'
    
    async def test_graphql(self, session: aiohttp.ClientSession, base_url: str) -> dict | None:
        """Test for GraphQL introspection."""
        for path in self.api_paths['graphql']:
            url = urljoin(base_url, path)
            try:
                # Test GET with query param
                async with session.get(
                    f"{url}?query={{__schema{{types{{name}}}}}}",
                    timeout=self.timeout, ssl=False
                ) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        if '__schema' in content or 'types' in content:
                            return {
                                'url': url,
                                'method': 'GET',
                                'introspection_enabled': True,
                                'severity': 'medium'
                            }
                
                # Test POST
                async with session.post(
                    url,
                    json={'query': self.graphql_introspection},
                    timeout=self.timeout, ssl=False
                ) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        if '__schema' in content:
                            return {
                                'url': url,
                                'method': 'POST',
                                'introspection_enabled': True,
                                'severity': 'medium'
                            }
            except:
                pass
        return None
    
    async def fuzz_host(self, session: aiohttp.ClientSession, host: str) -> dict:
        """Fuzz API endpoints for a single host."""
        result = {
            'host': host,
            'endpoints_found': [],
            'graphql': None,
            'critical_findings': [],
            'auth_endpoints': [],
            'admin_endpoints': [],
            'data_endpoints': []
        }
        
        base_url = f"https://{host}" if not host.startswith('http') else host
        
        # Fuzz all categories
        all_paths = []
        for category, paths in self.api_paths.items():
            if category != 'graphql':
                all_paths.extend(paths)
        
        tasks = []
        for path in all_paths:
            url = urljoin(base_url + '/', path.lstrip('/'))
            tasks.append(self.check_endpoint(session, url))
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for resp in responses:
            if isinstance(resp, dict) and resp:
                result['endpoints_found'].append(resp)
                
                # Categorize findings
                if resp['findings']:
                    for finding in resp['findings']:
                        if finding['severity'] == 'critical':
                            result['critical_findings'].append(resp)
                        elif finding['category'] == 'auth_bypass':
                            result['auth_endpoints'].append(resp)
                
                # Categorize by path
                url_path = urlparse(resp['url']).path.lower()
                if any(p in url_path for p in ['auth', 'login', 'token', 'oauth']):
                    result['auth_endpoints'].append(resp)
                elif any(p in url_path for p in ['admin', 'internal', 'debug']):
                    result['admin_endpoints'].append(resp)
                elif any(p in url_path for p in ['user', 'data', 'export', 'backup']):
                    result['data_endpoints'].append(resp)
        
        # Test GraphQL
        graphql_result = await self.test_graphql(session, base_url)
        if graphql_result:
            result['graphql'] = graphql_result
        
        return result
    
    async def fuzz_async(self, hosts: list, output_dir: str) -> dict:
        """Fuzz API endpoints for multiple hosts."""
        learn("API Endpoint Fuzzing",
              "APIs often have less security than web interfaces:\n\n"
              "• Undocumented endpoints with sensitive data\n"
              "• Debug/admin endpoints left exposed\n"
              "• GraphQL introspection revealing schema\n"
              "• Missing authentication on internal APIs\n\n"
              "We fuzz common API paths and analyze responses for:\n"
              "1. Swagger/OpenAPI documentation\n"
              "2. GraphQL introspection\n"
              "3. Authentication endpoints\n"
              "4. Data exposure\n"
              "5. Debug information",
              self.learn_mode)
        
        info(f"Fuzzing API endpoints on {len(hosts)} hosts...")
        
        results = {
            'total_hosts': len(hosts),
            'hosts_with_apis': 0,
            'total_endpoints': 0,
            'critical_findings': [],
            'graphql_endpoints': [],
            'swagger_docs': [],
            'auth_endpoints': [],
            'admin_endpoints': [],
            'data_endpoints': [],
            'by_host': {}
        }
        
        connector = aiohttp.TCPConnector(limit=30, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            semaphore = asyncio.Semaphore(10)
            
            async def fuzz_with_limit(host):
                async with semaphore:
                    return await self.fuzz_host(session, host)
            
            tasks = [fuzz_with_limit(host) for host in hosts]
            host_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for host_result in host_results:
                if isinstance(host_result, dict):
                    host = host_result['host']
                    results['by_host'][host] = host_result
                    
                    if host_result['endpoints_found']:
                        results['hosts_with_apis'] += 1
                        results['total_endpoints'] += len(host_result['endpoints_found'])
                        
                        # Collect critical findings
                        results['critical_findings'].extend(host_result['critical_findings'])
                        results['auth_endpoints'].extend(host_result['auth_endpoints'])
                        results['admin_endpoints'].extend(host_result['admin_endpoints'])
                        results['data_endpoints'].extend(host_result['data_endpoints'])
                        
                        # Check for swagger/openapi
                        for ep in host_result['endpoints_found']:
                            if any(s in ep['url'].lower() for s in ['swagger', 'openapi', 'api-docs']):
                                results['swagger_docs'].append(ep)
                    
                    if host_result['graphql']:
                        results['graphql_endpoints'].append(host_result['graphql'])
        
        # Report findings
        success(f"Found {results['total_endpoints']} API endpoints on {results['hosts_with_apis']} hosts")
        
        if results['critical_findings']:
            warning(f"🚨 {len(results['critical_findings'])} CRITICAL findings!")
        
        if results['graphql_endpoints']:
            info(f"Found {len(results['graphql_endpoints'])} GraphQL endpoints with introspection")
        
        if results['swagger_docs']:
            info(f"Found {len(results['swagger_docs'])} Swagger/OpenAPI docs")
        
        if results['admin_endpoints']:
            warning(f"Found {len(results['admin_endpoints'])} admin/internal endpoints")
        
        # Save results
        output_file = Path(output_dir) / f"api_fuzzing_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Save critical findings separately
        if results['critical_findings']:
            critical_file = Path(output_dir) / "api_critical_findings.txt"
            with open(critical_file, 'w') as f:
                f.write("# Critical API Findings\n\n")
                for finding in results['critical_findings']:
                    f.write(f"URL: {finding['url']}\n")
                    f.write(f"Status: {finding['status']}\n")
                    f.write(f"Findings: {finding['findings']}\n")
                    f.write(f"Preview: {finding['content_preview'][:200]}\n")
                    f.write("-" * 50 + "\n")
        
        return results
    
    def fuzz(self, hosts: list, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.fuzz_async(hosts, output_dir))
