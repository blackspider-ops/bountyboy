"""
IDOR (Insecure Direct Object Reference) / Broken Access Control Scanner

Detects access control vulnerabilities:
- Sequential ID enumeration
- UUID/GUID prediction
- Parameter manipulation
- Horizontal privilege escalation
- Vertical privilege escalation

WHY IDOR?
IDOR is the #1 most common vulnerability in bug bounties:
- Access other users' data by changing IDs
- View/modify resources you shouldn't access
- Often overlooked by developers
- Easy to find, high impact

This is bread-and-butter bug bounty hunting - consistent $500-$5000 payouts.
"""
import asyncio
import aiohttp
import re
import json
import random
import string
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from src.utils import learn, success, error, info, warning, timestamp


class IDORScanner:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        self.timeout = aiohttp.ClientTimeout(total=10)
        
        # Parameters commonly vulnerable to IDOR
        self.idor_params = [
            'id', 'user_id', 'userId', 'user', 'uid', 'account_id', 'accountId',
            'account', 'profile_id', 'profileId', 'profile', 'member_id', 'memberId',
            'order_id', 'orderId', 'order', 'invoice_id', 'invoiceId', 'invoice',
            'doc_id', 'docId', 'document_id', 'documentId', 'file_id', 'fileId',
            'report_id', 'reportId', 'ticket_id', 'ticketId', 'message_id', 'messageId',
            'comment_id', 'commentId', 'post_id', 'postId', 'item_id', 'itemId',
            'product_id', 'productId', 'customer_id', 'customerId', 'client_id',
            'project_id', 'projectId', 'task_id', 'taskId', 'record_id', 'recordId',
            'ref', 'reference', 'no', 'number', 'num', 'key', 'token',
        ]
        
        # URL path patterns that might contain IDs
        self.path_patterns = [
            r'/users?/(\d+)',
            r'/accounts?/(\d+)',
            r'/profiles?/(\d+)',
            r'/orders?/(\d+)',
            r'/invoices?/(\d+)',
            r'/documents?/(\d+)',
            r'/files?/(\d+)',
            r'/reports?/(\d+)',
            r'/api/v\d+/\w+/(\d+)',
            r'/(\d+)/?$',
            # UUID patterns
            r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
        ]
        
        # Test ID values
        self.test_ids = {
            'sequential': ['1', '2', '100', '1000', '99999'],
            'negative': ['-1', '0'],
            'special': ['null', 'undefined', 'NaN', 'true', 'false'],
            'injection': ["1'", '1"', '1;--', '1 OR 1=1'],
        }
    
    def extract_ids_from_url(self, url: str) -> list:
        """Extract potential IDs from URL path and parameters."""
        ids_found = []
        parsed = urlparse(url)
        
        # Check path for IDs
        for pattern in self.path_patterns:
            matches = re.findall(pattern, parsed.path, re.IGNORECASE)
            for match in matches:
                ids_found.append({
                    'location': 'path',
                    'pattern': pattern,
                    'value': match,
                    'type': 'uuid' if '-' in match else 'numeric'
                })
        
        # Check query parameters
        query_params = parse_qs(parsed.query)
        for param, values in query_params.items():
            if param.lower() in [p.lower() for p in self.idor_params]:
                for value in values:
                    ids_found.append({
                        'location': 'param',
                        'param': param,
                        'value': value,
                        'type': 'uuid' if '-' in value else 'numeric'
                    })
        
        return ids_found
    
    def generate_test_ids(self, original_id: str, id_type: str) -> list:
        """Generate test IDs based on original."""
        test_values = []
        
        if id_type == 'numeric':
            try:
                orig_int = int(original_id)
                # Adjacent IDs
                test_values.extend([str(orig_int - 1), str(orig_int + 1)])
                # Common IDs
                test_values.extend(['1', '2', '0', '-1'])
                # Large/small
                test_values.extend([str(orig_int * 2), str(orig_int // 2)])
            except ValueError:
                pass
            test_values.extend(self.test_ids['sequential'])
            test_values.extend(self.test_ids['negative'])
        
        elif id_type == 'uuid':
            # Generate similar UUIDs (change last few chars)
            if len(original_id) >= 4:
                test_values.append(original_id[:-4] + '0000')
                test_values.append(original_id[:-4] + 'ffff')
                # Random UUID
                test_values.append(
                    f"{original_id[:8]}-{original_id[9:13]}-{original_id[14:18]}-"
                    f"{original_id[19:23]}-{''.join(random.choices('0123456789abcdef', k=12))}"
                )
        
        test_values.extend(self.test_ids['special'])
        
        return list(set(test_values))
    
    def modify_url_id(self, url: str, id_info: dict, new_id: str) -> str:
        """Create URL with modified ID."""
        parsed = urlparse(url)
        
        if id_info['location'] == 'path':
            # Replace ID in path
            new_path = re.sub(
                id_info['pattern'],
                lambda m: m.group(0).replace(id_info['value'], new_id),
                parsed.path
            )
            return urlunparse((
                parsed.scheme, parsed.netloc, new_path,
                parsed.params, parsed.query, parsed.fragment
            ))
        
        elif id_info['location'] == 'param':
            # Replace ID in query param
            query_params = parse_qs(parsed.query)
            query_params[id_info['param']] = [new_id]
            new_query = urlencode(query_params, doseq=True)
            return urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
        
        return url
    
    async def get_baseline(self, session: aiohttp.ClientSession, url: str) -> dict | None:
        """Get baseline response for comparison."""
        try:
            async with session.get(
                url, timeout=self.timeout, ssl=False
            ) as resp:
                content = await resp.text()
                return {
                    'status': resp.status,
                    'length': len(content),
                    'content_hash': hash(content),
                    'content_preview': content[:500]
                }
        except Exception:
            return None
    
    async def test_idor(self, session: aiohttp.ClientSession, original_url: str,
                        test_url: str, baseline: dict, id_info: dict, 
                        test_id: str) -> dict | None:
        """Test for IDOR vulnerability."""
        try:
            async with session.get(
                test_url, timeout=self.timeout, ssl=False
            ) as resp:
                content = await resp.text()
                
                # Analyze response
                result = {
                    'original_url': original_url,
                    'test_url': test_url,
                    'original_id': id_info['value'],
                    'test_id': test_id,
                    'location': id_info['location'],
                    'status': resp.status,
                    'length': len(content),
                    'baseline_status': baseline['status'],
                    'baseline_length': baseline['length'],
                }
                
                # Check for potential IDOR
                is_vulnerable = False
                severity = 'info'
                
                # Same status, different content = potential IDOR
                if resp.status == 200 and baseline['status'] == 200:
                    if len(content) != baseline['length']:
                        is_vulnerable = True
                        severity = 'high'
                        result['reason'] = 'Different content returned for different ID'
                    elif hash(content) != baseline['content_hash']:
                        is_vulnerable = True
                        severity = 'high'
                        result['reason'] = 'Content differs for different ID'
                
                # Got 200 when baseline was 403/401 = access control bypass
                if resp.status == 200 and baseline['status'] in [401, 403]:
                    is_vulnerable = True
                    severity = 'critical'
                    result['reason'] = 'Access control bypass - got 200 instead of 401/403'
                
                # Check for data in response
                if resp.status == 200:
                    sensitive_patterns = [
                        r'"email":', r'"phone":', r'"address":',
                        r'"password":', r'"ssn":', r'"credit',
                        r'"user":', r'"account":', r'"profile":',
                    ]
                    for pattern in sensitive_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            is_vulnerable = True
                            severity = 'high'
                            result['reason'] = f'Sensitive data pattern found: {pattern}'
                            break
                
                if is_vulnerable:
                    result['vulnerable'] = True
                    result['severity'] = severity
                    result['content_preview'] = content[:500]
                    return result
                
        except Exception:
            pass
        return None
    
    async def scan_url(self, session: aiohttp.ClientSession, url: str) -> dict:
        """Scan a URL for IDOR vulnerabilities."""
        result = {
            'url': url,
            'ids_found': [],
            'vulnerabilities': [],
            'tests_performed': 0
        }
        
        # Extract IDs from URL
        ids = self.extract_ids_from_url(url)
        result['ids_found'] = ids
        
        if not ids:
            return result
        
        # Get baseline response
        baseline = await self.get_baseline(session, url)
        if not baseline:
            return result
        
        # Test each ID
        for id_info in ids:
            test_ids = self.generate_test_ids(id_info['value'], id_info['type'])
            
            for test_id in test_ids[:10]:  # Limit tests per ID
                if test_id == id_info['value']:
                    continue
                
                test_url = self.modify_url_id(url, id_info, test_id)
                result['tests_performed'] += 1
                
                finding = await self.test_idor(
                    session, url, test_url, baseline, id_info, test_id
                )
                
                if finding:
                    result['vulnerabilities'].append(finding)
                
                await asyncio.sleep(0.1)  # Rate limiting
        
        return result
    
    async def scan_host(self, session: aiohttp.ClientSession, host: str) -> dict:
        """Scan a host for IDOR by discovering endpoints."""
        result = {
            'host': host,
            'endpoints_tested': [],
            'vulnerabilities': [],
            'total_tests': 0
        }
        
        base_url = f"https://{host}" if not host.startswith('http') else host
        
        # Common API endpoints to test
        test_endpoints = [
            '/api/user/1', '/api/users/1', '/api/account/1',
            '/api/profile/1', '/api/order/1', '/api/orders/1',
            '/api/v1/user/1', '/api/v1/users/1',
            '/user/1', '/users/1', '/account/1', '/profile/1',
            '/api/me', '/api/user/me',
        ]
        
        # Also add endpoints with query params
        param_endpoints = [
            '/api/user?id=1', '/api/users?user_id=1',
            '/api/data?id=1', '/api/get?id=1',
            '/api/view?id=1', '/api/show?id=1',
        ]
        
        all_endpoints = test_endpoints + param_endpoints
        
        for endpoint in all_endpoints:
            url = f"{base_url}{endpoint}"
            result['endpoints_tested'].append(url)
            
            scan_result = await self.scan_url(session, url)
            result['total_tests'] += scan_result['tests_performed']
            result['vulnerabilities'].extend(scan_result['vulnerabilities'])
        
        return result
    
    async def scan_async(self, hosts: list, discovered_urls: list, output_dir: str) -> dict:
        """Scan for IDOR vulnerabilities."""
        learn("IDOR / Broken Access Control Scanning",
              "IDOR is the #1 most common bug bounty vulnerability:\n\n"
              "• Change user_id=123 to user_id=124 → access another user's data\n"
              "• Modify order IDs to view other orders\n"
              "• Access admin resources by guessing IDs\n\n"
              "We test by:\n"
              "1. Finding IDs in URLs (path and parameters)\n"
              "2. Generating test IDs (adjacent, common, special)\n"
              "3. Comparing responses for different IDs\n"
              "4. Detecting access control bypasses\n\n"
              "Consistent $500-$5000 payouts for IDOR findings",
              self.learn_mode)
        
        info(f"Scanning {len(hosts)} hosts for IDOR vulnerabilities...")
        
        results = {
            'total_hosts': len(hosts),
            'total_urls_tested': 0,
            'total_tests': 0,
            'critical_findings': [],
            'high_findings': [],
            'all_vulnerabilities': [],
            'by_host': {}
        }
        
        connector = aiohttp.TCPConnector(limit=15, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            semaphore = asyncio.Semaphore(5)
            
            # Scan hosts
            async def scan_with_limit(host):
                async with semaphore:
                    return await self.scan_host(session, host)
            
            tasks = [scan_with_limit(host) for host in hosts]
            host_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for host_result in host_results:
                if isinstance(host_result, dict):
                    host = host_result['host']
                    results['by_host'][host] = host_result
                    results['total_urls_tested'] += len(host_result['endpoints_tested'])
                    results['total_tests'] += host_result['total_tests']
                    
                    for vuln in host_result['vulnerabilities']:
                        results['all_vulnerabilities'].append(vuln)
                        if vuln.get('severity') == 'critical':
                            results['critical_findings'].append(vuln)
                        elif vuln.get('severity') == 'high':
                            results['high_findings'].append(vuln)
            
            # Also scan discovered URLs if provided
            if discovered_urls:
                info(f"Also testing {len(discovered_urls)} discovered URLs...")
                for url in discovered_urls[:50]:  # Limit
                    scan_result = await self.scan_url(session, url)
                    results['total_tests'] += scan_result['tests_performed']
                    for vuln in scan_result['vulnerabilities']:
                        results['all_vulnerabilities'].append(vuln)
                        if vuln.get('severity') == 'critical':
                            results['critical_findings'].append(vuln)
                        elif vuln.get('severity') == 'high':
                            results['high_findings'].append(vuln)
        
        # Report findings
        if results['critical_findings']:
            warning(f"🚨 {len(results['critical_findings'])} CRITICAL IDOR vulnerabilities!")
        
        if results['high_findings']:
            warning(f"⚠️ {len(results['high_findings'])} HIGH severity IDOR findings")
        
        success(f"Performed {results['total_tests']} IDOR tests on {results['total_urls_tested']} URLs")
        
        # Save results
        output_file = Path(output_dir) / f"idor_scan_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Save vulnerabilities for manual verification
        if results['all_vulnerabilities']:
            vuln_file = Path(output_dir) / "idor_vulnerabilities.txt"
            with open(vuln_file, 'w') as f:
                f.write("# IDOR Vulnerabilities Found\n")
                f.write("# VERIFY MANUALLY BEFORE REPORTING!\n\n")
                for vuln in results['all_vulnerabilities']:
                    f.write(f"Severity: {vuln.get('severity', 'unknown')}\n")
                    f.write(f"Original URL: {vuln['original_url']}\n")
                    f.write(f"Test URL: {vuln['test_url']}\n")
                    f.write(f"Original ID: {vuln['original_id']}\n")
                    f.write(f"Test ID: {vuln['test_id']}\n")
                    f.write(f"Reason: {vuln.get('reason', 'N/A')}\n")
                    f.write(f"Status: {vuln['status']} (baseline: {vuln['baseline_status']})\n")
                    f.write("-" * 50 + "\n")
        
        return results
    
    def scan(self, hosts: list, discovered_urls: list, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.scan_async(hosts, discovered_urls or [], output_dir))
