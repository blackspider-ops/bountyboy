"""
SQL Injection Scanner Module

Basic SQLi detection through error-based testing:
- Error-based SQLi detection
- Time-based blind SQLi detection
- Common injection points

WHY SQLI SCANNING?
SQL injection is still one of the most critical vulnerabilities:
- Database access
- Data theft
- Authentication bypass
- Remote code execution (in some cases)

This is a BASIC scanner - for thorough testing, use sqlmap.
We're looking for low-hanging fruit and obvious vulnerabilities.
"""
import asyncio
import aiohttp
import re
import time
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from pathlib import Path
from src.utils import learn, success, error, info, warning, timestamp

class SQLiScanner:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        
        # Error-based payloads
        self.error_payloads = [
            "'",
            "''",
            '"',
            '`',
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "1 AND 1=1",
            "1 AND 1=2",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "admin'--",
            "') OR ('1'='1",
            "1; SELECT 1",
            "1 UNION SELECT NULL",
            "1' UNION SELECT NULL--",
        ]
        
        # Time-based payloads (use with caution)
        self.time_payloads = [
            "1' AND SLEEP(3)--",
            "1' AND BENCHMARK(5000000,SHA1('test'))--",
            "1'; WAITFOR DELAY '0:0:3'--",
            "1' AND pg_sleep(3)--",
        ]
        
        # SQL error patterns
        self.error_patterns = [
            # MySQL
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            
            # PostgreSQL
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
            
            # Microsoft SQL Server
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
            r"System\.Data\.SqlClient\.SqlException",
            r"Unclosed quotation mark after the character string",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            
            # Oracle
            r"\bORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_",
            r"Warning.*\Wora_",
            r"oracle\.jdbc\.driver",
            
            # SQLite
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]",
            
            # Generic
            r"SQL syntax",
            r"SQL error",
            r"syntax error",
            r"unterminated quoted string",
            r"quoted string not properly terminated",
            r"You have an error in your SQL syntax",
        ]
        
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.error_patterns]
    
    def check_sql_errors(self, response_text: str) -> list:
        """Check response for SQL error messages."""
        errors = []
        for pattern in self.compiled_patterns:
            match = pattern.search(response_text)
            if match:
                errors.append(match.group(0))
        return errors
    
    async def test_parameter(self, session: aiohttp.ClientSession, 
                             url: str, param: str, original_value: str) -> dict | None:
        """Test a single parameter for SQLi."""
        parsed = urlparse(url)
        
        for payload in self.error_payloads:
            # Build test URL
            query_params = parse_qs(parsed.query)
            query_params[param] = [f"{original_value}{payload}"]
            
            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            try:
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as resp:
                    text = await resp.text()
                    
                    # Check for SQL errors
                    errors = self.check_sql_errors(text)
                    if errors:
                        return {
                            'url': url,
                            'test_url': test_url,
                            'param': param,
                            'payload': payload,
                            'type': 'error_based',
                            'errors': errors[:3],  # Limit errors
                            'severity': 'HIGH'
                        }
            
            except Exception:
                pass
        
        return None
    
    async def test_time_based(self, session: aiohttp.ClientSession,
                               url: str, param: str, original_value: str) -> dict | None:
        """Test for time-based blind SQLi."""
        parsed = urlparse(url)
        
        for payload in self.time_payloads[:2]:  # Only test first 2
            query_params = parse_qs(parsed.query)
            query_params[param] = [f"{original_value}{payload}"]
            
            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            try:
                start = time.time()
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=15),
                    ssl=False
                ) as resp:
                    await resp.text()
                elapsed = time.time() - start
                
                # If response took > 2.5 seconds, might be time-based SQLi
                if elapsed > 2.5:
                    return {
                        'url': url,
                        'test_url': test_url,
                        'param': param,
                        'payload': payload,
                        'type': 'time_based',
                        'delay': round(elapsed, 2),
                        'severity': 'HIGH',
                        'note': 'Potential time-based blind SQLi - verify manually'
                    }
            
            except asyncio.TimeoutError:
                # Timeout could indicate successful sleep
                return {
                    'url': url,
                    'test_url': test_url,
                    'param': param,
                    'payload': payload,
                    'type': 'time_based',
                    'delay': 'timeout',
                    'severity': 'HIGH',
                    'note': 'Request timed out - possible time-based SQLi'
                }
            except Exception:
                pass
        
        return None
    
    async def scan_url(self, session: aiohttp.ClientSession, url: str) -> list:
        """Scan a URL for SQLi vulnerabilities."""
        findings = []
        
        parsed = urlparse(url)
        if not parsed.query:
            return findings
        
        query_params = parse_qs(parsed.query)
        
        for param, values in query_params.items():
            original_value = values[0] if values else ''
            
            # Test error-based
            result = await self.test_parameter(session, url, param, original_value)
            if result:
                findings.append(result)
                continue  # Found vuln, skip time-based for this param
            
            # Test time-based (slower, so only if error-based didn't find anything)
            result = await self.test_time_based(session, url, param, original_value)
            if result:
                findings.append(result)
        
        return findings
    
    async def scan_async(self, urls: list, output_dir: str) -> dict:
        """Scan multiple URLs for SQLi vulnerabilities."""
        learn("SQL Injection Scanning",
              "We're testing for SQL injection - one of the most critical vulns:\n\n"
              "• Error-based: Inject quotes to trigger SQL errors\n"
              "• Time-based: Inject SLEEP() to detect blind SQLi\n\n"
              "What we're looking for:\n"
              "• SQL error messages in response\n"
              "• Delayed responses (time-based)\n\n"
              "⚠️ This is basic scanning. For thorough testing, use sqlmap.",
              self.learn_mode)
        
        info(f"Scanning {len(urls)} URLs for SQL injection...")
        
        results = {
            'total_urls': len(urls),
            'vulnerable': [],
            'by_type': {
                'error_based': [],
                'time_based': []
            }
        }
        
        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(5)
            
            async def scan_with_limit(url):
                async with semaphore:
                    return await self.scan_url(session, url)
            
            tasks = [scan_with_limit(url) for url in urls[:100]]  # Limit URLs
            all_findings = await asyncio.gather(*tasks, return_exceptions=True)
            
            for findings in all_findings:
                if isinstance(findings, list):
                    for finding in findings:
                        results['vulnerable'].append(finding)
                        sqli_type = finding.get('type', 'unknown')
                        if sqli_type in results['by_type']:
                            results['by_type'][sqli_type].append(finding)
        
        # Report findings
        if results['vulnerable']:
            warning(f"🚨 Found {len(results['vulnerable'])} potential SQL injection points!")
            
            for vuln in results['vulnerable'][:10]:
                warning(f"  [{vuln['severity']}] {vuln['type'].upper()}")
                warning(f"      URL: {vuln['url']}")
                warning(f"      Param: {vuln['param']}")
                if vuln.get('errors'):
                    warning(f"      Error: {vuln['errors'][0][:50]}...")
        else:
            info("No SQL injection vulnerabilities found")
        
        # Save results
        import json
        output_file = Path(output_dir) / f"sqli_scan_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def scan(self, urls: list, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.scan_async(urls, output_dir))
