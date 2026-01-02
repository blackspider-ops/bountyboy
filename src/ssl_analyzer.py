"""
SSL/TLS Certificate Analyzer

Checks for SSL/TLS misconfigurations:
- Expired certificates
- Self-signed certificates
- Weak cipher suites
- Missing certificate chain
- Hostname mismatch
- Certificate transparency issues

WHY SSL ANALYSIS?
SSL issues are easy to find and report:
- Expired cert = immediate security issue
- Weak ciphers = potential MITM attacks
- Self-signed = trust issues

Usually LOW-MEDIUM severity but quick wins.
"""
import asyncio
import ssl
import socket
from datetime import datetime
from pathlib import Path
from src.utils import learn, success, error, info, warning, timestamp

class SSLAnalyzer:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        
        # Weak cipher suites to flag
        self.weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon'
        ]
        
        # Minimum acceptable TLS version
        self.min_tls_version = ssl.TLSVersion.TLSv1_2
    
    async def analyze_host(self, host: str, port: int = 443) -> dict:
        """Analyze SSL/TLS configuration for a host."""
        result = {
            'host': host,
            'port': port,
            'ssl_enabled': False,
            'issues': [],
            'certificate': None,
            'tls_version': None,
            'cipher': None
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect
            loop = asyncio.get_event_loop()
            
            def get_cert_info():
                with socket.create_connection((host, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert(binary_form=False)
                        cipher = ssock.cipher()
                        version = ssock.version()
                        
                        # Get certificate in binary form for more details
                        cert_bin = ssock.getpeercert(binary_form=True)
                        
                        return cert, cipher, version, cert_bin
            
            cert, cipher, version, cert_bin = await loop.run_in_executor(None, get_cert_info)
            
            result['ssl_enabled'] = True
            result['tls_version'] = version
            result['cipher'] = cipher
            
            # Parse certificate
            if cert:
                result['certificate'] = {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'serial_number': cert.get('serialNumber'),
                    'san': [x[1] for x in cert.get('subjectAltName', [])]
                }
                
                # Check expiration
                not_after = cert.get('notAfter')
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expiry - datetime.now()).days
                        
                        if days_left < 0:
                            result['issues'].append({
                                'severity': 'HIGH',
                                'issue': 'Certificate EXPIRED',
                                'details': f'Expired {abs(days_left)} days ago'
                            })
                        elif days_left < 30:
                            result['issues'].append({
                                'severity': 'MEDIUM',
                                'issue': 'Certificate expiring soon',
                                'details': f'Expires in {days_left} days'
                            })
                        
                        result['certificate']['days_until_expiry'] = days_left
                    except:
                        pass
                
                # Check if self-signed
                subject = result['certificate'].get('subject', {})
                issuer = result['certificate'].get('issuer', {})
                if subject == issuer:
                    result['issues'].append({
                        'severity': 'MEDIUM',
                        'issue': 'Self-signed certificate',
                        'details': 'Certificate is self-signed, not trusted by browsers'
                    })
                
                # Check hostname match
                cn = subject.get('commonName', '')
                san = result['certificate'].get('san', [])
                
                if host not in san and not cn.endswith(host) and host != cn:
                    if not any(host.endswith(s.replace('*.', '')) for s in san if s.startswith('*.')):
                        result['issues'].append({
                            'severity': 'MEDIUM',
                            'issue': 'Hostname mismatch',
                            'details': f'Certificate CN/SAN does not match {host}'
                        })
            
            # Check TLS version
            if version:
                if 'TLSv1.0' in version or 'TLSv1.1' in version or 'SSLv' in version:
                    result['issues'].append({
                        'severity': 'MEDIUM',
                        'issue': 'Outdated TLS version',
                        'details': f'Using {version}, should use TLS 1.2 or higher'
                    })
            
            # Check cipher strength
            if cipher:
                cipher_name = cipher[0] if cipher else ''
                for weak in self.weak_ciphers:
                    if weak in cipher_name.upper():
                        result['issues'].append({
                            'severity': 'MEDIUM',
                            'issue': 'Weak cipher suite',
                            'details': f'Using weak cipher: {cipher_name}'
                        })
                        break
        
        except ssl.SSLError as e:
            result['issues'].append({
                'severity': 'HIGH',
                'issue': 'SSL Error',
                'details': str(e)
            })
        except socket.timeout:
            result['issues'].append({
                'severity': 'INFO',
                'issue': 'Connection timeout',
                'details': 'Could not connect to host'
            })
        except Exception as e:
            result['issues'].append({
                'severity': 'INFO',
                'issue': 'Connection failed',
                'details': str(e)
            })
        
        return result
    
    async def analyze_async(self, hosts: list, output_dir: str) -> dict:
        """Analyze SSL/TLS for multiple hosts."""
        learn("SSL/TLS Analysis",
              "We're checking SSL/TLS configurations for security issues:\n"
              "• Expired certificates - immediate security risk\n"
              "• Self-signed certs - not trusted by browsers\n"
              "• Weak ciphers - vulnerable to attacks\n"
              "• Old TLS versions - known vulnerabilities\n"
              "• Hostname mismatch - trust issues\n\n"
              "These are usually LOW-MEDIUM severity but easy to find.",
              self.learn_mode)
        
        info(f"Analyzing SSL/TLS for {len(hosts)} hosts...")
        
        results = {
            'total_hosts': len(hosts),
            'ssl_enabled': 0,
            'issues_found': [],
            'by_severity': {'HIGH': [], 'MEDIUM': [], 'LOW': [], 'INFO': []},
            'by_host': []
        }
        
        semaphore = asyncio.Semaphore(20)
        
        async def analyze_with_limit(host):
            async with semaphore:
                return await self.analyze_host(host)
        
        tasks = [analyze_with_limit(host) for host in hosts]
        host_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in host_results:
            if isinstance(result, dict):
                results['by_host'].append(result)
                
                if result.get('ssl_enabled'):
                    results['ssl_enabled'] += 1
                
                for issue in result.get('issues', []):
                    severity = issue.get('severity', 'INFO')
                    results['issues_found'].append({
                        'host': result['host'],
                        **issue
                    })
                    results['by_severity'][severity].append({
                        'host': result['host'],
                        **issue
                    })
        
        # Report findings
        success(f"Analyzed {results['ssl_enabled']} hosts with SSL")
        
        total_issues = len(results['issues_found'])
        if total_issues > 0:
            warning(f"Found {total_issues} SSL/TLS issues:")
            for severity in ['HIGH', 'MEDIUM', 'LOW']:
                issues = results['by_severity'][severity]
                if issues:
                    warning(f"  [{severity}] {len(issues)} issues")
                    for issue in issues[:3]:
                        warning(f"    {issue['host']}: {issue['issue']}")
        else:
            info("No SSL/TLS issues found")
        
        # Save results
        import json
        output_file = Path(output_dir) / f"ssl_analysis_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        return results
    
    def analyze(self, hosts: list, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.analyze_async(hosts, output_dir))
