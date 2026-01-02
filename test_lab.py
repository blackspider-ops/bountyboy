#!/usr/bin/env python3
"""
BountyBoy - ULTIMATE Lab Tester

Runs ALL modules against local vulnerable apps.
This is the full arsenal test for local labs.
"""
import asyncio
import click
import urllib3
import json
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.utils import load_config, ensure_dirs, learn, success, error, info, warning, timestamp

# Import ALL modules
from src.scanner import Scanner
from src.js_analyzer import JSAnalyzer
from src.wayback import WaybackAnalyzer
from src.fuzzer import PathFuzzer
from src.cors_checker import CORSChecker
from src.header_analyzer import HeaderAnalyzer
from src.ssl_analyzer import SSLAnalyzer
from src.google_dorker import GoogleDorker
from src.dns_analyzer import DNSAnalyzer
from src.open_redirect import OpenRedirectFinder
from src.sqli_scanner import SQLiScanner
from src.xss_scanner import XSSScanner
from src.favicon_hash import FaviconHasher
from src.api_fuzzer import APIFuzzer
from src.ssrf_scanner import SSRFScanner
from src.jwt_analyzer import JWTAnalyzer
from src.idor_scanner import IDORScanner
from src.param_miner import ParamMiner
from src.report_generator import ReportGenerator

urllib3.disable_warnings()
console = Console()

BANNER = """
[bold cyan]
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   🧪 BountyBoy ULTIMATE LAB TESTER 🧪                                         ║
║                                                                               ║
║   Running ALL modules against local vulnerable applications                   ║
║   Full Arsenal Mode - Every scanner, every check, everything!                 ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
[/bold cyan]
"""

@click.command()
@click.option('--target', '-t', required=True, help='Target URL (e.g., localhost:3000)')
@click.option('--learn', 'learn_mode', is_flag=True, help='Enable learning mode')
@click.option('--config', '-c', default='config.yaml', help='Config file')
@click.option('--report', is_flag=True, help='Generate reports')
def main(target: str, learn_mode: bool, config: str, report: bool):
    """
    ULTIMATE Lab Tester - Run ALL BountyBoy modules.
    
    Examples:
        python test_lab.py -t localhost:3000 --learn --report
        python test_lab.py -t localhost:8080 --learn --report
    """
    console.print(BANNER)
    start_time = datetime.now()
    
    # Load config
    try:
        cfg = load_config(config)
    except FileNotFoundError:
        error(f"Config not found: {config}")
        return
    
    # Setup directories
    dirs = ensure_dirs(target, cfg)
    
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Mode:[/bold] ULTIMATE (All Modules)\n"
        f"[bold]Learn:[/bold] {'ON' if learn_mode else 'OFF'}\n"
        f"[bold]Report:[/bold] {'ON' if report else 'OFF'}\n"
        f"[bold]Output:[/bold] {dirs['base']}",
        title="🎯 Configuration",
        border_style="cyan"
    ))
    
    # Results container
    results = initialize_results(target)
    hosts = [target]
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 1: RECONNAISSANCE
    # ═══════════════════════════════════════════════════════════════
    print_phase("PHASE 1: RECONNAISSANCE")
    
    # JavaScript Analysis
    console.print("[cyan]▶ JavaScript Analysis[/cyan]")
    js = JSAnalyzer(cfg, learn_mode)
    js_results = js.analyze(hosts, dirs['scans'])
    results['js_secrets'] = js_results.get('secrets', [])
    results['js_endpoints'] = js_results.get('api_endpoints', [])
    
    # Security Headers
    console.print("\n[cyan]▶ Security Headers Analysis[/cyan]")
    headers = HeaderAnalyzer(cfg, learn_mode)
    header_results = headers.analyze(hosts, dirs['scans'])
    results['header_issues'] = header_results.get('common_missing', {})
    results['header_score'] = header_results.get('average_score', 0)
    
    # Favicon Hash
    console.print("\n[cyan]▶ Favicon Hash Analysis[/cyan]")
    favicon = FaviconHasher(cfg, learn_mode)
    favicon_results = favicon.analyze(hosts, dirs['scans'])
    results['favicon_identified'] = favicon_results.get('identified', [])
    results['favicon_hashes'] = favicon_results.get('unknown_hashes', [])
    
    # Path Fuzzing
    console.print("\n[cyan]▶ Path Fuzzing (Admin, Backup, Config files)[/cyan]")
    fuzzer = PathFuzzer(cfg, learn_mode)
    fuzz_results = fuzzer.fuzz(hosts, dirs['scans'])
    results['fuzz_findings'] = fuzz_results.get('critical_findings', [])
    results['fuzz_interesting'] = fuzz_results.get('interesting_findings', [])
    results['fuzz_total'] = fuzz_results.get('total_found', 0)
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 2: API & ENDPOINT DISCOVERY
    # ═══════════════════════════════════════════════════════════════
    print_phase("PHASE 2: API & ENDPOINT DISCOVERY")
    
    # API Endpoint Fuzzing
    console.print("[cyan]▶ API Endpoint Fuzzing[/cyan]")
    api = APIFuzzer(cfg, learn_mode)
    api_results = api.fuzz(hosts, dirs['scans'])
    results['api_endpoints'] = api_results.get('total_endpoints', 0)
    results['api_critical'] = api_results.get('critical_findings', [])
    results['graphql_endpoints'] = api_results.get('graphql_endpoints', [])
    results['swagger_docs'] = api_results.get('swagger_docs', [])
    
    # Parameter Mining
    console.print("\n[cyan]▶ Parameter Mining[/cyan]")
    params = ParamMiner(cfg, learn_mode)
    param_results = params.mine(hosts, [], '', dirs['scans'])
    results['reflected_params'] = param_results.get('reflected_params', [])
    results['hidden_params'] = param_results.get('hidden_params_found', 0)
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 3: VULNERABILITY SCANNING
    # ═══════════════════════════════════════════════════════════════
    print_phase("PHASE 3: VULNERABILITY SCANNING")
    
    # CORS Check
    console.print("[cyan]▶ CORS Misconfiguration Check[/cyan]")
    cors = CORSChecker(cfg, learn_mode)
    cors_results = cors.check(hosts, target.split(':')[0], dirs['scans'])
    results['cors_vulns'] = cors_results.get('vulnerable_endpoints', [])
    
    # Open Redirect
    console.print("\n[cyan]▶ Open Redirect Detection[/cyan]")
    redirect = OpenRedirectFinder(cfg, learn_mode)
    redirect_results = redirect.scan(hosts, dirs['scans'])
    results['open_redirects'] = redirect_results.get('vulnerable', [])
    
    # SQLi Quick Check
    console.print("\n[cyan]▶ SQL Injection Scanning[/cyan]")
    sqli = SQLiScanner(cfg, learn_mode)
    sqli_results = sqli.scan(hosts, dirs['scans'])
    results['sqli_vulns'] = sqli_results.get('vulnerable', [])
    results['sqli_errors'] = sqli_results.get('error_based', [])
    
    # XSS Quick Check
    console.print("\n[cyan]▶ XSS Scanning[/cyan]")
    xss = XSSScanner(cfg, learn_mode)
    xss_results = xss.scan(hosts, dirs['scans'])
    results['xss_vulns'] = xss_results.get('vulnerable', [])
    results['xss_reflected'] = xss_results.get('reflected', [])
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 4: HIGH-VALUE VULNERABILITY CHECKS
    # ═══════════════════════════════════════════════════════════════
    print_phase("PHASE 4: HIGH-VALUE VULNERABILITY CHECKS")
    
    # SSRF Scanner
    console.print("[cyan]▶ SSRF Vulnerability Scanning[/cyan]")
    ssrf = SSRFScanner(cfg, learn_mode)
    ssrf_results = ssrf.scan(hosts, dirs['scans'])
    results['ssrf_critical'] = ssrf_results.get('critical_findings', [])
    results['ssrf_high'] = ssrf_results.get('high_findings', [])
    results['ssrf_potential'] = ssrf_results.get('potential_findings', [])
    
    # JWT Analysis
    console.print("\n[cyan]▶ JWT Token Analysis[/cyan]")
    jwt = JWTAnalyzer(cfg, learn_mode)
    jwt_results = jwt.analyze(hosts, dirs['scans'])
    results['jwt_found'] = jwt_results.get('total_jwts', 0)
    results['jwt_vulns'] = jwt_results.get('critical_findings', [])
    results['jwt_weak_secrets'] = jwt_results.get('weak_secrets_found', [])
    
    # IDOR Scanner
    console.print("\n[cyan]▶ IDOR / Access Control Testing[/cyan]")
    idor = IDORScanner(cfg, learn_mode)
    # Use discovered API endpoints for IDOR testing
    discovered_urls = [f"http://{target}{ep}" for ep in results.get('js_endpoints', [])[:20] if ep.startswith('/')]
    idor_results = idor.scan(hosts, discovered_urls, dirs['scans'])
    results['idor_critical'] = idor_results.get('critical_findings', [])
    results['idor_high'] = idor_results.get('high_findings', [])
    results['idor_tests'] = idor_results.get('total_tests', 0)
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 5: DNS & INFRASTRUCTURE
    # ═══════════════════════════════════════════════════════════════
    print_phase("PHASE 5: DNS & INFRASTRUCTURE ANALYSIS")
    
    # DNS Analysis (limited for localhost)
    console.print("[cyan]▶ DNS Security Analysis[/cyan]")
    dns = DNSAnalyzer(cfg, learn_mode)
    dns_results = dns.analyze(target.split(':')[0], dirs['scans'])
    results['dns_vulns'] = dns_results.get('vulnerabilities', [])
    
    # Google Dork Generation
    console.print("\n[cyan]▶ Google Dork Generation[/cyan]")
    google = GoogleDorker(cfg, learn_mode)
    google_results = google.generate_dorks(target.split(':')[0])
    results['google_dorks'] = google_results.get('total_dorks', 0)
    
    # ═══════════════════════════════════════════════════════════════
    # FINALIZE
    # ═══════════════════════════════════════════════════════════════
    duration = datetime.now() - start_time
    results['end_time'] = datetime.now().isoformat()
    results['duration_seconds'] = duration.total_seconds()
    
    # Print summary
    print_summary(results, duration)
    
    # Generate reports
    if report:
        console.print("\n[cyan]Generating reports...[/cyan]")
        reporter = ReportGenerator(cfg)
        report_paths = reporter.generate(results, dirs['reports'])
        success(f"HTML Report: {report_paths['html']}")
        success(f"Markdown Report: {report_paths['markdown']}")
    
    # Save JSON results
    json_path = Path(dirs['reports']) / f"ultimate_results_{timestamp()}.json"
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    info(f"JSON Results: {json_path}")
    
    return results


def initialize_results(target: str) -> dict:
    """Initialize results container."""
    return {
        'target': target,
        'mode': 'ultimate_lab_test',
        'start_time': datetime.now().isoformat(),
        'subdomains': [target],
        'alive_hosts': [target],
        # Recon
        'js_secrets': [],
        'js_endpoints': [],
        'header_issues': {},
        'header_score': 0,
        'favicon_identified': [],
        'favicon_hashes': [],
        'fuzz_findings': [],
        'fuzz_interesting': [],
        'fuzz_total': 0,
        # API
        'api_endpoints': 0,
        'api_critical': [],
        'graphql_endpoints': [],
        'swagger_docs': [],
        'reflected_params': [],
        'hidden_params': 0,
        # Vulns
        'cors_vulns': [],
        'open_redirects': [],
        'sqli_vulns': [],
        'sqli_errors': [],
        'xss_vulns': [],
        'xss_reflected': [],
        # High-value
        'ssrf_critical': [],
        'ssrf_high': [],
        'ssrf_potential': [],
        'jwt_found': 0,
        'jwt_vulns': [],
        'jwt_weak_secrets': [],
        'idor_critical': [],
        'idor_high': [],
        'idor_tests': 0,
        # Infrastructure
        'dns_vulns': [],
        'google_dorks': 0,
    }


def print_phase(title: str):
    """Print phase header."""
    console.print(f"\n[bold magenta]{'═' * 70}[/bold magenta]")
    console.print(f"[bold magenta]  {title}[/bold magenta]")
    console.print(f"[bold magenta]{'═' * 70}[/bold magenta]\n")


def count_vulns(results: dict) -> int:
    """Count all vulnerabilities."""
    return (
        len(results.get('js_secrets', [])) +
        len(results.get('fuzz_findings', [])) +
        len(results.get('api_critical', [])) +
        len(results.get('cors_vulns', [])) +
        len(results.get('open_redirects', [])) +
        len(results.get('sqli_vulns', [])) +
        len(results.get('xss_vulns', [])) +
        len(results.get('ssrf_critical', [])) +
        len(results.get('ssrf_high', [])) +
        len(results.get('jwt_vulns', [])) +
        len(results.get('jwt_weak_secrets', [])) +
        len(results.get('idor_critical', [])) +
        len(results.get('idor_high', [])) +
        len(results.get('dns_vulns', []))
    )


def print_summary(results: dict, duration):
    """Print comprehensive summary."""
    console.print(f"\n[bold magenta]{'═' * 70}[/bold magenta]")
    console.print("[bold magenta]  🎯 ULTIMATE SCAN COMPLETE - FINAL SUMMARY 🎯[/bold magenta]")
    console.print(f"[bold magenta]{'═' * 70}[/bold magenta]\n")
    
    # Recon table
    table1 = Table(title="📡 Reconnaissance", show_header=True, header_style="bold cyan")
    table1.add_column("Finding", style="dim")
    table1.add_column("Count", justify="right")
    table1.add_column("Status", justify="center")
    
    def status(count, critical=False):
        if critical and count > 0:
            return "🚨"
        elif count > 0:
            return "✓"
        return "○"
    
    table1.add_row("JS Secrets", str(len(results.get('js_secrets', []))), status(len(results.get('js_secrets', [])), True))
    table1.add_row("JS Endpoints", str(len(results.get('js_endpoints', []))), status(len(results.get('js_endpoints', []))))
    table1.add_row("Critical Paths", str(len(results.get('fuzz_findings', []))), status(len(results.get('fuzz_findings', [])), True))
    table1.add_row("Total Paths Found", str(results.get('fuzz_total', 0)), status(results.get('fuzz_total', 0)))
    table1.add_row("Security Header Score", f"{results.get('header_score', 0)}/7", "⚠️" if results.get('header_score', 0) < 5 else "✓")
    table1.add_row("Favicon Identified", str(len(results.get('favicon_identified', []))), status(len(results.get('favicon_identified', []))))
    
    console.print(table1)
    
    # API table
    table2 = Table(title="\n🔌 API & Endpoints", show_header=True, header_style="bold cyan")
    table2.add_column("Finding", style="dim")
    table2.add_column("Count", justify="right")
    table2.add_column("Status", justify="center")
    
    table2.add_row("API Endpoints", str(results.get('api_endpoints', 0)), status(results.get('api_endpoints', 0)))
    table2.add_row("API Critical", str(len(results.get('api_critical', []))), status(len(results.get('api_critical', [])), True))
    table2.add_row("GraphQL Endpoints", str(len(results.get('graphql_endpoints', []))), status(len(results.get('graphql_endpoints', []))))
    table2.add_row("Swagger Docs", str(len(results.get('swagger_docs', []))), status(len(results.get('swagger_docs', []))))
    table2.add_row("Reflected Params", str(len(results.get('reflected_params', []))), status(len(results.get('reflected_params', [])), True))
    
    console.print(table2)
    
    # Vulnerability table
    table3 = Table(title="\n🔥 Vulnerabilities", show_header=True, header_style="bold cyan")
    table3.add_column("Vulnerability", style="dim")
    table3.add_column("Count", justify="right")
    table3.add_column("Severity", justify="center")
    
    table3.add_row("CORS Misconfig", str(len(results.get('cors_vulns', []))), status(len(results.get('cors_vulns', [])), True))
    table3.add_row("Open Redirects", str(len(results.get('open_redirects', []))), status(len(results.get('open_redirects', [])), True))
    table3.add_row("SQLi Vulns", str(len(results.get('sqli_vulns', []))), status(len(results.get('sqli_vulns', [])), True))
    table3.add_row("XSS Vulns", str(len(results.get('xss_vulns', []))), status(len(results.get('xss_vulns', [])), True))
    
    console.print(table3)
    
    # High-value table
    table4 = Table(title="\n💰 High-Value Findings", show_header=True, header_style="bold red")
    table4.add_column("Vulnerability", style="dim")
    table4.add_column("Count", justify="right")
    table4.add_column("$$$ Potential", justify="center")
    
    ssrf_total = len(results.get('ssrf_critical', [])) + len(results.get('ssrf_high', []))
    jwt_total = len(results.get('jwt_vulns', [])) + len(results.get('jwt_weak_secrets', []))
    idor_total = len(results.get('idor_critical', [])) + len(results.get('idor_high', []))
    
    table4.add_row("SSRF (Critical+High)", str(ssrf_total), "🚨 $10k+" if ssrf_total > 0 else "○")
    table4.add_row("JWT Vulnerabilities", str(jwt_total), "🚨 $5k+" if jwt_total > 0 else "○")
    table4.add_row("IDOR (Critical+High)", str(idor_total), "🚨 $1k+" if idor_total > 0 else "○")
    table4.add_row("IDOR Tests Performed", str(results.get('idor_tests', 0)), "✓" if results.get('idor_tests', 0) > 0 else "○")
    
    console.print(table4)
    
    # Total findings
    total = count_vulns(results)
    if total > 0:
        console.print(Panel(
            f"[bold red]🚨 {total} TOTAL FINDINGS REQUIRE MANUAL VERIFICATION[/bold red]\n\n"
            f"[yellow]Critical Paths:[/yellow] {len(results.get('fuzz_findings', []))}\n"
            f"[yellow]JS Secrets:[/yellow] {len(results.get('js_secrets', []))}\n"
            f"[yellow]CORS Issues:[/yellow] {len(results.get('cors_vulns', []))}\n"
            f"[yellow]High-Value Vulns:[/yellow] {ssrf_total + jwt_total + idor_total}\n\n"
            "Review the output files and verify before reporting.",
            title="⚠️ Action Required",
            border_style="red"
        ))
    else:
        console.print(Panel(
            "[green]No critical vulnerabilities found in automated scan.[/green]\n\n"
            "This doesn't mean the target is secure - manual testing recommended.",
            title="✓ Scan Complete",
            border_style="green"
        ))
    
    console.print(f"\n[bold]Target:[/bold] {results['target']}")
    console.print(f"[bold]Duration:[/bold] {duration.total_seconds():.1f} seconds")
    console.print(f"[bold]Google Dorks Generated:[/bold] {results.get('google_dorks', 0)}")


if __name__ == "__main__":
    main()
