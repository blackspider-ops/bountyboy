#!/usr/bin/env python3
"""
BountyBoy - Local Lab Tester

Tests all modules against local vulnerable apps (Juice Shop, DVWA, etc.)
Skips subdomain discovery since we're testing localhost.
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

from src.utils import load_config, ensure_dirs, learn, success, error, info, warning, timestamp
from src.scanner import Scanner
from src.js_analyzer import JSAnalyzer
from src.fuzzer import PathFuzzer
from src.cors_checker import CORSChecker
from src.header_analyzer import HeaderAnalyzer
from src.ssl_analyzer import SSLAnalyzer
from src.google_dorker import GoogleDorker
from src.open_redirect import OpenRedirectFinder
from src.sqli_scanner import SQLiScanner
from src.xss_scanner import XSSScanner
from src.api_fuzzer import APIFuzzer
from src.ssrf_scanner import SSRFScanner
from src.jwt_analyzer import JWTAnalyzer
from src.idor_scanner import IDORScanner
from src.report_generator import ReportGenerator

urllib3.disable_warnings()
console = Console()

BANNER = """
[bold cyan]
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   🧪 BountyBoy LOCAL LAB TESTER 🧪                                            ║
║                                                                               ║
║   Testing modules against local vulnerable applications                       ║
║   Skips subdomain discovery - goes straight to vulnerability scanning         ║
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
    Test BountyBoy modules against local vulnerable apps.
    
    Examples:
        python test_local.py -t localhost:3000 --learn
        python test_local.py -t localhost:8080 --learn --report
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
        f"[bold]Learn:[/bold] {'ON' if learn_mode else 'OFF'}\n"
        f"[bold]Report:[/bold] {'ON' if report else 'OFF'}\n"
        f"[bold]Output:[/bold] {dirs['base']}",
        title="🎯 Configuration",
        border_style="cyan"
    ))
    
    # Results container
    results = {
        'target': target,
        'mode': 'local_test',
        'start_time': datetime.now().isoformat(),
        'subdomains': [target],  # Just the target itself
        'alive_hosts': [target],
        'vulnerabilities': [],
        'js_secrets': [],
        'js_endpoints': [],
        'fuzz_findings': [],
        'cors_vulns': [],
        'header_issues': {},
        'ssl_issues': [],
        'open_redirects': [],
        'sqli_vulns': [],
        'xss_vulns': [],
        'api_endpoints': [],
        'api_critical': [],
        'graphql_endpoints': [],
        'ssrf_vulns': [],
        'jwt_vulns': [],
        'jwt_weak_secrets': [],
        'idor_vulns': [],
    }
    
    hosts = [target]
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 1: BASIC ANALYSIS
    # ═══════════════════════════════════════════════════════════════
    print_phase("PHASE 1: BASIC ANALYSIS")
    
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
    
    # Path Fuzzing
    console.print("\n[cyan]▶ Path Fuzzing[/cyan]")
    fuzzer = PathFuzzer(cfg, learn_mode)
    fuzz_results = fuzzer.fuzz(hosts, dirs['scans'])
    results['fuzz_findings'] = fuzz_results.get('critical_findings', [])
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 2: VULNERABILITY SCANNING
    # ═══════════════════════════════════════════════════════════════
    print_phase("PHASE 2: VULNERABILITY SCANNING")
    
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
    console.print("\n[cyan]▶ SQL Injection Quick Check[/cyan]")
    sqli = SQLiScanner(cfg, learn_mode)
    sqli_results = sqli.scan(hosts, dirs['scans'])
    results['sqli_vulns'] = sqli_results.get('vulnerable', [])
    
    # XSS Quick Check
    console.print("\n[cyan]▶ XSS Quick Check[/cyan]")
    xss = XSSScanner(cfg, learn_mode)
    xss_results = xss.scan(hosts, dirs['scans'])
    results['xss_vulns'] = xss_results.get('vulnerable', [])
    
    # API Endpoint Fuzzing
    console.print("\n[cyan]▶ API Endpoint Fuzzing[/cyan]")
    api = APIFuzzer(cfg, learn_mode)
    api_results = api.fuzz(hosts, dirs['scans'])
    results['api_endpoints'] = api_results.get('endpoints_found', [])
    results['api_critical'] = api_results.get('critical_findings', [])
    results['graphql_endpoints'] = api_results.get('graphql_endpoints', [])
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 3: HIGH-VALUE VULNERABILITY CHECKS
    # ═══════════════════════════════════════════════════════════════
    print_phase("PHASE 3: HIGH-VALUE VULNERABILITY CHECKS")
    
    # SSRF Scanner
    console.print("[cyan]▶ SSRF Vulnerability Scanning[/cyan]")
    ssrf = SSRFScanner(cfg, learn_mode)
    ssrf_results = ssrf.scan(hosts, dirs['scans'])
    results['ssrf_vulns'] = ssrf_results.get('critical_findings', []) + ssrf_results.get('high_findings', [])
    
    # JWT Analysis
    console.print("\n[cyan]▶ JWT Token Analysis[/cyan]")
    jwt = JWTAnalyzer(cfg, learn_mode)
    jwt_results = jwt.analyze(hosts, dirs['scans'])
    results['jwt_vulns'] = jwt_results.get('critical_findings', [])
    results['jwt_weak_secrets'] = jwt_results.get('weak_secrets_found', [])
    
    # IDOR Scanner
    console.print("\n[cyan]▶ IDOR / Access Control Testing[/cyan]")
    idor = IDORScanner(cfg, learn_mode)
    idor_results = idor.scan(hosts, [], dirs['scans'])
    results['idor_vulns'] = idor_results.get('critical_findings', []) + idor_results.get('high_findings', [])
    
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
    json_path = Path(dirs['reports']) / f"results_{timestamp()}.json"
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    info(f"JSON Results: {json_path}")


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
        len(results.get('cors_vulns', [])) +
        len(results.get('open_redirects', [])) +
        len(results.get('sqli_vulns', [])) +
        len(results.get('xss_vulns', [])) +
        len(results.get('api_critical', [])) +
        len(results.get('ssrf_vulns', [])) +
        len(results.get('jwt_vulns', [])) +
        len(results.get('jwt_weak_secrets', [])) +
        len(results.get('idor_vulns', []))
    )


def print_summary(results: dict, duration):
    """Print summary."""
    console.print(f"\n[bold magenta]{'═' * 70}[/bold magenta]")
    console.print("[bold magenta]  SCAN COMPLETE - FINAL SUMMARY[/bold magenta]")
    console.print(f"[bold magenta]{'═' * 70}[/bold magenta]\n")
    
    table = Table(title="📊 Results", show_header=True, header_style="bold cyan")
    table.add_column("Category", style="dim")
    table.add_column("Count", justify="right")
    table.add_column("Status", justify="center")
    
    def add_row(label, count, critical=False):
        if critical and count > 0:
            status = "🚨"
        elif count > 0:
            status = "✓"
        else:
            status = "○"
        table.add_row(label, str(count), status)
    
    add_row("JS Secrets", len(results.get('js_secrets', [])), True)
    add_row("JS Endpoints", len(results.get('js_endpoints', [])))
    add_row("Critical Paths", len(results.get('fuzz_findings', [])), True)
    add_row("CORS Issues", len(results.get('cors_vulns', [])), True)
    add_row("Open Redirects", len(results.get('open_redirects', [])), True)
    add_row("SQLi Vulns", len(results.get('sqli_vulns', [])), True)
    add_row("XSS Vulns", len(results.get('xss_vulns', [])), True)
    add_row("API Endpoints", len(results.get('api_endpoints', [])))
    add_row("API Critical", len(results.get('api_critical', [])), True)
    add_row("GraphQL", len(results.get('graphql_endpoints', [])))
    add_row("SSRF Vulns", len(results.get('ssrf_vulns', [])), True)
    add_row("JWT Vulns", len(results.get('jwt_vulns', [])), True)
    add_row("JWT Weak Secrets", len(results.get('jwt_weak_secrets', [])), True)
    add_row("IDOR Vulns", len(results.get('idor_vulns', [])), True)
    
    console.print(table)
    
    total = count_vulns(results)
    if total > 0:
        console.print(Panel(
            f"[bold red]🚨 {total} FINDINGS REQUIRE MANUAL VERIFICATION[/bold red]\n\n"
            "Review the output files and verify before reporting.",
            title="⚠️ Action Required",
            border_style="red"
        ))
    
    console.print(f"\n[dim]Completed in {duration.total_seconds():.1f} seconds[/dim]")


if __name__ == "__main__":
    main()
