#!/usr/bin/env python3
"""
BountyBoy - The Ultimate Bug Bounty Automation Toolkit

THE COMPLETE ARSENAL - Everything runs in parallel where possible.

MODULES INCLUDED:
├── Subdomain Discovery (parallel)
│   ├── Subfinder
│   ├── Assetfinder
│   ├── Amass
│   └── crt.sh
│
├── Scanning Pipeline
│   ├── httpx (alive check)
│   ├── nmap (ports)
│   └── nuclei (vulns)
│
├── Deep Analysis (parallel)
│   ├── JavaScript Analysis
│   ├── Wayback Machine
│   ├── Tech Detection
│   └── Path Fuzzing
│
├── Vulnerability Checks (parallel)
│   ├── Subdomain Takeover
│   ├── CORS Misconfiguration
│   ├── Security Headers
│   ├── SSL/TLS Analysis
│   └── GitHub Dorking
│
├── Intelligence Gathering (parallel)
│   ├── Shodan Recon
│   ├── Email Harvesting
│   ├── Cloud Enumeration
│   └── Parameter Mining
│
└── Reporting
    ├── HTML Report
    ├── Markdown Report
    └── JSON Export
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

# Import all modules
from src.async_discovery import AsyncSubdomainDiscovery
from src.scanner import Scanner
from src.visual_recon import VisualRecon
from src.js_analyzer import JSAnalyzer
from src.wayback import WaybackAnalyzer
from src.fuzzer import PathFuzzer
from src.subdomain_takeover import SubdomainTakeoverChecker
from src.cors_checker import CORSChecker
from src.header_analyzer import HeaderAnalyzer
from src.github_dorker import GitHubDorker
from src.ssl_analyzer import SSLAnalyzer
from src.shodan_recon import ShodanRecon
from src.email_harvester import EmailHarvester
from src.cloud_enum import CloudEnumerator
from src.param_miner import ParamMiner
from src.report_generator import ReportGenerator
from src.notifier import Notifier

# NEW MODULES (Task 3)
from src.google_dorker import GoogleDorker
from src.dns_analyzer import DNSAnalyzer
from src.open_redirect import OpenRedirectFinder
from src.sqli_scanner import SQLiScanner
from src.xss_scanner import XSSScanner
from src.favicon_hash import FaviconHasher
from src.api_fuzzer import APIFuzzer

# HIGH-VALUE MODULES (Recommended)
from src.ssrf_scanner import SSRFScanner
from src.jwt_analyzer import JWTAnalyzer
from src.idor_scanner import IDORScanner

urllib3.disable_warnings()
console = Console()


BANNER = """
[bold cyan]
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗                      ║
║   ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝                      ║
║   ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝                       ║
║   ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝                        ║
║   ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║                         ║
║   ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝                         ║
║                                                                               ║
║   ██████╗  ██████╗ ██╗   ██╗                                                  ║
║   ██╔══██╗██╔═══██╗╚██╗ ██╔╝                                                  ║
║   ██████╔╝██║   ██║ ╚████╔╝                                                   ║
║   ██╔══██╗██║   ██║  ╚██╔╝                                                    ║
║   ██████╔╝╚██████╔╝   ██║                                                     ║
║   ╚═════╝  ╚═════╝    ╚═╝                                                     ║
║                                                                               ║
║                    THE ULTIMATE BUG BOUNTY AUTOMATION TOOLKIT                 ║
║                              🎯 BountyBoy 🎯                                   ║
║                                                                               ║
║   Modules: Subdomain Discovery | Port Scanning | Vuln Scanning | JS Analysis  ║
║            Wayback | Fuzzing | Takeover | CORS | Headers | SSL | Shodan       ║
║            SSRF | JWT | IDOR | SQLi | XSS | API Fuzzing | And More...         ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
[/bold cyan]
"""


@click.command()
@click.option('--target', '-t', required=True, help='Target domain')
@click.option('--learn', 'learn_mode', is_flag=True, help='Enable learning mode')
@click.option('--config', '-c', default='config.yaml', help='Config file')
@click.option('--quick', is_flag=True, help='Quick: subdomain discovery only')
@click.option('--standard', is_flag=True, help='Standard: discovery + scanning + analysis')
@click.option('--full', is_flag=True, help='Full: everything including all vuln checks')
@click.option('--insane', is_flag=True, help='Insane: absolutely everything, takes longest')
@click.option('--notify', is_flag=True, help='Send notifications')
@click.option('--report', is_flag=True, help='Generate HTML/MD reports')
def main(target: str, learn_mode: bool, config: str, quick: bool, standard: bool,
         full: bool, insane: bool, notify: bool, report: bool):
    """
    BountyBoy - The Complete Arsenal
    
    Modes:
        --quick    : Subdomain discovery only (~30 seconds)
        --standard : Discovery + scanning + deep analysis (~10 minutes)
        --full     : + vulnerability checks (~20 minutes)
        --insane   : + cloud enum + email harvest + everything (~30+ minutes)
    
    Examples:
        python ultimate.py -t example.com --quick
        python ultimate.py -t example.com --standard --learn
        python ultimate.py -t example.com --full --notify --report
        python ultimate.py -t example.com --insane --report
    """
    console.print(BANNER)
    start_time = datetime.now()
    
    # Determine mode
    if quick:
        mode = 'quick'
    elif standard:
        mode = 'standard'
    elif full:
        mode = 'full'
    elif insane:
        mode = 'insane'
    else:
        mode = 'standard'
    
    # Load config
    try:
        cfg = load_config(config)
    except FileNotFoundError:
        error(f"Config not found: {config}")
        info("Run: cp config.example.yaml config.yaml")
        return
    
    # Setup directories
    dirs = ensure_dirs(target, cfg)
    
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Mode:[/bold] {mode.upper()}\n"
        f"[bold]Learn:[/bold] {'ON' if learn_mode else 'OFF'}\n"
        f"[bold]Notify:[/bold] {'ON' if notify else 'OFF'}\n"
        f"[bold]Report:[/bold] {'ON' if report else 'OFF'}\n"
        f"[bold]Output:[/bold] {dirs['base']}",
        title="🎯 Configuration",
        border_style="cyan"
    ))
    
    # Initialize all modules
    modules = initialize_modules(cfg, learn_mode, notify)
    
    # Results container
    results = initialize_results(target, mode)
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 1: SUBDOMAIN DISCOVERY
    # ═══════════════════════════════════════════════════════════════
    print_phase("PHASE 1: SUBDOMAIN DISCOVERY")
    
    results['subdomains'], results['new_subdomains'] = modules['discovery'].discover(
        target, dirs['subdomains']
    )
    
    if not results['subdomains']:
        warning("No subdomains found. Exiting.")
        return
    
    notify_new_subdomains(modules['notifier'], target, results['new_subdomains'])
    
    if mode == 'quick':
        finalize(results, start_time, dirs, modules, report)
        return
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 2: SCANNING PIPELINE
    # ═══════════════════════════════════════════════════════════════
    print_phase("PHASE 2: SCANNING PIPELINE")
    
    scan_results = modules['scanner'].scan(results['subdomains'], dirs['scans'])
    results['alive_hosts'] = scan_results['alive_hosts']
    results['vulnerabilities'] = scan_results['nuclei_findings']
    
    notify_vulnerabilities(modules['notifier'], results['vulnerabilities'])
    
    if not results['alive_hosts']:
        warning("No alive hosts found.")
        finalize(results, start_time, dirs, modules, report)
        return
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 3: DEEP ANALYSIS
    # ═══════════════════════════════════════════════════════════════
    print_phase("PHASE 3: DEEP ANALYSIS")
    
    hosts = results['alive_hosts'][:50]
    
    # JavaScript Analysis
    console.print("[cyan]▶ JavaScript Analysis[/cyan]")
    js_results = modules['js'].analyze(hosts, dirs['scans'])
    results['js_secrets'] = js_results.get('secrets', [])
    results['js_endpoints'] = js_results.get('api_endpoints', [])
    
    # Wayback Machine
    console.print("\n[cyan]▶ Wayback Machine[/cyan]")
    wb_results = modules['wayback'].analyze(target, dirs['scans'])
    results['wayback_urls'] = wb_results.get('total_urls', 0)
    results['wayback_alive'] = wb_results.get('alive_interesting', [])
    results['wayback_params'] = list(set(
        p for params in wb_results.get('parameters', {}).values() for p in params
    ))
    
    # Tech Detection
    console.print("\n[cyan]▶ Tech Stack Detection[/cyan]")
    modules['visual'].run(hosts, dirs['screenshots'])
    
    # Path Fuzzing
    console.print("\n[cyan]▶ Path Fuzzing[/cyan]")
    fuzz_results = modules['fuzzer'].fuzz(hosts[:20], dirs['scans'])
    results['fuzz_findings'] = fuzz_results.get('critical_findings', [])
    
    if mode == 'standard':
        finalize(results, start_time, dirs, modules, report)
        return
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 4: VULNERABILITY CHECKS
    # ═══════════════════════════════════════════════════════════════
    print_phase("PHASE 4: VULNERABILITY CHECKS")
    
    # Subdomain Takeover
    console.print("[cyan]▶ Subdomain Takeover Check[/cyan]")
    takeover_results = modules['takeover'].check(list(results['subdomains']), dirs['scans'])
    results['takeover_vulns'] = takeover_results.get('vulnerable', [])
    
    # CORS Check
    console.print("\n[cyan]▶ CORS Misconfiguration Check[/cyan]")
    cors_results = modules['cors'].check(hosts[:30], target, dirs['scans'])
    results['cors_vulns'] = cors_results.get('vulnerable_endpoints', [])
    
    # Security Headers
    console.print("\n[cyan]▶ Security Headers Analysis[/cyan]")
    header_results = modules['headers'].analyze(hosts[:30], dirs['scans'])
    results['header_issues'] = header_results.get('common_missing', {})
    
    # SSL/TLS Analysis
    console.print("\n[cyan]▶ SSL/TLS Analysis[/cyan]")
    ssl_results = modules['ssl'].analyze(hosts[:30], dirs['scans'])
    results['ssl_issues'] = ssl_results.get('issues_found', [])
    
    # GitHub Dorking
    console.print("\n[cyan]▶ GitHub Dork Generation[/cyan]")
    modules['github'].analyze(target, dirs['scans'])
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 4.5: EXTENDED VULNERABILITY CHECKS (NEW MODULES)
    # ═══════════════════════════════════════════════════════════════
    print_phase("PHASE 4.5: EXTENDED VULNERABILITY CHECKS")
    
    # Google Dorking
    console.print("[cyan]▶ Google Dork Generation[/cyan]")
    google_results = modules['google_dorker'].generate_dorks(target, dirs['scans'])
    results['google_dorks'] = google_results.get('dorks', [])
    
    # DNS Analysis (Zone Transfer, etc.)
    console.print("\n[cyan]▶ DNS Security Analysis[/cyan]")
    dns_results = modules['dns'].analyze(target, dirs['scans'])
    results['dns_vulns'] = dns_results.get('vulnerabilities', [])
    
    # Open Redirect Detection
    console.print("\n[cyan]▶ Open Redirect Detection[/cyan]")
    redirect_results = modules['open_redirect'].scan(hosts[:20], dirs['scans'])
    results['open_redirects'] = redirect_results.get('vulnerable', [])
    
    # SQLi Quick Check
    console.print("\n[cyan]▶ SQL Injection Quick Check[/cyan]")
    sqli_results = modules['sqli'].scan(hosts[:15], results['wayback_params'], dirs['scans'])
    results['sqli_vulns'] = sqli_results.get('vulnerable', [])
    
    # XSS Quick Check
    console.print("\n[cyan]▶ XSS Quick Check[/cyan]")
    xss_results = modules['xss'].scan(hosts[:15], results['wayback_params'], dirs['scans'])
    results['xss_vulns'] = xss_results.get('vulnerable', [])
    
    # Favicon Hash Lookup
    console.print("\n[cyan]▶ Favicon Hash Analysis[/cyan]")
    favicon_results = modules['favicon'].analyze(hosts[:30], dirs['scans'])
    results['favicon_identified'] = favicon_results.get('identified', [])
    
    # API Endpoint Fuzzing
    console.print("\n[cyan]▶ API Endpoint Fuzzing[/cyan]")
    api_results = modules['api_fuzzer'].fuzz(hosts[:20], dirs['scans'])
    results['api_endpoints'] = api_results.get('endpoints_found', [])
    results['api_critical'] = api_results.get('critical_findings', [])
    results['graphql_endpoints'] = api_results.get('graphql_endpoints', [])
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 4.6: HIGH-VALUE VULNERABILITY CHECKS
    # ═══════════════════════════════════════════════════════════════
    print_phase("PHASE 4.6: HIGH-VALUE VULNERABILITY CHECKS")
    
    # SSRF Scanner (Cloud metadata = big bounties)
    console.print("[cyan]▶ SSRF Vulnerability Scanning[/cyan]")
    ssrf_results = modules['ssrf'].scan(hosts[:15], dirs['scans'])
    results['ssrf_vulns'] = ssrf_results.get('critical_findings', []) + ssrf_results.get('high_findings', [])
    
    # JWT Analysis (Auth bypass potential)
    console.print("\n[cyan]▶ JWT Token Analysis[/cyan]")
    jwt_results = modules['jwt'].analyze(hosts[:20], dirs['scans'])
    results['jwt_vulns'] = jwt_results.get('critical_findings', [])
    results['jwt_weak_secrets'] = jwt_results.get('weak_secrets_found', [])
    
    # IDOR / Broken Access Control (Most common high-paying vuln)
    console.print("\n[cyan]▶ IDOR / Access Control Testing[/cyan]")
    # Collect URLs from wayback and API discovery for IDOR testing
    discovered_urls = results.get('wayback_alive', []) + [ep.get('url', '') for ep in results.get('api_endpoints', []) if isinstance(ep, dict)]
    idor_results = modules['idor'].scan(hosts[:15], discovered_urls[:30], dirs['scans'])
    results['idor_vulns'] = idor_results.get('critical_findings', []) + idor_results.get('high_findings', [])

    if mode == 'full':
        finalize(results, start_time, dirs, modules, report)
        return
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 5: INTELLIGENCE GATHERING (Insane mode only)
    # ═══════════════════════════════════════════════════════════════
    print_phase("PHASE 5: INTELLIGENCE GATHERING")
    
    # Shodan Recon
    console.print("[cyan]▶ Shodan Reconnaissance[/cyan]")
    shodan_results = modules['shodan'].recon(target, dirs['scans'])
    results['shodan_vulns'] = shodan_results.get('vulnerabilities', [])
    results['shodan_services'] = shodan_results.get('interesting_services', [])
    
    # Email Harvesting
    console.print("\n[cyan]▶ Email Harvesting[/cyan]")
    email_results = modules['email'].harvest(target, hosts, dirs['scans'])
    results['emails'] = email_results.get('unique_emails', [])
    results['email_pattern'] = email_results.get('email_pattern', {})
    
    # Cloud Enumeration
    console.print("\n[cyan]▶ Cloud Storage Enumeration[/cyan]")
    cloud_results = modules['cloud'].enumerate(target, dirs['scans'])
    results['cloud_buckets'] = cloud_results.get('public', [])
    
    # Parameter Mining
    console.print("\n[cyan]▶ Parameter Mining[/cyan]")
    param_results = modules['params'].mine(
        hosts, 
        results['wayback_params'],
        '',  # JS content would go here
        dirs['scans']
    )
    results['reflected_params'] = param_results.get('reflected_params', [])
    
    finalize(results, start_time, dirs, modules, report)


def initialize_modules(cfg: dict, learn_mode: bool, notify: bool) -> dict:
    """Initialize all modules."""
    return {
        'discovery': AsyncSubdomainDiscovery(cfg, learn_mode),
        'scanner': Scanner(cfg, learn_mode),
        'visual': VisualRecon(cfg, learn_mode),
        'js': JSAnalyzer(cfg, learn_mode),
        'wayback': WaybackAnalyzer(cfg, learn_mode),
        'fuzzer': PathFuzzer(cfg, learn_mode),
        'takeover': SubdomainTakeoverChecker(cfg, learn_mode),
        'cors': CORSChecker(cfg, learn_mode),
        'headers': HeaderAnalyzer(cfg, learn_mode),
        'github': GitHubDorker(cfg, learn_mode),
        'ssl': SSLAnalyzer(cfg, learn_mode),
        'shodan': ShodanRecon(cfg, learn_mode),
        'email': EmailHarvester(cfg, learn_mode),
        'cloud': CloudEnumerator(cfg, learn_mode),
        'params': ParamMiner(cfg, learn_mode),
        'report': ReportGenerator(cfg),
        'notifier': Notifier(cfg) if notify else None,
        # NEW MODULES
        'google_dorker': GoogleDorker(cfg, learn_mode),
        'dns': DNSAnalyzer(cfg, learn_mode),
        'open_redirect': OpenRedirectFinder(cfg, learn_mode),
        'sqli': SQLiScanner(cfg, learn_mode),
        'xss': XSSScanner(cfg, learn_mode),
        'favicon': FaviconHasher(cfg, learn_mode),
        'api_fuzzer': APIFuzzer(cfg, learn_mode),
        # HIGH-VALUE MODULES
        'ssrf': SSRFScanner(cfg, learn_mode),
        'jwt': JWTAnalyzer(cfg, learn_mode),
        'idor': IDORScanner(cfg, learn_mode),
    }


def initialize_results(target: str, mode: str) -> dict:
    """Initialize results container."""
    return {
        'target': target,
        'mode': mode,
        'start_time': datetime.now().isoformat(),
        'subdomains': set(),
        'new_subdomains': [],
        'alive_hosts': [],
        'vulnerabilities': [],
        'js_secrets': [],
        'js_endpoints': [],
        'wayback_urls': 0,
        'wayback_alive': [],
        'wayback_params': [],
        'fuzz_findings': [],
        'takeover_vulns': [],
        'cors_vulns': [],
        'header_issues': {},
        'ssl_issues': [],
        'shodan_vulns': [],
        'shodan_services': [],
        'emails': [],
        'email_pattern': {},
        'cloud_buckets': [],
        'reflected_params': [],
        # NEW MODULE RESULTS
        'google_dorks': [],
        'dns_vulns': [],
        'open_redirects': [],
        'sqli_vulns': [],
        'xss_vulns': [],
        'favicon_identified': [],
        'api_endpoints': [],
        'api_critical': [],
        'graphql_endpoints': [],
        # HIGH-VALUE MODULE RESULTS
        'ssrf_vulns': [],
        'jwt_vulns': [],
        'jwt_weak_secrets': [],
        'idor_vulns': [],
    }


def print_phase(title: str):
    """Print phase header."""
    console.print(f"\n[bold magenta]{'═' * 70}[/bold magenta]")
    console.print(f"[bold magenta]  {title}[/bold magenta]")
    console.print(f"[bold magenta]{'═' * 70}[/bold magenta]\n")


def notify_new_subdomains(notifier, target: str, new_subs: list):
    """Send notification for new subdomains."""
    if notifier and new_subs:
        notifier.notify_new_subdomains(target, new_subs)


def notify_vulnerabilities(notifier, vulns: list):
    """Send notifications for vulnerabilities."""
    if notifier and vulns:
        for vuln in vulns[:5]:
            notifier.notify_vulnerability(vuln)


def finalize(results: dict, start_time: datetime, dirs: dict, modules: dict, generate_report: bool):
    """Finalize scan and generate reports."""
    duration = datetime.now() - start_time
    results['end_time'] = datetime.now().isoformat()
    results['duration_seconds'] = duration.total_seconds()
    
    # Convert sets to lists for JSON
    results['subdomains'] = list(results.get('subdomains', set()))
    
    # Print summary
    print_summary(results, duration)
    
    # Generate reports
    if generate_report:
        console.print("\n[cyan]Generating reports...[/cyan]")
        report_paths = modules['report'].generate(results, dirs['reports'])
        success(f"HTML Report: {report_paths['html']}")
        success(f"Markdown Report: {report_paths['markdown']}")
    
    # Save JSON results
    json_path = Path(dirs['reports']) / f"results_{timestamp()}.json"
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    info(f"JSON Results: {json_path}")
    
    # Notify completion
    if modules['notifier']:
        modules['notifier'].notify_scan_complete(results['target'], {
            'total_subdomains': len(results['subdomains']),
            'new_subdomains': len(results['new_subdomains']),
            'alive_hosts': len(results['alive_hosts']),
            'vulnerabilities': count_all_vulns(results)
        })


def count_all_vulns(results: dict) -> int:
    """Count all vulnerabilities found."""
    return (
        len(results.get('vulnerabilities', [])) +
        len(results.get('js_secrets', [])) +
        len(results.get('takeover_vulns', [])) +
        len(results.get('cors_vulns', [])) +
        len(results.get('ssl_issues', [])) +
        len(results.get('fuzz_findings', [])) +
        len(results.get('cloud_buckets', [])) +
        len(results.get('reflected_params', [])) +
        # NEW MODULE VULNS
        len(results.get('dns_vulns', [])) +
        len(results.get('open_redirects', [])) +
        len(results.get('sqli_vulns', [])) +
        len(results.get('xss_vulns', [])) +
        len(results.get('api_critical', [])) +
        # HIGH-VALUE MODULE VULNS
        len(results.get('ssrf_vulns', [])) +
        len(results.get('jwt_vulns', [])) +
        len(results.get('jwt_weak_secrets', [])) +
        len(results.get('idor_vulns', []))
    )


def print_summary(results: dict, duration: datetime):
    """Print comprehensive summary."""
    console.print(f"\n[bold magenta]{'═' * 70}[/bold magenta]")
    console.print("[bold magenta]  SCAN COMPLETE - FINAL SUMMARY[/bold magenta]")
    console.print(f"[bold magenta]{'═' * 70}[/bold magenta]\n")
    
    # Create summary table
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
    
    add_row("Subdomains", len(results.get('subdomains', [])))
    add_row("NEW Subdomains", len(results.get('new_subdomains', [])))
    add_row("Alive Hosts", len(results.get('alive_hosts', [])))
    add_row("Nuclei Findings", len(results.get('vulnerabilities', [])), True)
    add_row("JS Secrets", len(results.get('js_secrets', [])), True)
    add_row("JS Endpoints", len(results.get('js_endpoints', [])))
    add_row("Wayback URLs", results.get('wayback_urls', 0))
    add_row("Wayback Alive", len(results.get('wayback_alive', [])))
    add_row("Critical Paths", len(results.get('fuzz_findings', [])), True)
    add_row("Takeover Vulns", len(results.get('takeover_vulns', [])), True)
    add_row("CORS Issues", len(results.get('cors_vulns', [])), True)
    add_row("SSL Issues", len(results.get('ssl_issues', [])))
    add_row("Shodan CVEs", len(results.get('shodan_vulns', [])), True)
    add_row("Cloud Buckets", len(results.get('cloud_buckets', [])), True)
    add_row("Emails Found", len(results.get('emails', [])))
    add_row("Reflected Params", len(results.get('reflected_params', [])), True)
    # NEW MODULE RESULTS
    add_row("DNS Vulns", len(results.get('dns_vulns', [])), True)
    add_row("Open Redirects", len(results.get('open_redirects', [])), True)
    add_row("SQLi Vulns", len(results.get('sqli_vulns', [])), True)
    add_row("XSS Vulns", len(results.get('xss_vulns', [])), True)
    add_row("Favicon IDs", len(results.get('favicon_identified', [])))
    add_row("API Endpoints", len(results.get('api_endpoints', [])))
    add_row("API Critical", len(results.get('api_critical', [])), True)
    add_row("GraphQL Endpoints", len(results.get('graphql_endpoints', [])))
    # HIGH-VALUE MODULE RESULTS
    add_row("SSRF Vulns", len(results.get('ssrf_vulns', [])), True)
    add_row("JWT Vulns", len(results.get('jwt_vulns', [])), True)
    add_row("JWT Weak Secrets", len(results.get('jwt_weak_secrets', [])), True)
    add_row("IDOR Vulns", len(results.get('idor_vulns', [])), True)
    
    console.print(table)
    
    # Critical findings alert
    total_critical = count_all_vulns(results)
    if total_critical > 0:
        console.print(Panel(
            f"[bold red]🚨 {total_critical} FINDINGS REQUIRE MANUAL VERIFICATION[/bold red]\n\n"
            "Review the output files and verify before reporting.",
            title="⚠️ Action Required",
            border_style="red"
        ))
    
    console.print(f"\n[dim]Completed in {duration.total_seconds():.1f} seconds[/dim]")


if __name__ == "__main__":
    main()
