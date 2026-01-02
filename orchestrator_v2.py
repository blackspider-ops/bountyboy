#!/usr/bin/env python3
"""
BountyBoy - Orchestrator v2

UPGRADED from v1:
- Parallel subdomain discovery (all tools run simultaneously)
- JavaScript file analysis (find secrets and endpoints)
- Wayback Machine integration (find forgotten URLs)
- Path fuzzing (find hidden files and directories)
- Smarter pipeline with async operations

This is the "run everything" script. It chains all modules together
and runs as much as possible in parallel.
"""
import asyncio
import click
import urllib3
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from src.utils import load_config, ensure_dirs, learn, success, error, info, warning
from src.async_discovery import AsyncSubdomainDiscovery
from src.scanner import Scanner
from src.visual_recon import VisualRecon
from src.js_analyzer import JSAnalyzer
from src.wayback import WaybackAnalyzer
from src.fuzzer import PathFuzzer
from src.notifier import Notifier

urllib3.disable_warnings()
console = Console()


def print_banner():
    """Print cool banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║   ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗     ║
    ║   ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝     ║
    ║   ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝      ║
    ║   ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝       ║
    ║   ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║        ║
    ║   ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝        ║
    ║   ██████╗  ██████╗ ██╗   ██╗                                 ║
    ║   ██╔══██╗██╔═══██╗╚██╗ ██╔╝                                 ║
    ║   ██████╔╝██║   ██║ ╚████╔╝                                  ║
    ║   ██╔══██╗██║   ██║  ╚██╔╝                                   ║
    ║   ██████╔╝╚██████╔╝   ██║                                    ║
    ║   ╚═════╝  ╚═════╝    ╚═╝                                    ║
    ║                                                              ║
    ║              Automated Recon Pipeline v2.0                   ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="cyan")


@click.command()
@click.option('--target', '-t', required=True, help='Target domain')
@click.option('--learn', 'learn_mode', is_flag=True, help='Enable learning explanations')
@click.option('--config', '-c', default='config.yaml', help='Config file path')
@click.option('--quick', is_flag=True, help='Quick scan (subdomain discovery only)')
@click.option('--full', is_flag=True, help='Full scan (everything including fuzzing)')
@click.option('--no-scan', is_flag=True, help='Skip port scanning')
@click.option('--no-js', is_flag=True, help='Skip JS analysis')
@click.option('--no-wayback', is_flag=True, help='Skip Wayback analysis')
@click.option('--no-fuzz', is_flag=True, help='Skip path fuzzing')
@click.option('--notify', is_flag=True, help='Send notifications')
def main(target: str, learn_mode: bool, config: str, quick: bool, full: bool,
         no_scan: bool, no_js: bool, no_wayback: bool, no_fuzz: bool, notify: bool):
    """
    BountyBoy v2 - Parallel Recon Pipeline
    
    Examples:
        # Quick subdomain discovery
        python orchestrator_v2.py -t example.com --quick
        
        # Full scan with learning
        python orchestrator_v2.py -t example.com --full --learn
        
        # Custom scan
        python orchestrator_v2.py -t example.com --no-fuzz --no-wayback
    """
    print_banner()
    start_time = datetime.now()
    
    # Load config
    try:
        cfg = load_config(config)
    except FileNotFoundError:
        error(f"Config not found: {config}")
        return
    
    # Setup
    dirs = ensure_dirs(target, cfg)
    
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Mode:[/bold] {'Quick' if quick else 'Full' if full else 'Standard'}\n"
        f"[bold]Learn:[/bold] {'ON' if learn_mode else 'OFF'}\n"
        f"[bold]Output:[/bold] {dirs['base']}",
        title="🎯 Scan Configuration",
        border_style="cyan"
    ))
    
    # Initialize modules
    discovery = AsyncSubdomainDiscovery(cfg, learn_mode)
    scanner = Scanner(cfg, learn_mode)
    visual = VisualRecon(cfg, learn_mode)
    js_analyzer = JSAnalyzer(cfg, learn_mode)
    wayback = WaybackAnalyzer(cfg, learn_mode)
    fuzzer = PathFuzzer(cfg, learn_mode)
    notifier = Notifier(cfg) if notify else None
    
    # Results tracking
    results = {
        'target': target,
        'subdomains': set(),
        'new_subdomains': [],
        'alive_hosts': [],
        'scan_results': [],
        'vulnerabilities': [],
        'js_findings': {},
        'wayback_findings': {},
        'fuzz_findings': {}
    }
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 1: SUBDOMAIN DISCOVERY (Parallel)
    # ═══════════════════════════════════════════════════════════════
    console.print("\n[bold magenta]═══ PHASE 1: PARALLEL SUBDOMAIN DISCOVERY ═══[/bold magenta]\n")
    
    learn("Parallel vs Sequential",
          "Old way: Run Subfinder, wait, run Assetfinder, wait, run crt.sh = 60+ seconds\n"
          "New way: Run ALL tools simultaneously = ~20 seconds\n\n"
          "We're using Python's asyncio to fire all tools at once. "
          "The total time is the time of the SLOWEST tool, not the SUM of all tools.",
          learn_mode)
    
    results['subdomains'], results['new_subdomains'] = discovery.discover(
        target, dirs['subdomains']
    )
    
    if results['new_subdomains'] and notifier:
        notifier.notify_new_subdomains(target, results['new_subdomains'])
    
    if not results['subdomains']:
        warning("No subdomains found")
        return
    
    if quick:
        print_summary(results, start_time)
        return
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 2: SCANNING PIPELINE
    # ═══════════════════════════════════════════════════════════════
    if not no_scan:
        console.print("\n[bold magenta]═══ PHASE 2: SCANNING PIPELINE ═══[/bold magenta]\n")
        
        scan_results = scanner.scan(results['subdomains'], dirs['scans'])
        results['alive_hosts'] = scan_results['alive_hosts']
        results['scan_results'] = scan_results['scan_results']
        results['vulnerabilities'] = scan_results['nuclei_findings']
        
        if notifier and results['vulnerabilities']:
            for vuln in results['vulnerabilities']:
                notifier.notify_vulnerability(vuln)
    else:
        # Just do alive check
        results['alive_hosts'] = list(results['subdomains'])
    
    if not results['alive_hosts']:
        warning("No alive hosts to analyze")
        print_summary(results, start_time)
        return
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 3: PARALLEL ANALYSIS (JS + Wayback + Visual)
    # ═══════════════════════════════════════════════════════════════
    console.print("\n[bold magenta]═══ PHASE 3: DEEP ANALYSIS ═══[/bold magenta]\n")
    
    learn("Deep Analysis Phase",
          "Now we go deeper. While basic scanning finds obvious stuff, "
          "deep analysis finds the hidden gems:\n"
          "• JS files might contain API keys and secret endpoints\n"
          "• Wayback Machine reveals forgotten pages\n"
          "• Tech detection tells us HOW to attack each target",
          learn_mode)
    
    # Run analyses (these could be parallelized further)
    
    # JavaScript Analysis
    if not no_js and results['alive_hosts']:
        console.print("[cyan]▶ JavaScript Analysis[/cyan]")
        results['js_findings'] = js_analyzer.analyze(
            results['alive_hosts'][:50],  # Limit to 50 hosts
            dirs['scans']
        )
    
    # Wayback Machine
    if not no_wayback:
        console.print("\n[cyan]▶ Wayback Machine Analysis[/cyan]")
        results['wayback_findings'] = wayback.analyze(target, dirs['scans'])
    
    # Visual Recon
    console.print("\n[cyan]▶ Visual Recon & Tech Detection[/cyan]")
    visual_results = visual.run(results['alive_hosts'][:100], dirs['screenshots'])
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 4: PATH FUZZING (if full scan)
    # ═══════════════════════════════════════════════════════════════
    if full and not no_fuzz:
        console.print("\n[bold magenta]═══ PHASE 4: PATH FUZZING ═══[/bold magenta]\n")
        
        results['fuzz_findings'] = fuzzer.fuzz(
            results['alive_hosts'][:30],  # Limit to 30 hosts
            dirs['scans']
        )
    
    # ═══════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════
    print_summary(results, start_time)
    
    if notifier:
        notifier.notify_scan_complete(target, {
            'total_subdomains': len(results['subdomains']),
            'new_subdomains': len(results['new_subdomains']),
            'alive_hosts': len(results['alive_hosts']),
            'vulnerabilities': len(results['vulnerabilities'])
        })
    
    # Learning wrap-up
    learn("What Now?",
          "Automation is done. Here's your attack plan:\n\n"
          "1. CHECK CRITICAL FINDINGS FIRST\n"
          "   - Exposed .git? Clone it, read source code\n"
          "   - .env file? Check for credentials\n"
          "   - Nuclei vulns? Verify and exploit\n\n"
          "2. REVIEW JS ANALYSIS\n"
          "   - Found API endpoints? Test for IDOR, auth bypass\n"
          "   - Found secrets? Verify they're valid\n\n"
          "3. CHECK WAYBACK URLS\n"
          "   - Old admin panels still alive? Test them\n"
          "   - Found parameters? Test for injection\n\n"
          "4. MANUAL TESTING\n"
          "   - Focus on NEW subdomains\n"
          "   - Test interesting tech stacks\n"
          "   - Look for business logic flaws\n\n"
          "Remember: Automation finds targets. YOU find bugs.",
          learn_mode)


def print_summary(results: dict, start_time: datetime):
    """Print scan summary."""
    duration = datetime.now() - start_time
    
    # Create summary table
    table = Table(title="Scan Summary", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="dim")
    table.add_column("Count", justify="right")
    
    table.add_row("Total Subdomains", str(len(results['subdomains'])))
    table.add_row("New Subdomains", str(len(results['new_subdomains'])))
    table.add_row("Alive Hosts", str(len(results['alive_hosts'])))
    table.add_row("Vulnerabilities", str(len(results['vulnerabilities'])))
    
    if results.get('js_findings'):
        js = results['js_findings']
        table.add_row("JS Files Analyzed", str(js.get('total_js_files', 0)))
        table.add_row("Secrets Found", str(len(js.get('secrets', []))))
        table.add_row("API Endpoints", str(len(js.get('api_endpoints', []))))
    
    if results.get('wayback_findings'):
        wb = results['wayback_findings']
        table.add_row("Wayback URLs", str(wb.get('total_urls', 0)))
        table.add_row("Alive Historical", str(len(wb.get('alive_interesting', []))))
    
    if results.get('fuzz_findings'):
        fz = results['fuzz_findings']
        table.add_row("Paths Found", str(fz.get('total_found', 0)))
        table.add_row("Critical Paths", str(len(fz.get('critical_findings', []))))
    
    console.print("\n")
    console.print(table)
    console.print(f"\n[dim]Completed in {duration.total_seconds():.1f} seconds[/dim]")


if __name__ == "__main__":
    main()
