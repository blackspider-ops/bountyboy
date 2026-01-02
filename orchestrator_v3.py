#!/usr/bin/env python3
"""
BountyBoy - Orchestrator v3 - FULL ARSENAL

Everything runs in parallel where possible:

PHASE 1: DISCOVERY
├── Subdomain enumeration (parallel tools)
└── Compare with previous results

PHASE 2: RECONNAISSANCE  
├── Alive host detection
├── Port scanning
└── Vulnerability scanning (nuclei)

PHASE 3: DEEP ANALYSIS (parallel)
├── JavaScript analysis (secrets, endpoints)
├── Wayback Machine (historical URLs)
├── Tech stack detection
└── Path fuzzing

PHASE 4: VULNERABILITY CHECKS (parallel)
├── Subdomain takeover
├── CORS misconfiguration
├── Security headers
└── GitHub dorking (generates URLs)

PHASE 5: REPORTING
└── Generate comprehensive report
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
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from src.utils import load_config, ensure_dirs, learn, success, error, info, warning, timestamp
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
from src.notifier import Notifier

urllib3.disable_warnings()
console = Console()


BANNER = r"""
[cyan]
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║   ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗        ║
    ║   ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝        ║
    ║   ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝         ║
    ║   ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝          ║
    ║   ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║           ║
    ║   ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝           ║
    ║   ██████╗  ██████╗ ██╗   ██╗                                    ║
    ║   ██╔══██╗██╔═══██╗╚██╗ ██╔╝                                    ║
    ║   ██████╔╝██║   ██║ ╚████╔╝                                     ║
    ║   ██╔══██╗██║   ██║  ╚██╔╝                                      ║
    ║   ██████╔╝╚██████╔╝   ██║                                       ║
    ║   ╚═════╝  ╚═════╝    ╚═╝                                       ║
    ║                                                                  ║
    ║              AUTOMATED RECON PIPELINE v3.0                       ║
    ║                    Full Arsenal Mode                             ║
    ╚══════════════════════════════════════════════════════════════════╝
[/cyan]
"""


@click.command()
@click.option('--target', '-t', required=True, help='Target domain')
@click.option('--learn', 'learn_mode', is_flag=True, help='Enable learning explanations')
@click.option('--config', '-c', default='config.yaml', help='Config file path')
@click.option('--quick', is_flag=True, help='Quick mode: subdomain discovery only')
@click.option('--recon', is_flag=True, help='Recon mode: discovery + scanning')
@click.option('--full', is_flag=True, help='Full mode: everything including vuln checks')
@click.option('--notify', is_flag=True, help='Send notifications')
@click.option('--output', '-o', default=None, help='Custom output directory')
def main(target: str, learn_mode: bool, config: str, quick: bool, recon: bool, 
         full: bool, notify: bool, output: str):
    """
    BountyBoy v3 - Full Arsenal
    
    Modes:
        --quick  : Subdomain discovery only (~30 seconds)
        --recon  : Discovery + port scanning + nuclei (~5 minutes)
        --full   : Everything including vuln checks (~15 minutes)
    
    Examples:
        python orchestrator_v3.py -t example.com --quick
        python orchestrator_v3.py -t example.com --recon --learn
        python orchestrator_v3.py -t example.com --full --notify
    """
    console.print(BANNER)
    start_time = datetime.now()
    
    # Determine mode
    if quick:
        mode = 'quick'
    elif recon:
        mode = 'recon'
    elif full:
        mode = 'full'
    else:
        mode = 'standard'
    
    # Load config
    try:
        cfg = load_config(config)
    except FileNotFoundError:
        error(f"Config not found: {config}")
        return
    
    # Setup directories
    dirs = ensure_dirs(target, cfg)
    if output:
        dirs['base'] = output
        Path(output).mkdir(parents=True, exist_ok=True)
    
    # Print config
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Mode:[/bold] {mode.upper()}\n"
        f"[bold]Learn:[/bold] {'ON' if learn_mode else 'OFF'}\n"
        f"[bold]Notify:[/bold] {'ON' if notify else 'OFF'}\n"
        f"[bold]Output:[/bold] {dirs['base']}",
        title="🎯 Configuration",
        border_style="cyan"
    ))
    
    # Initialize all modules
    modules = {
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
        'notifier': Notifier(cfg) if notify else None
    }
    
    # Results container
    results = {
        'target': target,
        'mode': mode,
        'start_time': start_time.isoformat(),
        'subdomains': set(),
        'new_subdomains': [],
        'alive_hosts': [],
        'vulnerabilities': [],
        'js_secrets': [],
        'takeover_vulns': [],
        'cors_vulns': [],
        'header_issues': [],
        'wayback_alive': [],
        'fuzz_findings': []
    }
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 1: SUBDOMAIN DISCOVERY
    # ═══════════════════════════════════════════════════════════════
    console.print("\n[bold magenta]══════════════════════════════════════════════════════════════[/bold magenta]")
    console.print("[bold magenta]  PHASE 1: SUBDOMAIN DISCOVERY[/bold magenta]")
    console.print("[bold magenta]══════════════════════════════════════════════════════════════[/bold magenta]\n")
    
    results['subdomains'], results['new_subdomains'] = modules['discovery'].discover(
        target, dirs['subdomains']
    )
    
    if not results['subdomains']:
        warning("No subdomains found. Exiting.")
        return
    
    if modules['notifier'] and results['new_subdomains']:
        modules['notifier'].notify_new_subdomains(target, results['new_subdomains'])
    
    if mode == 'quick':
        print_final_report(results, start_time, dirs)
        return
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 2: SCANNING
    # ═══════════════════════════════════════════════════════════════
    console.print("\n[bold magenta]══════════════════════════════════════════════════════════════[/bold magenta]")
    console.print("[bold magenta]  PHASE 2: SCANNING PIPELINE[/bold magenta]")
    console.print("[bold magenta]══════════════════════════════════════════════════════════════[/bold magenta]\n")
    
    scan_results = modules['scanner'].scan(results['subdomains'], dirs['scans'])
    results['alive_hosts'] = scan_results['alive_hosts']
    results['vulnerabilities'] = scan_results['nuclei_findings']
    
    if modules['notifier'] and results['vulnerabilities']:
        for vuln in results['vulnerabilities'][:5]:  # Limit notifications
            modules['notifier'].notify_vulnerability(vuln)
    
    if not results['alive_hosts']:
        warning("No alive hosts found. Exiting.")
        print_final_report(results, start_time, dirs)
        return
    
    if mode == 'recon':
        print_final_report(results, start_time, dirs)
        return
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 3: DEEP ANALYSIS (Parallel)
    # ═══════════════════════════════════════════════════════════════
    console.print("\n[bold magenta]══════════════════════════════════════════════════════════════[/bold magenta]")
    console.print("[bold magenta]  PHASE 3: DEEP ANALYSIS[/bold magenta]")
    console.print("[bold magenta]══════════════════════════════════════════════════════════════[/bold magenta]\n")
    
    learn("Parallel Deep Analysis",
          "We're running multiple analysis modules simultaneously:\n"
          "• JavaScript analysis - finding secrets in JS files\n"
          "• Wayback Machine - finding forgotten URLs\n"
          "• Tech detection - identifying frameworks\n"
          "• Path fuzzing - finding hidden files\n\n"
          "All running at the same time for maximum speed.",
          learn_mode)
    
    # Run analyses
    hosts_to_analyze = results['alive_hosts'][:50]  # Limit for speed
    
    console.print("[cyan]▶ JavaScript Analysis[/cyan]")
    js_results = modules['js'].analyze(hosts_to_analyze, dirs['scans'])
    results['js_secrets'] = js_results.get('secrets', [])
    
    console.print("\n[cyan]▶ Wayback Machine[/cyan]")
    wb_results = modules['wayback'].analyze(target, dirs['scans'])
    results['wayback_alive'] = wb_results.get('alive_interesting', [])
    
    console.print("\n[cyan]▶ Tech Stack Detection[/cyan]")
    modules['visual'].run(hosts_to_analyze, dirs['screenshots'])
    
    if mode == 'full':
        console.print("\n[cyan]▶ Path Fuzzing[/cyan]")
        fuzz_results = modules['fuzzer'].fuzz(hosts_to_analyze[:20], dirs['scans'])
        results['fuzz_findings'] = fuzz_results.get('critical_findings', [])
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 4: VULNERABILITY CHECKS (Full mode only)
    # ═══════════════════════════════════════════════════════════════
    if mode == 'full':
        console.print("\n[bold magenta]══════════════════════════════════════════════════════════════[/bold magenta]")
        console.print("[bold magenta]  PHASE 4: VULNERABILITY CHECKS[/bold magenta]")
        console.print("[bold magenta]══════════════════════════════════════════════════════════════[/bold magenta]\n")
        
        learn("Automated Vulnerability Checks",
              "Now we check for specific vulnerability classes:\n"
              "• Subdomain Takeover - dangling DNS records\n"
              "• CORS Misconfiguration - cross-origin issues\n"
              "• Security Headers - missing protections\n"
              "• GitHub Dorking - leaked secrets in code\n\n"
              "These are common, easy-to-find vulnerabilities.",
              learn_mode)
        
        console.print("[cyan]▶ Subdomain Takeover Check[/cyan]")
        takeover_results = modules['takeover'].check(list(results['subdomains']), dirs['scans'])
        results['takeover_vulns'] = takeover_results.get('vulnerable', [])
        
        console.print("\n[cyan]▶ CORS Misconfiguration Check[/cyan]")
        cors_results = modules['cors'].check(hosts_to_analyze[:30], target, dirs['scans'])
        results['cors_vulns'] = cors_results.get('vulnerable_endpoints', [])
        
        console.print("\n[cyan]▶ Security Headers Analysis[/cyan]")
        header_results = modules['headers'].analyze(hosts_to_analyze[:30], dirs['scans'])
        results['header_issues'] = header_results.get('common_missing', {})
        
        console.print("\n[cyan]▶ GitHub Dork Generation[/cyan]")
        modules['github'].analyze(target, dirs['scans'])
    
    # ═══════════════════════════════════════════════════════════════
    # FINAL REPORT
    # ═══════════════════════════════════════════════════════════════
    print_final_report(results, start_time, dirs)
    
    # Save full results
    results['subdomains'] = list(results['subdomains'])
    results['end_time'] = datetime.now().isoformat()
    
    report_file = Path(dirs['reports']) / f"full_report_{timestamp()}.json"
    with open(report_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    info(f"\nFull report saved to: {report_file}")
    
    # Notify completion
    if modules['notifier']:
        modules['notifier'].notify_scan_complete(target, {
            'total_subdomains': len(results['subdomains']),
            'new_subdomains': len(results['new_subdomains']),
            'alive_hosts': len(results['alive_hosts']),
            'vulnerabilities': len(results['vulnerabilities']) + len(results['takeover_vulns']) + len(results['cors_vulns'])
        })


def print_final_report(results: dict, start_time: datetime, dirs: dict):
    """Print comprehensive final report."""
    duration = datetime.now() - start_time
    
    console.print("\n[bold magenta]══════════════════════════════════════════════════════════════[/bold magenta]")
    console.print("[bold magenta]  SCAN COMPLETE - FINAL REPORT[/bold magenta]")
    console.print("[bold magenta]══════════════════════════════════════════════════════════════[/bold magenta]\n")
    
    # Summary table
    table = Table(title="📊 Results Summary", show_header=True, header_style="bold cyan")
    table.add_column("Category", style="dim")
    table.add_column("Count", justify="right")
    table.add_column("Status", justify="center")
    
    # Add rows with status indicators
    sub_count = len(results.get('subdomains', []))
    table.add_row("Subdomains Found", str(sub_count), "✓" if sub_count > 0 else "○")
    
    new_count = len(results.get('new_subdomains', []))
    table.add_row("NEW Subdomains", str(new_count), "🎯" if new_count > 0 else "○")
    
    alive_count = len(results.get('alive_hosts', []))
    table.add_row("Alive Hosts", str(alive_count), "✓" if alive_count > 0 else "○")
    
    vuln_count = len(results.get('vulnerabilities', []))
    table.add_row("Nuclei Findings", str(vuln_count), "🚨" if vuln_count > 0 else "✓")
    
    secrets_count = len(results.get('js_secrets', []))
    table.add_row("JS Secrets Found", str(secrets_count), "🚨" if secrets_count > 0 else "✓")
    
    takeover_count = len(results.get('takeover_vulns', []))
    table.add_row("Takeover Vulns", str(takeover_count), "🚨" if takeover_count > 0 else "✓")
    
    cors_count = len(results.get('cors_vulns', []))
    table.add_row("CORS Issues", str(cors_count), "⚠️" if cors_count > 0 else "✓")
    
    wayback_count = len(results.get('wayback_alive', []))
    table.add_row("Wayback URLs Alive", str(wayback_count), "🎯" if wayback_count > 0 else "○")
    
    fuzz_count = len(results.get('fuzz_findings', []))
    table.add_row("Critical Paths Found", str(fuzz_count), "🚨" if fuzz_count > 0 else "✓")
    
    console.print(table)
    
    # Critical findings highlight
    critical_count = vuln_count + secrets_count + takeover_count + fuzz_count
    if critical_count > 0:
        console.print(Panel(
            f"[bold red]🚨 {critical_count} CRITICAL FINDINGS REQUIRE ATTENTION![/bold red]\n\n"
            "Check the output files for details and verify manually before reporting.",
            title="⚠️ Action Required",
            border_style="red"
        ))
    
    # Timing
    console.print(f"\n[dim]Completed in {duration.total_seconds():.1f} seconds[/dim]")
    console.print(f"[dim]Results saved to: {dirs['base']}[/dim]")


if __name__ == "__main__":
    main()
