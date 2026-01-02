#!/usr/bin/env python3
"""
BountyBoy - Orchestrator v1

Chains all recon modules together:
1. Subdomain Discovery → Find all subdomains
2. Scanning Pipeline → Check alive, port scan, vuln scan
3. Visual Recon → Screenshots and tech detection
4. Notifications → Alert on interesting findings

Run with --learn flag to understand what each step does.
"""
import click
import urllib3
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.utils import load_config, ensure_dirs, learn, success, error, info, warning
from src.subdomain_discovery import SubdomainDiscovery
from src.scanner import Scanner
from src.visual_recon import VisualRecon
from src.notifier import Notifier

# Disable SSL warnings for recon
urllib3.disable_warnings()

console = Console()

@click.command()
@click.option('--target', '-t', required=True, help='Target domain to scan')
@click.option('--learn', 'learn_mode', is_flag=True, help='Enable learning mode with explanations')
@click.option('--config', '-c', default='config.yaml', help='Path to config file')
@click.option('--skip-scan', is_flag=True, help='Skip port scanning (subdomain discovery only)')
@click.option('--skip-visual', is_flag=True, help='Skip visual recon')
@click.option('--notify', is_flag=True, help='Send notifications for findings')
def main(target: str, learn_mode: bool, config: str, skip_scan: bool, skip_visual: bool, notify: bool):
    """
    BountyBoy v1 - Automated recon pipeline.
    
    Example:
        python orchestrator.py --target example.com --learn
    """
    console.print(Panel.fit(
        f"[bold blue]🎯 BountyBoy[/bold blue]\n"
        f"Target: [green]{target}[/green]\n"
        f"Learn Mode: {'[green]ON[/green]' if learn_mode else '[dim]OFF[/dim]'}",
        border_style="blue"
    ))
    
    # Load config
    try:
        cfg = load_config(config)
    except FileNotFoundError:
        error(f"Config file not found: {config}")
        error("Copy config.example.yaml to config.yaml and customize it")
        return
    
    # Setup directories
    dirs = ensure_dirs(target, cfg)
    info(f"Output directory: {dirs['base']}")
    
    # Initialize modules
    discovery = SubdomainDiscovery(cfg, learn_mode)
    scanner = Scanner(cfg, learn_mode)
    visual = VisualRecon(cfg, learn_mode)
    notifier = Notifier(cfg) if notify else None
    
    # Results summary
    summary = {
        'total_subdomains': 0,
        'new_subdomains': 0,
        'alive_hosts': 0,
        'vulnerabilities': 0
    }
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 1: SUBDOMAIN DISCOVERY
    # ═══════════════════════════════════════════════════════════════
    console.print("\n[bold cyan]═══ PHASE 1: SUBDOMAIN DISCOVERY ═══[/bold cyan]\n")
    
    learn("Why Subdomain Discovery First?",
          "Subdomains are your attack surface. main.target.com might be hardened, "
          "but staging.target.com or dev-api.target.com might be wide open. "
          "More subdomains = more chances to find bugs. We find them ALL first.",
          learn_mode)
    
    subdomains, new_subs = discovery.discover(target, dirs['subdomains'])
    summary['total_subdomains'] = len(subdomains)
    summary['new_subdomains'] = len(new_subs)
    
    if new_subs and notifier:
        notifier.notify_new_subdomains(target, new_subs)
    
    if not subdomains:
        warning("No subdomains found. Check if target is correct.")
        return
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 2: SCANNING PIPELINE
    # ═══════════════════════════════════════════════════════════════
    if not skip_scan:
        console.print("\n[bold cyan]═══ PHASE 2: SCANNING PIPELINE ═══[/bold cyan]\n")
        
        learn("Why Scan After Discovery?",
              "Now we know WHAT exists. Next we need to know what's RUNNING. "
              "Which hosts are alive? What ports are open? What services? "
              "Any known vulnerabilities? Scanning answers these questions.",
              learn_mode)
        
        scan_results = scanner.scan(subdomains, dirs['scans'])
        summary['alive_hosts'] = len(scan_results['alive_hosts'])
        summary['vulnerabilities'] = len(scan_results['nuclei_findings'])
        
        # Notify on vulnerabilities
        if notifier and scan_results['nuclei_findings']:
            for finding in scan_results['nuclei_findings']:
                notifier.notify_vulnerability(finding)
        
        alive_hosts = scan_results['alive_hosts']
    else:
        info("Skipping scan phase (--skip-scan)")
        alive_hosts = list(subdomains)
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 3: VISUAL RECON
    # ═══════════════════════════════════════════════════════════════
    if not skip_visual and alive_hosts:
        console.print("\n[bold cyan]═══ PHASE 3: VISUAL RECON ═══[/bold cyan]\n")
        
        learn("Why Visual Recon?",
              "Numbers and ports don't tell the whole story. "
              "A screenshot of an admin panel is worth 1000 port scans. "
              "Tech detection tells you HOW to attack. Visual recon is the bridge "
              "between automated discovery and manual hacking.",
              learn_mode)
        
        visual_results = visual.run(alive_hosts, dirs['screenshots'])
        
        if visual_results['screenshot_report']:
            success(f"Screenshot report: {visual_results['screenshot_report']}")
    else:
        if skip_visual:
            info("Skipping visual recon (--skip-visual)")
    
    # ═══════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════
    console.print("\n[bold cyan]═══ SCAN COMPLETE ═══[/bold cyan]\n")
    
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Total Subdomains:[/bold] {summary['total_subdomains']}\n"
        f"[bold]New Subdomains:[/bold] {summary['new_subdomains']}\n"
        f"[bold]Alive Hosts:[/bold] {summary['alive_hosts']}\n"
        f"[bold]Vulnerabilities:[/bold] {summary['vulnerabilities']}\n\n"
        f"[dim]Results saved to: {dirs['base']}[/dim]",
        title="Summary",
        border_style="green"
    ))
    
    if notifier:
        notifier.notify_scan_complete(target, summary)
    
    # Learning wrap-up
    learn("What's Next?",
          "Automation found the targets. Now YOU do the hacking.\n\n"
          "1. Check screenshot report - look for admin panels, login pages\n"
          "2. Review nuclei findings - verify and exploit\n"
          "3. Focus on NEW subdomains - they're often untested\n"
          "4. Check tech stacks - WordPress? Look for plugin vulns\n"
          "5. Manual testing on interesting targets\n\n"
          "Automation replaces boring work. Your brain does the real hacking.",
          learn_mode)


if __name__ == "__main__":
    main()
