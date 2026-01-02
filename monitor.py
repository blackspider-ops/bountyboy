#!/usr/bin/env python3
"""
Monitoring Script

Sets up automated daily scans via cron.
Compares results with previous runs.
Sends notifications when new assets appear.

This is the "run while you sleep" part.
"""
import os
import sys
import click
from pathlib import Path
from datetime import datetime
from rich.console import Console

from src.utils import load_config, ensure_dirs, info, success, error, warning

console = Console()

@click.command()
@click.option('--setup-cron', is_flag=True, help='Set up daily cron job')
@click.option('--remove-cron', is_flag=True, help='Remove cron job')
@click.option('--config', '-c', default='config.yaml', help='Path to config file')
@click.option('--run-all', is_flag=True, help='Run scan on all configured targets')
def main(setup_cron: bool, remove_cron: bool, config: str, run_all: bool):
    """
    Bug Bounty Monitoring - Automated daily scans.
    
    Examples:
        # Set up daily monitoring
        python monitor.py --setup-cron
        
        # Run scan on all targets now
        python monitor.py --run-all
    """
    try:
        cfg = load_config(config)
    except FileNotFoundError:
        error(f"Config file not found: {config}")
        return
    
    if setup_cron:
        setup_cron_job(cfg)
    elif remove_cron:
        remove_cron_job()
    elif run_all:
        run_all_targets(cfg)
    else:
        click.echo("Use --setup-cron, --remove-cron, or --run-all")
        click.echo("Run 'python monitor.py --help' for more info")


def setup_cron_job(config: dict):
    """Set up cron job for daily monitoring."""
    script_path = Path(__file__).resolve()
    working_dir = script_path.parent
    venv_python = working_dir / "venv" / "bin" / "python"
    
    # Use venv python if exists, otherwise system python
    python_path = str(venv_python) if venv_python.exists() else sys.executable
    
    # Run daily at 3 AM
    cron_line = f"0 3 * * * cd {working_dir} && {python_path} {script_path} --run-all >> {working_dir}/logs/cron.log 2>&1"
    
    info("Setting up cron job for daily monitoring...")
    info(f"Cron entry: {cron_line}")
    
    # Create logs directory
    (working_dir / "logs").mkdir(exist_ok=True)
    
    # Check if cron job already exists
    existing = os.popen("crontab -l 2>/dev/null").read()
    
    if "monitor.py --run-all" in existing:
        warning("Cron job already exists")
        return
    
    # Add new cron job
    new_crontab = existing + cron_line + "\n"
    
    # Write to temp file and install
    temp_file = "/tmp/bugbounty_cron"
    with open(temp_file, 'w') as f:
        f.write(new_crontab)
    
    result = os.system(f"crontab {temp_file}")
    os.remove(temp_file)
    
    if result == 0:
        success("Cron job installed! Scans will run daily at 3 AM")
        info("Check logs/cron.log for output")
    else:
        error("Failed to install cron job")


def remove_cron_job():
    """Remove the monitoring cron job."""
    existing = os.popen("crontab -l 2>/dev/null").read()
    
    if "monitor.py --run-all" not in existing:
        warning("No cron job found")
        return
    
    # Remove our line
    new_lines = [line for line in existing.split('\n') 
                 if "monitor.py --run-all" not in line and line.strip()]
    new_crontab = '\n'.join(new_lines) + '\n' if new_lines else ''
    
    temp_file = "/tmp/bugbounty_cron"
    with open(temp_file, 'w') as f:
        f.write(new_crontab)
    
    result = os.system(f"crontab {temp_file}")
    os.remove(temp_file)
    
    if result == 0:
        success("Cron job removed")
    else:
        error("Failed to remove cron job")


def run_all_targets(config: dict):
    """Run scan on all configured targets."""
    targets = config.get('targets', [])
    
    if not targets:
        error("No targets configured in config.yaml")
        return
    
    info(f"Running scan on {len(targets)} targets...")
    info(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    for target in targets:
        console.print(f"\n[bold]{'='*50}[/bold]")
        console.print(f"[bold cyan]Scanning: {target}[/bold cyan]")
        console.print(f"[bold]{'='*50}[/bold]\n")
        
        # Import and run orchestrator
        from orchestrator import main as run_orchestrator
        from click.testing import CliRunner
        
        runner = CliRunner()
        result = runner.invoke(run_orchestrator, [
            '--target', target,
            '--notify'  # Enable notifications for automated runs
        ])
        
        if result.exit_code != 0:
            error(f"Scan failed for {target}")
            if result.output:
                console.print(result.output)
    
    success(f"All scans complete at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
