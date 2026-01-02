#!/usr/bin/env python3
"""
Tool Installation Checker (macOS)

Checks if all required external tools are installed.
Provides macOS-specific installation instructions.
"""
import shutil
import subprocess
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

REQUIRED_TOOLS = {
    'go': {
        'description': 'Go programming language (required for most tools)',
        'install': 'brew install go',
        'url': 'https://golang.org/',
        'critical': True
    },
    'subfinder': {
        'description': 'Passive subdomain enumeration',
        'install': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
        'url': 'https://github.com/projectdiscovery/subfinder',
        'critical': False
    },
    'amass': {
        'description': 'Comprehensive subdomain discovery',
        'install': 'go install -v github.com/owasp-amass/amass/v4/...@master',
        'url': 'https://github.com/owasp-amass/amass',
        'critical': False
    },
    'assetfinder': {
        'description': 'Quick asset discovery',
        'install': 'go install github.com/tomnomnom/assetfinder@latest',
        'url': 'https://github.com/tomnomnom/assetfinder',
        'critical': False
    },
    'httpx': {
        'description': 'HTTP probing and alive check',
        'install': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
        'url': 'https://github.com/projectdiscovery/httpx',
        'critical': False
    },
    'nmap': {
        'description': 'Port scanning',
        'install': 'brew install nmap',
        'url': 'https://nmap.org/',
        'critical': False
    },
    'nuclei': {
        'description': 'Vulnerability scanning with templates',
        'install': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
        'url': 'https://github.com/projectdiscovery/nuclei',
        'critical': False
    }
}

# EyeWitness is optional - we have built-in tech detection
OPTIONAL_TOOLS = {
    'eyewitness': {
        'description': 'Web screenshots (optional)',
        'install': 'pip install eyewitness  # or install from GitHub',
        'url': 'https://github.com/RedSiege/EyeWitness'
    }
}

def check_tool(name: str) -> bool:
    """Check if a tool is installed."""
    return shutil.which(name) is not None

def check_venv() -> bool:
    """Check if running in virtual environment."""
    return sys.prefix != sys.base_prefix

def check_go_path() -> bool:
    """Check if Go bin is in PATH."""
    try:
        result = subprocess.run(['go', 'env', 'GOPATH'], capture_output=True, text=True)
        if result.returncode == 0:
            gopath = result.stdout.strip()
            return f"{gopath}/bin" in os.environ.get('PATH', '')
    except:
        pass
    return False

def main():
    console.print("\n[bold cyan]Bug Bounty Tools Check (macOS)[/bold cyan]\n")
    
    # Check virtual environment
    if check_venv():
        console.print("[green]✓[/green] Running in virtual environment\n")
    else:
        console.print("[yellow]⚠[/yellow] Not in virtual environment. Run: [cyan]source venv/bin/activate[/cyan]\n")
    
    # Main tools table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Description")
    
    missing = []
    go_installed = False
    
    for tool, info in REQUIRED_TOOLS.items():
        installed = check_tool(tool)
        if tool == 'go':
            go_installed = installed
        status = "[green]✓ Installed[/green]" if installed else "[red]✗ Missing[/red]"
        table.add_row(tool, status, info['description'])
        
        if not installed:
            missing.append(tool)
    
    console.print(table)
    
    # Optional tools
    console.print("\n[dim]Optional tools:[/dim]")
    for tool, info in OPTIONAL_TOOLS.items():
        installed = check_tool(tool)
        status = "[green]✓[/green]" if installed else "[dim]○[/dim]"
        console.print(f"  {status} {tool} - {info['description']}")
    
    if missing:
        console.print(f"\n[yellow]Missing {len(missing)} tools.[/yellow]\n")
        
        # Check Go first
        if not go_installed:
            console.print(Panel(
                "[bold]Step 1: Install Go[/bold]\n\n"
                "brew install go\n\n"
                "[bold]Step 2: Add Go bin to PATH[/bold]\n\n"
                "echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.zshrc\n"
                "source ~/.zshrc",
                title="⚠️ Go Required First",
                border_style="yellow"
            ))
        else:
            # Check if Go path is configured
            if not check_go_path():
                console.print(Panel(
                    "Go is installed but bin folder not in PATH.\n\n"
                    "Run these commands:\n"
                    "echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.zshrc\n"
                    "source ~/.zshrc",
                    title="⚠️ Configure Go PATH",
                    border_style="yellow"
                ))
            
            console.print("\n[bold]Install missing tools:[/bold]\n")
            for tool in missing:
                if tool == 'go':
                    continue
                info = REQUIRED_TOOLS[tool]
                console.print(f"[cyan]{info['install']}[/cyan]")
    else:
        console.print("\n[green]All tools installed! You're ready to hunt.[/green]\n")
    
    # Quick install script
    if missing and go_installed:
        console.print(Panel(
            "# Copy and run this to install all missing tools:\n" +
            "\n".join(REQUIRED_TOOLS[t]['install'] for t in missing if t != 'go'),
            title="Quick Install",
            border_style="blue"
        ))


if __name__ == "__main__":
    import os
    main()
