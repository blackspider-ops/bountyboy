"""Utility functions for BountyBoy."""
import os
import subprocess
import yaml
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

console = Console()

# Add Go bin to PATH for tool discovery
GOPATH = os.path.expanduser("~/go")
GO_BIN = os.path.join(GOPATH, "bin")
if GO_BIN not in os.environ.get('PATH', ''):
    os.environ['PATH'] = f"{GO_BIN}:{os.environ.get('PATH', '')}"

def load_config(config_path: str = "config.yaml") -> dict:
    """Load configuration from YAML file."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def ensure_dirs(target: str, config: dict) -> dict:
    """Create directory structure for a target."""
    base = Path(config['output']['data_dir']) / "targets" / target.replace('.', '_')
    dirs = {
        'base': base,
        'subdomains': base / "subdomains",
        'history': base / "subdomains" / "history",
        'scans': base / "scans",
        'screenshots': base / "screenshots",
        'reports': base / "reports"
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return {k: str(v) for k, v in dirs.items()}

def run_tool(cmd: list, timeout: int = 300) -> tuple[bool, str]:
    """Run external tool and return success status and output."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except FileNotFoundError:
        return False, f"Tool not found: {cmd[0]}"

def check_tool_installed(tool: str) -> bool:
    """Check if a tool is installed and accessible."""
    try:
        subprocess.run([tool, "--help"], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def timestamp() -> str:
    """Get current timestamp string."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def diff_files(old_file: str, new_file: str) -> list:
    """Find new lines in new_file that weren't in old_file."""
    old_lines = set()
    if os.path.exists(old_file):
        with open(old_file, 'r') as f:
            old_lines = set(line.strip() for line in f if line.strip())
    
    with open(new_file, 'r') as f:
        new_lines = set(line.strip() for line in f if line.strip())
    
    return list(new_lines - old_lines)

def learn(topic: str, explanation: str, learn_mode: bool = False):
    """Print learning explanation if learn mode is enabled."""
    if learn_mode:
        console.print(Panel(explanation, title=f"📚 Learn: {topic}", border_style="blue"))

def success(msg: str):
    """Print success message."""
    console.print(f"[green]✓[/green] {msg}")

def error(msg: str):
    """Print error message."""
    console.print(f"[red]✗[/red] {msg}")

def info(msg: str):
    """Print info message."""
    console.print(f"[blue]ℹ[/blue] {msg}")

def warning(msg: str):
    """Print warning message."""
    console.print(f"[yellow]⚠[/yellow] {msg}")
