# 🛠️ Utility Scripts

Deep dive into helper scripts for learning, monitoring, and setup.

---

## 📄 learn.py - Interactive Learning Module

### Overview

```python
"""
Interactive Bug Bounty Learning Module

Learn bug bounty concepts interactively.
Understand what each tool does and why.
"""
```

**Purpose:** Teach bug bounty concepts to beginners while they use the tool.

---

### Lesson Structure

```python
LESSONS = {
    "intro": {
        "title": "Introduction to Bug Bounty",
        "content": """
# What is Bug Bounty?

Companies pay hackers to find security vulnerabilities...
"""
    },
    "subdomains": {
        "title": "Subdomain Discovery",
        "content": """
# Why Subdomains Matter

Main website is usually well-secured. But subdomains...
"""
    },
    ...
}
```

**Available topics:**
- `intro` - What is bug bounty, how it works
- `subdomains` - Why subdomain discovery matters
- `scanning` - Port scanning and service detection
- `visual` - Screenshots and tech detection
- `methodology` - Complete hunting workflow
- `tips` - Pro tips for success

---

### CLI Interface

```python
@click.command()
@click.argument('topic', required=False)
def main(topic: str):
    if not topic:
        # List all topics
        for key, lesson in LESSONS.items():
            console.print(f"  [green]{key}[/green] - {lesson['title']}")
        return
    
    if topic not in LESSONS:
        console.print(f"[red]Unknown topic: {topic}[/red]")
        return
    
    # Display lesson
    lesson = LESSONS[topic]
    console.print(Panel(
        Markdown(lesson['content']),
        title=f"📚 {lesson['title']}"
    ))
```

**Usage:**
```bash
python learn.py              # List all topics
python learn.py intro        # Learn about bug bounty basics
python learn.py methodology  # Learn the full methodology
python learn.py tips         # Pro tips
```

---

### Lesson Content Example

```python
"methodology": {
    "content": """
# The Complete Methodology

## Phase 1: Reconnaissance (Automated)
Target → Subdomain Discovery → Alive Check → Port Scan → Screenshots

## Phase 2: Analysis (Semi-automated)
- Review screenshots for interesting targets
- Check nuclei findings
- Identify tech stacks

## Phase 3: Manual Testing (Your brain)
Focus on:
1. New subdomains - Untested, likely vulnerable
2. Admin panels - Auth bypass, default creds
3. API endpoints - IDOR, broken auth

## Payout Ranges (typical):
- Low: $50-$200
- Medium: $200-$1000
- High: $1000-$5000
- Critical: $5000-$50000+
"""
}
```

**Why include learning?**
- Bug bounty has steep learning curve
- Context helps understand tool output
- Teaches methodology, not just tools
- Builds better hunters

---

## 📄 monitor.py - Automated Monitoring

### Overview

```python
"""
Monitoring Script

Sets up automated daily scans via cron.
Compares results with previous runs.
Sends notifications when new assets appear.

This is the "run while you sleep" part.
"""
```

**Purpose:** Automate daily scans to catch new assets before other hunters.

---

### Cron Setup

```python
def setup_cron_job(config):
    script_path = Path(__file__).resolve()
    working_dir = script_path.parent
    venv_python = working_dir / "venv" / "bin" / "python"
    
    # Run daily at 3 AM
    cron_line = f"0 3 * * * cd {working_dir} && {venv_python} {script_path} --run-all >> {working_dir}/logs/cron.log 2>&1"
    
    # Check if already exists
    existing = os.popen("crontab -l 2>/dev/null").read()
    if "monitor.py --run-all" in existing:
        warning("Cron job already exists")
        return
    
    # Add new cron job
    new_crontab = existing + cron_line + "\n"
    # ... install crontab
```

**Cron format:** `minute hour day month weekday command`
- `0 3 * * *` = Every day at 3:00 AM

**Why 3 AM?**
- Low traffic time
- Won't interfere with work
- Results ready in morning

---

### Running All Targets

```python
def run_all_targets(config):
    targets = config.get('targets', [])
    
    for target in targets:
        # Import and run orchestrator
        from orchestrator import main as run_orchestrator
        from click.testing import CliRunner
        
        runner = CliRunner()
        result = runner.invoke(run_orchestrator, [
            '--target', target,
            '--notify'  # Enable notifications
        ])
```

**How it works:**
1. Read targets from config.yaml
2. Run orchestrator for each target
3. Enable notifications (Discord/Slack)
4. Log output to logs/cron.log

---

### CLI Commands

```python
@click.command()
@click.option('--setup-cron', is_flag=True, help='Set up daily cron job')
@click.option('--remove-cron', is_flag=True, help='Remove cron job')
@click.option('--run-all', is_flag=True, help='Run scan on all targets')
def main(setup_cron, remove_cron, run_all):
```

**Usage:**
```bash
# Set up daily monitoring
python monitor.py --setup-cron

# Remove cron job
python monitor.py --remove-cron

# Run scan on all targets now
python monitor.py --run-all
```

---

### Config Targets

```yaml
# config.yaml
targets:
  - example.com
  - target2.com
  - target3.com
```

**Why monitor multiple targets?**
- Bug bounty programs have many domains
- New assets appear constantly
- First to find = first to get paid

---

## 📄 tools_check.py - Tool Installation Checker

### Overview

```python
"""
Tool Installation Checker (macOS)

Checks if all required external tools are installed.
Provides macOS-specific installation instructions.
"""
```

**Purpose:** Verify all external tools are installed before running scans.

---

### Required Tools

```python
REQUIRED_TOOLS = {
    'go': {
        'description': 'Go programming language (required for most tools)',
        'install': 'brew install go',
        'critical': True
    },
    'subfinder': {
        'description': 'Passive subdomain enumeration',
        'install': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    },
    'httpx': {
        'description': 'HTTP probing and alive check',
        'install': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
    },
    'nmap': {
        'description': 'Port scanning',
        'install': 'brew install nmap',
    },
    'nuclei': {
        'description': 'Vulnerability scanning with templates',
        'install': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    },
}
```

**Tool categories:**
- **Go tools:** subfinder, httpx, nuclei, amass, assetfinder
- **System tools:** nmap (brew install)
- **Optional:** eyewitness (screenshots)

---

### Check Logic

```python
def check_tool(name: str) -> bool:
    """Check if a tool is installed."""
    return shutil.which(name) is not None

def check_go_path() -> bool:
    """Check if Go bin is in PATH."""
    result = subprocess.run(['go', 'env', 'GOPATH'], capture_output=True, text=True)
    gopath = result.stdout.strip()
    return f"{gopath}/bin" in os.environ.get('PATH', '')
```

**Why check Go path?**
- Go tools install to `$GOPATH/bin`
- Must be in PATH to run
- Common setup issue

---

### Output Display

```python
def main():
    # Check virtual environment
    if check_venv():
        console.print("[green]✓[/green] Running in virtual environment")
    else:
        console.print("[yellow]⚠[/yellow] Not in venv. Run: source venv/bin/activate")
    
    # Check each tool
    table = Table(show_header=True)
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Description")
    
    for tool, info in REQUIRED_TOOLS.items():
        installed = check_tool(tool)
        status = "[green]✓ Installed[/green]" if installed else "[red]✗ Missing[/red]"
        table.add_row(tool, status, info['description'])
```

**Output example:**
```
Bug Bounty Tools Check (macOS)

✓ Running in virtual environment

┌──────────┬─────────────┬────────────────────────────────┐
│ Tool     │ Status      │ Description                    │
├──────────┼─────────────┼────────────────────────────────┤
│ go       │ ✓ Installed │ Go programming language        │
│ subfinder│ ✓ Installed │ Passive subdomain enumeration  │
│ httpx    │ ✗ Missing   │ HTTP probing and alive check   │
│ nmap     │ ✓ Installed │ Port scanning                  │
│ nuclei   │ ✓ Installed │ Vulnerability scanning         │
└──────────┴─────────────┴────────────────────────────────┘

Missing 1 tools.

Install missing tools:
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

---

### Quick Install Script

```python
if missing and go_installed:
    console.print(Panel(
        "# Copy and run this to install all missing tools:\n" +
        "\n".join(REQUIRED_TOOLS[t]['install'] for t in missing if t != 'go'),
        title="Quick Install"
    ))
```

**Generates copy-paste commands:**
```bash
# Copy and run this to install all missing tools:
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

---

## 🎯 Usage Summary

| Script | Purpose | When to Use |
|--------|---------|-------------|
| `learn.py` | Learn concepts | New to bug bounty |
| `monitor.py` | Automated scans | Daily monitoring |
| `tools_check.py` | Verify setup | Before first run |

---

## ⚠️ Common Issues

### Go tools not found
```bash
# Add Go bin to PATH
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.zshrc
source ~/.zshrc
```

### Virtual environment not activated
```bash
source venv/bin/activate
```

### Cron job not running
```bash
# Check cron logs
tail -f bountyboy/logs/cron.log

# Verify cron is installed
crontab -l
```

### Permission denied on cron
```bash
# macOS may need Full Disk Access for cron
# System Preferences → Security & Privacy → Privacy → Full Disk Access
# Add /usr/sbin/cron
```

