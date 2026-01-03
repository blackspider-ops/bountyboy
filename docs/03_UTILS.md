# 🔧 Utility Functions (src/utils.py)

Core utility functions used throughout BountyBoy.

---

## 📄 File Overview

```python
"""Utility functions for BountyBoy."""
import os
import subprocess
import yaml
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
```

**Imports explained:**
- `os` - Operating system interface (PATH, file operations)
- `subprocess` - Run external commands (nmap, subfinder, etc.)
- `yaml` - Parse YAML config files
- `pathlib.Path` - Modern path handling (better than os.path)
- `datetime` - Timestamps for files
- `rich` - Beautiful terminal output

---

## 🔑 Go PATH Setup

```python
console = Console()

# Add Go bin to PATH for tool discovery
GOPATH = os.path.expanduser("~/go")
GO_BIN = os.path.join(GOPATH, "bin")
if GO_BIN not in os.environ.get('PATH', ''):
    os.environ['PATH'] = f"{GO_BIN}:{os.environ.get('PATH', '')}"
```

**Line-by-line:**

```python
console = Console()
```
- Creates Rich console for colored output
- Global so all functions can use it

```python
GOPATH = os.path.expanduser("~/go")
```
- `~/go` is default Go workspace
- `expanduser` converts `~` to actual home path (`/Users/username/go`)

```python
GO_BIN = os.path.join(GOPATH, "bin")
```
- Go installs binaries to `~/go/bin/`
- This is where subfinder, httpx, nuclei live

```python
if GO_BIN not in os.environ.get('PATH', ''):
    os.environ['PATH'] = f"{GO_BIN}:{os.environ.get('PATH', '')}"
```
- **WHY?** Python subprocess needs tools in PATH
- Check if already in PATH (avoid duplicates)
- Prepend Go bin to PATH
- `os.environ.get('PATH', '')` - get PATH or empty string if not set

**Why do this in code?**
- User might not have Go in PATH
- Works even if shell profile not loaded
- Makes tool discovery automatic

---

## ⚙️ load_config()

```python
def load_config(config_path: str = "config.yaml") -> dict:
    """Load configuration from YAML file."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)
```

**Line-by-line:**

```python
def load_config(config_path: str = "config.yaml") -> dict:
```
- Type hints: takes string, returns dict
- Default path is `config.yaml` in current directory

```python
with open(config_path, 'r') as f:
```
- `with` ensures file is closed even if error
- `'r'` = read mode

```python
return yaml.safe_load(f)
```
- `safe_load` vs `load`:
  - `load` can execute arbitrary Python code (security risk!)
  - `safe_load` only parses data (safe)
- Returns Python dict from YAML

**Why YAML over JSON?**
- YAML supports comments
- More readable
- Easier to edit by hand

---

## 📁 ensure_dirs()

```python
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
```

**Line-by-line:**

```python
base = Path(config['output']['data_dir']) / "targets" / target.replace('.', '_')
```
- `Path()` creates path object (modern Python way)
- `/` operator joins paths (cleaner than `os.path.join`)
- `target.replace('.', '_')` - `example.com` → `example_com`
  - **WHY?** Dots in folder names can cause issues on some systems

```python
dirs = {
    'base': base,
    'subdomains': base / "subdomains",
    ...
}
```
- Dictionary of all directories we need
- Using Path `/` operator for clean joining

```python
for d in dirs.values():
    d.mkdir(parents=True, exist_ok=True)
```
- `parents=True` - create parent directories if needed
- `exist_ok=True` - don't error if already exists
- **WHY both?** Idempotent - can run multiple times safely

```python
return {k: str(v) for k, v in dirs.items()}
```
- Convert Path objects to strings
- **WHY?** Some functions expect strings, not Path objects

**Directory structure created:**
```
data/targets/example_com/
├── subdomains/
│   ├── current.txt
│   └── history/
│       └── 20260103_120000.txt
├── scans/
├── screenshots/
└── reports/
```

---

## 🔨 run_tool()

```python
def run_tool(cmd: list, timeout: int = 300) -> tuple[bool, str]:
    """Run external tool and return success status and output."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except FileNotFoundError:
        return False, f"Tool not found: {cmd[0]}"
```

**Line-by-line:**

```python
def run_tool(cmd: list, timeout: int = 300) -> tuple[bool, str]:
```
- `cmd: list` - command as list: `["nmap", "-sV", "target.com"]`
- `timeout: int = 300` - 5 minute default timeout
- Returns tuple: (success: bool, output: str)

```python
result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
```
- `subprocess.run` - run command and wait for completion
- `capture_output=True` - capture stdout and stderr
- `text=True` - return strings not bytes
- `timeout=timeout` - kill if takes too long

```python
return result.returncode == 0, result.stdout
```
- `returncode == 0` means success (Unix convention)
- Return stdout as the output

```python
except subprocess.TimeoutExpired:
    return False, "Timeout"
```
- Handle timeout gracefully
- Don't crash, just return failure

```python
except FileNotFoundError:
    return False, f"Tool not found: {cmd[0]}"
```
- Tool not installed
- `cmd[0]` is the command name (e.g., "nmap")

**Why list for cmd?**
```python
# GOOD - safe from shell injection
run_tool(["nmap", "-sV", target])

# BAD - vulnerable to injection
os.system(f"nmap -sV {target}")  # If target is "; rm -rf /" = disaster
```

---

## ✅ check_tool_installed()

```python
def check_tool_installed(tool: str) -> bool:
    """Check if a tool is installed and accessible."""
    try:
        subprocess.run([tool, "--help"], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
```

**Logic:**
1. Try running `tool --help`
2. If it runs = tool exists
3. If FileNotFoundError = not installed
4. If timeout = something wrong, treat as not installed

**Why `--help`?**
- Almost all tools support `--help`
- Quick to run
- Doesn't do anything harmful

**Why 5 second timeout?**
- `--help` should be instant
- If it takes longer, something's wrong

---

## ⏰ timestamp()

```python
def timestamp() -> str:
    """Get current timestamp string."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")
```

**Format:** `20260103_143052` (YYYYMMDD_HHMMSS)

**Why this format?**
- Sortable alphabetically = chronologically
- No special characters (safe for filenames)
- Human readable
- Unique per second

**Used for:**
- Scan result files: `scan_20260103_143052.json`
- Reports: `report_20260103_143052.html`
- History files

---

## 📊 diff_files()

```python
def diff_files(old_file: str, new_file: str) -> list:
    """Find new lines in new_file that weren't in old_file."""
    old_lines = set()
    if os.path.exists(old_file):
        with open(old_file, 'r') as f:
            old_lines = set(line.strip() for line in f if line.strip())
    
    with open(new_file, 'r') as f:
        new_lines = set(line.strip() for line in f if line.strip())
    
    return list(new_lines - old_lines)
```

**Purpose:** Find NEW subdomains that weren't in previous scan.

**Line-by-line:**

```python
old_lines = set()
if os.path.exists(old_file):
```
- Start with empty set
- Only read old file if it exists (first run won't have it)

```python
old_lines = set(line.strip() for line in f if line.strip())
```
- Set comprehension
- `line.strip()` removes whitespace
- `if line.strip()` skips empty lines
- **WHY set?** O(1) lookup, automatic deduplication

```python
return list(new_lines - old_lines)
```
- Set subtraction: items in new but not in old
- Convert to list for return

**Example:**
```
old_file:           new_file:           result:
www.example.com     www.example.com     
api.example.com     api.example.com     
                    dev.example.com     dev.example.com (NEW!)
                    staging.example.com staging.example.com (NEW!)
```

---

## 📚 learn()

```python
def learn(topic: str, explanation: str, learn_mode: bool = False):
    """Print learning explanation if learn mode is enabled."""
    if learn_mode:
        console.print(Panel(explanation, title=f"📚 Learn: {topic}", border_style="blue"))
```

**Purpose:** Educational mode - explains what each step does.

**Why conditional?**
- Only show when `--learn` flag used
- Experienced users don't need explanations
- Keeps output clean by default

**Rich Panel:**
- Creates bordered box
- Blue border for learning content
- 📚 emoji for visual distinction

---

## 🎨 Output Functions

```python
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
```

**Rich markup:**
- `[green]text[/green]` - colored text
- Consistent visual language throughout app

**Why separate functions?**
- DRY (Don't Repeat Yourself)
- Easy to change format everywhere
- Consistent styling

**Visual output:**
```
✓ Found 247 subdomains          (green = success)
✗ nmap not installed            (red = error)
ℹ Scanning 50 hosts...          (blue = info)
⚠ Rate limited, slowing down    (yellow = warning)
```
