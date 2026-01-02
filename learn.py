#!/usr/bin/env python3
"""
Interactive Bug Bounty Learning Module

Learn bug bounty concepts interactively.
Understand what each tool does and why.
"""
import click
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()

LESSONS = {
    "intro": {
        "title": "Introduction to Bug Bounty",
        "content": """
# What is Bug Bounty?

Companies pay hackers to find security vulnerabilities in their systems.
Instead of getting in trouble for hacking, you get paid.

## How it works:
1. Company creates a "bug bounty program" on platforms like HackerOne, Bugcrowd
2. They define what you can test (scope) and what's off-limits
3. You find bugs, report them responsibly
4. If valid, you get paid. Payouts range from $50 to $100,000+

## Why automation matters:
- Manual recon takes hours. Automation takes minutes.
- While you sleep, your scripts find new targets
- Speed wins. First to find = first to get paid
- Automation handles boring stuff. You do the creative hacking.

## The workflow:
```
Find targets → Scan them → Identify weaknesses → Exploit → Report → Get paid
     ↑                                                              |
     └──────────────── Automation handles this loop ────────────────┘
```
"""
    },
    "subdomains": {
        "title": "Subdomain Discovery",
        "content": """
# Why Subdomains Matter

Main website (target.com) is usually well-secured. But companies have MANY subdomains:
- staging.target.com (test environment)
- dev-api.target.com (development API)
- admin.target.com (admin panel)
- old.target.com (forgotten legacy system)

These are often:
- Less secured
- Running outdated software
- Forgotten by the security team
- Your best chance at finding bugs

## Discovery Methods:

### Passive (doesn't touch target):
- **Certificate Transparency**: SSL certs are logged publicly
- **Search engines**: Google dorking, Shodan
- **DNS databases**: VirusTotal, SecurityTrails

### Active (touches target):
- **DNS brute forcing**: Try common names (admin, dev, staging)
- **DNS zone transfer**: Sometimes misconfigured servers leak everything

## Tools we use:
- **Subfinder**: Fast passive enumeration
- **Amass**: Comprehensive, does both passive and active
- **Assetfinder**: Quick and lightweight
- **crt.sh**: Certificate transparency search

## Pro tip:
Run discovery DAILY. New subdomains = new attack surface = bugs before anyone else.
"""
    },
    "scanning": {
        "title": "Port Scanning & Service Detection",
        "content": """
# Scanning: What's Running?

You found 500 subdomains. Now what? You need to know:
- Which ones are actually alive?
- What ports are open?
- What services are running?
- Any known vulnerabilities?

## The Smart Scanning Approach:

### Step 1: Alive check (httpx)
Don't waste time on dead hosts. httpx quickly checks which respond.

### Step 2: Quick port scan (nmap top 1000)
Full scan = 65535 ports = slow. Top 1000 covers 99% of services.

### Step 3: Full scan on interesting targets
Found port 8080? That's interesting. Now do full scan on THAT host.

### Step 4: Vulnerability scan (nuclei)
Check for known CVEs, misconfigurations, exposed files.

## Interesting ports to watch:
- 8080, 8443: Alternative HTTP/HTTPS (often dev servers)
- 9000: PHP-FPM, debug ports
- 3000: Node.js dev servers
- 5000: Flask dev servers
- 27017: MongoDB (often no auth!)
- 6379: Redis (often no auth!)

## What nuclei finds:
- Exposed .git folders (source code leak!)
- Default credentials
- Known CVEs
- Misconfigurations
- Sensitive file exposure
"""
    },
    "visual": {
        "title": "Visual Recon & Tech Detection",
        "content": """
# Seeing is Believing

Port scan says "443 open". But what IS it?
- Login page? Test for auth bypass
- Admin panel? Test for default creds
- API docs? Look for sensitive endpoints
- Error page? Check for info disclosure

## Screenshots (EyeWitness)
Takes screenshot of every web server. You can browse 500 sites in 5 minutes.

What to look for:
- Admin panels
- Login pages
- API documentation
- Error messages
- Development/staging indicators
- Outdated UI (old = vulnerable)

## Tech Stack Detection
Knowing the technology changes your attack:

| Technology | What to test |
|------------|--------------|
| WordPress | Plugin vulns, xmlrpc, wp-config |
| Django | Debug mode, SSTI, admin panel |
| Node.js | Prototype pollution, SSRF |
| PHP | LFI, RCE, type juggling |
| Java | Deserialization, Log4j |
| .NET | ViewState, padding oracle |

## Exposed files to check:
- /.git/config (source code!)
- /.env (credentials!)
- /phpinfo.php (server info)
- /server-status (Apache info)
- /robots.txt (hidden paths)
- /sitemap.xml (site structure)
"""
    },
    "methodology": {
        "title": "Bug Bounty Methodology",
        "content": """
# The Complete Methodology

## Phase 1: Reconnaissance (Automated)
```
Target → Subdomain Discovery → Alive Check → Port Scan → Screenshots
```
This is what our automation does. Run it daily.

## Phase 2: Analysis (Semi-automated)
- Review screenshots for interesting targets
- Check nuclei findings
- Identify tech stacks
- Prioritize targets

## Phase 3: Manual Testing (Your brain)
Focus on:
1. **New subdomains** - Untested, likely vulnerable
2. **Admin panels** - Auth bypass, default creds
3. **API endpoints** - IDOR, broken auth
4. **File uploads** - RCE potential
5. **User input** - XSS, SQLi, SSTI

## Common Bug Types:
- **IDOR**: Change user ID, access other users' data
- **XSS**: Inject JavaScript, steal sessions
- **SQLi**: Inject SQL, dump database
- **SSRF**: Make server request internal resources
- **Auth bypass**: Access without credentials
- **Info disclosure**: Leak sensitive data

## Reporting Tips:
- Clear title describing the vulnerability
- Step-by-step reproduction
- Impact explanation (why it matters)
- Proof of concept (screenshots, video)
- Suggested fix

## Payout Ranges (typical):
- Low: $50-$200
- Medium: $200-$1000
- High: $1000-$5000
- Critical: $5000-$50000+
"""
    },
    "tips": {
        "title": "Pro Tips",
        "content": """
# Pro Tips for Bug Bounty Success

## Speed Wins
- First to find = first to get paid
- Automation gives you speed advantage
- Monitor for new assets 24/7

## Focus on New
- New subdomains are gold
- New features have bugs
- Acquisitions = new attack surface

## Go Deep, Not Wide
- Don't spray and pray
- Pick one target, learn it deeply
- Understand the business logic

## Read the Docs
- API documentation reveals endpoints
- JavaScript files contain secrets
- Error messages leak info

## Think Like a Developer
- What shortcuts would they take?
- Where would they forget validation?
- What edge cases exist?

## Common Mistakes to Avoid
- Testing out of scope
- Not reading program rules
- Duplicate reports
- Poor report quality
- Giving up too early

## Resources to Learn More
- PortSwigger Web Security Academy (free!)
- HackerOne Hacktivity (see real reports)
- Bug Bounty Bootcamp (book)
- LiveOverflow (YouTube)
- STÖK (YouTube)

## The Grind
- Most hunters find nothing for weeks
- Then one bug pays for months
- Consistency beats talent
- Keep learning, keep hunting
"""
    }
}

@click.command()
@click.argument('topic', required=False)
def main(topic: str):
    """
    Interactive bug bounty learning.
    
    Topics: intro, subdomains, scanning, visual, methodology, tips
    
    Examples:
        python learn.py              # List all topics
        python learn.py intro        # Learn about bug bounty basics
        python learn.py methodology  # Learn the full methodology
    """
    if not topic:
        console.print("\n[bold cyan]Bug Bounty Learning Module[/bold cyan]\n")
        console.print("Available topics:\n")
        
        for key, lesson in LESSONS.items():
            console.print(f"  [green]{key}[/green] - {lesson['title']}")
        
        console.print("\nUsage: python learn.py <topic>")
        console.print("Example: python learn.py intro\n")
        return
    
    if topic not in LESSONS:
        console.print(f"[red]Unknown topic: {topic}[/red]")
        console.print(f"Available: {', '.join(LESSONS.keys())}")
        return
    
    lesson = LESSONS[topic]
    console.print(Panel(
        Markdown(lesson['content']),
        title=f"📚 {lesson['title']}",
        border_style="blue"
    ))


if __name__ == "__main__":
    main()
