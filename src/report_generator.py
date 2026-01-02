"""
Report Generator Module

Generates comprehensive HTML and Markdown reports:
- Executive summary
- Detailed findings
- Severity breakdown
- Recommendations
- Evidence/screenshots

WHY REPORTS?
Good reports = faster payouts:
- Clear, professional presentation
- Easy for triagers to understand
- All evidence in one place
- Severity justification
"""
import json
from pathlib import Path
from datetime import datetime
from src.utils import timestamp

class ReportGenerator:
    def __init__(self, config: dict):
        self.config = config
    
    def generate_html(self, results: dict, output_dir: str) -> str:
        """Generate HTML report."""
        target = results.get('target', 'Unknown')
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Report - {target}</title>
    <style>
        :root {{
            --bg-dark: #1a1a2e;
            --bg-card: #16213e;
            --accent: #0f3460;
            --highlight: #e94560;
            --text: #eee;
            --text-dim: #888;
            --success: #00d26a;
            --warning: #ffc107;
            --danger: #dc3545;
            --info: #17a2b8;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        header {{
            text-align: center;
            padding: 40px 0;
            border-bottom: 2px solid var(--accent);
            margin-bottom: 30px;
        }}
        
        h1 {{
            color: var(--highlight);
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .subtitle {{
            color: var(--text-dim);
            font-size: 1.2em;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .summary-card {{
            background: var(--bg-card);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border-left: 4px solid var(--accent);
        }}
        
        .summary-card.critical {{
            border-left-color: var(--danger);
        }}
        
        .summary-card.high {{
            border-left-color: #ff6b6b;
        }}
        
        .summary-card.medium {{
            border-left-color: var(--warning);
        }}
        
        .summary-card.low {{
            border-left-color: var(--info);
        }}
        
        .summary-card .number {{
            font-size: 3em;
            font-weight: bold;
            color: var(--highlight);
        }}
        
        .summary-card .label {{
            color: var(--text-dim);
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        
        section {{
            background: var(--bg-card);
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        
        h2 {{
            color: var(--highlight);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--accent);
        }}
        
        h3 {{
            color: var(--text);
            margin: 15px 0 10px 0;
        }}
        
        .finding {{
            background: var(--bg-dark);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid var(--accent);
        }}
        
        .finding.critical {{
            border-left-color: var(--danger);
        }}
        
        .finding.high {{
            border-left-color: #ff6b6b;
        }}
        
        .finding.medium {{
            border-left-color: var(--warning);
        }}
        
        .finding.low {{
            border-left-color: var(--info);
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .severity-badge.critical {{
            background: var(--danger);
        }}
        
        .severity-badge.high {{
            background: #ff6b6b;
        }}
        
        .severity-badge.medium {{
            background: var(--warning);
            color: #000;
        }}
        
        .severity-badge.low {{
            background: var(--info);
        }}
        
        .severity-badge.info {{
            background: var(--text-dim);
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--accent);
        }}
        
        th {{
            background: var(--accent);
            color: var(--text);
        }}
        
        tr:hover {{
            background: rgba(255,255,255,0.05);
        }}
        
        code {{
            background: var(--bg-dark);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            color: var(--success);
        }}
        
        pre {{
            background: var(--bg-dark);
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
        }}
        
        .url {{
            color: var(--info);
            word-break: break-all;
        }}
        
        footer {{
            text-align: center;
            padding: 20px;
            color: var(--text-dim);
            font-size: 0.9em;
        }}
        
        .progress-bar {{
            background: var(--bg-dark);
            border-radius: 10px;
            height: 20px;
            overflow: hidden;
            margin: 10px 0;
        }}
        
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--highlight), var(--success));
            transition: width 0.3s;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🎯 Bug Bounty Report</h1>
            <p class="subtitle">Target: <strong>{target}</strong></p>
            <p class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <div class="summary-grid">
            <div class="summary-card">
                <div class="number">{len(results.get('subdomains', []))}</div>
                <div class="label">Subdomains</div>
            </div>
            <div class="summary-card">
                <div class="number">{len(results.get('alive_hosts', []))}</div>
                <div class="label">Alive Hosts</div>
            </div>
            <div class="summary-card critical">
                <div class="number">{len(results.get('vulnerabilities', []))}</div>
                <div class="label">Nuclei Findings</div>
            </div>
            <div class="summary-card high">
                <div class="number">{len(results.get('js_secrets', []))}</div>
                <div class="label">JS Secrets</div>
            </div>
            <div class="summary-card medium">
                <div class="number">{len(results.get('takeover_vulns', []))}</div>
                <div class="label">Takeover Vulns</div>
            </div>
            <div class="summary-card low">
                <div class="number">{len(results.get('cors_vulns', []))}</div>
                <div class="label">CORS Issues</div>
            </div>
        </div>
"""
        
        # Vulnerabilities section
        vulns = results.get('vulnerabilities', [])
        if vulns:
            html += """
        <section>
            <h2>🚨 Nuclei Findings</h2>
"""
            for vuln in vulns:
                severity = vuln.get('info', {}).get('severity', 'info')
                name = vuln.get('info', {}).get('name', 'Unknown')
                host = vuln.get('host', '')
                html += f"""
            <div class="finding {severity}">
                <span class="severity-badge {severity}">{severity}</span>
                <h3>{name}</h3>
                <p class="url">{host}</p>
            </div>
"""
            html += "        </section>\n"
        
        # JS Secrets section
        secrets = results.get('js_secrets', [])
        if secrets:
            html += """
        <section>
            <h2>🔑 JavaScript Secrets</h2>
"""
            for secret in secrets[:10]:
                html += f"""
            <div class="finding high">
                <code>{secret[:100]}...</code>
            </div>
"""
            html += "        </section>\n"
        
        # Subdomains section
        subs = results.get('subdomains', [])
        if subs:
            html += f"""
        <section>
            <h2>🌐 Subdomains ({len(subs)})</h2>
            <table>
                <tr><th>Subdomain</th></tr>
"""
            for sub in sorted(subs)[:50]:
                html += f"                <tr><td>{sub}</td></tr>\n"
            if len(subs) > 50:
                html += f"                <tr><td><em>... and {len(subs) - 50} more</em></td></tr>\n"
            html += """            </table>
        </section>
"""
        
        # Footer
        html += """
        <footer>
            <p>Generated by BountyBoy 🎯</p>
            <p>Always verify findings manually before reporting</p>
        </footer>
    </div>
</body>
</html>
"""
        
        # Save report
        output_file = Path(output_dir) / f"report_{timestamp()}.html"
        with open(output_file, 'w') as f:
            f.write(html)
        
        return str(output_file)
    
    def generate_markdown(self, results: dict, output_dir: str) -> str:
        """Generate Markdown report."""
        target = results.get('target', 'Unknown')
        
        md = f"""# Bug Bounty Report: {target}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Executive Summary

| Metric | Count |
|--------|-------|
| Subdomains | {len(results.get('subdomains', []))} |
| Alive Hosts | {len(results.get('alive_hosts', []))} |
| Nuclei Findings | {len(results.get('vulnerabilities', []))} |
| JS Secrets | {len(results.get('js_secrets', []))} |
| Takeover Vulns | {len(results.get('takeover_vulns', []))} |
| CORS Issues | {len(results.get('cors_vulns', []))} |

---

## Critical Findings

"""
        
        # Vulnerabilities
        vulns = results.get('vulnerabilities', [])
        if vulns:
            md += "### Nuclei Findings\n\n"
            for vuln in vulns:
                severity = vuln.get('info', {}).get('severity', 'info').upper()
                name = vuln.get('info', {}).get('name', 'Unknown')
                host = vuln.get('host', '')
                md += f"- **[{severity}]** {name}\n  - URL: `{host}`\n\n"
        
        # JS Secrets
        secrets = results.get('js_secrets', [])
        if secrets:
            md += "### JavaScript Secrets\n\n"
            for secret in secrets[:10]:
                md += f"```\n{secret[:100]}...\n```\n\n"
        
        # Takeover
        takeover = results.get('takeover_vulns', [])
        if takeover:
            md += "### Subdomain Takeover\n\n"
            for t in takeover:
                md += f"- **{t.get('subdomain')}** → {t.get('service')}\n"
        
        # Subdomains
        subs = results.get('subdomains', [])
        if subs:
            md += f"\n---\n\n## Subdomains ({len(subs)})\n\n"
            for sub in sorted(subs)[:50]:
                md += f"- {sub}\n"
            if len(subs) > 50:
                md += f"\n*... and {len(subs) - 50} more*\n"
        
        md += "\n---\n\n*Report generated by BountyBoy 🎯*\n"
        
        # Save report
        output_file = Path(output_dir) / f"report_{timestamp()}.md"
        with open(output_file, 'w') as f:
            f.write(md)
        
        return str(output_file)
    
    def generate(self, results: dict, output_dir: str) -> dict:
        """Generate all report formats."""
        html_path = self.generate_html(results, output_dir)
        md_path = self.generate_markdown(results, output_dir)
        
        return {
            'html': html_path,
            'markdown': md_path
        }
