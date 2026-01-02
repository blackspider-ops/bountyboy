"""
Visual Recon Module

Screenshots and tech stack identification:
- EyeWitness - Screenshots all web servers
- Tech detection - Identify frameworks, CMS, etc.

WHY VISUAL RECON?
Port scan tells you "port 443 is open". Screenshot tells you "it's an admin panel".
Tech detection tells you "it's running WordPress 5.2". Now you know exactly
what to attack and how.
"""
import json
import requests
from pathlib import Path
from src.utils import run_tool, learn, success, error, info, warning, timestamp, check_tool_installed

class VisualRecon:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        self.recon_config = config['visual_recon']
    
    def take_screenshots(self, hosts: list, output_dir: str) -> str:
        """Take screenshots of all web servers using EyeWitness."""
        learn("Screenshots with EyeWitness",
              "EyeWitness visits each URL and takes a screenshot. "
              "You can browse 500 subdomains in 5 minutes instead of clicking each one. "
              "Spot admin panels, login pages, API docs instantly. "
              "Visual recon is underrated - your eyes catch things tools miss.",
              self.learn_mode)
        
        if not self.recon_config['screenshots']:
            info("Screenshots disabled in config")
            return ""
        
        if not check_tool_installed("eyewitness"):
            # Try alternative name
            if not check_tool_installed("EyeWitness"):
                error("EyeWitness not installed - skipping screenshots")
                return ""
        
        # Write URLs to file
        input_file = Path(output_dir) / "screenshot_targets.txt"
        with open(input_file, 'w') as f:
            for host in hosts:
                f.write(f"https://{host}\n")
                f.write(f"http://{host}\n")
        
        report_dir = Path(output_dir) / f"eyewitness_{timestamp()}"
        
        success_flag, output = run_tool(
            ["eyewitness", "-f", str(input_file), "-d", str(report_dir), 
             "--no-prompt", "--timeout", str(self.recon_config['timeout'])],
            timeout=len(hosts) * self.recon_config['timeout'] + 60
        )
        
        if success_flag:
            report_path = report_dir / "report.html"
            if report_path.exists():
                success(f"Screenshots saved to {report_dir}")
                return str(report_path)
        
        error("EyeWitness failed or produced no output")
        return ""
    
    def detect_tech_stack(self, hosts: list, output_dir: str) -> dict:
        """Detect technology stack for each host."""
        learn("Tech Stack Detection",
              "Knowing the tech stack changes your attack approach completely. "
              "WordPress? Look for plugin vulns. Django? Check for debug mode. "
              "Node.js? Try prototype pollution. Tech detection guides your testing.",
              self.learn_mode)
        
        if not self.recon_config['tech_detection']:
            info("Tech detection disabled in config")
            return {}
        
        results = {}
        
        for host in hosts:
            info(f"Detecting tech stack for {host}...")
            tech = self._detect_single_host(host)
            if tech:
                results[host] = tech
                success(f"  {host}: {', '.join(tech[:5])}")  # Show first 5
        
        # Save results
        output_file = Path(output_dir) / f"tech_stack_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def _detect_single_host(self, host: str) -> list:
        """Detect tech stack for a single host using headers and response analysis."""
        technologies = []
        
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{host}"
                resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                
                # Check headers
                headers = resp.headers
                
                # Server header
                if 'Server' in headers:
                    server = headers['Server']
                    technologies.append(f"Server: {server}")
                    if 'nginx' in server.lower():
                        technologies.append("nginx")
                    elif 'apache' in server.lower():
                        technologies.append("Apache")
                    elif 'iis' in server.lower():
                        technologies.append("IIS")
                
                # X-Powered-By
                if 'X-Powered-By' in headers:
                    powered = headers['X-Powered-By']
                    technologies.append(f"Powered-By: {powered}")
                    if 'php' in powered.lower():
                        technologies.append("PHP")
                    elif 'asp' in powered.lower():
                        technologies.append("ASP.NET")
                    elif 'express' in powered.lower():
                        technologies.append("Express.js")
                
                # Check response body for common patterns
                body = resp.text.lower()
                
                if 'wp-content' in body or 'wordpress' in body:
                    technologies.append("WordPress")
                if 'drupal' in body:
                    technologies.append("Drupal")
                if 'joomla' in body:
                    technologies.append("Joomla")
                if 'react' in body or 'reactdom' in body:
                    technologies.append("React")
                if 'angular' in body or 'ng-' in body:
                    technologies.append("Angular")
                if 'vue' in body or 'vuejs' in body:
                    technologies.append("Vue.js")
                if 'laravel' in body:
                    technologies.append("Laravel")
                if 'django' in body or 'csrfmiddlewaretoken' in body:
                    technologies.append("Django")
                if 'rails' in body or 'csrf-token' in body:
                    technologies.append("Ruby on Rails")
                if 'next.js' in body or '_next' in body:
                    technologies.append("Next.js")
                if 'swagger' in body or 'openapi' in body:
                    technologies.append("Swagger/OpenAPI")
                
                # Check for common files
                self._check_common_files(host, protocol, technologies)
                
                break  # Success, no need to try other protocol
                
            except requests.RequestException:
                continue
        
        return list(set(technologies))  # Remove duplicates
    
    def _check_common_files(self, host: str, protocol: str, technologies: list):
        """Check for common files that reveal technology."""
        checks = [
            ('/robots.txt', 'robots.txt'),
            ('/wp-login.php', 'WordPress'),
            ('/wp-admin/', 'WordPress'),
            ('/administrator/', 'Joomla'),
            ('/user/login', 'Drupal'),
            ('/.git/config', 'Git Exposed'),
            ('/.env', 'Env File Exposed'),
            ('/server-status', 'Apache Status'),
            ('/elmah.axd', 'ELMAH (ASP.NET)'),
            ('/phpinfo.php', 'PHPInfo Exposed'),
            ('/api/swagger', 'Swagger API'),
            ('/graphql', 'GraphQL'),
        ]
        
        for path, tech in checks:
            try:
                resp = requests.get(f"{protocol}://{host}{path}", 
                                   timeout=5, verify=False, allow_redirects=False)
                if resp.status_code == 200:
                    technologies.append(tech)
                    if tech in ['Git Exposed', 'Env File Exposed', 'PHPInfo Exposed']:
                        warning(f"  ⚠️  INTERESTING: {tech} found at {path}")
            except requests.RequestException:
                pass
    
    def run(self, hosts: list, output_dir: str) -> dict:
        """Run full visual recon pipeline."""
        learn("Visual Recon Strategy",
              "We screenshot everything and detect tech stacks. "
              "This gives you a visual map of the attack surface. "
              "Admin panels, API docs, login pages - all visible at a glance. "
              "Combined with tech detection, you know exactly where to focus.",
              self.learn_mode)
        
        results = {
            'screenshot_report': '',
            'tech_stacks': {}
        }
        
        if not hosts:
            warning("No hosts to scan")
            return results
        
        info(f"Running visual recon on {len(hosts)} hosts...")
        
        # Screenshots
        results['screenshot_report'] = self.take_screenshots(hosts, output_dir)
        
        # Tech detection
        results['tech_stacks'] = self.detect_tech_stack(hosts, output_dir)
        
        # Summary
        if results['tech_stacks']:
            info("\nTech Stack Summary:")
            tech_count = {}
            for host, techs in results['tech_stacks'].items():
                for tech in techs:
                    tech_count[tech] = tech_count.get(tech, 0) + 1
            
            for tech, count in sorted(tech_count.items(), key=lambda x: -x[1])[:10]:
                info(f"  {tech}: {count} hosts")
        
        return results


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    
    from src.utils import load_config, ensure_dirs
    config = load_config()
    target = "example.com"
    dirs = ensure_dirs(target, config)
    
    recon = VisualRecon(config, learn_mode=True)
    results = recon.run(["www.example.com"], dirs['screenshots'])
    print(f"\nVisual recon complete")
