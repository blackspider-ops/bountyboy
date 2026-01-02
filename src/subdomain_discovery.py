"""
Subdomain Discovery Module

Chains multiple tools to find all subdomains:
- Subfinder: Fast passive subdomain enumeration
- Amass: Comprehensive subdomain discovery
- Assetfinder: Quick asset discovery
- crt.sh: Certificate transparency logs

WHY MULTIPLE TOOLS?
Each tool uses different data sources. Subfinder might find subdomains from
VirusTotal that Amass misses. Amass might find subdomains from DNS brute
forcing that Subfinder doesn't do. Combining them gives complete coverage.
"""
import requests
from pathlib import Path
from src.utils import run_tool, learn, success, error, info, timestamp, check_tool_installed

class SubdomainDiscovery:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        self.timeout = config['subdomain_discovery']['timeout']
    
    def run_subfinder(self, target: str) -> set:
        """Run subfinder for passive subdomain enumeration."""
        learn("Subfinder", 
              "Subfinder queries passive sources like VirusTotal, SecurityTrails, "
              "Shodan, etc. It doesn't touch the target directly - just collects "
              "subdomains that have been indexed by these services. Fast and stealthy.",
              self.learn_mode)
        
        if not check_tool_installed("subfinder"):
            error("subfinder not installed - skipping")
            return set()
        
        success_flag, output = run_tool(
            ["subfinder", "-d", target, "-silent"],
            timeout=self.timeout
        )
        
        if success_flag:
            subs = set(line.strip() for line in output.split('\n') if line.strip())
            success(f"Subfinder found {len(subs)} subdomains")
            return subs
        else:
            error(f"Subfinder failed: {output}")
            return set()
    
    def run_amass(self, target: str) -> set:
        """Run amass for comprehensive subdomain discovery."""
        learn("Amass",
              "Amass is more thorough than Subfinder. It does passive enumeration "
              "PLUS can do active DNS brute forcing. It's slower but finds more. "
              "We use passive mode (-passive) to stay quiet initially.",
              self.learn_mode)
        
        if not check_tool_installed("amass"):
            error("amass not installed - skipping")
            return set()
        
        success_flag, output = run_tool(
            ["amass", "enum", "-passive", "-d", target],
            timeout=self.timeout
        )
        
        if success_flag:
            subs = set(line.strip() for line in output.split('\n') if line.strip())
            success(f"Amass found {len(subs)} subdomains")
            return subs
        else:
            error(f"Amass failed: {output}")
            return set()
    
    def run_assetfinder(self, target: str) -> set:
        """Run assetfinder for quick asset discovery."""
        learn("Assetfinder",
              "Assetfinder is super fast and lightweight. It queries sources like "
              "crt.sh, Facebook, and others. Good for quick initial enumeration.",
              self.learn_mode)
        
        if not check_tool_installed("assetfinder"):
            error("assetfinder not installed - skipping")
            return set()
        
        success_flag, output = run_tool(
            ["assetfinder", "--subs-only", target],
            timeout=self.timeout
        )
        
        if success_flag:
            subs = set(line.strip() for line in output.split('\n') if line.strip())
            success(f"Assetfinder found {len(subs)} subdomains")
            return subs
        else:
            error(f"Assetfinder failed: {output}")
            return set()
    
    def run_crtsh(self, target: str) -> set:
        """Query crt.sh certificate transparency logs."""
        learn("crt.sh",
              "Certificate Transparency (CT) logs are public records of SSL certificates. "
              "When a company gets an SSL cert for staging.target.com, it gets logged. "
              "crt.sh lets us search these logs. Great for finding forgotten subdomains "
              "that got SSL certs but were never meant to be public.",
              self.learn_mode)
        
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{target}&output=json",
                timeout=30
            )
            if resp.status_code == 200:
                data = resp.json()
                subs = set()
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub and '*' not in sub:
                            subs.add(sub)
                success(f"crt.sh found {len(subs)} subdomains")
                return subs
        except Exception as e:
            error(f"crt.sh failed: {e}")
        return set()
    
    def discover(self, target: str, output_dir: str) -> tuple[set, list]:
        """
        Run all discovery tools and combine results.
        Returns (all_subdomains, new_subdomains)
        """
        learn("Subdomain Discovery Strategy",
              "We run multiple tools because each has different data sources. "
              "Tool A might find 100 subdomains, Tool B finds 80, but 20 of those "
              "are unique. Combined we get 120. More coverage = more attack surface.",
              self.learn_mode)
        
        info(f"Starting subdomain discovery for {target}")
        
        all_subs = set()
        tools_config = self.config['subdomain_discovery']['tools']
        
        if tools_config.get('subfinder'):
            all_subs.update(self.run_subfinder(target))
        
        if tools_config.get('amass'):
            all_subs.update(self.run_amass(target))
        
        if tools_config.get('assetfinder'):
            all_subs.update(self.run_assetfinder(target))
        
        if tools_config.get('crtsh'):
            all_subs.update(self.run_crtsh(target))
        
        # Filter to only include subdomains of target
        all_subs = {s for s in all_subs if s.endswith(target)}
        
        success(f"Total unique subdomains: {len(all_subs)}")
        
        # Save results
        output_path = Path(output_dir)
        current_file = output_path / "current.txt"
        history_file = output_path / "history" / f"{timestamp()}.txt"
        
        # Check for new subdomains
        new_subs = []
        if current_file.exists():
            with open(current_file, 'r') as f:
                old_subs = set(line.strip() for line in f if line.strip())
            new_subs = list(all_subs - old_subs)
            if new_subs:
                learn("New Subdomains Alert",
                      "NEW subdomains are gold! When a company launches a new subdomain, "
                      "it's often untested. Maybe it's a staging server. Maybe it's a new "
                      "feature. Either way, it hasn't been hammered by other hunters yet. "
                      "This is your competitive advantage.",
                      self.learn_mode)
                success(f"🎯 Found {len(new_subs)} NEW subdomains!")
                for sub in new_subs:
                    info(f"  NEW: {sub}")
        
        # Save current results
        with open(current_file, 'w') as f:
            f.write('\n'.join(sorted(all_subs)))
        
        # Save to history
        with open(history_file, 'w') as f:
            f.write('\n'.join(sorted(all_subs)))
        
        return all_subs, new_subs


if __name__ == "__main__":
    # Quick test
    from src.utils import load_config, ensure_dirs
    config = load_config()
    target = "example.com"
    dirs = ensure_dirs(target, config)
    
    discovery = SubdomainDiscovery(config, learn_mode=True)
    subs, new = discovery.discover(target, dirs['subdomains'])
    print(f"\nFound {len(subs)} total, {len(new)} new")
