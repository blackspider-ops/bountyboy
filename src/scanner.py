"""
Scanning Pipeline Module

Smart scanning workflow:
1. httpx - Check which hosts are actually alive
2. Nmap - Port scan (quick first, full on interesting targets)
3. Nuclei - Check for known vulnerabilities

WHY THIS ORDER?
No point scanning dead hosts. httpx filters them out fast.
Quick Nmap scan finds obvious stuff. Full scan only on interesting targets.
Nuclei runs last because it needs to know what services are running.
"""
import json
import asyncio
import aiohttp
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.utils import run_tool, learn, success, error, info, warning, timestamp, check_tool_installed

class Scanner:
    def __init__(self, config: dict, learn_mode: bool = False, deep_ports: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        self.deep_ports = deep_ports
        self.scan_config = config['scanning']
        # Aggressive timeouts for speed
        self.quick_timeout = 60  # 1 min per host max
        self.full_timeout = 180 if deep_ports else 120  # 3 min for deep, 2 min normal
        self.max_parallel = 10   # Scan 10 hosts at once
    
    def check_alive(self, subdomains: set, output_dir: str) -> list:
        """Use httpx to find alive hosts."""
        learn("Alive Host Detection",
              "Before scanning, we need to know which hosts are actually alive. "
              "A subdomain might exist in DNS but the server could be down. "
              "httpx probes each host and tells us which ones respond. "
              "This saves HOURS of scanning dead targets.",
              self.learn_mode)
        
        if not check_tool_installed("httpx"):
            warning("httpx not installed - assuming all hosts alive")
            return list(subdomains)
        
        # Write subdomains to temp file
        input_file = Path(output_dir) / "subdomains_input.txt"
        with open(input_file, 'w') as f:
            f.write('\n'.join(subdomains))
        
        success_flag, output = run_tool(
            ["httpx", "-l", str(input_file), "-silent", "-no-color", "-timeout", "5"],
            timeout=120  # 2 min max for all hosts
        )
        
        if success_flag:
            alive = [line.strip() for line in output.split('\n') if line.strip()]
            # Extract just the hostname from URLs
            alive_hosts = []
            for url in alive:
                host = url.replace('https://', '').replace('http://', '').split('/')[0]
                alive_hosts.append(host)
            alive_hosts = list(set(alive_hosts))
            success(f"Found {len(alive_hosts)} alive hosts out of {len(subdomains)}")
            return alive_hosts
        else:
            error(f"httpx failed: {output}")
            return list(subdomains)
    
    def quick_scan(self, host: str) -> dict:
        """Quick Nmap scan - top 100 ports only for speed."""
        if not check_tool_installed("nmap"):
            error("nmap not installed")
            return {}
        
        # Use top 100 ports instead of 1000 for speed
        success_flag, output = run_tool(
            ["nmap", "-sV", "--top-ports", "100", "-T4", "--max-retries", "1", 
             "--host-timeout", "30s", "-oG", "-", host],
            timeout=self.quick_timeout
        )
        
        if success_flag:
            return self._parse_nmap_output(output, host)
        return {'host': host, 'ports': []}
    
    def full_scan(self, host: str) -> dict:
        """Extended scan - top 1000 ports or all 65535 if deep_ports enabled."""
        if not check_tool_installed("nmap"):
            return {}
        
        if self.deep_ports:
            # Full 65535 port scan - SLOW but thorough
            learn("Deep Port Scan",
                  "Scanning ALL 65535 ports. This takes a long time but finds "
                  "hidden services on non-standard ports like debug servers, "
                  "admin panels on port 9999, etc.",
                  self.learn_mode)
            info(f"  Deep scanning all ports on {host} (this takes a while)...")
            success_flag, output = run_tool(
                ["nmap", "-sV", "-p-", "-T4", "--max-retries", "2",
                 "--host-timeout", "10m", "-oG", "-", host],
                timeout=900  # 15 min max for full scan
            )
        else:
            # Top 1000 instead of all ports - still thorough but 60x faster
            success_flag, output = run_tool(
                ["nmap", "-sV", "--top-ports", "1000", "-T4", "--max-retries", "1",
                 "--host-timeout", "60s", "-oG", "-", host],
                timeout=self.full_timeout
            )
        
        if success_flag:
            return self._parse_nmap_output(output, host)
        return {'host': host, 'ports': []}
    
    def _parse_nmap_output(self, output: str, host: str) -> dict:
        """Parse nmap grepable output."""
        result = {'host': host, 'ports': []}
        for line in output.split('\n'):
            if 'Ports:' in line:
                ports_section = line.split('Ports:')[1].split('Ignored')[0]
                for port_info in ports_section.split(','):
                    port_info = port_info.strip()
                    if '/' in port_info:
                        parts = port_info.split('/')
                        if len(parts) >= 5:
                            port_num = parts[0].strip()
                            state = parts[1].strip()
                            service = parts[4].strip() if len(parts) > 4 else 'unknown'
                            if state == 'open':
                                result['ports'].append({
                                    'port': port_num,
                                    'service': service
                                })
        return result
    
    def has_interesting_ports(self, scan_result: dict) -> bool:
        """Check if scan found interesting ports worth full scanning."""
        interesting = set(str(p) for p in self.scan_config['nmap']['interesting_ports'])
        found_ports = set(p['port'] for p in scan_result.get('ports', []))
        return bool(interesting & found_ports)
    
    def _scan_host(self, host: str) -> dict:
        """Scan a single host (for parallel execution)."""
        info(f"  Scanning {host}...")
        scan_result = self.quick_scan(host)
        
        if scan_result.get('ports'):
            success(f"  Found {len(scan_result['ports'])} open ports on {host}")
            
            # Full scan if interesting ports found
            if self.has_interesting_ports(scan_result):
                info(f"  Interesting ports found - running full scan...")
                scan_result = self.full_scan(host)
        
        return scan_result
    
    def run_nuclei(self, hosts: list, output_dir: str) -> list:
        """Run nuclei vulnerability scanner."""
        learn("Nuclei Vulnerability Scanner",
              "Nuclei uses templates to check for known vulnerabilities. "
              "Exposed .git folders. Default credentials. Known CVEs. "
              "It's like having a checklist of 1000+ things to test, "
              "but automated. Finds low-hanging fruit instantly.",
              self.learn_mode)
        
        if not check_tool_installed("nuclei"):
            error("nuclei not installed - skipping vulnerability scan")
            return []
        
        if not self.scan_config['nuclei']['enabled']:
            info("Nuclei disabled in config")
            return []
        
        # Write hosts to file
        input_file = Path(output_dir) / "nuclei_targets.txt"
        with open(input_file, 'w') as f:
            for host in hosts[:30]:  # Limit to 30 hosts for speed
                f.write(f"https://{host}\n")
                f.write(f"http://{host}\n")
        
        severity = ','.join(self.scan_config['nuclei']['severity'])
        tags = ','.join(self.scan_config['nuclei']['tags'])
        
        output_file = Path(output_dir) / f"nuclei_{timestamp()}.json"
        
        success_flag, output = run_tool(
            ["nuclei", "-l", str(input_file), "-severity", severity, 
             "-tags", tags, "-json", "-o", str(output_file),
             "-timeout", "5", "-retries", "1", "-c", "50"],  # Fast settings
            timeout=300  # 5 min max
        )
        
        findings = []
        if output_file.exists():
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                    except json.JSONDecodeError:
                        pass
        
        if findings:
            success(f"🚨 Nuclei found {len(findings)} potential vulnerabilities!")
            for f in findings[:10]:  # Show first 10
                severity = f.get('info', {}).get('severity', 'unknown')
                name = f.get('info', {}).get('name', 'Unknown')
                host = f.get('host', '')
                warning(f"  [{severity.upper()}] {name} - {host}")
        else:
            info("Nuclei found no vulnerabilities (this is normal)")
        
        return findings
    
    def scan(self, subdomains: set, output_dir: str) -> dict:
        """Run full scanning pipeline with parallel execution."""
        learn("Scanning Strategy",
              "We're smart about scanning. Check alive first (httpx). "
              "Quick scan everyone (top 100 ports). Full scan only interesting ones. "
              "Then nuclei for known vulns. This is 10x faster than scanning everything.",
              self.learn_mode)
        
        results = {
            'alive_hosts': [],
            'scan_results': [],
            'nuclei_findings': []
        }
        
        # Step 1: Find alive hosts
        info("Step 1: Checking alive hosts...")
        if self.scan_config['httpx_alive_check']:
            alive = self.check_alive(subdomains, output_dir)
        else:
            alive = list(subdomains)
        results['alive_hosts'] = alive
        
        if not alive:
            warning("No alive hosts found")
            return results
        
        # Step 2: Parallel scan all alive hosts
        info(f"Step 2: Quick scanning {len(alive)} hosts (parallel)...")
        
        # Use ThreadPoolExecutor for parallel nmap scans
        with ThreadPoolExecutor(max_workers=self.max_parallel) as executor:
            future_to_host = {executor.submit(self._scan_host, host): host for host in alive[:30]}  # Limit to 30
            
            for future in as_completed(future_to_host):
                try:
                    scan_result = future.result(timeout=self.full_timeout)
                    if scan_result:
                        results['scan_results'].append(scan_result)
                except Exception as e:
                    host = future_to_host[future]
                    warning(f"  Scan failed for {host}: {e}")
        
        # Save scan results
        scan_file = Path(output_dir) / f"scan_{timestamp()}.json"
        with open(scan_file, 'w') as f:
            json.dump(results['scan_results'], f, indent=2)
        
        # Step 3: Run nuclei
        info("Step 3: Running nuclei vulnerability scan...")
        results['nuclei_findings'] = self.run_nuclei(alive, output_dir)
        
        return results


if __name__ == "__main__":
    from src.utils import load_config, ensure_dirs
    config = load_config()
    target = "example.com"
    dirs = ensure_dirs(target, config)
    
    scanner = Scanner(config, learn_mode=True)
    # Test with dummy subdomains
    results = scanner.scan({"www.example.com", "mail.example.com"}, dirs['scans'])
    print(f"\nScan complete: {len(results['alive_hosts'])} alive hosts")
