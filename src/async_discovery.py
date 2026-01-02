"""
Async Subdomain Discovery Module

Runs ALL discovery tools simultaneously using asyncio.
Instead of: Subfinder (30s) → Assetfinder (20s) → crt.sh (10s) = 60s total
We get:     All three at once = ~30s total (speed of slowest tool)

WHY ASYNC?
Bug bounty is a race. Other hunters are scanning the same targets.
Running tools in parallel means you find things faster.
Faster discovery = first to find new assets = first to get paid.
"""
import asyncio
import aiohttp
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from src.utils import learn, success, error, info, timestamp, check_tool_installed

class AsyncSubdomainDiscovery:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        self.timeout = config['subdomain_discovery']['timeout']
        self.executor = ThreadPoolExecutor(max_workers=5)
    
    async def run_tool_async(self, cmd: list, tool_name: str) -> set:
        """Run a tool asynchronously using thread pool."""
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                self.executor,
                lambda: subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            )
            if result.returncode == 0:
                subs = set(line.strip() for line in result.stdout.split('\n') if line.strip())
                success(f"{tool_name} found {len(subs)} subdomains")
                return subs
        except subprocess.TimeoutExpired:
            error(f"{tool_name} timed out")
        except Exception as e:
            error(f"{tool_name} failed: {e}")
        return set()
    
    async def run_subfinder(self, target: str) -> set:
        """Run subfinder asynchronously."""
        if not check_tool_installed("subfinder"):
            error("subfinder not installed")
            return set()
        return await self.run_tool_async(
            ["subfinder", "-d", target, "-silent"],
            "Subfinder"
        )
    
    async def run_assetfinder(self, target: str) -> set:
        """Run assetfinder asynchronously."""
        if not check_tool_installed("assetfinder"):
            error("assetfinder not installed")
            return set()
        return await self.run_tool_async(
            ["assetfinder", "--subs-only", target],
            "Assetfinder"
        )
    
    async def run_amass(self, target: str) -> set:
        """Run amass asynchronously."""
        if not check_tool_installed("amass"):
            error("amass not installed")
            return set()
        return await self.run_tool_async(
            ["amass", "enum", "-passive", "-d", target],
            "Amass"
        )
    
    async def run_crtsh(self, target: str) -> set:
        """Query crt.sh asynchronously."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://crt.sh/?q=%.{target}&output=json",
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
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
    
    async def discover_async(self, target: str, output_dir: str) -> tuple[set, list]:
        """
        Run all discovery tools in parallel.
        Returns (all_subdomains, new_subdomains)
        """
        learn("Parallel Discovery",
              "We're running ALL tools at the same time. Subfinder, Assetfinder, "
              "crt.sh - all firing simultaneously. This cuts discovery time by 60-70%. "
              "In bug bounty, speed is money.",
              self.learn_mode)
        
        info(f"Starting PARALLEL subdomain discovery for {target}")
        
        tools_config = self.config['subdomain_discovery']['tools']
        tasks = []
        
        # Create tasks for enabled tools
        if tools_config.get('subfinder'):
            tasks.append(self.run_subfinder(target))
        if tools_config.get('assetfinder'):
            tasks.append(self.run_assetfinder(target))
        if tools_config.get('amass'):
            tasks.append(self.run_amass(target))
        if tools_config.get('crtsh'):
            tasks.append(self.run_crtsh(target))
        
        # Run all tasks simultaneously
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine results
        all_subs = set()
        for result in results:
            if isinstance(result, set):
                all_subs.update(result)
        
        # Filter to only include subdomains of target
        all_subs = {s for s in all_subs if s.endswith(target)}
        
        success(f"Total unique subdomains: {len(all_subs)}")
        
        # Save and compare with previous results
        output_path = Path(output_dir)
        current_file = output_path / "current.txt"
        history_file = output_path / "history" / f"{timestamp()}.txt"
        
        new_subs = []
        if current_file.exists():
            with open(current_file, 'r') as f:
                old_subs = set(line.strip() for line in f if line.strip())
            new_subs = list(all_subs - old_subs)
            if new_subs:
                success(f"🎯 Found {len(new_subs)} NEW subdomains!")
        
        # Save results
        with open(current_file, 'w') as f:
            f.write('\n'.join(sorted(all_subs)))
        with open(history_file, 'w') as f:
            f.write('\n'.join(sorted(all_subs)))
        
        return all_subs, new_subs
    
    def discover(self, target: str, output_dir: str) -> tuple[set, list]:
        """Synchronous wrapper for async discovery."""
        return asyncio.run(self.discover_async(target, output_dir))
