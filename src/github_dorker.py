"""
GitHub Dorking Module

Searches GitHub for leaked secrets related to a target:
- API keys accidentally committed
- Passwords in config files
- Internal URLs and endpoints
- AWS credentials
- Database connection strings

WHY GITHUB DORKING?
Developers make mistakes. They commit .env files, hardcode API keys,
push config files with passwords. GitHub indexes everything.
We search for these mistakes using "dorks" (special search queries).

This has found CRITICAL bugs - AWS keys, database passwords, admin tokens.
Companies pay BIG bounties for credential leaks.
"""
import asyncio
import aiohttp
import re
from pathlib import Path
from urllib.parse import quote
from src.utils import learn, success, error, info, warning, timestamp

class GitHubDorker:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        
        # GitHub dork queries - {query} will be replaced with target
        self.dorks = {
            'passwords': [
                '"{target}" password',
                '"{target}" passwd',
                '"{target}" pwd',
                '"{target}" secret',
                '"{target}" credentials',
            ],
            'api_keys': [
                '"{target}" api_key',
                '"{target}" apikey',
                '"{target}" api_secret',
                '"{target}" access_token',
                '"{target}" auth_token',
            ],
            'aws': [
                '"{target}" AWS_ACCESS_KEY_ID',
                '"{target}" AWS_SECRET_ACCESS_KEY',
                '"{target}" aws_key',
                '"{target}" s3.amazonaws.com',
            ],
            'database': [
                '"{target}" mysql_password',
                '"{target}" postgres_password',
                '"{target}" mongodb_uri',
                '"{target}" database_url',
                '"{target}" db_password',
            ],
            'config_files': [
                '"{target}" filename:.env',
                '"{target}" filename:config.php',
                '"{target}" filename:settings.py',
                '"{target}" filename:database.yml',
                '"{target}" filename:credentials',
            ],
            'private_keys': [
                '"{target}" BEGIN RSA PRIVATE KEY',
                '"{target}" BEGIN OPENSSH PRIVATE KEY',
                '"{target}" BEGIN PGP PRIVATE KEY',
            ],
            'internal': [
                '"{target}" internal',
                '"{target}" staging',
                '"{target}" dev.{target}',
                '"{target}" admin',
            ]
        }
    
    def generate_search_urls(self, target: str) -> dict:
        """Generate GitHub search URLs for all dorks."""
        urls = {}
        base_url = "https://github.com/search?type=code&q="
        
        for category, queries in self.dorks.items():
            urls[category] = []
            for query in queries:
                formatted = query.replace('{target}', target)
                search_url = base_url + quote(formatted)
                urls[category].append({
                    'query': formatted,
                    'url': search_url
                })
        
        return urls
    
    def analyze(self, target: str, output_dir: str) -> dict:
        """Generate GitHub dork URLs for manual review."""
        learn("GitHub Dorking",
              "We're generating GitHub search queries to find leaked secrets. "
              "GitHub's API has rate limits, so we generate URLs for manual review. "
              "Look for:\n"
              "• .env files with credentials\n"
              "• Config files with passwords\n"
              "• API keys in source code\n"
              "• AWS credentials\n"
              "• Database connection strings\n\n"
              "One leaked AWS key = Critical severity = Big bounty",
              self.learn_mode)
        
        info(f"Generating GitHub dork URLs for {target}...")
        
        results = {
            'target': target,
            'dork_urls': self.generate_search_urls(target),
            'total_dorks': 0
        }
        
        # Count total dorks
        for category, dorks in results['dork_urls'].items():
            results['total_dorks'] += len(dorks)
            info(f"  {category}: {len(dorks)} search queries")
        
        success(f"Generated {results['total_dorks']} GitHub dork URLs")
        
        # Save results
        output_file = Path(output_dir) / f"github_dorks_{timestamp()}.txt"
        with open(output_file, 'w') as f:
            f.write(f"# GitHub Dorks for {target}\n")
            f.write(f"# Generated: {timestamp()}\n\n")
            
            for category, dorks in results['dork_urls'].items():
                f.write(f"\n## {category.upper()}\n")
                for dork in dorks:
                    f.write(f"\nQuery: {dork['query']}\n")
                    f.write(f"URL: {dork['url']}\n")
        
        info(f"Saved to {output_file}")
        warning("⚠️  Open these URLs manually in browser (GitHub rate limits API)")
        
        return results
