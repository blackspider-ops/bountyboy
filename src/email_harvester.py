"""
Email Harvester Module

Finds email addresses associated with a target:
- Employee emails for phishing scope
- Contact emails
- Email patterns (first.last@, f.last@, etc.)

WHY EMAIL HARVESTING?
- Useful for social engineering scope
- Reveals email naming patterns
- Can find exposed credentials in breaches
- Helps understand organization structure

Sources:
- Hunter.io API
- Google dorking
- Website scraping
- Certificate transparency
"""
import asyncio
import aiohttp
import re
from pathlib import Path
from urllib.parse import quote
from src.utils import learn, success, error, info, warning, timestamp

class EmailHarvester:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        self.hunter_api_key = config.get('hunter', {}).get('api_key', '')
        
        # Email regex pattern
        self.email_pattern = re.compile(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        )
    
    async def search_hunter(self, session: aiohttp.ClientSession, domain: str) -> list:
        """Search Hunter.io for emails."""
        if not self.hunter_api_key:
            return []
        
        try:
            url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={self.hunter_api_key}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    emails = []
                    for email_data in data.get('data', {}).get('emails', []):
                        emails.append({
                            'email': email_data.get('value'),
                            'type': email_data.get('type'),
                            'confidence': email_data.get('confidence'),
                            'first_name': email_data.get('first_name'),
                            'last_name': email_data.get('last_name'),
                            'position': email_data.get('position'),
                            'source': 'hunter.io'
                        })
                    return emails
        except Exception:
            pass
        return []
    
    async def scrape_website(self, session: aiohttp.ClientSession, url: str) -> list:
        """Scrape a website for email addresses."""
        emails = []
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                   ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    found = self.email_pattern.findall(text)
                    for email in found:
                        # Filter out common false positives
                        if not any(fp in email.lower() for fp in 
                                  ['example.com', 'test.com', 'domain.com', '.png', '.jpg', '.gif']):
                            emails.append({
                                'email': email.lower(),
                                'source': url
                            })
        except Exception:
            pass
        return emails
    
    def generate_google_dorks(self, domain: str) -> list:
        """Generate Google dork queries for email discovery."""
        dorks = [
            f'site:{domain} "@{domain}"',
            f'site:{domain} "email" OR "contact"',
            f'"@{domain}" -site:{domain}',
            f'site:linkedin.com "@{domain}"',
            f'site:github.com "@{domain}"',
            f'filetype:pdf "@{domain}"',
            f'filetype:doc "@{domain}"',
            f'filetype:xls "@{domain}"',
        ]
        return [{'query': d, 'url': f"https://www.google.com/search?q={quote(d)}"} for d in dorks]
    
    def detect_email_pattern(self, emails: list, domain: str) -> dict:
        """Detect the email naming pattern used by the organization."""
        patterns = {
            'first.last': 0,
            'f.last': 0,
            'first_last': 0,
            'firstlast': 0,
            'first': 0,
            'last.first': 0,
            'flast': 0,
            'lastf': 0,
            'unknown': 0
        }
        
        for email_data in emails:
            email = email_data.get('email', '')
            first = email_data.get('first_name', '').lower()
            last = email_data.get('last_name', '').lower()
            
            if not first or not last:
                patterns['unknown'] += 1
                continue
            
            local = email.split('@')[0].lower()
            
            if local == f"{first}.{last}":
                patterns['first.last'] += 1
            elif local == f"{first[0]}.{last}":
                patterns['f.last'] += 1
            elif local == f"{first}_{last}":
                patterns['first_last'] += 1
            elif local == f"{first}{last}":
                patterns['firstlast'] += 1
            elif local == first:
                patterns['first'] += 1
            elif local == f"{last}.{first}":
                patterns['last.first'] += 1
            elif local == f"{first[0]}{last}":
                patterns['flast'] += 1
            elif local == f"{last}{first[0]}":
                patterns['lastf'] += 1
            else:
                patterns['unknown'] += 1
        
        # Find most common pattern
        most_common = max(patterns.items(), key=lambda x: x[1])
        return {
            'detected_pattern': most_common[0] if most_common[1] > 0 else 'unknown',
            'confidence': most_common[1],
            'all_patterns': patterns
        }
    
    async def harvest_async(self, target: str, hosts: list, output_dir: str) -> dict:
        """Harvest emails from multiple sources."""
        learn("Email Harvesting",
              "We're collecting email addresses associated with the target:\n"
              "• Hunter.io API - professional email finder\n"
              "• Website scraping - emails on web pages\n"
              "• Google dorks - emails indexed by Google\n\n"
              "This helps with:\n"
              "• Understanding organization structure\n"
              "• Finding email naming patterns\n"
              "• Social engineering scope (if allowed)",
              self.learn_mode)
        
        info(f"Harvesting emails for {target}...")
        
        results = {
            'target': target,
            'emails': [],
            'unique_emails': set(),
            'email_pattern': None,
            'google_dorks': [],
            'by_source': {}
        }
        
        async with aiohttp.ClientSession() as session:
            # Hunter.io search
            if self.hunter_api_key:
                info("  Searching Hunter.io...")
                hunter_emails = await self.search_hunter(session, target)
                for email in hunter_emails:
                    results['emails'].append(email)
                    results['unique_emails'].add(email['email'])
                if hunter_emails:
                    success(f"  Hunter.io found {len(hunter_emails)} emails")
            else:
                info("  No Hunter.io API key (add hunter.api_key to config)")
            
            # Scrape websites
            info("  Scraping websites for emails...")
            pages_to_scrape = [
                f"https://{target}",
                f"https://{target}/contact",
                f"https://{target}/about",
                f"https://{target}/team",
                f"https://www.{target}",
            ]
            
            # Add alive hosts
            for host in hosts[:10]:
                pages_to_scrape.append(f"https://{host}")
            
            for url in pages_to_scrape:
                scraped = await self.scrape_website(session, url)
                for email in scraped:
                    if email['email'] not in results['unique_emails']:
                        # Only include emails from target domain
                        if target in email['email']:
                            results['emails'].append(email)
                            results['unique_emails'].add(email['email'])
        
        # Generate Google dorks
        results['google_dorks'] = self.generate_google_dorks(target)
        
        # Detect email pattern
        if results['emails']:
            results['email_pattern'] = self.detect_email_pattern(results['emails'], target)
        
        # Convert set to list for JSON
        results['unique_emails'] = list(results['unique_emails'])
        
        # Report findings
        success(f"Found {len(results['unique_emails'])} unique emails")
        
        if results['email_pattern']:
            pattern = results['email_pattern']['detected_pattern']
            if pattern != 'unknown':
                info(f"Detected email pattern: {pattern}@{target}")
        
        info(f"Generated {len(results['google_dorks'])} Google dork queries")
        
        # Save results
        import json
        output_file = Path(output_dir) / f"emails_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save emails list
        if results['unique_emails']:
            emails_file = Path(output_dir) / "emails.txt"
            with open(emails_file, 'w') as f:
                f.write('\n'.join(sorted(results['unique_emails'])))
        
        return results
    
    def harvest(self, target: str, hosts: list, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.harvest_async(target, hosts, output_dir))
