"""
Google Dorking Module

Generates Google dork queries to find:
- Exposed files (PDFs, docs, configs)
- Login pages and admin panels
- Sensitive directories
- Database dumps
- Error messages with info disclosure
- Subdomains indexed by Google

WHY GOOGLE DORKING?
Google indexes EVERYTHING. Companies accidentally expose:
- Internal documents
- Config files with credentials
- Backup files
- Admin panels
- Error pages revealing stack traces

Google dorks are search queries that find these exposed assets.
"""
from pathlib import Path
from urllib.parse import quote
from src.utils import learn, success, info, warning, timestamp

class GoogleDorker:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        
        # Google dork templates
        self.dorks = {
            'sensitive_files': [
                'site:{target} filetype:pdf',
                'site:{target} filetype:doc OR filetype:docx',
                'site:{target} filetype:xls OR filetype:xlsx',
                'site:{target} filetype:ppt OR filetype:pptx',
                'site:{target} filetype:txt',
                'site:{target} filetype:log',
                'site:{target} filetype:sql',
                'site:{target} filetype:xml',
                'site:{target} filetype:json',
                'site:{target} filetype:csv',
                'site:{target} filetype:bak',
                'site:{target} filetype:old',
                'site:{target} filetype:conf',
                'site:{target} filetype:config',
                'site:{target} filetype:env',
            ],
            'config_files': [
                'site:{target} inurl:config',
                'site:{target} inurl:configuration',
                'site:{target} inurl:settings',
                'site:{target} inurl:setup',
                'site:{target} intitle:"index of" "config"',
                'site:{target} ext:xml inurl:config',
                'site:{target} ext:yml OR ext:yaml',
                'site:{target} ext:ini',
                'site:{target} ext:env',
                'site:{target} "DB_PASSWORD"',
                'site:{target} "database_password"',
                'site:{target} "mysql_password"',
            ],
            'admin_panels': [
                'site:{target} inurl:admin',
                'site:{target} inurl:administrator',
                'site:{target} inurl:login',
                'site:{target} inurl:signin',
                'site:{target} inurl:dashboard',
                'site:{target} inurl:portal',
                'site:{target} inurl:cpanel',
                'site:{target} inurl:wp-admin',
                'site:{target} inurl:phpmyadmin',
                'site:{target} intitle:"admin" OR intitle:"login"',
                'site:{target} intitle:"dashboard"',
                'site:{target} inurl:manage',
                'site:{target} inurl:management',
            ],
            'exposed_directories': [
                'site:{target} intitle:"index of"',
                'site:{target} intitle:"directory listing"',
                'site:{target} intitle:"index of" "backup"',
                'site:{target} intitle:"index of" "database"',
                'site:{target} intitle:"index of" "password"',
                'site:{target} intitle:"index of" ".git"',
                'site:{target} intitle:"index of" "wp-content"',
                'site:{target} intitle:"index of" "uploads"',
            ],
            'error_messages': [
                'site:{target} "sql syntax" OR "mysql error"',
                'site:{target} "ORA-" error',
                'site:{target} "PostgreSQL" error',
                'site:{target} "Warning: mysql"',
                'site:{target} "Fatal error" filetype:php',
                'site:{target} "Parse error" filetype:php',
                'site:{target} "stack trace"',
                'site:{target} "exception" "at line"',
                'site:{target} inurl:debug',
                'site:{target} "DEBUG = True"',
            ],
            'sensitive_info': [
                'site:{target} "password" filetype:txt',
                'site:{target} "username" "password" filetype:log',
                'site:{target} "api_key" OR "apikey"',
                'site:{target} "secret_key" OR "secretkey"',
                'site:{target} "access_token"',
                'site:{target} "private_key"',
                'site:{target} "BEGIN RSA PRIVATE KEY"',
                'site:{target} "AWS_ACCESS_KEY"',
                'site:{target} inurl:credentials',
                'site:{target} inurl:secret',
            ],
            'backup_files': [
                'site:{target} filetype:bak',
                'site:{target} filetype:backup',
                'site:{target} filetype:old',
                'site:{target} filetype:save',
                'site:{target} filetype:swp',
                'site:{target} filetype:tar',
                'site:{target} filetype:tar.gz',
                'site:{target} filetype:zip inurl:backup',
                'site:{target} filetype:sql inurl:backup',
                'site:{target} "backup" ext:sql',
            ],
            'api_endpoints': [
                'site:{target} inurl:api',
                'site:{target} inurl:/api/v1',
                'site:{target} inurl:/api/v2',
                'site:{target} inurl:graphql',
                'site:{target} inurl:swagger',
                'site:{target} inurl:api-docs',
                'site:{target} inurl:rest',
                'site:{target} filetype:json inurl:api',
                'site:{target} "swagger" OR "openapi"',
            ],
            'subdomains': [
                'site:*.{target}',
                'site:*.*.{target}',
                '-site:www.{target} site:{target}',
            ],
            'external_exposure': [
                '"{target}" site:pastebin.com',
                '"{target}" site:github.com',
                '"{target}" site:gitlab.com',
                '"{target}" site:trello.com',
                '"{target}" site:stackoverflow.com',
                '"{target}" site:jsfiddle.net',
                '"{target}" site:codepen.io',
            ]
        }
    
    def generate_dorks(self, target: str) -> dict:
        """Generate all Google dork URLs for a target."""
        results = {}
        
        for category, dork_templates in self.dorks.items():
            results[category] = []
            for template in dork_templates:
                query = template.replace('{target}', target)
                url = f"https://www.google.com/search?q={quote(query)}"
                results[category].append({
                    'query': query,
                    'url': url
                })
        
        return results
    
    def analyze(self, target: str, output_dir: str) -> dict:
        """Generate Google dork queries for a target."""
        learn("Google Dorking",
              "Google indexes everything - including things companies don't want public. "
              "We generate special search queries (dorks) to find:\n"
              "• Exposed config files with credentials\n"
              "• Backup files and database dumps\n"
              "• Admin panels and login pages\n"
              "• Error messages revealing internals\n"
              "• API documentation\n\n"
              "Open these URLs in your browser to search manually.",
              self.learn_mode)
        
        info(f"Generating Google dorks for {target}...")
        
        dorks = self.generate_dorks(target)
        
        total_dorks = sum(len(d) for d in dorks.values())
        success(f"Generated {total_dorks} Google dork queries")
        
        for category, queries in dorks.items():
            info(f"  {category}: {len(queries)} queries")
        
        # Save to file
        output_file = Path(output_dir) / f"google_dorks_{timestamp()}.txt"
        with open(output_file, 'w') as f:
            f.write(f"# Google Dorks for {target}\n")
            f.write(f"# Generated: {timestamp()}\n")
            f.write("# Open these URLs in your browser\n\n")
            
            for category, queries in dorks.items():
                f.write(f"\n{'='*60}\n")
                f.write(f"# {category.upper().replace('_', ' ')}\n")
                f.write(f"{'='*60}\n\n")
                
                for dork in queries:
                    f.write(f"Query: {dork['query']}\n")
                    f.write(f"URL: {dork['url']}\n\n")
        
        info(f"Saved to {output_file}")
        warning("⚠️  Open URLs in browser manually (Google blocks automated requests)")
        
        return {
            'target': target,
            'total_dorks': total_dorks,
            'dorks': dorks,
            'output_file': str(output_file)
        }
