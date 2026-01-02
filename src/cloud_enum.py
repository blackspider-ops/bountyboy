"""
Cloud Storage Enumeration Module

Finds exposed cloud storage buckets and blobs:
- AWS S3 buckets
- Azure Blob Storage
- Google Cloud Storage
- DigitalOcean Spaces

WHY CLOUD ENUMERATION?
Companies often misconfigure cloud storage:
- Public buckets with sensitive data
- Backup files exposed
- Database dumps
- Source code
- Customer data

This is often CRITICAL severity - data breaches pay big bounties.
"""
import asyncio
import aiohttp
from pathlib import Path
from src.utils import learn, success, error, info, warning, timestamp

class CloudEnumerator:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        
        # Common bucket name patterns
        self.patterns = [
            '{target}',
            '{target}-backup',
            '{target}-backups',
            '{target}-data',
            '{target}-files',
            '{target}-assets',
            '{target}-static',
            '{target}-media',
            '{target}-uploads',
            '{target}-images',
            '{target}-docs',
            '{target}-documents',
            '{target}-dev',
            '{target}-development',
            '{target}-staging',
            '{target}-prod',
            '{target}-production',
            '{target}-test',
            '{target}-testing',
            '{target}-logs',
            '{target}-db',
            '{target}-database',
            '{target}-private',
            '{target}-public',
            '{target}-internal',
            '{target}-external',
            '{target}-api',
            '{target}-app',
            '{target}-web',
            '{target}-cdn',
            '{target}-storage',
            '{target}-archive',
            'backup-{target}',
            'backups-{target}',
            'data-{target}',
            'files-{target}',
            '{keyword}-{target}',
            '{target}-{keyword}',
        ]
        
        self.keywords = ['backup', 'data', 'dev', 'prod', 'staging', 'test', 'logs', 'db']
    
    def generate_bucket_names(self, target: str) -> list:
        """Generate potential bucket names based on target."""
        # Clean target name
        clean_target = target.replace('.', '-').replace('_', '-').lower()
        short_target = clean_target.split('-')[0]  # First part only
        
        names = set()
        
        for pattern in self.patterns:
            if '{keyword}' in pattern:
                for keyword in self.keywords:
                    name = pattern.replace('{target}', clean_target).replace('{keyword}', keyword)
                    names.add(name)
                    name = pattern.replace('{target}', short_target).replace('{keyword}', keyword)
                    names.add(name)
            else:
                name = pattern.replace('{target}', clean_target)
                names.add(name)
                name = pattern.replace('{target}', short_target)
                names.add(name)
        
        return list(names)
    
    async def check_s3_bucket(self, session: aiohttp.ClientSession, bucket: str) -> dict | None:
        """Check if an S3 bucket exists and is accessible."""
        urls = [
            f"https://{bucket}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket}",
        ]
        
        for url in urls:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5),
                                       ssl=False) as resp:
                    
                    if resp.status == 200:
                        # Bucket exists and is public!
                        return {
                            'bucket': bucket,
                            'provider': 'AWS S3',
                            'url': url,
                            'status': 'PUBLIC',
                            'severity': 'HIGH'
                        }
                    elif resp.status == 403:
                        # Bucket exists but access denied
                        return {
                            'bucket': bucket,
                            'provider': 'AWS S3',
                            'url': url,
                            'status': 'EXISTS (Access Denied)',
                            'severity': 'INFO'
                        }
                    elif resp.status == 404:
                        # Check if it's a "bucket not found" vs "key not found"
                        text = await resp.text()
                        if 'NoSuchBucket' not in text:
                            return {
                                'bucket': bucket,
                                'provider': 'AWS S3',
                                'url': url,
                                'status': 'EXISTS (Empty or No Index)',
                                'severity': 'LOW'
                            }
            except:
                pass
        
        return None
    
    async def check_azure_blob(self, session: aiohttp.ClientSession, container: str) -> dict | None:
        """Check if an Azure blob container exists."""
        # Azure uses account.blob.core.windows.net/container format
        # We'll check common patterns
        url = f"https://{container}.blob.core.windows.net/?comp=list"
        
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    return {
                        'bucket': container,
                        'provider': 'Azure Blob',
                        'url': url,
                        'status': 'PUBLIC',
                        'severity': 'HIGH'
                    }
                elif resp.status == 403:
                    return {
                        'bucket': container,
                        'provider': 'Azure Blob',
                        'url': url,
                        'status': 'EXISTS (Access Denied)',
                        'severity': 'INFO'
                    }
        except:
            pass
        
        return None
    
    async def check_gcp_bucket(self, session: aiohttp.ClientSession, bucket: str) -> dict | None:
        """Check if a GCP bucket exists."""
        url = f"https://storage.googleapis.com/{bucket}"
        
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    return {
                        'bucket': bucket,
                        'provider': 'Google Cloud Storage',
                        'url': url,
                        'status': 'PUBLIC',
                        'severity': 'HIGH'
                    }
                elif resp.status == 403:
                    return {
                        'bucket': bucket,
                        'provider': 'Google Cloud Storage',
                        'url': url,
                        'status': 'EXISTS (Access Denied)',
                        'severity': 'INFO'
                    }
        except:
            pass
        
        return None
    
    async def check_do_spaces(self, session: aiohttp.ClientSession, space: str) -> dict | None:
        """Check if a DigitalOcean Space exists."""
        # DO Spaces use region-specific URLs
        regions = ['nyc3', 'sfo2', 'sfo3', 'ams3', 'sgp1', 'fra1']
        
        for region in regions:
            url = f"https://{space}.{region}.digitaloceanspaces.com"
            
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        return {
                            'bucket': space,
                            'provider': 'DigitalOcean Spaces',
                            'url': url,
                            'status': 'PUBLIC',
                            'severity': 'HIGH'
                        }
                    elif resp.status == 403:
                        return {
                            'bucket': space,
                            'provider': 'DigitalOcean Spaces',
                            'url': url,
                            'status': 'EXISTS (Access Denied)',
                            'severity': 'INFO'
                        }
            except:
                pass
        
        return None
    
    async def enumerate_async(self, target: str, output_dir: str) -> dict:
        """Enumerate cloud storage for a target."""
        learn("Cloud Storage Enumeration",
              "We're checking for exposed cloud storage buckets. "
              "Companies often misconfigure these:\n"
              "• AWS S3 buckets left public\n"
              "• Azure Blob containers without auth\n"
              "• GCP buckets with public access\n\n"
              "What we might find:\n"
              "• Database backups\n"
              "• Source code\n"
              "• Customer data\n"
              "• API keys and credentials\n\n"
              "This is often CRITICAL severity!",
              self.learn_mode)
        
        info(f"Enumerating cloud storage for {target}...")
        
        bucket_names = self.generate_bucket_names(target)
        info(f"Generated {len(bucket_names)} potential bucket names")
        
        results = {
            'target': target,
            'buckets_checked': len(bucket_names),
            'found': [],
            'public': [],
            'by_provider': {
                'AWS S3': [],
                'Azure Blob': [],
                'Google Cloud Storage': [],
                'DigitalOcean Spaces': []
            }
        }
        
        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(30)
            
            async def check_all_providers(name):
                async with semaphore:
                    findings = []
                    
                    # Check S3
                    s3 = await self.check_s3_bucket(session, name)
                    if s3:
                        findings.append(s3)
                    
                    # Check Azure
                    azure = await self.check_azure_blob(session, name)
                    if azure:
                        findings.append(azure)
                    
                    # Check GCP
                    gcp = await self.check_gcp_bucket(session, name)
                    if gcp:
                        findings.append(gcp)
                    
                    # Check DO Spaces
                    do = await self.check_do_spaces(session, name)
                    if do:
                        findings.append(do)
                    
                    return findings
            
            tasks = [check_all_providers(name) for name in bucket_names]
            all_findings = await asyncio.gather(*tasks, return_exceptions=True)
            
            for findings in all_findings:
                if isinstance(findings, list):
                    for finding in findings:
                        results['found'].append(finding)
                        results['by_provider'][finding['provider']].append(finding)
                        
                        if finding['status'] == 'PUBLIC':
                            results['public'].append(finding)
        
        # Report findings
        if results['public']:
            warning(f"🚨 Found {len(results['public'])} PUBLIC buckets!")
            for bucket in results['public']:
                warning(f"  [{bucket['severity']}] {bucket['provider']}: {bucket['url']}")
        
        if results['found']:
            info(f"Found {len(results['found'])} total buckets/containers")
            for provider, buckets in results['by_provider'].items():
                if buckets:
                    info(f"  {provider}: {len(buckets)}")
        else:
            info("No cloud storage found")
        
        # Save results
        import json
        output_file = Path(output_dir) / f"cloud_enum_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def enumerate(self, target: str, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.enumerate_async(target, output_dir))
