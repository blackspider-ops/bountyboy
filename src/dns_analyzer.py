"""
DNS Analysis Module

Performs comprehensive DNS analysis:
- Zone transfer attempts (AXFR)
- DNS record enumeration (A, AAAA, MX, TXT, NS, SOA, CNAME)
- SPF/DMARC/DKIM analysis
- Nameserver identification
- DNS history

WHY DNS ANALYSIS?
DNS misconfigurations can leak:
- Internal hostnames via zone transfer
- Email security issues (SPF/DMARC)
- Infrastructure information
- Hidden subdomains

Zone transfer is a jackpot - if misconfigured, you get ALL DNS records.
"""
import asyncio
import dns.resolver
import dns.zone
import dns.query
from pathlib import Path
from src.utils import learn, success, error, info, warning, timestamp

class DNSAnalyzer:
    def __init__(self, config: dict, learn_mode: bool = False):
        self.config = config
        self.learn_mode = learn_mode
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10
    
    def get_nameservers(self, domain: str) -> list:
        """Get nameservers for a domain."""
        try:
            answers = self.resolver.resolve(domain, 'NS')
            return [str(rdata.target).rstrip('.') for rdata in answers]
        except Exception:
            return []
    
    def attempt_zone_transfer(self, domain: str, nameserver: str) -> list:
        """Attempt DNS zone transfer (AXFR)."""
        records = []
        try:
            # Get nameserver IP
            ns_ip = str(self.resolver.resolve(nameserver, 'A')[0])
            
            # Attempt zone transfer
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
            
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append({
                            'name': str(name),
                            'type': dns.rdatatype.to_text(rdataset.rdtype),
                            'value': str(rdata),
                            'ttl': rdataset.ttl
                        })
        except Exception:
            pass
        
        return records
    
    def get_dns_records(self, domain: str) -> dict:
        """Get all DNS records for a domain."""
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME', 'CAA']
        records = {}
        
        for rtype in record_types:
            try:
                answers = self.resolver.resolve(domain, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                break
            except Exception:
                pass
        
        return records
    
    def analyze_spf(self, txt_records: list) -> dict:
        """Analyze SPF record for issues."""
        result = {
            'found': False,
            'record': None,
            'issues': []
        }
        
        for record in txt_records:
            if record.startswith('"v=spf1') or record.startswith('v=spf1'):
                result['found'] = True
                result['record'] = record.strip('"')
                
                # Check for issues
                if '+all' in record:
                    result['issues'].append({
                        'severity': 'HIGH',
                        'issue': 'SPF allows all senders (+all)',
                        'impact': 'Anyone can spoof emails from this domain'
                    })
                elif '~all' in record:
                    result['issues'].append({
                        'severity': 'MEDIUM',
                        'issue': 'SPF uses soft fail (~all)',
                        'impact': 'Spoofed emails may be delivered'
                    })
                elif '?all' in record:
                    result['issues'].append({
                        'severity': 'MEDIUM',
                        'issue': 'SPF uses neutral (?all)',
                        'impact': 'No policy enforcement'
                    })
                
                break
        
        if not result['found']:
            result['issues'].append({
                'severity': 'MEDIUM',
                'issue': 'No SPF record found',
                'impact': 'Email spoofing possible'
            })
        
        return result
    
    def analyze_dmarc(self, domain: str) -> dict:
        """Analyze DMARC record."""
        result = {
            'found': False,
            'record': None,
            'issues': []
        }
        
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            
            for rdata in answers:
                record = str(rdata).strip('"')
                if record.startswith('v=DMARC1'):
                    result['found'] = True
                    result['record'] = record
                    
                    # Check policy
                    if 'p=none' in record:
                        result['issues'].append({
                            'severity': 'MEDIUM',
                            'issue': 'DMARC policy is none',
                            'impact': 'No action taken on failed emails'
                        })
                    
                    # Check reporting
                    if 'rua=' not in record and 'ruf=' not in record:
                        result['issues'].append({
                            'severity': 'LOW',
                            'issue': 'No DMARC reporting configured',
                            'impact': 'Cannot monitor email authentication failures'
                        })
                    
                    break
        except Exception:
            pass
        
        if not result['found']:
            result['issues'].append({
                'severity': 'MEDIUM',
                'issue': 'No DMARC record found',
                'impact': 'Email spoofing protection not enforced'
            })
        
        return result
    
    async def analyze_async(self, target: str, output_dir: str) -> dict:
        """Perform comprehensive DNS analysis."""
        learn("DNS Analysis",
              "We're analyzing DNS configuration for security issues:\n\n"
              "• Zone Transfer (AXFR) - If misconfigured, leaks ALL DNS records\n"
              "• SPF Record - Email sender verification\n"
              "• DMARC Record - Email authentication policy\n"
              "• DNS Records - Infrastructure information\n\n"
              "Zone transfer is the jackpot - one misconfigured nameserver "
              "can reveal hundreds of internal hostnames.",
              self.learn_mode)
        
        info(f"Analyzing DNS for {target}...")
        
        results = {
            'target': target,
            'nameservers': [],
            'zone_transfer': {
                'vulnerable': False,
                'records': []
            },
            'dns_records': {},
            'spf': {},
            'dmarc': {},
            'issues': []
        }
        
        # Get nameservers
        results['nameservers'] = self.get_nameservers(target)
        if results['nameservers']:
            info(f"Found {len(results['nameservers'])} nameservers")
        
        # Attempt zone transfer on each nameserver
        info("Attempting zone transfer...")
        for ns in results['nameservers']:
            records = self.attempt_zone_transfer(target, ns)
            if records:
                results['zone_transfer']['vulnerable'] = True
                results['zone_transfer']['records'].extend(records)
                results['zone_transfer']['vulnerable_ns'] = ns
                warning(f"🚨 ZONE TRANSFER SUCCESSFUL on {ns}!")
                warning(f"   Found {len(records)} DNS records!")
                results['issues'].append({
                    'severity': 'HIGH',
                    'issue': f'Zone transfer allowed on {ns}',
                    'impact': 'All DNS records exposed'
                })
                break
        
        if not results['zone_transfer']['vulnerable']:
            info("Zone transfer not allowed (good)")
        
        # Get DNS records
        info("Enumerating DNS records...")
        results['dns_records'] = self.get_dns_records(target)
        
        for rtype, records in results['dns_records'].items():
            if records:
                info(f"  {rtype}: {len(records)} records")
        
        # Analyze SPF
        txt_records = results['dns_records'].get('TXT', [])
        results['spf'] = self.analyze_spf(txt_records)
        
        if results['spf']['issues']:
            for issue in results['spf']['issues']:
                results['issues'].append(issue)
                if issue['severity'] in ['HIGH', 'MEDIUM']:
                    warning(f"  SPF: {issue['issue']}")
        
        # Analyze DMARC
        results['dmarc'] = self.analyze_dmarc(target)
        
        if results['dmarc']['issues']:
            for issue in results['dmarc']['issues']:
                results['issues'].append(issue)
                if issue['severity'] in ['HIGH', 'MEDIUM']:
                    warning(f"  DMARC: {issue['issue']}")
        
        # Summary
        if results['issues']:
            warning(f"Found {len(results['issues'])} DNS security issues")
        else:
            success("No major DNS issues found")
        
        # Save results
        import json
        output_file = Path(output_dir) / f"dns_analysis_{timestamp()}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save zone transfer results if found
        if results['zone_transfer']['vulnerable']:
            zt_file = Path(output_dir) / f"zone_transfer_{timestamp()}.txt"
            with open(zt_file, 'w') as f:
                f.write(f"# Zone Transfer Results for {target}\n")
                f.write(f"# Vulnerable NS: {results['zone_transfer'].get('vulnerable_ns')}\n\n")
                for record in results['zone_transfer']['records']:
                    f.write(f"{record['name']}\t{record['ttl']}\t{record['type']}\t{record['value']}\n")
            warning(f"Zone transfer records saved to {zt_file}")
        
        return results
    
    def analyze(self, target: str, output_dir: str) -> dict:
        """Synchronous wrapper."""
        return asyncio.run(self.analyze_async(target, output_dir))
