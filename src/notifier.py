"""
Notification Module

Send alerts when interesting things are found:
- New subdomains discovered
- Vulnerabilities detected
- Interesting ports found

WHY NOTIFICATIONS?
Your automation runs 24/7. You can't watch it constantly.
Notifications let you know immediately when something interesting happens.
New subdomain at 3am? You get a ping. Critical vuln found? Instant alert.
"""
import json
import requests
from src.utils import info, success, error

class Notifier:
    def __init__(self, config: dict):
        self.config = config['notifications']
        self.enabled = self.config.get('enabled', False)
    
    def send(self, title: str, message: str, severity: str = "info"):
        """Send notification through configured channels."""
        if not self.enabled:
            return
        
        # Discord
        if self.config.get('discord_webhook'):
            self._send_discord(title, message, severity)
        
        # Slack
        if self.config.get('slack_webhook'):
            self._send_slack(title, message, severity)
    
    def _send_discord(self, title: str, message: str, severity: str):
        """Send Discord webhook notification."""
        colors = {
            'critical': 0xFF0000,  # Red
            'high': 0xFF6600,      # Orange
            'medium': 0xFFFF00,    # Yellow
            'info': 0x00FF00,      # Green
            'new': 0x00FFFF        # Cyan
        }
        
        payload = {
            "embeds": [{
                "title": f"🎯 {title}",
                "description": message,
                "color": colors.get(severity, 0x00FF00)
            }]
        }
        
        try:
            resp = requests.post(
                self.config['discord_webhook'],
                json=payload,
                timeout=10
            )
            if resp.status_code == 204:
                success("Discord notification sent")
            else:
                error(f"Discord notification failed: {resp.status_code}")
        except Exception as e:
            error(f"Discord notification error: {e}")
    
    def _send_slack(self, title: str, message: str, severity: str):
        """Send Slack webhook notification."""
        emoji = {
            'critical': '🚨',
            'high': '⚠️',
            'medium': '📢',
            'info': 'ℹ️',
            'new': '🆕'
        }
        
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji.get(severity, 'ℹ️')} {title}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": message
                    }
                }
            ]
        }
        
        try:
            resp = requests.post(
                self.config['slack_webhook'],
                json=payload,
                timeout=10
            )
            if resp.status_code == 200:
                success("Slack notification sent")
            else:
                error(f"Slack notification failed: {resp.status_code}")
        except Exception as e:
            error(f"Slack notification error: {e}")
    
    def notify_new_subdomains(self, target: str, subdomains: list):
        """Send notification about new subdomains."""
        if not subdomains:
            return
        
        message = f"**Target:** {target}\n"
        message += f"**Count:** {len(subdomains)} new subdomains\n\n"
        message += "**New subdomains:**\n"
        for sub in subdomains[:10]:  # Limit to 10
            message += f"• {sub}\n"
        if len(subdomains) > 10:
            message += f"... and {len(subdomains) - 10} more"
        
        self.send("New Subdomains Found!", message, "new")
    
    def notify_vulnerability(self, finding: dict):
        """Send notification about vulnerability found."""
        severity = finding.get('info', {}).get('severity', 'unknown')
        name = finding.get('info', {}).get('name', 'Unknown Vulnerability')
        host = finding.get('host', 'Unknown host')
        
        message = f"**Vulnerability:** {name}\n"
        message += f"**Severity:** {severity.upper()}\n"
        message += f"**Host:** {host}\n"
        
        if finding.get('matched-at'):
            message += f"**URL:** {finding['matched-at']}\n"
        
        self.send(f"Vulnerability Found: {name}", message, severity)
    
    def notify_interesting_port(self, host: str, port: str, service: str):
        """Send notification about interesting port found."""
        message = f"**Host:** {host}\n"
        message += f"**Port:** {port}\n"
        message += f"**Service:** {service}\n"
        
        self.send(f"Interesting Port: {host}:{port}", message, "info")
    
    def notify_scan_complete(self, target: str, summary: dict):
        """Send notification when scan completes."""
        message = f"**Target:** {target}\n"
        message += f"**Subdomains:** {summary.get('total_subdomains', 0)}\n"
        message += f"**New subdomains:** {summary.get('new_subdomains', 0)}\n"
        message += f"**Alive hosts:** {summary.get('alive_hosts', 0)}\n"
        message += f"**Vulnerabilities:** {summary.get('vulnerabilities', 0)}\n"
        
        self.send("Scan Complete", message, "info")
