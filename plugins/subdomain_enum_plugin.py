#!/usr/bin/env python3
"""
Subdomain Enumeration Plugin for O-Hunter
Discovers subdomains using various techniques
"""

import requests
import socket
import dns.resolver
import sys
import os
from urllib.parse import urlparse
import concurrent.futures
import time

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.plugin_system import PluginBase

class SubdomainEnumPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "SubdomainEnumPlugin"
        self.version = "1.0.0"
        self.author = "O-Hunter Team"
        self.description = "Discovers subdomains using DNS enumeration and common wordlists"
        self.category = "Reconnaissance"
        
        # Common subdomain wordlist
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'test', 'staging',
            'dev', 'api', 'admin', 'blog', 'shop', 'forum', 'support', 'help', 'docs',
            'cdn', 'static', 'assets', 'img', 'images', 'css', 'js', 'media', 'files',
            'download', 'uploads', 'secure', 'ssl', 'vpn', 'remote', 'demo', 'beta',
            'alpha', 'preview', 'mobile', 'm', 'wap', 'app', 'apps', 'service', 'services',
            'portal', 'dashboard', 'panel', 'control', 'manage', 'manager', 'login',
            'signin', 'signup', 'register', 'account', 'accounts', 'user', 'users',
            'client', 'clients', 'customer', 'customers', 'partner', 'partners',
            'affiliate', 'affiliates', 'reseller', 'resellers', 'vendor', 'vendors'
        ]
    
    def resolve_subdomain(self, subdomain):
        """
        Resolve a subdomain to check if it exists
        
        Args:
            subdomain (str): Subdomain to resolve
            
        Returns:
            dict: Resolution result
        """
        try:
            # Try to resolve the subdomain
            result = socket.gethostbyname(subdomain)
            return {
                'subdomain': subdomain,
                'ip': result,
                'exists': True,
                'error': None
            }
        except socket.gaierror:
            return {
                'subdomain': subdomain,
                'ip': None,
                'exists': False,
                'error': 'DNS resolution failed'
            }
        except Exception as e:
            return {
                'subdomain': subdomain,
                'ip': None,
                'exists': False,
                'error': str(e)
            }
    
    def check_subdomain_http(self, subdomain):
        """
        Check if subdomain responds to HTTP requests
        
        Args:
            subdomain (str): Subdomain to check
            
        Returns:
            dict: HTTP check result
        """
        protocols = ['https', 'http']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{subdomain}"
                response = requests.get(url, timeout=5, allow_redirects=True)
                
                return {
                    'subdomain': subdomain,
                    'url': url,
                    'status_code': response.status_code,
                    'accessible': True,
                    'protocol': protocol,
                    'title': self.extract_title(response.text),
                    'server': response.headers.get('Server', 'Unknown')
                }
                
            except requests.exceptions.RequestException:
                continue
        
        return {
            'subdomain': subdomain,
            'url': None,
            'status_code': None,
            'accessible': False,
            'protocol': None,
            'title': None,
            'server': None
        }
    
    def extract_title(self, html_content):
        """Extract title from HTML content"""
        try:
            start = html_content.lower().find('<title>')
            if start == -1:
                return None
            
            start += 7  # Length of '<title>'
            end = html_content.lower().find('</title>', start)
            if end == -1:
                return None
            
            title = html_content[start:end].strip()
            return title[:100] if len(title) > 100 else title
        except:
            return None
    
    def enumerate_subdomains_dns(self, domain, wordlist=None):
        """
        Enumerate subdomains using DNS resolution
        
        Args:
            domain (str): Target domain
            wordlist (list): List of subdomain names to try
            
        Returns:
            list: Found subdomains
        """
        if not wordlist:
            wordlist = self.common_subdomains
        
        found_subdomains = []
        
        # Use ThreadPoolExecutor for concurrent DNS resolution
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            # Create subdomain candidates
            subdomain_candidates = [f"{sub}.{domain}" for sub in wordlist]
            
            # Submit resolution tasks
            future_to_subdomain = {
                executor.submit(self.resolve_subdomain, subdomain): subdomain 
                for subdomain in subdomain_candidates
            }
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result['exists']:
                    found_subdomains.append(result)
        
        return found_subdomains
    
    def check_zone_transfer(self, domain):
        """
        Check for DNS zone transfer vulnerability
        
        Args:
            domain (str): Target domain
            
        Returns:
            dict: Zone transfer check result
        """
        try:
            # Get NS records
            ns_records = dns.resolver.resolve(domain, 'NS')
            
            for ns in ns_records:
                ns_server = str(ns).rstrip('.')
                
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain))
                    
                    # If we get here, zone transfer was successful
                    subdomains = []
                    for name, node in zone.nodes.items():
                        subdomain = f"{name}.{domain}" if name != '@' else domain
                        subdomains.append(subdomain)
                    
                    return {
                        'vulnerable': True,
                        'ns_server': ns_server,
                        'subdomains': subdomains[:50],  # Limit to first 50
                        'total_records': len(subdomains)
                    }
                    
                except Exception:
                    continue
            
            return {
                'vulnerable': False,
                'ns_server': None,
                'subdomains': [],
                'total_records': 0
            }
            
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'ns_server': None,
                'subdomains': [],
                'total_records': 0
            }
    
    def scan(self, target_url, params=None):
        """
        Main scan method for subdomain enumeration
        
        Args:
            target_url (str): Target URL to scan
            params (dict): Plugin parameters
            
        Returns:
            list: List of findings
        """
        findings = []
        
        try:
            # Extract domain from URL
            parsed_url = urlparse(target_url)
            domain = parsed_url.netloc
            
            if not domain:
                finding = self.create_finding(
                    vulnerability="Invalid Target URL",
                    severity="Low",
                    evidence=f"Could not extract domain from {target_url}",
                    remediation="Provide a valid URL with domain name"
                )
                findings.append(finding)
                return findings
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Check for zone transfer vulnerability
            zone_transfer_result = self.check_zone_transfer(domain)
            
            if zone_transfer_result['vulnerable']:
                finding = self.create_finding(
                    vulnerability="DNS Zone Transfer Vulnerability",
                    severity="High",
                    evidence=f"DNS zone transfer allowed on {zone_transfer_result['ns_server']} for domain {domain}. Found {zone_transfer_result['total_records']} DNS records.",
                    remediation="Configure DNS servers to restrict zone transfers to authorized servers only"
                )
                findings.append(finding)
                
                # Add subdomains found via zone transfer
                for subdomain in zone_transfer_result['subdomains'][:10]:  # Show first 10
                    finding = self.create_finding(
                        vulnerability="Subdomain Discovered via Zone Transfer",
                        severity="Medium",
                        evidence=f"Subdomain found: {subdomain}",
                        remediation="Review exposed subdomains and ensure proper access controls"
                    )
                    findings.append(finding)
            
            # Perform DNS enumeration
            max_subdomains = params.get('max_subdomains', 50) if params else 50
            wordlist = self.common_subdomains[:max_subdomains]
            
            found_subdomains = self.enumerate_subdomains_dns(domain, wordlist)
            
            if found_subdomains:
                # Check HTTP accessibility for found subdomains
                accessible_subdomains = []
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_subdomain = {
                        executor.submit(self.check_subdomain_http, sub['subdomain']): sub 
                        for sub in found_subdomains[:20]  # Limit HTTP checks
                    }
                    
                    for future in concurrent.futures.as_completed(future_to_subdomain):
                        http_result = future.result()
                        if http_result['accessible']:
                            accessible_subdomains.append(http_result)
                
                # Create findings for discovered subdomains
                finding = self.create_finding(
                    vulnerability="Subdomain Enumeration Results",
                    severity="Informational",
                    evidence=f"Discovered {len(found_subdomains)} subdomains for {domain}, {len(accessible_subdomains)} are HTTP accessible",
                    remediation="Review discovered subdomains for security misconfigurations and unnecessary exposure"
                )
                findings.append(finding)
                
                # Add individual subdomain findings
                for sub in accessible_subdomains[:10]:  # Show first 10 accessible
                    finding = self.create_finding(
                        vulnerability="Accessible Subdomain Discovered",
                        severity="Low",
                        evidence=f"Subdomain {sub['subdomain']} is accessible at {sub['url']} (Status: {sub['status_code']}, Server: {sub['server']}, Title: {sub['title'] or 'N/A'})",
                        remediation="Ensure subdomain has proper security controls and is not exposing sensitive information"
                    )
                    findings.append(finding)
                
                # Check for interesting subdomains
                interesting_keywords = ['admin', 'test', 'dev', 'staging', 'beta', 'api', 'panel', 'cpanel', 'webmail']
                for sub in found_subdomains:
                    subdomain_name = sub['subdomain'].lower()
                    for keyword in interesting_keywords:
                        if keyword in subdomain_name:
                            finding = self.create_finding(
                                vulnerability="Potentially Sensitive Subdomain",
                                severity="Medium",
                                evidence=f"Found potentially sensitive subdomain: {sub['subdomain']} (IP: {sub['ip']})",
                                remediation="Review subdomain for sensitive information exposure and implement proper access controls"
                            )
                            findings.append(finding)
                            break
            
            else:
                finding = self.create_finding(
                    vulnerability="Limited Subdomain Discovery",
                    severity="Informational",
                    evidence=f"No subdomains discovered for {domain} using common wordlist",
                    remediation="This could indicate good security practices or the need for more comprehensive enumeration"
                )
                findings.append(finding)
        
        except Exception as e:
            finding = self.create_finding(
                vulnerability="Subdomain Enumeration Error",
                severity="Low",
                evidence=f"Error during subdomain enumeration: {str(e)}",
                remediation="Check network connectivity and DNS configuration"
            )
            findings.append(finding)
        
        return findings

# Plugin instance (required for plugin system)
plugin = SubdomainEnumPlugin()

