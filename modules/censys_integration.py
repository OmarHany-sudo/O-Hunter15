#!/usr/bin/env python3
"""
Censys API Integration Module
Provides reconnaissance capabilities using Censys search engine
"""

import requests
import base64
from urllib.parse import urlparse
import json

class CensysIntegration:
    def __init__(self, api_id=None, api_secret=None):
        """
        Initialize Censys integration
        
        Args:
            api_id (str): Censys API ID
            api_secret (str): Censys API Secret
        """
        self.api_id = api_id
        self.api_secret = api_secret
        self.base_url = "https://search.censys.io/api/v2"
        self.findings = []
        
        # Setup authentication
        if self.api_id and self.api_secret:
            credentials = f"{self.api_id}:{self.api_secret}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            self.headers = {
                'Authorization': f'Basic {encoded_credentials}',
                'Content-Type': 'application/json',
                'User-Agent': 'O-Hunter-Scanner'
            }
        else:
            self.headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'O-Hunter-Scanner'
            }
    
    def search_hosts(self, query, max_results=10):
        """
        Search for hosts using Censys
        
        Args:
            query (str): Search query
            max_results (int): Maximum number of results
            
        Returns:
            dict: Search results
        """
        if not self.api_id or not self.api_secret:
            return {
                'error': 'Censys API credentials not configured',
                'results': []
            }
        
        try:
            data = {
                'q': query,
                'per_page': min(max_results, 100),
                'virtual_hosts': 'EXCLUDE'
            }
            
            response = requests.post(
                f"{self.base_url}/hosts/search",
                headers=self.headers,
                json=data,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    'error': f'HTTP {response.status_code}: {response.text}',
                    'results': []
                }
                
        except Exception as e:
            return {
                'error': f'Error searching hosts: {str(e)}',
                'results': []
            }
    
    def get_host_details(self, ip_address):
        """
        Get detailed information about a specific host
        
        Args:
            ip_address (str): IP address to lookup
            
        Returns:
            dict: Host details
        """
        if not self.api_id or not self.api_secret:
            return {
                'error': 'Censys API credentials not configured'
            }
        
        try:
            response = requests.get(
                f"{self.base_url}/hosts/{ip_address}",
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    'error': f'HTTP {response.status_code}: {response.text}'
                }
                
        except Exception as e:
            return {
                'error': f'Error getting host details: {str(e)}'
            }
    
    def analyze_target_domain(self, target_url):
        """
        Analyze target domain using Censys
        
        Args:
            target_url (str): Target URL to analyze
            
        Returns:
            list: List of findings
        """
        self.findings = []
        
        # Extract domain from URL
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc
        
        if not domain:
            self.findings.append({
                'vulnerability': 'Invalid Target URL',
                'severity': 'Low',
                'evidence': f'Could not extract domain from {target_url}',
                'remediation': 'Provide a valid URL with domain name'
            })
            return self.findings
        
        if not self.api_id or not self.api_secret:
            self.findings.append({
                'vulnerability': 'Censys Integration Unavailable',
                'severity': 'Informational',
                'evidence': 'Censys API credentials not configured',
                'remediation': 'Configure Censys API credentials to enable reconnaissance features'
            })
            return self.findings
        
        try:
            # Search for hosts related to the domain
            search_results = self.search_hosts(f'services.http.request.get.headers.host: {domain}')
            
            if 'error' in search_results:
                self.findings.append({
                    'vulnerability': 'Censys Search Error',
                    'severity': 'Low',
                    'evidence': search_results['error'],
                    'remediation': 'Check Censys API configuration and quota limits'
                })
                return self.findings
            
            results = search_results.get('result', {}).get('hits', [])
            
            if results:
                # Analyze discovered hosts
                exposed_services = []
                open_ports = set()
                technologies = set()
                
                for host in results[:5]:  # Limit to first 5 results
                    ip = host.get('ip', 'Unknown')
                    services = host.get('services', [])
                    
                    for service in services:
                        port = service.get('port', 0)
                        service_name = service.get('service_name', 'unknown')
                        
                        open_ports.add(port)
                        
                        # Check for potentially risky services
                        risky_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379, 27017]
                        if port in risky_ports:
                            exposed_services.append(f"{ip}:{port} ({service_name})")
                        
                        # Extract technology information
                        if 'http' in service:
                            http_info = service['http']
                            if 'response' in http_info:
                                response = http_info['response']
                                if 'headers' in response:
                                    headers = response['headers']
                                    server = headers.get('server', '')
                                    if server:
                                        technologies.add(server)
                
                # Generate findings based on analysis
                if exposed_services:
                    self.findings.append({
                        'vulnerability': 'Exposed Network Services',
                        'severity': 'Medium',
                        'evidence': f'Found {len(exposed_services)} exposed services: {", ".join(exposed_services[:10])}',
                        'remediation': 'Review exposed services and ensure only necessary services are publicly accessible. Implement proper access controls and firewall rules.'
                    })
                
                if open_ports:
                    port_list = sorted(list(open_ports))
                    self.findings.append({
                        'vulnerability': 'Open Network Ports',
                        'severity': 'Informational',
                        'evidence': f'Discovered open ports: {", ".join(map(str, port_list[:20]))}',
                        'remediation': 'Regularly audit open ports and close unnecessary services to reduce attack surface.'
                    })
                
                if technologies:
                    self.findings.append({
                        'vulnerability': 'Technology Stack Disclosure',
                        'severity': 'Informational',
                        'evidence': f'Detected technologies: {", ".join(list(technologies)[:10])}',
                        'remediation': 'Consider hiding server banners and technology information to reduce information disclosure.'
                    })
                
                # General reconnaissance finding
                self.findings.append({
                    'vulnerability': 'Internet Exposure Analysis',
                    'severity': 'Informational',
                    'evidence': f'Found {len(results)} hosts associated with domain {domain} in Censys database',
                    'remediation': 'Regularly monitor your internet-facing assets and ensure proper security controls are in place.'
                })
            
            else:
                self.findings.append({
                    'vulnerability': 'Limited Internet Exposure',
                    'severity': 'Informational',
                    'evidence': f'No hosts found for domain {domain} in Censys database',
                    'remediation': 'This could indicate good security practices or limited internet exposure. Continue monitoring for changes.'
                })
        
        except Exception as e:
            self.findings.append({
                'vulnerability': 'Censys Analysis Error',
                'severity': 'Low',
                'evidence': f'Error during Censys analysis: {str(e)}',
                'remediation': 'Check network connectivity and Censys API configuration'
            })
        
        return self.findings
    
    def search_certificates(self, domain):
        """
        Search for SSL certificates related to domain
        
        Args:
            domain (str): Domain to search certificates for
            
        Returns:
            dict: Certificate search results
        """
        if not self.api_id or not self.api_secret:
            return {
                'error': 'Censys API credentials not configured',
                'results': []
            }
        
        try:
            data = {
                'q': f'names: {domain}',
                'per_page': 10
            }
            
            response = requests.post(
                f"{self.base_url}/certificates/search",
                headers=self.headers,
                json=data,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    'error': f'HTTP {response.status_code}: {response.text}',
                    'results': []
                }
                
        except Exception as e:
            return {
                'error': f'Error searching certificates: {str(e)}',
                'results': []
            }
    
    def get_findings(self):
        """Get all findings from Censys integration"""
        return self.findings

# Example usage
if __name__ == "__main__":
    # Note: You need to provide actual Censys API credentials
    censys = CensysIntegration(api_id="your_api_id", api_secret="your_api_secret")
    
    findings = censys.analyze_target_domain("https://example.com")
    
    for finding in findings:
        print(f"[{finding['severity']}] {finding['vulnerability']}")
        print(f"Evidence: {finding['evidence']}")
        print(f"Remediation: {finding['remediation']}")
        print("-" * 50)

