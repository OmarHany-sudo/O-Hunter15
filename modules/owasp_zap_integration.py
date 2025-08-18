#!/usr/bin/env python3
"""
OWASP ZAP API Integration Module
Integrates with OWASP ZAP for advanced vulnerability scanning
"""

import requests
import time
import json
from urllib.parse import urljoin, urlparse

class OWASPZAPIntegration:
    def __init__(self, zap_proxy_url='http://127.0.0.1:8080', api_key=None):
        """
        Initialize OWASP ZAP integration
        
        Args:
            zap_proxy_url (str): ZAP proxy URL
            api_key (str): ZAP API key (optional)
        """
        self.zap_url = zap_proxy_url
        self.api_key = api_key
        self.findings = []
        
    def is_zap_running(self):
        """Check if ZAP is running and accessible"""
        try:
            response = requests.get(f"{self.zap_url}/JSON/core/view/version/", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def start_spider_scan(self, target_url):
        """Start spider scan on target URL"""
        try:
            params = {
                'url': target_url,
                'maxChildren': '10',
                'recurse': 'true'
            }
            if self.api_key:
                params['apikey'] = self.api_key
                
            response = requests.get(
                f"{self.zap_url}/JSON/spider/action/scan/",
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('scan', None)
            return None
        except Exception as e:
            print(f"Error starting spider scan: {e}")
            return None
    
    def get_spider_status(self, scan_id):
        """Get spider scan status"""
        try:
            params = {'scanId': scan_id}
            if self.api_key:
                params['apikey'] = self.api_key
                
            response = requests.get(
                f"{self.zap_url}/JSON/spider/view/status/",
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return int(data.get('status', 0))
            return 0
        except:
            return 0
    
    def start_active_scan(self, target_url):
        """Start active scan on target URL"""
        try:
            params = {
                'url': target_url,
                'recurse': 'true',
                'inScopeOnly': 'false'
            }
            if self.api_key:
                params['apikey'] = self.api_key
                
            response = requests.get(
                f"{self.zap_url}/JSON/ascan/action/scan/",
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('scan', None)
            return None
        except Exception as e:
            print(f"Error starting active scan: {e}")
            return None
    
    def get_active_scan_status(self, scan_id):
        """Get active scan status"""
        try:
            params = {'scanId': scan_id}
            if self.api_key:
                params['apikey'] = self.api_key
                
            response = requests.get(
                f"{self.zap_url}/JSON/ascan/view/status/",
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return int(data.get('status', 0))
            return 0
        except:
            return 0
    
    def get_alerts(self, target_url):
        """Get alerts/vulnerabilities found by ZAP"""
        try:
            params = {'baseurl': target_url}
            if self.api_key:
                params['apikey'] = self.api_key
                
            response = requests.get(
                f"{self.zap_url}/JSON/core/view/alerts/",
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('alerts', [])
            return []
        except Exception as e:
            print(f"Error getting alerts: {e}")
            return []
    
    def convert_zap_alert_to_finding(self, alert):
        """Convert ZAP alert to O-Hunter finding format"""
        # Map ZAP risk levels to O-Hunter severity
        risk_mapping = {
            'High': 'High',
            'Medium': 'Medium', 
            'Low': 'Low',
            'Informational': 'Informational'
        }
        
        return {
            'vulnerability': alert.get('name', 'Unknown Vulnerability'),
            'severity': risk_mapping.get(alert.get('risk', 'Low'), 'Low'),
            'evidence': f"Found at {alert.get('url', 'Unknown URL')} - {alert.get('description', 'No description')}",
            'remediation': alert.get('solution', 'No remediation available'),
            'cwe_id': alert.get('cweid', ''),
            'wasc_id': alert.get('wascid', ''),
            'reference': alert.get('reference', '')
        }
    
    def scan_with_zap(self, target_url, scan_type='passive'):
        """
        Perform vulnerability scan using OWASP ZAP
        
        Args:
            target_url (str): Target URL to scan
            scan_type (str): Type of scan ('passive', 'active', 'full')
        
        Returns:
            list: List of findings
        """
        self.findings = []
        
        # Check if ZAP is running
        if not self.is_zap_running():
            self.findings.append({
                'vulnerability': 'OWASP ZAP Not Available',
                'severity': 'Informational',
                'evidence': 'OWASP ZAP proxy is not running or not accessible',
                'remediation': 'Start OWASP ZAP proxy on http://127.0.0.1:8080 to enable advanced scanning'
            })
            return self.findings
        
        try:
            # For passive scanning, just get existing alerts
            if scan_type == 'passive':
                alerts = self.get_alerts(target_url)
                for alert in alerts:
                    finding = self.convert_zap_alert_to_finding(alert)
                    self.findings.append(finding)
                return self.findings
            
            # For active scanning, run spider first
            if scan_type in ['active', 'full']:
                print(f"Starting spider scan for {target_url}")
                spider_scan_id = self.start_spider_scan(target_url)
                
                if spider_scan_id:
                    # Wait for spider to complete (max 2 minutes)
                    max_wait = 120
                    wait_time = 0
                    while wait_time < max_wait:
                        status = self.get_spider_status(spider_scan_id)
                        if status >= 100:
                            break
                        time.sleep(5)
                        wait_time += 5
                    
                    print("Spider scan completed")
                
                # Start active scan
                print(f"Starting active scan for {target_url}")
                active_scan_id = self.start_active_scan(target_url)
                
                if active_scan_id:
                    # Wait for active scan to complete (max 5 minutes)
                    max_wait = 300
                    wait_time = 0
                    while wait_time < max_wait:
                        status = self.get_active_scan_status(active_scan_id)
                        if status >= 100:
                            break
                        time.sleep(10)
                        wait_time += 10
                    
                    print("Active scan completed")
                
                # Get all alerts after scanning
                alerts = self.get_alerts(target_url)
                for alert in alerts:
                    finding = self.convert_zap_alert_to_finding(alert)
                    self.findings.append(finding)
            
        except Exception as e:
            self.findings.append({
                'vulnerability': 'ZAP Integration Error',
                'severity': 'Low',
                'evidence': f'Error during ZAP integration: {str(e)}',
                'remediation': 'Check ZAP configuration and ensure it is properly running'
            })
        
        return self.findings
    
    def get_findings(self):
        """Get all findings from ZAP integration"""
        return self.findings

# Example usage
if __name__ == "__main__":
    zap = OWASPZAPIntegration()
    findings = zap.scan_with_zap("http://example.com", "passive")
    for finding in findings:
        print(f"[{finding['severity']}] {finding['vulnerability']}")
        print(f"Evidence: {finding['evidence']}")
        print(f"Remediation: {finding['remediation']}")
        print("-" * 50)

