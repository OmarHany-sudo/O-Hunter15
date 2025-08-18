#!/usr/bin/env python3
"""
Custom Headers Plugin for O-Hunter
Advanced security headers analysis plugin
"""

import requests
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.plugin_system import PluginBase

class CustomHeadersPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "CustomHeadersPlugin"
        self.version = "1.0.0"
        self.author = "O-Hunter Team"
        self.description = "Advanced security headers analysis with custom checks"
        self.category = "Security Headers"
        
        # Define security headers to check
        self.security_headers = {
            'Strict-Transport-Security': {
                'severity': 'Medium',
                'description': 'HSTS header missing',
                'remediation': 'Implement HTTP Strict Transport Security (HSTS) to force HTTPS connections'
            },
            'Content-Security-Policy': {
                'severity': 'Medium',
                'description': 'CSP header missing',
                'remediation': 'Implement Content Security Policy to prevent XSS and data injection attacks'
            },
            'X-Frame-Options': {
                'severity': 'Medium',
                'description': 'X-Frame-Options header missing',
                'remediation': 'Set X-Frame-Options to prevent clickjacking attacks'
            },
            'X-Content-Type-Options': {
                'severity': 'Low',
                'description': 'X-Content-Type-Options header missing',
                'remediation': 'Set X-Content-Type-Options: nosniff to prevent MIME-sniffing attacks'
            },
            'Referrer-Policy': {
                'severity': 'Low',
                'description': 'Referrer-Policy header missing',
                'remediation': 'Set Referrer-Policy to control referrer information sent with requests'
            },
            'Permissions-Policy': {
                'severity': 'Low',
                'description': 'Permissions-Policy header missing',
                'remediation': 'Set Permissions-Policy to control browser features and APIs'
            },
            'Cross-Origin-Embedder-Policy': {
                'severity': 'Low',
                'description': 'COEP header missing',
                'remediation': 'Set Cross-Origin-Embedder-Policy for enhanced security isolation'
            },
            'Cross-Origin-Opener-Policy': {
                'severity': 'Low',
                'description': 'COOP header missing',
                'remediation': 'Set Cross-Origin-Opener-Policy to isolate browsing context'
            }
        }
        
        # Insecure headers to flag
        self.insecure_headers = {
            'Server': {
                'severity': 'Informational',
                'description': 'Server information disclosure',
                'remediation': 'Remove or obfuscate server banner to reduce information disclosure'
            },
            'X-Powered-By': {
                'severity': 'Informational',
                'description': 'Technology stack disclosure',
                'remediation': 'Remove X-Powered-By header to hide technology information'
            }
        }
    
    def analyze_csp_policy(self, csp_value):
        """Analyze Content Security Policy for common issues"""
        issues = []
        
        if not csp_value:
            return issues
        
        csp_lower = csp_value.lower()
        
        # Check for unsafe directives
        if "'unsafe-inline'" in csp_lower:
            issues.append("CSP allows unsafe-inline which reduces XSS protection")
        
        if "'unsafe-eval'" in csp_lower:
            issues.append("CSP allows unsafe-eval which can enable code injection")
        
        if "*" in csp_value and "data:" not in csp_lower:
            issues.append("CSP uses wildcard (*) which may be too permissive")
        
        if "http:" in csp_lower and "https:" in csp_lower:
            issues.append("CSP allows both HTTP and HTTPS sources")
        
        return issues
    
    def analyze_hsts_policy(self, hsts_value):
        """Analyze HSTS policy for best practices"""
        issues = []
        
        if not hsts_value:
            return issues
        
        hsts_lower = hsts_value.lower()
        
        # Extract max-age value
        if "max-age=" in hsts_lower:
            try:
                max_age_start = hsts_lower.find("max-age=") + 8
                max_age_end = hsts_lower.find(";", max_age_start)
                if max_age_end == -1:
                    max_age_end = len(hsts_lower)
                
                max_age = int(hsts_lower[max_age_start:max_age_end].strip())
                
                # Check if max-age is too short (less than 6 months)
                if max_age < 15552000:  # 6 months in seconds
                    issues.append(f"HSTS max-age ({max_age}) is less than recommended 6 months")
                
            except ValueError:
                issues.append("HSTS max-age value is not a valid number")
        else:
            issues.append("HSTS header missing max-age directive")
        
        # Check for includeSubDomains
        if "includesubdomains" not in hsts_lower:
            issues.append("HSTS header missing includeSubDomains directive")
        
        return issues
    
    def scan(self, target_url, params=None):
        """
        Scan target for security headers
        
        Args:
            target_url (str): Target URL to scan
            params (dict): Plugin parameters
            
        Returns:
            list: List of findings
        """
        findings = []
        
        try:
            # Make request to target
            response = requests.get(target_url, timeout=10, allow_redirects=True)
            headers = response.headers
            
            # Check for missing security headers
            for header_name, header_info in self.security_headers.items():
                if header_name not in headers:
                    finding = self.create_finding(
                        vulnerability=f"Missing {header_name} Header",
                        severity=header_info['severity'],
                        evidence=f"Security header '{header_name}' not found in response from {target_url}",
                        remediation=header_info['remediation']
                    )
                    findings.append(finding)
                else:
                    # Analyze specific headers for issues
                    header_value = headers[header_name]
                    
                    if header_name == 'Content-Security-Policy':
                        csp_issues = self.analyze_csp_policy(header_value)
                        for issue in csp_issues:
                            finding = self.create_finding(
                                vulnerability="Content Security Policy Issue",
                                severity="Medium",
                                evidence=f"CSP header found but has issue: {issue}. Current value: {header_value}",
                                remediation="Review and strengthen Content Security Policy configuration"
                            )
                            findings.append(finding)
                    
                    elif header_name == 'Strict-Transport-Security':
                        hsts_issues = self.analyze_hsts_policy(header_value)
                        for issue in hsts_issues:
                            finding = self.create_finding(
                                vulnerability="HSTS Configuration Issue",
                                severity="Low",
                                evidence=f"HSTS header found but has issue: {issue}. Current value: {header_value}",
                                remediation="Review and strengthen HSTS configuration"
                            )
                            findings.append(finding)
            
            # Check for information disclosure headers
            for header_name, header_info in self.insecure_headers.items():
                if header_name in headers:
                    header_value = headers[header_name]
                    finding = self.create_finding(
                        vulnerability=f"{header_name} Header Disclosure",
                        severity=header_info['severity'],
                        evidence=f"Header '{header_name}' reveals information: {header_value}",
                        remediation=header_info['remediation']
                    )
                    findings.append(finding)
            
            # Check for deprecated headers
            deprecated_headers = ['X-XSS-Protection', 'Public-Key-Pins']
            for header_name in deprecated_headers:
                if header_name in headers:
                    finding = self.create_finding(
                        vulnerability=f"Deprecated {header_name} Header",
                        severity="Low",
                        evidence=f"Deprecated header '{header_name}' found with value: {headers[header_name]}",
                        remediation=f"Remove deprecated {header_name} header and use modern alternatives"
                    )
                    findings.append(finding)
            
            # Check response status
            if response.status_code != 200:
                finding = self.create_finding(
                    vulnerability="Non-200 Response Status",
                    severity="Informational",
                    evidence=f"Target returned status code {response.status_code}",
                    remediation="Verify target accessibility and check for redirects or errors"
                )
                findings.append(finding)
            
            # Add summary finding
            security_headers_present = sum(1 for header in self.security_headers if header in headers)
            total_security_headers = len(self.security_headers)
            
            finding = self.create_finding(
                vulnerability="Security Headers Summary",
                severity="Informational",
                evidence=f"Found {security_headers_present}/{total_security_headers} recommended security headers",
                remediation="Implement missing security headers to improve overall security posture"
            )
            findings.append(finding)
            
        except requests.exceptions.RequestException as e:
            finding = self.create_finding(
                vulnerability="Request Error",
                severity="Low",
                evidence=f"Failed to connect to {target_url}: {str(e)}",
                remediation="Check target URL accessibility and network connectivity"
            )
            findings.append(finding)
        
        except Exception as e:
            finding = self.create_finding(
                vulnerability="Plugin Execution Error",
                severity="Low",
                evidence=f"Unexpected error during scan: {str(e)}",
                remediation="Check plugin configuration and target accessibility"
            )
            findings.append(finding)
        
        return findings

# Plugin instance (required for plugin system)
plugin = CustomHeadersPlugin()

