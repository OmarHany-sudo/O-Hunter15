#!/usr/bin/env python3
"""
Enhanced O-Hunter Scanner with Async Support and Plugin System
"""

import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.headers import HeadersChecker
from modules.sqli import SQLInjectionChecker
from modules.xss import XSSChecker
from modules.ssrf import SSRFChecker
from modules.rce import RCEChecker
from modules.xxe import XXEChecker
from modules.open_redirect import OpenRedirectChecker
from modules.http_request_smuggling import HTTPRequestSmugglingChecker
from modules.insecure_deserialization import InsecureDeserializationChecker
from modules.directory_enumeration import DirectoryEnumerationChecker
from modules.weak_credentials import WeakCredentialsChecker
from modules.masscan_scanner import MassscanScanner
from modules.nmap_scanner import NmapScanner
from modules.webanalyze_scanner import WebanalyzeScanner

# Import enhanced components
try:
    from core.async_scanner import AsyncScanner
    from core.plugin_system import PluginManager
    ENHANCED_FEATURES_AVAILABLE = True
except ImportError:
    ENHANCED_FEATURES_AVAILABLE = False

class Scanner:
    def __init__(self, use_async=False, enable_plugins=True):
        """
        Initialize the scanner
        
        Args:
            use_async (bool): Use async scanner for better performance
            enable_plugins (bool): Enable plugin system
        """
        self.findings = []
        self.use_async = use_async and ENHANCED_FEATURES_AVAILABLE
        self.enable_plugins = enable_plugins and ENHANCED_FEATURES_AVAILABLE
        
        # Initialize core modules
        self.headers_checker = HeadersChecker()
        self.sqli_checker = SQLInjectionChecker()
        self.xss_checker = XSSChecker()
        self.ssrf_checker = SSRFChecker()
        self.rce_checker = RCEChecker()
        self.xxe_checker = XXEChecker()
        self.open_redirect_checker = OpenRedirectChecker()
        self.http_smuggling_checker = HTTPRequestSmugglingChecker()
        self.insecure_deserialization_checker = InsecureDeserializationChecker()
        self.directory_enum_checker = DirectoryEnumerationChecker()
        self.weak_creds_checker = WeakCredentialsChecker()
        self.masscan_scanner = MassscanScanner()
        self.nmap_scanner = NmapScanner()
        self.webanalyze_scanner = WebanalyzeScanner()
        
        # Initialize async scanner if requested and available
        if self.use_async:
            self.async_scanner = AsyncScanner()
        
        # Initialize plugin system if enabled and available
        if self.enable_plugins:
            self.plugin_manager = PluginManager()
            self.plugin_manager.load_all_plugins()
    
    def scan_headers(self, target_url):
        """Scan security headers"""
        try:
            findings = self.headers_checker.check_headers(target_url)
            self.findings.extend(findings)
        except Exception as e:
            self.findings.append({
                'vulnerability': 'Headers Check Error',
                'severity': 'Low',
                'evidence': f'Error checking headers: {str(e)}',
                'remediation': 'Check target URL accessibility'
            })
    
    def run_all_scans(self, target_url, **kwargs):
        """
        Run all available scans
        
        Args:
            target_url (str): Target URL to scan
            **kwargs: Module-specific parameters
        """
        if self.use_async:
            # Use async scanner for better performance
            async_findings = self.async_scanner.run_comprehensive_scan(target_url, **kwargs)
            self.findings.extend(async_findings)
        else:
            # Use traditional synchronous scanning
            self._run_sync_scans(target_url, **kwargs)
        
        # Run plugins if enabled
        if self.enable_plugins:
            try:
                plugin_findings = self.plugin_manager.run_all_plugins(target_url, kwargs)
                self.findings.extend(plugin_findings)
            except Exception as e:
                self.findings.append({
                    'vulnerability': 'Plugin System Error',
                    'severity': 'Low',
                    'evidence': f'Error running plugins: {str(e)}',
                    'remediation': 'Check plugin configuration and dependencies'
                })
    
    def _run_sync_scans(self, target_url, **kwargs):
        """Run synchronous scans (legacy method)"""
        # Headers check (always run)
        self.scan_headers(target_url)
        
        # SQL Injection
        if kwargs.get('sqli_params'):
            try:
                findings = self.sqli_checker.check_sql_injection(target_url, kwargs['sqli_params'])
                self.findings.extend(findings)
            except Exception as e:
                self.findings.append({
                    'vulnerability': 'SQL Injection Check Error',
                    'severity': 'Low',
                    'evidence': f'Error during SQL injection check: {str(e)}',
                    'remediation': 'Check target URL and parameters'
                })
        
        # XSS
        if kwargs.get('xss_params'):
            try:
                findings = self.xss_checker.check_xss(target_url, kwargs['xss_params'])
                self.findings.extend(findings)
            except Exception as e:
                self.findings.append({
                    'vulnerability': 'XSS Check Error',
                    'severity': 'Low',
                    'evidence': f'Error during XSS check: {str(e)}',
                    'remediation': 'Check target URL and parameters'
                })
        
        # SSRF
        if kwargs.get('ssrf_params'):
            try:
                findings = self.ssrf_checker.check_ssrf(target_url, kwargs['ssrf_params'])
                self.findings.extend(findings)
            except Exception as e:
                self.findings.append({
                    'vulnerability': 'SSRF Check Error',
                    'severity': 'Low',
                    'evidence': f'Error during SSRF check: {str(e)}',
                    'remediation': 'Check target URL and parameters'
                })
        
        # RCE
        if kwargs.get('rce_params'):
            try:
                findings = self.rce_checker.check_rce(target_url, kwargs['rce_params'])
                self.findings.extend(findings)
            except Exception as e:
                self.findings.append({
                    'vulnerability': 'RCE Check Error',
                    'severity': 'Low',
                    'evidence': f'Error during RCE check: {str(e)}',
                    'remediation': 'Check target URL and parameters'
                })
        
        # XXE
        if kwargs.get('xxe_params'):
            try:
                findings = self.xxe_checker.check_xxe(target_url, kwargs['xxe_params'])
                self.findings.extend(findings)
            except Exception as e:
                self.findings.append({
                    'vulnerability': 'XXE Check Error',
                    'severity': 'Low',
                    'evidence': f'Error during XXE check: {str(e)}',
                    'remediation': 'Check target URL and parameters'
                })
        
        # Open Redirect
        if kwargs.get('open_redirect_params'):
            try:
                findings = self.open_redirect_checker.check_open_redirect(target_url, kwargs['open_redirect_params'])
                self.findings.extend(findings)
            except Exception as e:
                self.findings.append({
                    'vulnerability': 'Open Redirect Check Error',
                    'severity': 'Low',
                    'evidence': f'Error during Open Redirect check: {str(e)}',
                    'remediation': 'Check target URL and parameters'
                })
        
        # HTTP Request Smuggling
        if kwargs.get('http_request_smuggling_params'):
            try:
                findings = self.http_smuggling_checker.check_http_smuggling(target_url, kwargs['http_request_smuggling_params'])
                self.findings.extend(findings)
            except Exception as e:
                self.findings.append({
                    'vulnerability': 'HTTP Smuggling Check Error',
                    'severity': 'Low',
                    'evidence': f'Error during HTTP Smuggling check: {str(e)}',
                    'remediation': 'Check target URL and server configuration'
                })
        
        # Insecure Deserialization
        if kwargs.get('insecure_deserialization_params'):
            try:
                findings = self.insecure_deserialization_checker.check_insecure_deserialization(target_url, kwargs['insecure_deserialization_params'])
                self.findings.extend(findings)
            except Exception as e:
                self.findings.append({
                    'vulnerability': 'Insecure Deserialization Check Error',
                    'severity': 'Low',
                    'evidence': f'Error during Insecure Deserialization check: {str(e)}',
                    'remediation': 'Check target URL and parameters'
                })
        
        # Directory Enumeration
        if kwargs.get('dir_enum_params'):
            try:
                findings = self.directory_enum_checker.enumerate_directories(target_url, kwargs['dir_enum_params'])
                self.findings.extend(findings)
            except Exception as e:
                self.findings.append({
                    'vulnerability': 'Directory Enumeration Error',
                    'severity': 'Low',
                    'evidence': f'Error during directory enumeration: {str(e)}',
                    'remediation': 'Check target URL accessibility'
                })
        
        # Weak Credentials
        if kwargs.get('weak_creds_params'):
            try:
                findings = self.weak_creds_checker.check_weak_credentials(target_url, kwargs['weak_creds_params'])
                self.findings.extend(findings)
            except Exception as e:
                self.findings.append({
                    'vulnerability': 'Weak Credentials Check Error',
                    'severity': 'Low',
                    'evidence': f'Error during weak credentials check: {str(e)}',
                    'remediation': 'Check login URL and form parameters'
                })
        
        # Masscan Port Scanning
        if kwargs.get('masscan_params'):
            try:
                findings = self.masscan_scanner.scan_ports(kwargs['masscan_params']['target_ip'], kwargs['masscan_params'])
                self.findings.extend(findings)
            except Exception as e:
                self.findings.append({
                    'vulnerability': 'Masscan Error',
                    'severity': 'Low',
                    'evidence': f'Error during port scanning: {str(e)}',
                    'remediation': 'Check Masscan installation and target IP'
                })
        
        # Nmap Service Detection
        if kwargs.get('nmap_params'):
            try:
                findings = self.nmap_scanner.scan_services(kwargs['nmap_params']['target_ip'], kwargs['nmap_params'])
                self.findings.extend(findings)
            except Exception as e:
                self.findings.append({
                    'vulnerability': 'Nmap Error',
                    'severity': 'Low',
                    'evidence': f'Error during service detection: {str(e)}',
                    'remediation': 'Check Nmap installation and target IP'
                })
        
        # Technology Stack Analysis
        if kwargs.get('webanalyze_params'):
            try:
                findings = self.webanalyze_scanner.analyze_technologies(target_url, kwargs['webanalyze_params'])
                self.findings.extend(findings)
            except Exception as e:
                self.findings.append({
                    'vulnerability': 'Technology Analysis Error',
                    'severity': 'Low',
                    'evidence': f'Error during technology analysis: {str(e)}',
                    'remediation': 'Check target URL accessibility'
                })
    
    def run_specific_plugin(self, plugin_name, target_url, params=None):
        """
        Run a specific plugin
        
        Args:
            plugin_name (str): Name of the plugin to run
            target_url (str): Target URL
            params (dict): Plugin parameters
            
        Returns:
            list: Plugin findings
        """
        if not self.enable_plugins:
            return []
        
        try:
            return self.plugin_manager.run_plugin(plugin_name, target_url, params)
        except Exception as e:
            return [{
                'vulnerability': f'Plugin Error - {plugin_name}',
                'severity': 'Low',
                'evidence': f'Error running plugin: {str(e)}',
                'remediation': 'Check plugin configuration and dependencies'
            }]
    
    def list_available_plugins(self):
        """List all available plugins"""
        if not self.enable_plugins:
            return {}
        
        return self.plugin_manager.list_plugins()
    
    def get_findings(self):
        """Get all findings"""
        return self.findings
    
    def clear_findings(self):
        """Clear all findings"""
        self.findings = []
    
    def get_scan_summary(self):
        """Get scan summary statistics"""
        if not self.findings:
            return {
                'total_findings': 0,
                'by_severity': {},
                'by_category': {}
            }
        
        # Count by severity
        severity_counts = {}
        category_counts = {}
        
        for finding in self.findings:
            severity = finding.get('severity', 'Unknown')
            category = finding.get('category', 'General')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
        
        return {
            'total_findings': len(self.findings),
            'by_severity': severity_counts,
            'by_category': category_counts,
            'async_enabled': self.use_async,
            'plugins_enabled': self.enable_plugins,
            'enhanced_features_available': ENHANCED_FEATURES_AVAILABLE
        }

# Example usage
if __name__ == "__main__":
    # Test with async scanner and plugins
    scanner = Scanner(use_async=True, enable_plugins=True)
    
    scanner.run_all_scans(
        "https://example.com",
        sqli_params={'param_name': 'id'},
        xss_params={'param_name': 'search'}
    )
    
    findings = scanner.get_findings()
    summary = scanner.get_scan_summary()
    
    print(f"Scan completed: {summary['total_findings']} findings")
    print(f"Async enabled: {summary['async_enabled']}")
    print(f"Plugins enabled: {summary['plugins_enabled']}")
    print(f"Enhanced features available: {summary['enhanced_features_available']}")
    
    for finding in findings[:5]:  # Show first 5 findings
        print(f"[{finding['severity']}] {finding['vulnerability']}")
        print(f"Evidence: {finding['evidence']}")
        print("-" * 50)

