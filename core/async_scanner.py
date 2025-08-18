#!/usr/bin/env python3
"""
Async Scanner Module
High-performance vulnerability scanner with async/multithreading support
"""

import asyncio
import aiohttp
import concurrent.futures
import threading
import time
from typing import List, Dict, Any, Optional
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

class AsyncScanner:
    def __init__(self, max_workers=10, timeout=30):
        """
        Initialize async scanner
        
        Args:
            max_workers (int): Maximum number of worker threads
            timeout (int): Request timeout in seconds
        """
        self.max_workers = max_workers
        self.timeout = timeout
        self.findings = []
        self.lock = threading.Lock()
        
        # Initialize modules
        self.modules = {
            'headers': HeadersChecker(),
            'sqli': SQLInjectionChecker(),
            'xss': XSSChecker(),
            'ssrf': SSRFChecker(),
            'rce': RCEChecker(),
            'xxe': XXEChecker(),
            'open_redirect': OpenRedirectChecker(),
            'http_smuggling': HTTPRequestSmugglingChecker(),
            'insecure_deserialization': InsecureDeserializationChecker(),
            'directory_enum': DirectoryEnumerationChecker(),
            'weak_creds': WeakCredentialsChecker(),
            'masscan': MassscanScanner(),
            'nmap': NmapScanner(),
            'webanalyze': WebanalyzeScanner()
        }
    
    def add_finding(self, finding):
        """Thread-safe method to add findings"""
        with self.lock:
            self.findings.append(finding)
    
    def add_findings(self, findings):
        """Thread-safe method to add multiple findings"""
        with self.lock:
            self.findings.extend(findings)
    
    async def async_http_request(self, session, url, method='GET', **kwargs):
        """
        Make async HTTP request
        
        Args:
            session: aiohttp session
            url (str): Target URL
            method (str): HTTP method
            **kwargs: Additional request parameters
            
        Returns:
            dict: Response data or error info
        """
        try:
            async with session.request(method, url, timeout=self.timeout, **kwargs) as response:
                text = await response.text()
                return {
                    'status_code': response.status,
                    'headers': dict(response.headers),
                    'text': text,
                    'url': str(response.url),
                    'error': None
                }
        except Exception as e:
            return {
                'status_code': None,
                'headers': {},
                'text': '',
                'url': url,
                'error': str(e)
            }
    
    async def run_async_module(self, module_name, target_url, params=None):
        """
        Run a module asynchronously
        
        Args:
            module_name (str): Name of the module to run
            target_url (str): Target URL
            params (dict): Module parameters
            
        Returns:
            list: Module findings
        """
        if module_name not in self.modules:
            return []
        
        module = self.modules[module_name]
        
        try:
            # Create async HTTP session
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=30)
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                # Run module with async session if supported
                if hasattr(module, 'scan_async'):
                    findings = await module.scan_async(target_url, session, params or {})
                else:
                    # Fallback to sync method in thread pool
                    loop = asyncio.get_event_loop()
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                        if module_name == 'headers':
                            findings = await loop.run_in_executor(executor, module.check_headers, target_url)
                        elif module_name == 'sqli':
                            findings = await loop.run_in_executor(executor, module.check_sql_injection, target_url, params or {})
                        elif module_name == 'xss':
                            findings = await loop.run_in_executor(executor, module.check_xss, target_url, params or {})
                        elif module_name == 'ssrf':
                            findings = await loop.run_in_executor(executor, module.check_ssrf, target_url, params or {})
                        elif module_name == 'rce':
                            findings = await loop.run_in_executor(executor, module.check_rce, target_url, params or {})
                        elif module_name == 'xxe':
                            findings = await loop.run_in_executor(executor, module.check_xxe, target_url, params or {})
                        elif module_name == 'open_redirect':
                            findings = await loop.run_in_executor(executor, module.check_open_redirect, target_url, params or {})
                        elif module_name == 'http_smuggling':
                            findings = await loop.run_in_executor(executor, module.check_http_smuggling, target_url, params or {})
                        elif module_name == 'insecure_deserialization':
                            findings = await loop.run_in_executor(executor, module.check_insecure_deserialization, target_url, params or {})
                        elif module_name == 'directory_enum':
                            findings = await loop.run_in_executor(executor, module.enumerate_directories, target_url, params or {})
                        elif module_name == 'weak_creds':
                            findings = await loop.run_in_executor(executor, module.check_weak_credentials, target_url, params or {})
                        elif module_name == 'masscan':
                            findings = await loop.run_in_executor(executor, module.scan_ports, params.get('target_ip', target_url), params or {})
                        elif module_name == 'nmap':
                            findings = await loop.run_in_executor(executor, module.scan_services, params.get('target_ip', target_url), params or {})
                        elif module_name == 'webanalyze':
                            findings = await loop.run_in_executor(executor, module.analyze_technologies, target_url, params or {})
                        else:
                            findings = []
                
                return findings if findings else []
                
        except Exception as e:
            return [{
                'vulnerability': f'{module_name.title()} Module Error',
                'severity': 'Low',
                'evidence': f'Error running {module_name} module: {str(e)}',
                'remediation': f'Check {module_name} module configuration and target accessibility'
            }]
    
    async def run_parallel_scans(self, target_url, scan_configs):
        """
        Run multiple scans in parallel
        
        Args:
            target_url (str): Target URL
            scan_configs (list): List of scan configurations
            
        Returns:
            list: Combined findings from all scans
        """
        tasks = []
        
        for config in scan_configs:
            module_name = config['module']
            params = config.get('params', {})
            task = self.run_async_module(module_name, target_url, params)
            tasks.append(task)
        
        # Run all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine all findings
        all_findings = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                all_findings.append({
                    'vulnerability': f'Scan Error - {scan_configs[i]["module"]}',
                    'severity': 'Low',
                    'evidence': f'Error during scan: {str(result)}',
                    'remediation': 'Check scan configuration and target accessibility'
                })
            elif isinstance(result, list):
                all_findings.extend(result)
        
        return all_findings
    
    def run_async_scan(self, target_url, scan_configs):
        """
        Run async scan (wrapper for sync interface)
        
        Args:
            target_url (str): Target URL
            scan_configs (list): List of scan configurations
            
        Returns:
            list: Scan findings
        """
        # Create new event loop for this thread
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            findings = loop.run_until_complete(self.run_parallel_scans(target_url, scan_configs))
            loop.close()
            return findings
        except Exception as e:
            return [{
                'vulnerability': 'Async Scan Error',
                'severity': 'Low',
                'evidence': f'Error during async scan: {str(e)}',
                'remediation': 'Check scan configuration and system resources'
            }]
    
    def run_comprehensive_scan(self, target_url, **kwargs):
        """
        Run comprehensive scan with all available modules
        
        Args:
            target_url (str): Target URL
            **kwargs: Module-specific parameters
            
        Returns:
            list: All findings
        """
        self.findings = []
        start_time = time.time()
        
        # Build scan configurations
        scan_configs = []
        
        # Always include headers check
        scan_configs.append({'module': 'headers', 'params': {}})
        
        # Add other modules based on parameters
        if kwargs.get('sqli_params'):
            scan_configs.append({'module': 'sqli', 'params': kwargs['sqli_params']})
        
        if kwargs.get('xss_params'):
            scan_configs.append({'module': 'xss', 'params': kwargs['xss_params']})
        
        if kwargs.get('ssrf_params'):
            scan_configs.append({'module': 'ssrf', 'params': kwargs['ssrf_params']})
        
        if kwargs.get('rce_params'):
            scan_configs.append({'module': 'rce', 'params': kwargs['rce_params']})
        
        if kwargs.get('xxe_params'):
            scan_configs.append({'module': 'xxe', 'params': kwargs['xxe_params']})
        
        if kwargs.get('open_redirect_params'):
            scan_configs.append({'module': 'open_redirect', 'params': kwargs['open_redirect_params']})
        
        if kwargs.get('http_request_smuggling_params'):
            scan_configs.append({'module': 'http_smuggling', 'params': kwargs['http_request_smuggling_params']})
        
        if kwargs.get('insecure_deserialization_params'):
            scan_configs.append({'module': 'insecure_deserialization', 'params': kwargs['insecure_deserialization_params']})
        
        if kwargs.get('dir_enum_params'):
            scan_configs.append({'module': 'directory_enum', 'params': kwargs['dir_enum_params']})
        
        if kwargs.get('weak_creds_params'):
            scan_configs.append({'module': 'weak_creds', 'params': kwargs['weak_creds_params']})
        
        if kwargs.get('masscan_params'):
            scan_configs.append({'module': 'masscan', 'params': kwargs['masscan_params']})
        
        if kwargs.get('nmap_params'):
            scan_configs.append({'module': 'nmap', 'params': kwargs['nmap_params']})
        
        if kwargs.get('webanalyze_params'):
            scan_configs.append({'module': 'webanalyze', 'params': kwargs['webanalyze_params']})
        
        # Run scans
        findings = self.run_async_scan(target_url, scan_configs)
        self.findings.extend(findings)
        
        # Add performance metrics
        end_time = time.time()
        scan_duration = end_time - start_time
        
        self.findings.append({
            'vulnerability': 'Scan Performance Metrics',
            'severity': 'Informational',
            'evidence': f'Completed {len(scan_configs)} modules in {scan_duration:.2f} seconds using async/parallel processing',
            'remediation': 'Performance metrics for monitoring scan efficiency'
        })
        
        return self.findings
    
    def get_findings(self):
        """Get all findings"""
        return self.findings
    
    def clear_findings(self):
        """Clear all findings"""
        with self.lock:
            self.findings = []

# Example usage
if __name__ == "__main__":
    scanner = AsyncScanner(max_workers=10)
    
    findings = scanner.run_comprehensive_scan(
        "https://example.com",
        sqli_params={'param_name': 'id'},
        xss_params={'param_name': 'search'},
        ssrf_params={'param_name': 'url'}
    )
    
    print(f"Found {len(findings)} vulnerabilities:")
    for finding in findings:
        print(f"[{finding['severity']}] {finding['vulnerability']}")
        print(f"Evidence: {finding['evidence']}")
        print("-" * 50)

