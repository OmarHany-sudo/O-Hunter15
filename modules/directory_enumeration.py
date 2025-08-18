import requests
import threading
from concurrent.futures import ThreadPoolExecutor

class DirectoryEnumerationScanner:
    def __init__(self):
        self.findings = []
        # Common directories and files to check
        self.common_paths = [
            'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
            'backup', 'backups', 'config', 'database', 'db', 'test',
            'dev', 'development', 'staging', 'temp', 'tmp', 'uploads',
            'files', 'images', 'css', 'js', 'api', 'v1', 'v2',
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
            'readme.txt', 'changelog.txt', 'install.php', 'setup.php',
            'phpinfo.php', 'info.php', 'test.php', 'debug.php'
        ]

    def check_directory_enumeration(self, target_url, custom_paths=None):
        print(f"Checking for directory enumeration on {target_url}")
        
        paths_to_check = self.common_paths
        if custom_paths:
            paths_to_check.extend(custom_paths)
        
        # Use threading for faster scanning
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for path in paths_to_check:
                test_url = f"{target_url.rstrip('/')}/{path}"
                futures.append(executor.submit(self._check_path, test_url, path))
            
            # Wait for all threads to complete
            for future in futures:
                future.result()
        
        print("Directory enumeration scan complete.")

    def _check_path(self, test_url, path):
        try:
            response = requests.get(test_url, timeout=5, allow_redirects=False)
            if response.status_code == 200:
                self.findings.append({
                    'vulnerability': 'Directory/File Disclosure',
                    'severity': 'Medium',
                    'evidence': f'Accessible path found: {test_url} (Status: {response.status_code})',
                    'remediation': 'Restrict access to sensitive directories and files. Implement proper access controls.'
                })
                print(f"Found accessible path: {test_url}")
            elif response.status_code == 403:
                self.findings.append({
                    'vulnerability': 'Directory/File Enumeration',
                    'severity': 'Low',
                    'evidence': f'Directory exists but access forbidden: {test_url} (Status: {response.status_code})',
                    'remediation': 'Consider hiding directory structure to prevent information disclosure.'
                })
        except requests.exceptions.RequestException:
            # Ignore connection errors for non-existent paths
            pass

    def get_findings(self):
        return self.findings

