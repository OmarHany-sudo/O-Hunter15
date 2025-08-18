import requests

class OpenRedirectScanner:
    def __init__(self):
        self.findings = []

    def check_open_redirect(self, target_url, param_name):
        print(f"Checking for Open Redirect on {target_url} with parameter {param_name}")
        payloads = [
            "https://evil.com",
            "//evil.com",
            "\\evil.com",
            "http://google.com",
            "https://google.com",
        ]
        
        for payload in payloads:
            test_url = f"{target_url}?{param_name}={payload}"
            try:
                response = requests.get(test_url, timeout=5, allow_redirects=False)
                if response.status_code in [301, 302, 303, 307, 308] and 'Location' in response.headers and 'evil.com' in response.headers['Location']:
                    self.findings.append({
                        'vulnerability': 'Open Redirect',
                        'severity': 'Medium',
                        'evidence': f'Open Redirect detected with payload: {payload} on {test_url}',
                        'remediation': 'Validate and sanitize all redirect URLs. Use a whitelist of trusted domains.'
                    })
                    print(f"Open Redirect detected: {test_url}")
                    return
            except requests.exceptions.RequestException as e:
                print(f"Error checking Open Redirect on {test_url}: {e}")
        print("Open Redirect scan complete.")

    def get_findings(self):
        return self.findings


