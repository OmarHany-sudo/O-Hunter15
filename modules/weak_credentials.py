import requests

class WeakCredentialsScanner:
    def __init__(self):
        self.findings = []
        self.common_credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("user", "user"),
            ("test", "test"),
            ("root", "root"),
            ("admin", "123456"),
            ("admin", ""),
        ]

    def check_weak_credentials(self, login_url, username_field, password_field, custom_credentials=None):
        print(f"Checking for weak credentials on {login_url}")
        
        credentials_to_check = self.common_credentials
        if custom_credentials:
            credentials_to_check.extend(custom_credentials)

        for username, password in credentials_to_check:
            data = {
                username_field: username,
                password_field: password
            }
            try:
                response = requests.post(login_url, data=data, timeout=5)
                # This is a generic check. A more robust check would involve analyzing
                # the response content for specific success/failure messages or redirects.
                if "welcome" in response.text.lower() or "dashboard" in response.text.lower() or response.status_code == 200:
                    self.findings.append({
                        'vulnerability': 'Weak Credentials',
                        'severity': 'High',
                        'evidence': f'Weak credentials found: username={username}, password={password} on {login_url}',
                        'remediation': 'Enforce strong password policies, implement multi-factor authentication, and use brute-force protection mechanisms.'
                    })
                    print(f"Weak credentials found: {username}/{password}")
                    return
            except requests.exceptions.RequestException as e:
                print(f"Error checking weak credentials on {login_url}: {e}")
        print("Weak credentials scan complete.")

    def get_findings(self):
        return self.findings


