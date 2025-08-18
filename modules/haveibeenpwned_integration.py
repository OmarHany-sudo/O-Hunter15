#!/usr/bin/env python3
"""
HaveIBeenPwned API Integration Module
Checks for compromised passwords and breached accounts
"""

import requests
import hashlib
import time
from urllib.parse import quote

class HaveIBeenPwnedIntegration:
    def __init__(self, api_key=None):
        """
        Initialize HaveIBeenPwned integration
        
        Args:
            api_key (str): HaveIBeenPwned API key (optional for password checking)
        """
        self.api_key = api_key
        self.base_url = "https://api.pwnedpasswords.com"
        self.breach_url = "https://haveibeenpwned.com/api/v3"
        self.findings = []
        
    def check_password_pwned(self, password):
        """
        Check if password has been compromised using k-anonymity
        
        Args:
            password (str): Password to check
            
        Returns:
            dict: Result with breach count and status
        """
        try:
            # Hash the password with SHA-1
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            
            # Use k-anonymity - send only first 5 characters
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Query the API
            response = requests.get(
                f"{self.base_url}/range/{prefix}",
                timeout=10,
                headers={'User-Agent': 'O-Hunter-Scanner'}
            )
            
            if response.status_code == 200:
                # Parse response to find our hash
                for line in response.text.splitlines():
                    hash_suffix, count = line.split(':')
                    if hash_suffix == suffix:
                        return {
                            'pwned': True,
                            'count': int(count),
                            'message': f'Password found in {count} data breaches'
                        }
                
                return {
                    'pwned': False,
                    'count': 0,
                    'message': 'Password not found in known breaches'
                }
            else:
                return {
                    'pwned': None,
                    'count': 0,
                    'message': 'Unable to check password'
                }
                
        except Exception as e:
            return {
                'pwned': None,
                'count': 0,
                'message': f'Error checking password: {str(e)}'
            }
    
    def check_email_breaches(self, email):
        """
        Check if email has been in data breaches (requires API key)
        
        Args:
            email (str): Email address to check
            
        Returns:
            list: List of breaches
        """
        if not self.api_key:
            return {
                'breaches': [],
                'message': 'API key required for breach checking'
            }
        
        try:
            headers = {
                'hibp-api-key': self.api_key,
                'User-Agent': 'O-Hunter-Scanner'
            }
            
            response = requests.get(
                f"{self.breach_url}/breachedaccount/{quote(email)}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                breaches = response.json()
                return {
                    'breaches': breaches,
                    'message': f'Email found in {len(breaches)} breaches'
                }
            elif response.status_code == 404:
                return {
                    'breaches': [],
                    'message': 'Email not found in any breaches'
                }
            else:
                return {
                    'breaches': [],
                    'message': f'Error checking email: HTTP {response.status_code}'
                }
                
        except Exception as e:
            return {
                'breaches': [],
                'message': f'Error checking email: {str(e)}'
            }
    
    def check_common_passwords(self, target_url, common_passwords=None):
        """
        Check common passwords against HaveIBeenPwned
        
        Args:
            target_url (str): Target URL (for context)
            common_passwords (list): List of common passwords to check
            
        Returns:
            list: List of findings
        """
        self.findings = []
        
        if not common_passwords:
            common_passwords = [
                'password', '123456', 'password123', 'admin', 'qwerty',
                'letmein', 'welcome', 'monkey', '1234567890', 'abc123',
                'Password1', 'password1', '12345678', 'welcome123',
                'admin123', 'root', 'toor', 'pass', 'test', 'guest'
            ]
        
        pwned_passwords = []
        
        for password in common_passwords:
            result = self.check_password_pwned(password)
            
            if result['pwned']:
                pwned_passwords.append({
                    'password': password,
                    'count': result['count']
                })
            
            # Rate limiting - be respectful to the API
            time.sleep(0.1)
        
        if pwned_passwords:
            # Sort by breach count (most compromised first)
            pwned_passwords.sort(key=lambda x: x['count'], reverse=True)
            
            top_pwned = pwned_passwords[:5]  # Show top 5 most compromised
            
            evidence = f"Common passwords found in data breaches: "
            evidence += ", ".join([f"{p['password']} ({p['count']} breaches)" for p in top_pwned])
            
            self.findings.append({
                'vulnerability': 'Commonly Compromised Passwords',
                'severity': 'High',
                'evidence': evidence,
                'remediation': 'Avoid using commonly compromised passwords. Implement strong password policies and consider password complexity requirements.'
            })
        
        # Add informational finding about password checking
        self.findings.append({
            'vulnerability': 'Password Breach Check Available',
            'severity': 'Informational',
            'evidence': f'Checked {len(common_passwords)} common passwords against HaveIBeenPwned database',
            'remediation': 'Regularly check passwords against known breach databases and implement password policies to prevent use of compromised passwords.'
        })
        
        return self.findings
    
    def check_email_list(self, target_url, email_list=None):
        """
        Check list of emails for breaches
        
        Args:
            target_url (str): Target URL (for context)
            email_list (list): List of email addresses to check
            
        Returns:
            list: List of findings
        """
        if not self.api_key:
            self.findings.append({
                'vulnerability': 'Email Breach Check Unavailable',
                'severity': 'Informational',
                'evidence': 'HaveIBeenPwned API key not configured',
                'remediation': 'Configure HaveIBeenPwned API key to enable email breach checking'
            })
            return self.findings
        
        if not email_list:
            # Try to extract domain from target URL for common email patterns
            from urllib.parse import urlparse
            domain = urlparse(target_url).netloc
            if domain:
                email_list = [
                    f'admin@{domain}',
                    f'info@{domain}',
                    f'contact@{domain}',
                    f'support@{domain}',
                    f'webmaster@{domain}'
                ]
        
        if not email_list:
            return self.findings
        
        breached_emails = []
        
        for email in email_list:
            result = self.check_email_breaches(email)
            
            if result['breaches']:
                breached_emails.append({
                    'email': email,
                    'breach_count': len(result['breaches']),
                    'breaches': result['breaches'][:3]  # Show first 3 breaches
                })
            
            # Rate limiting for API calls
            time.sleep(1.5)  # HaveIBeenPwned requires 1.5s between requests
        
        if breached_emails:
            evidence = f"Email addresses found in data breaches: "
            evidence += ", ".join([f"{e['email']} ({e['breach_count']} breaches)" for e in breached_emails])
            
            self.findings.append({
                'vulnerability': 'Email Addresses in Data Breaches',
                'severity': 'Medium',
                'evidence': evidence,
                'remediation': 'Monitor breached email addresses and ensure associated accounts use strong, unique passwords. Consider implementing multi-factor authentication.'
            })
        
        return self.findings
    
    def get_findings(self):
        """Get all findings from HaveIBeenPwned integration"""
        return self.findings

# Example usage
if __name__ == "__main__":
    hibp = HaveIBeenPwnedIntegration()
    
    # Check common passwords
    findings = hibp.check_common_passwords("http://example.com")
    
    for finding in findings:
        print(f"[{finding['severity']}] {finding['vulnerability']}")
        print(f"Evidence: {finding['evidence']}")
        print(f"Remediation: {finding['remediation']}")
        print("-" * 50)

