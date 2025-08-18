from Wappalyzer import Wappalyzer, WebPage
import requests

class WebanalyzeScanner:
    def __init__(self):
        self.findings = []

    def analyze_technologies(self, target_url):
        print(f"Analyzing technologies for: {target_url}")
        try:
            response = requests.get(target_url, timeout=10)
            webpage = WebPage.new_from_response(response)
            wappalyzer = Wappalyzer.latest()
            technologies = wappalyzer.analyze(webpage)
            
            if technologies:
                self.findings.append({
                    'vulnerability': 'Technology Stack Disclosure',
                    'severity': 'Informational',
                    'evidence': f'Detected technologies on {target_url}: {', '.join(technologies)}',
                    'remediation': 'Be aware that disclosing technology stack can aid attackers. Ensure all components are up-to-date and securely configured.'
                })
                print(f"Detected technologies: {', '.join(technologies)}")
            else:
                print("No specific technologies detected.")

        except requests.exceptions.RequestException as e:
            print(f"Error analyzing technologies for {target_url}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred during webanalyze scan: {e}")
        print("Webanalyze scan complete.")

    def get_findings(self):
        return self.findings


