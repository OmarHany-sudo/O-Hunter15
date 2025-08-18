import nmap

class NmapScanner:
    def __init__(self):
        self.findings = []
        self.nm = nmap.PortScanner()

    def scan_services_and_vulnerabilities(self, target_ip, arguments="-sV -sC"):
        print(f"Starting Nmap service and vulnerability scan on {target_ip} with arguments {arguments}")
        try:
            # nmap.PortScanner().scan() can take a while, consider running in a separate thread/process
            self.nm.scan(target_ip, arguments=arguments)

            for host in self.nm.all_hosts():
                print(f"Host : {host} ({self.nm[host].hostname()})")
                print(f"State : {self.nm[host].state()}")
                for proto in self.nm[host].all_protocols():
                    print(f"----------")
                    print(f"Protocol : {proto}")

                    lport = self.nm[host][proto].keys()
                    for port in lport:
                        service = self.nm[host][proto][port]
                        print(f"port : {port}\tstate : {service["state"]}\tservice : {service["name"]}")
                        
                        if service["state"] == "open":
                            self.findings.append({
                                    'vulnerability': 'Open Port/Service Detected',
                                    'severity': 'Informational',
                                    'evidence': f'Port {port}/{proto} is open with service {service["name"]} on {host}',
                                    'remediation': 'Review necessity of open ports and services. Ensure services are up-to-date and securely configured.'
                                })

                        # Check for NSE script output (simplified example)
                        if 'script' in service:
                            for script_id, script_output in service['script'].items():
                                if "vulnerable" in script_output.lower() or "exploit" in script_output.lower():
                                    self.findings.append({
                                        'vulnerability': f'Potential Vulnerability via Nmap Script ({script_id})',
                                        'severity': 'High',
                                        'evidence': f'Nmap script {script_id} found potential vulnerability on {host}:{port}. Output: {script_output}',
                                        'remediation': 'Investigate the Nmap script output and apply relevant patches or configurations.'
                                    })

            print("Nmap scan complete.")
        except nmap.PortScannerError as e:
            print(f"Error running Nmap: {e}. Make sure nmap is installed and accessible.")
        except Exception as e:
            print(f"An unexpected error occurred during Nmap scan: {e}")

    def get_findings(self):
        return self.findings


