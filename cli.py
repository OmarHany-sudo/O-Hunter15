#!/usr/bin/env python3
import argparse
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.scanner import Scanner
from core.report_generator import ReportGenerator

ASCII_LOGO = """
  ____ _   _ _   _ ____   _____
 / ___| | | | \ | |  _ \ / ____|
| |   | | | |  \| | |_) | (___   ___ _ __ __ _ _ __ ___   ___
| |   | | | | . ` |  _ < \___ \ / __| \'__/ _` | \'_ ` _ \ / _ \
| |___| |_| | |\  | |_) |____) | (__| | | (_| | | | | | |  __/
 \_____\___/|_| \_|____/|_____/ \___|_|  \__,_|_| |_| |_|\___|

Developed by Eng. Omar Hany
"""

def main():
    print(ASCII_LOGO)
    
    parser = argparse.ArgumentParser(description=\'O-Hunter: Web Vulnerability Scanner\')
    parser.add_argument(\'--target\', \'-t\', required=True, help=\'Target URL to scan\')
    parser.add_argument(\'--mode\', \'-m\', choices=[\'passive\', \'active\', \'full\'], default=\'passive\',
                        help=\'Scan mode (default: passive)\')
    parser.add_argument(\'--output\', \'-o\', help=\'Output file path\')
    parser.add_argument(\'--format\', \'-f\', choices=[\'json\', \'html\'], default=\'json\',
                        help=\'Output format (default: json)\')
    parser.add_argument(\'--plugin\', \'-p\', help=\'Specific plugins to run (comma-separated)\')
    parser.add_argument(\'--exploit\', action=\'store_true\', 
                        help=\'Enable advanced exploitation (requires confirmation)\')
    parser.add_argument(\'--rce\', action=\'store_true\', help=\'Enable Remote Code Execution (RCE) scan\')
    parser.add_argument(\'--xxe\', action=\'store_true\', help=\'Enable XML External Entity (XXE) scan\')
    parser.add_argument(\'--open-redirect\', action=\'store_true\', help=\'Enable Open Redirect scan\')
    parser.add_argument(\'--http-smuggling\', action=\'store_true\', help=\'Enable HTTP Request Smuggling scan\')
    parser.add_argument(\'--insecure-deserialization\', action=\'store_true\', help=\'Enable Insecure Deserialization scan\')
    parser.add_argument(\'--dir-enum\', action=\'store_true\', help=\'Enable Directory Enumeration scan\')
    parser.add_argument(\'--weak-creds\', action=\'store_true\', help=\'Enable Weak Credentials scan\')
    parser.add_argument(\'--masscan\', action=\'store_true\', help=\'Enable Masscan port scan\')
    parser.add_argument(\'--nmap\', action=\'store_true\', help=\'Enable Nmap service and vulnerability scan\')
    parser.add_argument(\'--webanalyze\', action=\'store_true\', help=\'Enable Webanalyze technology detection\')
    
    args = parser.parse_args()
    
    # Safety check for exploit mode
    if args.exploit:
        print("⚠️  WARNING: Advanced exploitation mode enabled!")
        print("This mode may perform potentially destructive tests.")
        confirmation = input("Type \'YES\' to confirm: ")
        if confirmation != \'YES\':
            print("Exploitation mode cancelled. Running in safe mode.")
            args.exploit = False
    
    print(f"Starting scan of {args.target} in {args.mode} mode...")
    
    scanner = Scanner()
    
    # Configure scan parameters based on mode
    if args.mode == \'passive\':
        scanner.scan_headers(args.target)
    elif args.mode == \'active\':
        scanner.run_all_scans(
            args.target,
            sqli_params={\'param_name\': \'id\'}, # Example parameter
            xss_params={\'param_name\': \'search\'} # Example parameter
        )
    elif args.mode == \'full\':
        scanner.run_all_scans(
            args.target,
            idor_params={\'vulnerable_endpoint\': \'user\', \'valid_id\': \'1\', \'attacker_id\': \'2\'}, # Example parameters
            sqli_params={\'param_name\': \'id\'}, # Example parameter
            xss_params={\'param_name\': \'search\'}, # Example parameter
            auth_params={
                \'login_url\': f\"{args.target}/login\",
                \'username_field\': \'username\',
                \'password_field\': \'password\',
                \'common_credentials\': [(\'admin\', \'admin\'), (\'admin\', \'password\')] # Example credentials
            },
            sdi_params={\'artifact_path\': \'/download/app.zip\'}, # Example parameter
            lm_params={\'sensitive_action_path\': \'/login\'}, # Example parameter
            ssrf_params={\'param_name\': \'url\'}, # Example parameter
            rce_params={\'param_name\': \'cmd\'}, # Example parameter
            xxe_params={\'param_name\': \'xml_data\'}, # Example parameter
            open_redirect_params={\'param_name\': \'next\'}, # Example parameter
            http_request_smuggling_params={}, # No specific parameters needed for this module
            insecure_deserialization_params={\'param_name\': \'data\'}, # Example parameter
            dir_enum_params={}, # No specific parameters needed for this module
            weak_creds_params={\'login_url\': f\"{args.target}/login\", \'username_field\': \'username\', \'password_field\': \'password\'}, # Example parameters
            masscan_params={\'target_ip\': args.target.split(\'//\')[1].split(\'/\')[0]}, # Extract IP from URL
            nmap_params={\'target_ip\': args.target.split(\'//\')[1].split(\'/\')[0]}, # Extract IP from URL
            webanalyze_params={} # No specific parameters needed for this module
        )
    
    # Individual module calls based on arguments (for custom scans)
    if args.rce and args.mode != \'full\':
        scanner.run_all_scans(args.target, rce_params={\'param_name\': \'cmd\'}) 
    if args.xxe and args.mode != \'full\':
        scanner.run_all_scans(args.target, xxe_params={\'param_name\': \'xml_data\'}) 
    if args.open_redirect and args.mode != \'full\':
        scanner.run_all_scans(args.target, open_redirect_params={\'param_name\': \'next\'}) 
    if args.http_smuggling and args.mode != \'full\':
        scanner.run_all_scans(args.target, http_request_smuggling_params={}) 
    if args.insecure_deserialization and args.mode != \'full\':
        scanner.run_all_scans(args.target, insecure_deserialization_params={\'param_name\': \'data\'}) 
    if args.dir_enum and args.mode != \'full\':
        scanner.run_all_scans(args.target, dir_enum_params={}) 
    if args.weak_creds and args.mode != \'full\':
        scanner.run_all_scans(args.target, weak_creds_params={
            \'login_url\': f\"{args.target}/login\",
            \'username_field\': \'username\',
            \'password_field\': \'password\'
        }) 
    if args.masscan and args.mode != \'full\':
        scanner.run_all_scans(args.target, masscan_params={\'target_ip\': args.target.split(\'//\')[1].split(\'/\')[0]}) 
    if args.nmap and args.mode != \'full\':
        scanner.run_all_scans(args.target, nmap_params={\'target_ip\': args.target.split(\'//\')[1].split(\'/\')[0]}) 
    if args.webanalyze and args.mode != \'full\':
        scanner.run_all_scans(args.target, webanalyze_params={}) 

    findings = scanner.get_findings()
    
    print(f"\nScan complete. Found {len(findings)} potential vulnerabilities.")
    
    # Generate report
    if args.output:
        report_gen = ReportGenerator(findings, args.target)
        
        if args.format == \'json\':
            output_file = report_gen.generate_json_report(args.output)
        elif args.format == \'html\':
            output_file = report_gen.generate_html_report(args.output)
        
        print(f"Report saved to: {output_file}")
    else:
        # Print findings to console
        for finding in findings:
            print(f"\n[{finding[\'severity\']}] {finding[\'vulnerability\']}")
            print(f"Evidence: {finding[\'evidence\']}")
            print(f"Remediation: {finding[\'remediation\']}")

if __name__ == \'__main__\':
    main()

