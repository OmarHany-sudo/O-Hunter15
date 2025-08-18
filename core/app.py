import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from scanner import Scanner
from modules.owasp_zap_integration import OWASPZAPIntegration
from modules.haveibeenpwned_integration import HaveIBeenPwnedIntegration
from modules.censys_integration import CensysIntegration

# تحديد مسار الـ static folder بشكل صحيح
static_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'gui', 'ohunter-ui', 'dist')
app = Flask(__name__, static_folder=static_path, static_url_path='')
CORS(app)

@app.route('/')
def serve_frontend():
    """Serve the React frontend"""
    try:
        return send_from_directory(app.static_folder, 'index.html')
    except Exception as e:
        return jsonify({
            "error": "Frontend not available", 
            "message": "Please ensure the frontend is built properly",
            "details": str(e)
        }), 404

@app.route('/<path:path>')
def serve_static_files(path):
    """Serve static files for React app"""
    try:
        return send_from_directory(app.static_folder, path)
    except Exception:
        # If file not found, serve index.html for React Router
        return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/scan', methods=['POST'])
def scan_endpoint():
    """Main scanning endpoint with API integrations"""
    try:
        data = request.get_json()
        target_url = data.get('target_url')
        scan_type = data.get('scan_type', 'basic')
        options = data.get('options', {})
        
        if not target_url:
            return jsonify({'error': 'Target URL is required'}), 400
        
        scanner = Scanner()
        all_findings = []
        
        # Run core scanner based on scan type and options
        if scan_type == 'quick':
            scanner.scan_headers(target_url)
        elif scan_type == 'full':
            scanner.run_all_scans(
                target_url,
                sqli_params={'param_name': 'id'},
                xss_params={'param_name': 'search'},
                ssrf_params={'param_name': 'url'},
                rce_params={'param_name': 'cmd'} if options.get('rce') else None,
                xxe_params={'param_name': 'xml_data'} if options.get('xxe') else None,
                open_redirect_params={'param_name': 'next'} if options.get('openRedirect') else None,
                http_request_smuggling_params={} if options.get('httpSmuggling') else None,
                insecure_deserialization_params={'param_name': 'data'} if options.get('insecureDeserialization') else None,
                dir_enum_params={} if options.get('dirEnum') else None,
                weak_creds_params={'login_url': f"{target_url}/login", 'username_field': 'username', 'password_field': 'password'} if options.get('weakCreds') else None,
                masscan_params={'target_ip': target_url.split('//')[1].split('/')[0]} if options.get('portScan') else None,
                nmap_params={'target_ip': target_url.split('//')[1].split('/')[0]} if options.get('serviceDetection') else None,
                webanalyze_params={} if options.get('techStack') else None
            )
        elif scan_type == 'custom':
            # Build scan parameters based on selected options
            scan_params = {}
            
            if options.get('sqli'):
                scan_params['sqli_params'] = {'param_name': 'id'}
            if options.get('xss'):
                scan_params['xss_params'] = {'param_name': 'search'}
            if options.get('ssrf'):
                scan_params['ssrf_params'] = {'param_name': 'url'}
            if options.get('rce'):
                scan_params['rce_params'] = {'param_name': 'cmd'}
            if options.get('xxe'):
                scan_params['xxe_params'] = {'param_name': 'xml_data'}
            if options.get('openRedirect'):
                scan_params['open_redirect_params'] = {'param_name': 'next'}
            if options.get('httpSmuggling'):
                scan_params['http_request_smuggling_params'] = {}
            if options.get('insecureDeserialization'):
                scan_params['insecure_deserialization_params'] = {'param_name': 'data'}
            if options.get('dirEnum'):
                scan_params['dir_enum_params'] = {}
            if options.get('weakCreds'):
                scan_params['weak_creds_params'] = {'login_url': f"{target_url}/login", 'username_field': 'username', 'password_field': 'password'}
            if options.get('portScan'):
                scan_params['masscan_params'] = {'target_ip': target_url.split('//')[1].split('/')[0]}
            if options.get('serviceDetection'):
                scan_params['nmap_params'] = {'target_ip': target_url.split('//')[1].split('/')[0]}
            if options.get('techStack'):
                scan_params['webanalyze_params'] = {}
            
            if options.get('headers') or options.get('ssl'):
                scanner.scan_headers(target_url)
            
            if scan_params:
                scanner.run_all_scans(target_url, **scan_params)
        else:
            # Basic scan
            scanner.scan_headers(target_url)
        
        # Get core findings
        core_findings = scanner.get_findings()
        all_findings.extend(core_findings)
        
        # API Integrations
        api_findings = []
        
        # OWASP ZAP Integration
        if options.get('zapIntegration', False):
            try:
                zap = OWASPZAPIntegration()
                zap_findings = zap.scan_with_zap(target_url, 'passive')
                api_findings.extend(zap_findings)
            except Exception as e:
                api_findings.append({
                    'vulnerability': 'ZAP Integration Error',
                    'severity': 'Low',
                    'evidence': f'Error integrating with OWASP ZAP: {str(e)}',
                    'remediation': 'Check OWASP ZAP configuration and ensure it is running'
                })
        
        # HaveIBeenPwned Integration
        if options.get('hibpIntegration', False) or scan_type == 'full':
            try:
                hibp_api_key = os.environ.get('HIBP_API_KEY')
                hibp = HaveIBeenPwnedIntegration(api_key=hibp_api_key)
                hibp_findings = hibp.check_common_passwords(target_url)
                api_findings.extend(hibp_findings)
            except Exception as e:
                api_findings.append({
                    'vulnerability': 'HaveIBeenPwned Integration Error',
                    'severity': 'Low',
                    'evidence': f'Error integrating with HaveIBeenPwned: {str(e)}',
                    'remediation': 'Check HaveIBeenPwned API configuration'
                })
        
        # Censys Integration
        if options.get('censysIntegration', False) or scan_type == 'full':
            try:
                censys_api_id = os.environ.get('CENSYS_API_ID')
                censys_api_secret = os.environ.get('CENSYS_API_SECRET')
                censys = CensysIntegration(api_id=censys_api_id, api_secret=censys_api_secret)
                censys_findings = censys.analyze_target_domain(target_url)
                api_findings.extend(censys_findings)
            except Exception as e:
                api_findings.append({
                    'vulnerability': 'Censys Integration Error',
                    'severity': 'Low',
                    'evidence': f'Error integrating with Censys: {str(e)}',
                    'remediation': 'Check Censys API configuration'
                })
        
        # Combine all findings
        all_findings.extend(api_findings)
        
        return jsonify({
            'target_url': target_url,
            'findings': all_findings,
            'total_findings': len(all_findings),
            'scan_type': scan_type,
            'api_integrations_used': len(api_findings) > 0,
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({
            'error': 'Scanning failed',
            'message': str(e),
            'status': 'error'
        }), 500

@app.route('/api/integrations/status', methods=['GET'])
def integrations_status():
    """Check status of API integrations"""
    try:
        status = {
            'owasp_zap': {
                'available': False,
                'message': 'Not running'
            },
            'haveibeenpwned': {
                'available': True,
                'message': 'Password checking available'
            },
            'censys': {
                'available': bool(os.environ.get('CENSYS_API_ID') and os.environ.get('CENSYS_API_SECRET')),
                'message': 'API credentials configured' if bool(os.environ.get('CENSYS_API_ID') and os.environ.get('CENSYS_API_SECRET')) else 'API credentials not configured'
            }
        }
        
        # Check ZAP status
        try:
            zap = OWASPZAPIntegration()
            if zap.is_zap_running():
                status['owasp_zap']['available'] = True
                status['owasp_zap']['message'] = 'Running and accessible'
        except:
            pass
        
        return jsonify(status)
        
    except Exception as e:
        return jsonify({
            'error': 'Failed to check integrations status',
            'message': str(e)
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for Railway"""
    return jsonify({
        'status': 'healthy', 
        'message': 'O-Hunter API is running',
        'version': '2.0.0',
        'frontend_available': os.path.exists(os.path.join(app.static_folder, 'index.html')),
        'api_integrations': {
            'owasp_zap': 'available',
            'haveibeenpwned': 'available',
            'censys': 'configurable'
        }
    })

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors by serving React app"""
    return serve_frontend()

if __name__ == '__main__':
    # قراءة البورت من متغير البيئة (Railway يستخدم PORT)
    port = int(os.environ.get("PORT", 8080))
    debug_mode = os.environ.get("FLASK_ENV") == "development"
    
    print(f"Starting O-Hunter v2.0 on port {port}")
    print(f"Static folder: {app.static_folder}")
    print(f"Frontend available: {os.path.exists(os.path.join(app.static_folder, 'index.html'))}")
    print("API Integrations:")
    print(f"  - OWASP ZAP: Available")
    print(f"  - HaveIBeenPwned: Available")
    print(f"  - Censys: {'Configured' if os.environ.get('CENSYS_API_ID') else 'Not configured'}")
    
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
