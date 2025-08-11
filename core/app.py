import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from scanner import Scanner

app = Flask(__name__, static_folder='../gui/ohunter-ui/dist', static_url_path='')
CORS(app)

@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/scan', methods=['POST'])
def scan_endpoint():
    data = request.get_json()
    target_url = data.get('target_url')
    
    if not target_url:
        return jsonify({'error': 'Target URL is required'}), 400
    
    scanner = Scanner()
    
    # Run basic scans
    scanner.run_all_scans(
        target_url,
        sqli_params={'param_name': 'id'},
        xss_params={'param_name': 'search'},
        ssrf_params={'param_name': 'url'}
    )
    
    findings = scanner.get_findings()
    
    return jsonify({
        'target_url': target_url,
        'findings': findings,
        'total_findings': len(findings)
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'message': 'O-Hunter API is running'})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
