#main.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from scanner_engine.vulnerability_scanner import VulnerabilityScanner

app = Flask(__name__)
CORS(app)  # This will allow your frontend to make requests to the backend

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    target_url = data.get('target')
    if not target_url:
        return jsonify({"error": "No target URL provided"}), 400

    endpoints = {
        "WebGoat/SqlInjectionAdvanced/lesson1": {"last_name": ""},
        "WebGoat/SqlInjectionAdvanced/lesson2": {"last_name": ""},
        "WebGoat/SqlInjectionAdvanced/lesson3": {"last_name": ""},
        "WebGoat/SqlInjectionAdvanced/challenge": {"username_reg": "Tom"},
        "WebGoat/XSS/attack": {"q": "test"},
        "WebGoat/Auth/login": {"username": "test", "password": "test"},
        "WebGoat/SensitiveData": {},
        "WebGoat/AccessControl/attack": {},
        "WebGoat/login": {},
        "WebGoat/CSRF": {}
    }
    base_url = target_url  # Using target_url as base_url
    target_ip = "127.0.0.1"  # Use actual IP based on the scan target

    scanner = VulnerabilityScanner(base_url, endpoints, target_ip, target_url)
    scanner.run_scans()
    scanner.generate_report()
    scanner.generate_pdf_report()
    results = scanner.results

    return jsonify({"report": {"vulnerabilities": results}}), 200

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
