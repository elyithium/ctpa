#main.py
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from scanner_engine.vulnerability_scanner import VulnerabilityScanner
import os
import json
from datetime import datetime

app = Flask(__name__)
CORS(app)  # This will allow your frontend to make requests to the backend

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    target_url = data.get('target')
    scanner_type = data.get('scannerType')

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

    if scanner_type == 'Full Scan':
        scanner.run_scans(scan_type='Full Scan')
    elif scanner_type == 'Broken Access Control':
        scanner.run_scans(scan_type='Broken Access Control')
    elif scanner_type == 'Injection':
        scanner.run_scans(scan_type='Injection')
    elif scanner_type == 'Cryptographic Failures':
        scanner.run_scans(scan_type='Cryptographic Failures')
    elif scanner_type == 'Security Misconfiguration':
        scanner.run_scans(scan_type='Security Misconfiguration')
    elif scanner_type == 'Reconnaissance':
        scanner.run_scans(scan_type='Reconnaissance')
    else:
        return jsonify({"error": "Invalid scanner type"}), 400

    scanner.generate_console_report()

    report_id, file_path = scanner.generate_pdf_report()

    report_data = {
        "_id": report_id,
        "vulnerabilities": scanner.results,
        "target": target_url,
        "createdAt": datetime.now().strftime('%a, %d %b %Y %H:%M:%S')
    }

    # Save the JSON report
    json_file_path = f"reports/vulnerability_report_{report_id}.json"
    with open(json_file_path, 'w') as json_file:
        json.dump(report_data, json_file)

    return jsonify({"report": report_data}), 200


@app.route('/api/report_data/<report_id>', methods=['GET'])
def get_report_data(report_id):
    try:
        file_path = f"reports/vulnerability_report_{report_id}.json"

        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                report_data = json.load(file)
            return jsonify({"report": report_data}), 200
        else:
            return jsonify({"error": "Report data not found"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/reports/<report_id>', methods=['GET'])
def get_report(report_id):
    try:
        # Assuming the report files are stored with the report ID as the filename
        file_path = f"./reports/{report_id}"
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        else:
            return jsonify({"error": "Report not found"}), 404
    except FileNotFoundError:
        return jsonify({"error": "Report not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
