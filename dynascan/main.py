# main.py
from scanner_engine.vulnerability_scanner import VulnerabilityScanner

if __name__ == "__main__":
    endpoints = {
        "WebGoat/SqlInjection/attack": {"username": "test", "password": "test"},
        "WebGoat/XSS/attack": {"q": "test"},
        "WebGoat/Auth/login": {"username": "test", "password": "test"},
        "WebGoat/SensitiveData": {},
        "WebGoat/AccessControl/attack": {},
        "WebGoat/Deserialization/attack": {"data": "test"}
    }

    base_url = "http://127.0.0.1:8080/"

    target_ip = "127.0.0.1"  

    scanner = VulnerabilityScanner(base_url, endpoints, target_ip)
    
    scanner.run_scans()

    scanner.generate_report()
