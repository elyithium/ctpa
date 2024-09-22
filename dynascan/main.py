#main.py
from scanner_engine.vulnerability_scanner import VulnerabilityScanner

if __name__ == "__main__":
    endpoints = {
        "WebGoat/SqlInjectionAdvanced/lesson1": {"last_name": ""},
        "WebGoat/SqlInjectionAdvanced/lesson2": {"last_name": ""},
        "WebGoat/SqlInjectionAdvanced/lesson3": {"last_name": ""},
        "WebGoat/SqlInjectionAdvanced/challenge": {"username_reg": "Tom"},
        "WebGoat/XSS/attack": {"q": "test"},
        "WebGoat/Auth/login": {"username": "test", "password": "test"},
        "WebGoat/SensitiveData": {},
        "WebGoat/AccessControl/attack": {},
        "WebGoat/Deserialization/attack": {"data": "test"},
        "WebGoat/login": {},
        "WebGoat/CSRF": {}  # CSRF endpoint
    }

    base_url = "http://127.0.0.1:8080/"
    target_ip = "127.0.0.1"

    host_info_url = "http://127.0.0.1:8080/WebGoat/login"

    scanner = VulnerabilityScanner(base_url, endpoints, target_ip, host_info_url)

    scanner.run_scans()
    scanner.generate_report()
