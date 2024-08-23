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

    scanner = VulnerabilityScanner("http://127.0.0.1:8080/", endpoints)
    scanner.run_scans()
    scanner.generate_report()
