from scanner_engine.vulnerability_scanner import VulnerabilityScanner

if __name__ == "__main__":
    # endpoints for site
    endpoints = {
          #"https://www.hackthissite.org/": {"username": "test", "password": "test"}
          "WebGoat/SqlInjection/attack": {"username": "test", "password": "test"},
          "WebGoat/XSS/attack": {"q": "test"},
          "WebGoat/Auth/login": {"username": "test", "password": "test"},
          "WebGoat/SensitiveData": {},
          "WebGoat/AccessControl/attack": {},
          "WebGoat/Deserialization/attack": {"data": "test"}
     }


     # Scanner Site and run scan call
    scanner = VulnerabilityScanner("http://127.0.0.1:8080/", endpoints)
    #scanner = VulnerabilityScanner("https://www.hackthissite.org/", endpoints)
    scanner.run_scans()

     # Generate Report Change to pdf or console
    scanner.generate_report(output_format='pdf')


    #Console Commands:
    #docker build -t dynascan .
    #docker run --network="host" -v "${pwd}/reports:/app/reports" -it --rm dynascan
