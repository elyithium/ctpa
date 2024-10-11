import socket


port_vulnerabilities = {
    111: [
        {
            "issue": "Portmap Service Vulnerability",
            "description": "Portmap service on port 111 is vulnerable to Denial of Service and Remote Code Execution.",
            "severity": "High"
        }
    ],
    8080: [
        {
            "issue": "Weak Authentication on Web Server",
            "description": "Port 8080 is used by web servers that may have weak authentication mechanisms.",
            "severity": "Medium"
        },
        {
            "issue": "Cross-Site Scripting (XSS)",
            "description": "Potential XSS vulnerability found on web server running on port 8080.",
            "severity": "High"
        }
    ],
    9090: [
        {
            "issue": "Weak Authentication",
            "description": "Port 9090 is often used by applications with weak or misconfigured authentication.",
            "severity": "Medium"
        },
        {
            "issue": "Directory Traversal",
            "description": "Applications running on port 9090 may be vulnerable to directory traversal attacks.",
            "severity": "High"
        }
    ]
}

common_tcp_ports = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723,
    3306, 3389, 5900, 8080, 8443, 8888, 9090, 49152, 49153, 49154, 49155, 49156,
    49157, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1720, 5060, 5061, 8000, 8008,
    8010, 8020, 8021, 8030, 8031, 8040, 8041, 8081, 8082, 8181, 8880, 8881, 9000,
    9001, 9002, 9003, 9091, 10000, 20000, 32768, 49158, 49159, 49160, 49161, 49162,
    49163, 49164, 49165, 49166, 49167, 49168, 49169, 49170, 49171, 49172, 49173,
    49174, 49175, 49176, 49177, 49178, 49179, 49180, 49181, 49182, 49183, 49184,
    49185, 49186, 49187, 49188, 49189, 49190, 49191, 49192, 49193, 49194, 49195
]

def scan_open_ports(target, ports):
    open_ports = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Set a timeout for the connection attempt
            result = sock.connect_ex((target, port))
            if result == 0:
                # If the port is open, check for known vulnerabilities
                port_vulns = port_vulnerabilities.get(port)

                if port_vulns:
                    open_ports.append({
                        "port": port,
                        "vulnerabilities": port_vulns
                    })
                else:
                    open_ports.append({
                        "port": port,
                        "vulnerabilities": [{
                            "issue": "Unknown Issues",
                            "description": f"No specific vulnerabilities known for port {port}.",
                            "severity": "Informational"
                        }]
                    })

            sock.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")

    return open_ports
