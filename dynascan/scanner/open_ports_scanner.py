import socket
from urllib.parse import urlparse


port_vulnerabilities = {
    111: ["Portmap service: Denial of Service", "Remote code execution"],
    8080: ["Weak authentication on web servers", "Cross-Site Scripting (XSS)"],
    9090: ["Weak authentication", "Directory traversal"]
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

    parsed_url = urlparse(target)
    target = parsed_url.hostname or target

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Set a timeout for the connection attempt
            result = sock.connect_ex((target, port))
            if result == 0:
                # If the port is open, check for known vulnerabilities
                vulns = port_vulnerabilities.get(port, ["No known vulnerabilities"])
                for vuln in vulns:
                    open_ports.append({
                        "issue": f"Open Port: {port}",
                        "description": f"Detected vulnerability: {vuln}",
                        "severity": "High" if port in port_vulnerabilities else "Informational",
                        "endpoint": f"{target}:{port}"
                    })
            sock.close()

        except Exception as e:
            open_ports.append({
                "issue": f"Open Port: {port}",
                "description": f"Error occurred while scanning port {port}: {str(e)}",
                "severity": "Medium",
                "endpoint": f"{target}:{port}"
            })

    return open_ports
