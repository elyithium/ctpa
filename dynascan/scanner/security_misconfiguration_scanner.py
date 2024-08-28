import requests

# Defining the headers that are required to be checked 
Header_list = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Feature-Policy"
]

def scan_security_misconfigurations(url):
    try:
        # Sending an HTTP GET request to the provided URL
        response = requests.get(url)
        response.raise_for_status()  # Check if the request returned an HTTP error
    except requests.RequestException as e:
        return [f"Error fetching URL {url}: {e}"]

    # Checking for missing headers
    missing_headers = []
    for header in Header_list:
        if header not in response.headers:
            missing_headers.append(f"{header} header missing")

    # Scan for RIA policy files
    ria_vulnerabilities = scan_for_ria_policy_files(url)
    
    return missing_headers + ria_vulnerabilities

def scan_for_ria_policy_files(base_url):
    # List of RIA policy files to check for
    policy_files = ["crossdomain.xml", "clientaccesspolicy.xml"]
    vulnerabilities = []
    
    # Iterate over the policy files and construct the Url
    for policy_file in policy_files:
        policy_url = f"{base_url}/{policy_file}"
        try:
            # Send a GET request to the policy file URL
            response = requests.get(policy_url)
            #If the status is OK
            if response.status_code == 200:
                 # Policy file was found
                vulnerabilities.append(f"Found {policy_file} at {policy_url}")
                # Check if the policy file is overly permissive - Policies with “*” in them should be closely examined
                if "*" in response.text:
                    vulnerabilities.append(f"Overly permissive policy found in {policy_file} at {policy_url}")
            else:
                 # Policy file was not found
                vulnerabilities.append(f"{policy_file} not found at {policy_url}")
      # Handling request exceptions
        except requests.RequestException as reqexceptions:
            vulnerabilities.append(f"Error accessing {policy_file} at {policy_url}: {reqexceptions}")
    
    return vulnerabilities
