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

        #  Sending an HTTP GET request to the provided Url
        response = requests.get(url)
        
        # Checks if the request returned an HTTP error 
        response.raise_for_status()  

    except requests.RequestException as e:

        return [f"Error fetching URL {url}: {e}"]


    # Checking for missing headers
    missing_headers = []

    for header in Header_list:

        if header not in response.headers:

            missing_headers.append(f"{header} header missing")

    # Returns the list of missing headers
    return missing_headers

