import pytest
import requests

BASE_URL = 'http://127.0.0.1:5000'  # Ensure this matches your Flask app URL

def test_establish_api_connection():
    """Test to ensure API connection is established."""
	# Prepare the payload for the POST request
    payload = {
        "target": "http://127.0.0.1:8080",
        "scannerType": "Full Scan"  # Use a valid scanner type
    }

    response = requests.post(f'{BASE_URL}/api/scan', json=payload)  # Change the endpoint as necessary

    # Assert the response status code
    assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"


def test_check_valid_url_submission():
    """Test to ensure valid URL submissions are processed correctly."""
    # Prepare a valid URL and payload
    valid_url = "http://127.0.0.1:8080"
    payload = {
        "target": valid_url,
        "scannerType": "Full Scan"
    }

    # Send the POST request
    response = requests.post(f'{BASE_URL}/api/scan', json=payload)

    # Assert the response status code and response content
    assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
    assert 'report' in response.json(), "Expected response to contain report data."

def test_check_invalid_url_submission():
    """Test to verify error handling for invalid URL submissions."""
    # Prepare an invalid URL and payload
    invalid_url = "invalid-url"
    payload = {
        "target": invalid_url,
        "scannerType": "Full Scan"
    }

    # Send the POST request
    response = requests.post(f'{BASE_URL}/api/scan', json=payload)

    # Assert the response status code and error message
    assert response.status_code == 400, f"Expected status code 400, got {response.status_code}"
    assert 'error' in response.json(), "Expected response to contain an error message."
    assert response.json()['error'] == "Please enter a valid URL.", "Expected specific error message for invalid URL."

# Run tests if this file is executed
if __name__ == "__main__":
    pytest.main()
