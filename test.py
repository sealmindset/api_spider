import requests
import yaml
import json
import sys

def load_swagger(file_path):
    """Load the swagger (OpenAPI) YAML file."""
    try:
        with open(file_path, 'r') as f:
            swagger = yaml.safe_load(f)
            print("Successfully loaded swagger file.")
            return swagger
    except Exception as e:
        print(f"Error loading swagger file: {e}")
        sys.exit(1)

def get_base_url(swagger):
    """Extract the base URL from the swagger file."""
    servers = swagger.get("servers", [])
    if servers:
        return servers[0].get("url")
    return None

def find_endpoint(swagger, keyword):
    """
    Search the swagger 'paths' for an endpoint containing the given keyword.
    Returns the first matching path.
    """
    for path in swagger.get("paths", {}):
        if keyword.lower() in path.lower():
            return path
    return None

def sign_up(base_url, sign_up_endpoint, email, password):
    url = base_url + sign_up_endpoint
    payload = {"email": email, "password": password}
    print(f"[*] Signing up at {url} with email: {email}")
    response = requests.post(url, json=payload)
    print(f"[+] Sign-up response: {response.status_code}\n{response.text}")
    return response

def check_user(base_url, check_endpoint, email):
    url = base_url + check_endpoint
    params = {"email": email}
    print(f"[*] Checking account existence at {url} for email: {email}")
    response = requests.get(url, params=params)
    print(f"[+] Check response: {response.status_code}\n{response.text}")
    return response

def sign_in(base_url, sign_in_endpoint, email, password):
    url = base_url + sign_in_endpoint
    payload = {"email": email, "password": password}
    print(f"[*] Signing in at {url} for email: {email}")
    response = requests.post(url, json=payload)
    print(f"[+] Sign-in response: {response.status_code}\n{response.text}")
    return response

def get_user_details(base_url, user_endpoint, token):
    url = base_url + user_endpoint
    headers = {"Authorization": f"Bearer {token}"}
    print(f"[*] Getting user details from {url}")
    response = requests.get(url, headers=headers)
    print(f"[+] User details response: {response.status_code}\n{response.text}")
    return response

def refresh_token(base_url, refresh_endpoint, refresh_token_value):
    url = base_url + refresh_endpoint
    payload = {"refreshToken": refresh_token_value}
    print(f"[*] Refreshing token at {url}")
    response = requests.post(url, json=payload)
    print(f"[+] Refresh token response: {response.status_code}\n{response.text}")
    return response

def main():
    # Load swagger file (snorefox.yml)
    swagger = load_swagger("snorefox.yml")
    
    # Get the base URL from swagger
    base_url = get_base_url(swagger)
    if not base_url:
        print("Base URL not found in swagger.")
        sys.exit(1)
    print(f"Base URL: {base_url}")

    # Dynamically find endpoints based on key text
    sign_up_endpoint = find_endpoint(swagger, "sign-up")
    sign_in_endpoint = find_endpoint(swagger, "sign-in")
    check_endpoint = find_endpoint(swagger, "auth/check")
    refresh_endpoint = find_endpoint(swagger, "refresh-tokens")
    user_endpoint = find_endpoint(swagger, "users/me")

    print("Detected endpoints:")
    print(f"  Sign-up: {sign_up_endpoint}")
    print(f"  Sign-in: {sign_in_endpoint}")
    print(f"  Auth Check: {check_endpoint}")
    print(f"  Refresh Tokens: {refresh_endpoint}")
    print(f"  User Details: {user_endpoint}")

    # Ensure all required endpoints are found
    if not all([sign_up_endpoint, sign_in_endpoint, check_endpoint, refresh_endpoint, user_endpoint]):
        print("One or more required endpoints were not found in the swagger file.")
        sys.exit(1)

    # Define credentials for the initial account
    password = "Password#123"
    initial_email = "user_initial@example.com"

    # --- Step 1: Sign-Up ---
    signup_resp = sign_up(base_url, sign_up_endpoint, initial_email, password)
    if signup_resp.status_code != 201:
        print("Sign-up failed. Exiting.")
        sys.exit(1)

    # --- Step 2: Check Account Existence ---
    check_resp = check_user(base_url, check_endpoint, initial_email)
    # (Optionally add validation logic on the check response)

    # --- Step 3: Sign-In ---
    signin_resp = sign_in(base_url, sign_in_endpoint, initial_email, password)
    if signin_resp.status_code != 200:
        print("Sign-in failed. Exiting.")
        sys.exit(1)
    tokens = signin_resp.json()
    access_token = tokens.get("accessToken")
    refresh_token_value = tokens.get("refreshToken")
    if not access_token:
        print("No access token received. Exiting.")
        sys.exit(1)

    # --- Step 4: Get User Details ---
    user_resp = get_user_details(base_url, user_endpoint, access_token)

    # --- Step 5: Refresh Tokens ---
    refresh_resp = refresh_token(base_url, refresh_endpoint, refresh_token_value)

    print("Authentication flow completed successfully.")

if __name__ == "__main__":
    main()
