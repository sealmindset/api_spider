import requests
import json
import time
from typing import Dict, Optional
from urllib.parse import urljoin

class BIQAuthClient:
    def __init__(self, base_url: str = "http://localhost:3000/api/v1/mobile"):
        self.base_url = base_url.rstrip('/')
        self.email = None
        self.password = None
        self.access_token = None
        self.refresh_token = None
        self.id_token = None
        self.user_id = None

    def sign_up(self, email: str, password: str) -> Dict:
        """Create a new account"""
        url = f"{self.base_url}/auth/sign-up"
        payload = {
            "email": email,
            "password": password
        }
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json'
        }

        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        self.email = email
        self.password = password
        self.user_id = data.get('id')
        
        return data

    def verify_account(self) -> Dict:
        """Verify that the account was created successfully"""
        if not self.email:
            raise ValueError("No email available. Please sign up first.")

        url = f"{self.base_url}/auth/check"
        params = {"email": self.email}
        headers = {'accept': 'application/json'}

        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
        
        return response.json()

    def sign_in(self) -> Dict:
        """Sign in to get access tokens"""
        if not (self.email and self.password):
            raise ValueError("No credentials available. Please sign up first.")

        url = f"{self.base_url}/auth/sign-in"
        payload = {
            "email": self.email,
            "password": self.password
        }
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json'
        }

        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        self.access_token = data.get('accessToken')
        self.refresh_token = data.get('refreshToken')
        self.id_token = data.get('idToken')
        
        return data

    def get_user_profile(self) -> Dict:
        """Get user profile information"""
        if not self.access_token:
            raise ValueError("No access token available. Please sign in first.")

        url = f"{self.base_url}/users/me"
        headers = {
            'accept': 'application/json',
            'Authorization': f'Bearer {self.access_token}'
        }

        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        return response.json()

    def get_subscription_status(self) -> Dict:
        """Get subscription information"""
        if not self.access_token:
            raise ValueError("No access token available. Please sign in first.")

        url = f"{self.base_url}/users/me/subscription"
        headers = {
            'accept': 'application/json',
            'Authorization': f'Bearer {self.access_token}'
        }

        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        return response.json()

    def get_device_info(self) -> Dict:
        """Get device information"""
        if not self.access_token:
            raise ValueError("No access token available. Please sign in first.")

        url = f"{self.base_url}/users/me/device-info"
        headers = {
            'accept': 'application/json',
            'Authorization': f'Bearer {self.access_token}'
        }

        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        return response.json()

    def get_personal_health_info(self) -> Dict:
        """Get personal health information"""
        if not self.access_token:
            raise ValueError("No access token available. Please sign in first.")

        url = f"{self.base_url}/users/me/personal-health-info"
        headers = {
            'accept': 'application/json',
            'Authorization': f'Bearer {self.access_token}'
        }

        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        return response.json()

    def refresh_tokens(self) -> Dict:
        """Refresh access and ID tokens using refresh token"""
        if not self.refresh_token:
            raise ValueError("No refresh token available. Please sign in first.")

        url = f"{self.base_url}/auth/refresh-tokens"
        payload = {"refreshToken": self.refresh_token}
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json'
        }

        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        self.access_token = data.get('accessToken')
        self.id_token = data.get('idToken')
        
        return data

def main():
    # Initialize the client
    client = BIQAuthClient()
    
    try:
        # Step 1: Sign up
        print("\nStep 1: Creating account...")
        signup_response = client.sign_up("user16mill@example.com", "Password#123")
        print(f"Account created with ID: {signup_response.get('id')}")

        # Step 2: Verify account
        print("\nStep 2: Verifying account...")
        verify_response = client.verify_account()
        print(f"Account verification status: {verify_response}")

        # Step 3: Sign in
        print("\nStep 3: Signing in...")
        signin_response = client.sign_in()
        print("Successfully signed in and received tokens")

        # Step 4: Get user profile
        print("\nStep 4: Getting user profile...")
        profile = client.get_user_profile()
        print(f"User profile ID: {profile.get('_id')}")

        # Step 5: Get subscription status
        print("\nStep 5: Getting subscription status...")
        subscription = client.get_subscription_status()
        print(f"Subscription type: {subscription.get('subscription', {}).get('subscriptionType')}")

        # Step 6: Get device info
        print("\nStep 6: Getting device info...")
        device_info = client.get_device_info()
        print(f"Device info: {device_info}")

        # Step 7: Get personal health info
        print("\nStep 7: Getting personal health info...")
        health_info = client.get_personal_health_info()
        print(f"Health info: {health_info}")

        # Step 8: Refresh tokens
        print("\nStep 8: Refreshing tokens...")
        refresh_response = client.refresh_tokens()
        print("Successfully refreshed tokens")

    except requests.exceptions.RequestException as e:
        print(f"Error during API request: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()