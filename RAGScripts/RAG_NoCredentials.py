#!/usr/bin/env python3

from typing import Dict, List, Any, Optional
import requests
from urllib.parse import urljoin
from .base_scanner import BaseScanner
from .utils.logger import setup_scanner_logger

class NoCredentialsScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("no_credentials_scanner")

    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, 
             headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None, 
             context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        # Use paths from the context if available
        sensitive_endpoints = []
        
        # If path is provided, use it as the primary endpoint to check
        if path:
            sensitive_endpoints.append(path)
            
        # Look for potential sensitive endpoints in the context if available
        if context and 'paths' in context:
            for api_path in context['paths']:
                # Look for endpoints that might be sensitive
                if any(keyword in api_path.lower() for keyword in ['debug', 'me', 'user', 'admin', 'profile', 'account', 'settings', 'dashboard', 'console', 'manage']):
                    sensitive_endpoints.append(api_path)
        
        # If no endpoints found in context, log warning and return
        if not sensitive_endpoints:
            self.logger.warning("No paths found in context for testing")
            return vulnerabilities
        
        # Test each sensitive endpoint without authentication
        for endpoint in sensitive_endpoints:
            try:
                test_url = urljoin(url, endpoint)
                self.logger.info(f"Testing endpoint without credentials: {test_url}")
                
                # Make request without any authentication
                response = requests.get(
                    test_url,
                    timeout=5,
                    allow_redirects=False  # Don't follow redirects to auth pages
                )
                
                # Check if endpoint is accessible (200 OK) without credentials
                if response.status_code == 200:
                    try:
                        # Try to parse response as JSON to check for actual data
                        response_data = response.json()
                        
                        # Check for sensitive data exposure in debug endpoint
                        if endpoint == "/users/v1/_debug" and "users" in response_data:
                            users = response_data.get("users", [])
                            exposed_data = [
                                {
                                    "username": user.get("username"),
                                    "email": user.get("email"),
                                    "admin": user.get("admin"),
                                    "has_password": "password" in user
                                } for user in users
                            ]
                            
                            finding = {
                                "type": "EXCESSIVE_DATA_EXPOSURE",
                                "severity": "CRITICAL",
                                "detail": "Debug endpoint exposes sensitive user data including credentials and roles without authentication",
                                "evidence": {
                                    "url": test_url,
                                    "method": "GET",
                                    "status_code": response.status_code,
                                    "headers": dict(response.headers),
                                    "exposed_data_sample": exposed_data[:2],
                                    "total_users_exposed": len(users),
                                    "authentication_state": "No credentials provided"
                                },
                                "remediation": {
                                    "description": "Debug endpoint exposing sensitive user data without authentication",
                                    "impact": "Unauthorized access to user credentials and role information",
                                    "steps": [
                                        "Remove or properly secure debug endpoints in production",
                                        "Implement authentication for all sensitive endpoints",
                                        "Limit exposed data to necessary fields only",
                                        "Add proper access controls and role checks",
                                        "Implement request logging and monitoring"
                                    ]
                                }
                            }
                            vulnerabilities.append(finding)
                            self.logger.warning(f"Found EXCESSIVE_DATA_EXPOSURE vulnerability at {endpoint}")
                            
                        else:
                            # Original NO_CREDENTIALS_REQUIRED finding
                            finding = {
                                "type": "NO_CREDENTIALS_REQUIRED",
                                "severity": "HIGH",
                                "detail": f"Sensitive endpoint {endpoint} is accessible without authentication",
                                "evidence": {
                                    "url": test_url,
                                    "method": "GET",
                                    "status_code": response.status_code,
                                    "headers": dict(response.headers),
                                    "response_sample": str(response_data)[:200],
                                    "authentication_state": "No credentials provided"
                                }
                            }
                            vulnerabilities.append(finding)
                        
            except requests.RequestException as e:
                self.logger.error(f"Error testing endpoint {endpoint}: {str(e)}")
                continue
                
        return vulnerabilities