#!/usr/bin/env python3
"""
Mass Assignment Vulnerability Scanner
Checks if an API endpoint is vulnerable to mass assignment attacks
by attempting to set unauthorized properties during object creation/update.
"""

import requests
import time
from typing import Dict, List, Optional, Any
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class MassAssignmentOnlyScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("mass_assignment_only")
        self.target = None
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, 
             headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None, 
             context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        self.base_url = url
        self.target = url
        vulnerabilities = []
        
        # Test payloads for mass assignment
        test_payloads = [
            {
                "username": f"test_mass_{int(time.time())}",
                "password": "test1",
                "email": f"test_mass_{int(time.time())}@dom.com",
                "internal_id": "12345",  # Restricted field
                "created_at": "2020-01-01",  # Timestamp manipulation
                "verified": True,  # Status manipulation
                "credits": 99999  # Balance manipulation
            },
            {
                "username": f"test_mass_{int(time.time())}_2",
                "password": "test2",
                "email": f"test_mass_{int(time.time())}_2@dom.com",
                "user_type": "premium",  # Role manipulation
                "account_balance": 1000000,  # Financial manipulation
                "verification_status": "verified"  # Status manipulation
            }
        ]
        
        for test_payload in test_payloads:
            try:
                # Headers setup
                request_headers = headers or {}
                request_headers['Content-Type'] = 'application/json'
                
                # Generate correlation ID for tracking related requests
                correlation_id = str(time.time())
                
                # Try to create user with restricted fields
                register_resp = requests.post(
                    f"{url}/users/v1/register",
                    json=test_payload,
                    headers=request_headers,
                    timeout=5
                )
                
                # Capture request/response data
                register_data, register_response = self.capture_transaction(
                    register_resp,
                    auth_state={"auth_type": "none"},
                    correlation_id=correlation_id
                )
                
                # Check if any restricted fields were accepted
                if register_resp.status_code == 200:
                    response_body = register_resp.json()
                    accepted_fields = []
                    
                    # Check which restricted fields were accepted
                    for field in ['internal_id', 'created_at', 'verified', 'credits',
                                'user_type', 'account_balance', 'verification_status']:
                        if field in test_payload and field in response_body:
                            if response_body[field] == test_payload[field]:
                                accepted_fields.append(field)
                    
                    if accepted_fields:
                        vulnerabilities.append({
                            "type": "MASS_ASSIGNMENT",
                            "severity": "HIGH",
                            "detail": f"Mass assignment vulnerability detected - unauthorized fields accepted: {', '.join(accepted_fields)}",
                            "evidence": {
                                "request": register_data,
                                "response": register_response,
                                "accepted_fields": accepted_fields,
                                "payload": test_payload
                            },
                            "remediation": "Implement proper input validation and whitelist only allowed fields"
                        })
                        
            except requests.RequestException as e:
                self.logger.error(f"Error in mass assignment check: {str(e)}")
                
        return vulnerabilities

# Keep the scan function for backward compatibility
scan = MassAssignmentOnlyScanner().scan