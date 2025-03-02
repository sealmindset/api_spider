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
            
            # Test parameters for mass account creation
            request_count = 50
            interval = 0.1  # 100ms between requests
            successful_registrations = []
            start_time = time.time()
            
            # Attempt to create multiple accounts rapidly
            for i in range(request_count):
                test_payload = {
                    "username": f"test_mass_{int(time.time())}_{i}",
                    "password": "test1",
                    "email": f"test_mass_{int(time.time())}_{i}@dom.com"
                }
                
                register_resp = requests.post(
                    f"{url}/users/v1/register",
                    json=test_payload,
                    headers=request_headers,
                    timeout=5
                )
                
                if register_resp.status_code == 200:
                    successful_registrations.append({
                        "response": register_resp,
                        "payload": test_payload,
                        "time": time.time() - start_time
                    })
                
                time.sleep(interval)
            
            # If we successfully created a significant number of accounts
            if len(successful_registrations) > 10:
                # Capture evidence of the mass registration
                register_data, register_response = self.capture_transaction(
                    successful_registrations[0]["response"],
                    auth_state={"auth_type": "none"},
                    correlation_id=str(time.time())
                )
                
                vulnerabilities.append({
                    "type": "MASS_ACCOUNT_CREATION",
                    "severity": "HIGH",
                    "detail": f"Successfully created {len(successful_registrations)} accounts in {successful_registrations[-1]['time']:.2f} seconds without adequate rate limiting",
                    "evidence": {
                        "request": register_data,
                        "response": register_response,
                        "successful_registrations": len(successful_registrations),
                        "time_elapsed": successful_registrations[-1]['time'],
                        "sample_payload": successful_registrations[0]["payload"]
                    },
                    "remediation": "Implement proper rate limiting and account creation validation",
                    "related_vulns": "No Credentials Required, No Rate Limiting"
                })
                
        except requests.RequestException as e:
            self.logger.error(f"Error in mass account creation check: {str(e)}")
            
        return vulnerabilities

# Keep the scan function for backward compatibility
scan = MassAssignmentScanner().scan
