#!/usr/bin/env python3
"""
Privilege Escalation Vulnerability Scanner
Checks if an API endpoint is vulnerable to privilege escalation attacks
by attempting to access privileged endpoints and functions without proper authorization.
"""

import requests
import uuid
import time
from urllib.parse import urljoin
from typing import Dict, List, Optional, Any
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class PrivilegeEscalationScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("privilege_escalation")
        self.target = None
        
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
            
            # Use finding IDs from previous scans for dependency tracking
            dependencies = context.get('finding_ids', [])
            self.logger.info(f"Using {len(dependencies)} dependencies from previous findings")
            
            # Use credentials discovered by other scanners
            credentials = context.get('credentials', [])
            self.logger.info(f"Using {len(credentials)} credentials from other scanners")
        
        # Use tokens from other scanners if available
        available_tokens = []
        if tokens and 'bearer' in tokens:
            available_tokens = [t.get('token') for t in tokens.get('bearer', [])]
            self.logger.info(f"Using {len(available_tokens)} bearer tokens from other scanners")
        
        # Generate correlation ID for tracking related requests
        correlation_id = str(uuid.uuid4())
        
        # Set up headers if not provided
        if headers is None:
            headers = {'Authorization': f'Bearer {token}'} if token else {}
        
        # Test privileged endpoints
        privileged_endpoints = [
            {'path': 'admin', 'role': 'admin'},
            {'path': 'admin/users', 'role': 'admin'},
            {'path': 'admin/settings', 'role': 'admin'},
            {'path': 'manage', 'role': 'manager'},
            {'path': 'api/v1/admin', 'role': 'admin'},
            {'path': 'dashboard', 'role': 'admin'},
            {'path': 'console', 'role': 'admin'},
            {'path': 'settings', 'role': 'admin'},
            {'path': 'users/v1/_debug', 'role': 'admin'}
        ]
        
        # First check if we can access the debug endpoint to establish baseline
        debug_accessible = False
        debug_users = []
        try:
            debug_url = urljoin(url + '/', 'users/v1/_debug')
            debug_resp = requests.get(debug_url, headers=headers, timeout=5)
            if debug_resp.status_code == 200:
                debug_accessible = True
                debug_data = debug_resp.json()
                if 'users' in debug_data:
                    debug_users = debug_data.get('users', [])
                    self.logger.info(f"Found {len(debug_users)} users in debug endpoint")
        except requests.RequestException as e:
            self.logger.error(f"Error accessing debug endpoint: {str(e)}")
        
        for endpoint in privileged_endpoints:
            try:
                test_url = urljoin(url + '/', endpoint['path'])
                self.logger.info(f"Testing privileged endpoint: {test_url}")
                
                # Skip debug endpoint if we already checked it
                if endpoint['path'] == 'users/v1/_debug' and debug_accessible:
                    continue
                
                # Track authentication state for attack chain building
                auth_state = {"token": token, "auth_type": "bearer"} if token else {"auth_type": "none"}
                
                # Try to access privileged endpoint
                response = requests.get(
                    test_url,
                    headers=headers,
                    timeout=5
                )
                
                # Capture transaction for evidence
                request_data, response_data = self.capture_transaction(
                    response,
                    auth_state=auth_state,
                    correlation_id=correlation_id
                )
                
                if response.status_code == 200:
                    # Verify this is actually returning privileged data, not just a 200 OK
                    is_privileged_data = False
                    try:
                        # Try to parse as JSON and look for indicators of privileged data
                        resp_json = response.json()
                        # Check for common admin data indicators
                        if any(key in resp_json for key in ['users', 'settings', 'admin', 'configuration', 'roles']):
                            is_privileged_data = True
                    except:
                        # If not JSON, check for admin-related terms in the response
                        admin_terms = ['admin', 'dashboard', 'management', 'configuration', 'settings']
                        if any(term in response.text.lower() for term in admin_terms):
                            is_privileged_data = True
                    
                    if is_privileged_data:
                        # Create finding with dependencies to show attack chain
                        finding = {
                            "type": "PRIVILEGE_ESCALATION",
                            "severity": "HIGH",
                            "detail": f"Unauthorized access to {endpoint['role']} endpoint: {endpoint['path']}",
                            "evidence": {
                                "request": request_data,
                                "response": response_data,
                                "auth_state": auth_state,
                                "correlation_id": correlation_id,
                                "required_role": endpoint['role']
                            },
                            "dependencies": self.context.get('finding_ids', []),
                            "context_update": {
                                "vulnerable_admin_endpoints": self.context.get("vulnerable_admin_endpoints", []) + [endpoint['path']]
                            },
                            "remediation": "Implement proper authorization checks and role-based access control"
                        }
                        vulnerabilities.append(finding)
                        self.logger.warning(f"Found privilege escalation vulnerability at {endpoint['path']}")
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing endpoint /{endpoint['path']}: {str(e)}")
                continue
        
        # Test function-level privilege escalation
        privileged_functions = [
            {
                'path': 'users/v1/admin/create',
                'method': 'POST',
                'payload': {"username": "test_admin", "password": "test123", "role": "admin"},
                'role': 'admin'
            },
            {
                'path': 'users/v1/role',
                'method': 'PUT',
                'payload': {"username": "test1", "role": "admin"},
                'role': 'admin'
            },
            {
                'path': 'api/v1/config',
                'method': 'PUT',
                'payload': {"setting": "debug", "value": "true"},
                'role': 'admin'
            }
        ]
        
        for function in privileged_functions:
            try:
                test_url = urljoin(url + '/', function['path'])
                self.logger.info(f"Testing privileged function: {test_url}")
                
                # Track authentication state for attack chain building
                auth_state = {"token": token, "auth_type": "bearer"} if token else {"auth_type": "none"}
                
                # Set up headers
                request_headers = headers.copy()
                request_headers['Content-Type'] = 'application/json'
                
                # Try to access privileged function
                response = requests.request(
                    function['method'],
                    test_url,
                    json=function['payload'],
                    headers=request_headers,
                    timeout=5
                )
                
                # Capture transaction for evidence
                request_data, response_data = self.capture_transaction(
                    response,
                    auth_state=auth_state,
                    correlation_id=correlation_id
                )
                
                if response.status_code in [200, 201, 204]:
                    # Create finding with dependencies to show attack chain
                    finding = {
                        "type": "PRIVILEGE_ESCALATION",
                        "severity": "CRITICAL",
                        "detail": f"Unauthorized access to {function['role']} function: {function['path']}",
                        "evidence": {
                            "request": request_data,
                            "response": response_data,
                            "auth_state": auth_state,
                            "correlation_id": correlation_id,
                            "required_role": function['role'],
                            "payload": function['payload']
                        },
                        "dependencies": self.context.get('finding_ids', []),
                        "context_update": {
                            "vulnerable_admin_functions": self.context.get("vulnerable_admin_functions", []) + [function['path']]
                        },
                        "remediation": "Implement proper authorization checks and role-based access control"
                    }
                    vulnerabilities.append(finding)
                    self.logger.warning(f"Found privilege escalation vulnerability at {function['path']}")
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing function {function['path']}: {str(e)}")
                continue
                
        return vulnerabilities

# Keep the scan function for backward compatibility
scan = PrivilegeEscalationScanner().scan