#!/usr/bin/env python3
import requests
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger
from urllib.parse import urljoin

class AuthLevelScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("auth_level_check")
        self.context = {}
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, 
             headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None, 
             context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
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
            
        # Set up headers if not provided
        if headers is None:
            headers = {'Authorization': f'Bearer {token}'} if token else {}
            
        # Generate correlation ID for tracking related requests
        correlation_id = str(uuid.uuid4())
        
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url.lstrip('/')
            
        self.logger.info(f"Testing endpoint: {method} {url}")
        
        # Test different privilege levels
        admin_endpoints = [
            {'path': 'admin', 'role': 'admin'},
            {'path': 'manage', 'role': 'manager'},
            {'path': 'console', 'role': 'admin'},
            {'path': 'dashboard', 'role': 'admin'},
            {'path': 'settings', 'role': 'admin'}
        ]
        
        for endpoint in admin_endpoints:
            try:
                test_url = urljoin(url + '/', endpoint['path'])
                self.logger.info(f"Testing admin endpoint: {test_url}")
                
                # Track authentication state for attack chain building
                auth_state = {"token": token, "auth_type": "bearer"} if token else None
                
                # Track authentication state for attack chain building
                auth_state = {"token": token, "auth_type": "bearer"} if token else None
                
                response = requests.request(method, test_url, headers=headers, timeout=5)
                
                # Capture transaction for evidence
                request_data, response_data = self.capture_transaction(
                    response,
                    auth_state=auth_state,
                    correlation_id=correlation_id
                )
                
                # Capture transaction for evidence
                request_data, response_data = self.capture_transaction(
                    response,
                    auth_state=auth_state,
                    correlation_id=correlation_id
                )
                
                if response.status_code == 200:
                    # Create finding with dependencies to show attack chain
                    finding = {
                        "type": "AUTH_LEVEL_BYPASS",
                        "severity": "HIGH",
                        "detail": f"Unauthorized access to {endpoint['role']} endpoint",
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
                        }
                    }
                    vulnerabilities.append(finding)
                    self.logger.warning(f"Found privilege escalation vulnerability")
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing endpoint /{endpoint['path']}: {str(e)}")
                continue
        
        # Test IDOR
        test_ids = ['123', 'admin_123', '../admin', '00000']
        for test_id in test_ids:
            try:
                test_url = urljoin(url + '/', test_id)
                self.logger.info(f"Testing IDOR with ID: {test_id}")
                
                # Track authentication state for attack chain building
                auth_state = {"token": token, "auth_type": "bearer"} if token else None
                
                # Track authentication state for attack chain building
                auth_state = {"token": token, "auth_type": "bearer"} if token else None
                
                response = requests.request(method, test_url, headers=headers, timeout=5)
                
                # Capture transaction for evidence
                request_data, response_data = self.capture_transaction(
                    response,
                    auth_state=auth_state,
                    correlation_id=correlation_id
                )
                
                # Capture transaction for evidence
                request_data, response_data = self.capture_transaction(
                    response,
                    auth_state=auth_state,
                    correlation_id=correlation_id
                )
                
                if response.status_code == 200:
                    # Create finding with dependencies to show attack chain
                    finding = {
                        "type": "IDOR",
                        "severity": "HIGH",
                        "detail": "Insecure Direct Object Reference detected",
                        "evidence": {
                            "request": request_data,
                            "response": response_data,
                            "auth_state": auth_state,
                            "correlation_id": correlation_id,
                            "test_id": test_id
                        },
                        "dependencies": self.context.get('finding_ids', []),
                        "context_update": {
                            "vulnerable_idor_ids": self.context.get("vulnerable_idor_ids", []) + [test_id]
                        }
                    }
                    vulnerabilities.append(finding)
                    self.logger.warning(f"Found IDOR vulnerability")
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing IDOR {test_id}: {str(e)}")
                continue
        
        return vulnerabilities

    def capture_transaction(self, response: requests.Response, auth_state: Dict[str, Any] = None, 
                           correlation_id: str = None) -> tuple:
        """Capture request/response details for evidence"""
        request = response.request
        
        req_data = {
            "method": request.method,
            "url": request.url,
            "headers": dict(request.headers),
            "body": request.body,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        res_data = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:500],  # Truncate long responses
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if auth_state:
            req_data["auth_state"] = auth_state
            res_data["auth_state"] = auth_state
            
        if correlation_id:
            req_data["correlation_id"] = correlation_id
            res_data["correlation_id"] = correlation_id
            
        return req_data, res_data
    
    def update_context(self, context_update: Dict[str, Any]) -> None:
        """Update scanner context with new information"""
        if not hasattr(self, 'context'):
            self.context = {}
            
        self.context.update(context_update)

scan = AuthLevelScanner().scan