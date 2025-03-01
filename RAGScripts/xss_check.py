#!/usr/bin/env python3

import requests
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from .base_scanner import BaseScanner
from .utils.logger import setup_scanner_logger

class XSSScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("xss_check")
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
        
        # Generate correlation ID for tracking related requests
        correlation_id = str(uuid.uuid4())
        
        # Set up headers if not provided
        if headers is None:
            headers = {'Authorization': f'Bearer {token}'} if token else {}
            
        self.logger.info(f"Testing endpoint: {method} {url}{path}")
        
        # XSS test payloads
        payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '\'"><script>alert(document.domain)</script>',
            '<svg/onload=alert(1)>',
            '"autofocus onfocus=alert(1)//'
        ]
        
        for payload in payloads:
            try:
                # Track authentication state for attack chain building
                auth_state = {"token": token, "auth_type": "bearer"} if token else None
                
                self.logger.info(f"Testing payload: {payload}")
                if method == 'GET':
                    test_resp = requests.get(
                        f"{url}{path}", 
                        params={'test': payload},
                        headers=headers,
                        timeout=5
                    )
                else:
                    test_resp = requests.request(
                        method,
                        f"{url}{path}",
                        json={'test': payload},
                        headers=headers,
                        timeout=5
                    )
                
                # Capture transaction for evidence
                request_data, response_data = self.capture_transaction(
                    test_resp,
                    auth_state=auth_state,
                    correlation_id=correlation_id
                )
                
                if payload in test_resp.text:
                    # Create finding with dependencies to show attack chain
                    dependencies = self.context.get('finding_ids', [])
                    
                    finding = {
                        "type": "XSS",
                        "severity": "HIGH",
                        "detail": f"Potential XSS vulnerability detected with payload: {payload}",
                        "evidence": {
                            "xss_request": request_data,
                            "xss_response": response_data,
                            "auth_state": auth_state,
                            "correlation_id": correlation_id,
                            "payload": payload
                        },
                        "dependencies": dependencies,  # Link to previous findings
                        "context_update": {  # Update context for future scanners
                            "vulnerable_xss_endpoints": self.context.get("vulnerable_xss_endpoints", []) + [path],
                            "xss_payloads": self.context.get("xss_payloads", []) + [payload]
                        }
                    }
                    vulnerabilities.append(finding)
                    self.logger.warning(f"Found XSS vulnerability with payload: {payload}")
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing XSS payload {payload}: {str(e)}")
                
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

scan = XSSScanner().scan