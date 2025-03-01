#!/usr/bin/env python3
"""Cross-Site Scripting (XSS) Scanner"""

from typing import Dict, List, Optional, Any
import requests
import uuid
from datetime import datetime
import time
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class XSSScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("xss")
        self.context = {}
        self.target = None
        self.time = time
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, 
             headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None, 
             context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        # Set target URL for make_request method
        self.target = url
        
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
        
        # Generate correlation ID for tracking related requests
        correlation_id = str(uuid.uuid4())
        
        # Set up headers if not provided
        if headers is None:
            headers = {'Authorization': f'Bearer {token}'} if token else {}
        
        # XSS test payloads
        xss_payloads = [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'\"><script>alert(1)</script>",
            "<img src=\"x\" onerror=\"javascript:alert(1)\">",
            "<body onload=alert(1)>",
            "<iframe onload=alert(1)>"
        ]
        
        for payload in xss_payloads:
            try:
                # Track authentication state for attack chain building
                auth_state = {"token": token, "auth_type": "bearer"} if token else None
                
                # Add Content-Type header
                request_headers = headers.copy()
                request_headers["Content-Type"] = "application/json"
                
                # Test payload in different request parameters
                test_data = {
                    "input": payload,
                    "search": payload,
                    "query": payload
                }
                
                test_resp = self.make_request(
                    method=method,
                    endpoint=path,
                    data=test_data,
                    headers=request_headers
                )
                
                # Capture transaction for evidence
                request_data, response_data = self.capture_transaction(
                    test_resp,
                    auth_state=auth_state,
                    correlation_id=correlation_id
                )
                
                if payload in test_resp.text:
                    # Get dependencies from context
                    deps = self.context.get('finding_ids', [])
                    
                    self.add_finding(
                        title="Cross-Site Scripting (XSS) Vulnerability",
                        description=f"XSS payload reflected in response: {payload}",
                        endpoint=path,
                        severity_level="tier2",
                        impact="Client-side code execution and session hijacking",
                        request=request_data,
                        response=response_data,
                        remediation="Implement proper input validation and output encoding",
                        dependencies=deps,
                        auth_state=auth_state
                    )
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing XSS payload {payload}: {str(e)}")
                
        return self.findings

scan = XSSScanner().scan