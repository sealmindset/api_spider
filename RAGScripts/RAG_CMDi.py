#!/usr/bin/env python3
"""Command Injection Scanner"""

from typing import Dict, List, Optional, Any
import requests
import uuid
import time
from datetime import datetime
from .base_scanner import BaseScanner
from .utils.logger import setup_scanner_logger

class CommandInjectionScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("cmdi")
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
            
        cmdi_payloads = [
            "; ls",
            "| ls",
            "`ls`",
            "$(ls)",
            "; sleep 5",
            "| sleep 5",
            "`sleep 5`",
            "$(sleep 5)"
        ]
        
        for payload in cmdi_payloads:
            try:
                # Track authentication state for attack chain building
                auth_state = {"token": token, "auth_type": "bearer"} if token else None
                
                # Add Content-Type header
                request_headers = headers.copy()
                request_headers["Content-Type"] = "application/json"
                
                # Make the request with timing measurement
                start_time = time.time()
                test_resp = requests.request(
                    method,
                    f"{url}{path}",
                    json={"command": payload, "input": payload, "query": payload},
                    headers=request_headers,
                    timeout=10
                )
                execution_time = time.time() - start_time
                
                # Capture transaction for evidence
                request_data, response_data = self.capture_transaction(
                    test_resp,
                    auth_state=auth_state,
                    correlation_id=correlation_id
                )
                
                # Check for command injection indicators
                if execution_time > 4 or "bin" in test_resp.text or "/etc" in test_resp.text:
                    # Create finding with dependencies to show attack chain
                    dependencies = self.context.get('finding_ids', [])
                    
                    finding = {
                        "type": "COMMAND_INJECTION",
                        "severity": "CRITICAL",
                        "detail": f"Potential command injection detected with payload: {payload}",
                        "evidence": {
                            "cmdi_request": request_data,
                            "cmdi_response": response_data,
                            "auth_state": auth_state,
                            "correlation_id": correlation_id,
                            "payload": payload,
                            "execution_time": execution_time
                        },
                        "dependencies": dependencies,  # Link to previous findings
                        "context_update": {  # Update context for future scanners
                            "vulnerable_cmdi_endpoints": self.context.get("vulnerable_cmdi_endpoints", []) + [path],
                            "cmdi_payloads": self.context.get("cmdi_payloads", []) + [payload]
                        }
                    }
                    vulnerabilities.append(finding)
                    self.logger.warning(f"Found command injection vulnerability with payload: {payload}")
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing command injection payload {payload}: {str(e)}")
                
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

scan = CommandInjectionScanner().scan