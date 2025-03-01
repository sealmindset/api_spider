#!/usr/bin/env python3
"""Host Header Injection Scanner"""

from typing import Dict, List, Optional, Any
import requests
import uuid
from datetime import datetime
from .base_scanner import BaseScanner
from .utils.logger import setup_scanner_logger

class HostHeaderScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("host_header")
        self.context = {}
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, 
             headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None, 
             context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        
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
        malicious_hosts = [
            "evil.com",
            "localhost",
            "127.0.0.1",
            "internal-service",
            "169.254.169.254",
            f"{url}@evil.com",
            f"{url}.evil.com"
        ]
        
        vulnerabilities = []
        
        for host in malicious_hosts:
            try:
                # Track authentication state for attack chain building
                auth_state = {"token": token, "auth_type": "bearer"} if token else None
                
                test_headers = {
                    "Host": host,
                    "X-Forwarded-Host": host,
                    "X-Host": host,
                    "X-Forwarded-Server": host,
                    "Content-Type": "application/json"
                }
                
                # Add auth headers if token provided
                if token:
                    test_headers["Authorization"] = f"Bearer {token}"
                
                test_resp = requests.request(
                    method,
                    f"{url}{path}",
                    headers=test_headers,
                    timeout=5
                )
                
                # Capture transaction for evidence
                request_data, response_data = self.capture_transaction(
                    test_resp,
                    auth_state=auth_state,
                    correlation_id=correlation_id
                )
                
                if host in test_resp.text or test_resp.status_code in [301, 302]:
                    # Create finding with dependencies to show attack chain
                    dependencies = self.context.get('finding_ids', [])
                    
                    finding = {
                        "type": "HOST_HEADER_INJECTION",
                        "severity": "HIGH",
                        "detail": f"Endpoint is vulnerable to Host header manipulation: {host}",
                        "evidence": {
                            "host_header_request": request_data,
                            "host_header_response": response_data,
                            "auth_state": auth_state,
                            "correlation_id": correlation_id,
                            "malicious_host": host
                        },
                        "dependencies": dependencies,  # Link to previous findings
                        "context_update": {  # Update context for future scanners
                            "vulnerable_host_header_endpoints": self.context.get("vulnerable_host_header_endpoints", []) + [path],
                            "malicious_hosts": self.context.get("malicious_hosts", []) + [host]
                        }
                    }
                    vulnerabilities.append(finding)
                    self.logger.warning(f"Found Host Header Injection vulnerability with host: {host}")
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing Host header {host}: {str(e)}")
                
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

scan = HostHeaderScanner().scan