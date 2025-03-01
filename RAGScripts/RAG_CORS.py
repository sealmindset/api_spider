#!/usr/bin/env python3
"""CORS Misconfiguration Scanner"""

from typing import Dict, List, Optional, Any
import requests
import uuid
from datetime import datetime
from .base_scanner import BaseScanner
from .utils.logger import setup_scanner_logger

class CORSScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("cors")
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
        
        test_origins = [
            "https://evil.com",
            "http://attacker.com",
            "null",
            "*",
            f"https://{url}.evil.com",
            "https://evil.{url}",
            "file://"
        ]
        
        for origin in test_origins:
            try:
                test_headers = {
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Authorization"
                }
                
                # Track authentication state for attack chain building
                auth_state = {"token": token, "auth_type": "bearer"} if token else None
                
                # Make the request
                test_resp = requests.options(
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
                
                acao = test_resp.headers.get("Access-Control-Allow-Origin")
                acac = test_resp.headers.get("Access-Control-Allow-Credentials")
                
                if acao and (acao == "*" or origin in acao):
                    # Create finding with dependencies to show attack chain
                    dependencies = self.context.get('finding_ids', [])
                    
                    finding = {
                        "type": "CORS_MISCONFIGURATION",
                        "severity": "HIGH",
                        "detail": f"Endpoint allows CORS from dangerous origin: {origin}",
                        "evidence": {
                            "cors_request": request_data,
                            "cors_response": response_data,
                            "auth_state": auth_state,
                            "correlation_id": correlation_id,
                            "origin": origin,
                            "allow_credentials": acac == "true"
                        },
                        "dependencies": dependencies,  # Link to previous findings
                        "context_update": {  # Update context for future scanners
                            "vulnerable_cors_endpoints": self.context.get("vulnerable_cors_endpoints", []) + [path],
                            "vulnerable_origins": self.context.get("vulnerable_origins", []) + [origin]
                        }
                    }
                    
                    # Add additional risk information if credentials are allowed
                    if acac == "true":
                        finding["severity"] = "CRITICAL"
                        finding["detail"] += " with credentials allowed"
                    
                    vulnerabilities.append(finding)
                    self.logger.warning(f"Found CORS misconfiguration vulnerability with origin {origin}")
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing CORS origin {origin}: {str(e)}")
                
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

scan = CORSScanner().scan