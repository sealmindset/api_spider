#!/usr/bin/env python3

import logging
from typing import Dict, List, Optional, Any
import requests
import uuid
from datetime import datetime
from .base_scanner import BaseScanner
from .utils.logger import setup_scanner_logger

class EnhancedScanner(BaseScanner):
    """Example scanner that demonstrates dependency tracking, credential sharing, and context maintenance"""
    
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, 
             headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None, 
             context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        
        logger = setup_scanner_logger("enhanced_scanner")
        vulnerabilities = []
        
        # Store context if provided
        if context:
            self.context = context
            logger.info(f"Received context with {len(context)} items")
            
            # Use finding IDs from previous scans for dependency tracking
            dependencies = context.get('finding_ids', [])
            logger.info(f"Using {len(dependencies)} dependencies from previous findings")
            
            # Use credentials discovered by other scanners
            credentials = context.get('credentials', [])
            logger.info(f"Using {len(credentials)} credentials from other scanners")
        
        # Use tokens from other scanners if available
        available_tokens = []
        if tokens and 'bearer' in tokens:
            available_tokens = [t.get('token') for t in tokens.get('bearer', [])]
            logger.info(f"Using {len(available_tokens)} bearer tokens from other scanners")
        
        # Generate correlation ID for tracking related requests
        correlation_id = str(uuid.uuid4())
        
        # Example: Test for privilege escalation using discovered tokens
        for token_value in available_tokens:
            try:
                # Try accessing admin endpoint with discovered token
                admin_url = f"{url}/admin"
                request_headers = headers or {}
                request_headers["Authorization"] = f"Bearer {token_value}"
                
                # Track authentication state for attack chain building
                auth_state = {"token": token_value, "auth_type": "bearer"}
                
                admin_resp = requests.get(
                    admin_url,
                    headers=request_headers,
                    timeout=5
                )
                
                # Capture transaction for evidence
                admin_req, admin_res = self.capture_transaction(
                    admin_resp,
                    auth_state=auth_state,
                    correlation_id=correlation_id
                )
                
                if admin_resp.status_code == 200:
                    # Create finding with dependencies to show attack chain
                    finding = {
                        "type": "PRIVILEGE_ESCALATION",
                        "severity": "HIGH",
                        "detail": "Successfully accessed admin endpoint using discovered token",
                        "evidence": {
                            "admin_request": admin_req,
                            "admin_response": admin_res,
                            "auth_state": auth_state,
                            "correlation_id": correlation_id,
                            "discovered_tokens": [token_value]
                        },
                        "dependencies": dependencies,  # Link to previous findings
                        "context_update": {  # Update context for future scanners
                            "admin_access": True,
                            "admin_token": token_value
                        }
                    }
                    vulnerabilities.append(finding)
                    logger.warning(f"Found privilege escalation vulnerability")
                    
            except requests.RequestException as e:
                logger.error(f"Error in privilege escalation check: {str(e)}")
        
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