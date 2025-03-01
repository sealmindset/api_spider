#!/usr/bin/env python3
import requests
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class AuthBypassScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("auth_check")
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
        
        # Generate correlation ID for tracking related requests
        correlation_id = str(uuid.uuid4())
        
        scenarios = [
            {
                'name': 'No auth token',
                'headers': {}
            },
            {
                'name': 'Empty token',
                'headers': {'Authorization': 'Bearer '}
            },
            {
                'name': 'Invalid JWT format',
                'headers': {'Authorization': 'Bearer invalid.token.here'}
            },
            {
                'name': 'SQL Injection in token',
                'headers': {'Authorization': "Bearer ' OR '1'='1"}
            }
        ]
        
        for scenario in scenarios:
            try:
                # Track authentication state for attack chain building
                auth_state = {"auth_type": "none" if not scenario['headers'] else "bearer"}
                
                response = requests.request(
                    method,
                    f"{url}{path}",
                    headers=scenario['headers'],
                    timeout=5,
                    verify=False
                )
                
                # Capture transaction for evidence
                request_data, response_data = self.capture_transaction(
                    response,
                    auth_state=auth_state,
                    correlation_id=correlation_id
                )
                
                if response.status_code in [200, 201, 202]:
                    # Create finding with dependencies to show attack chain
                    finding = {
                        "type": "MISSING_AUTHENTICATION",
                        "severity": "HIGH",
                        "detail": "Endpoint should require authentication",
                        "evidence": {
                            "auth_request": request_data,
                            "auth_response": response_data,
                            "auth_state": auth_state,
                            "correlation_id": correlation_id,
                            "scenario": scenario['name'],
                            "payload": scenario['headers']
                        },
                        "dependencies": self.context.get('finding_ids', []),
                        "context_update": {
                            "vulnerable_auth_endpoints": self.context.get("vulnerable_auth_endpoints", []) + [path]
                        }
                    }
                    vulnerabilities.append(finding)
                    
            except requests.RequestException as e:
                self.logger.error(f"Error in scenario {scenario['name']}: {str(e)}")
                
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

scan = AuthBypassScanner().scan