
#!/usr/bin/env python3
"""BOLA (Broken Object Level Authorization) Scanner"""

from typing import Dict, List, Optional, Any
import requests
import uuid
from datetime import datetime
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class BOLAScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("bola")
        self.target = None
        self.context = {}

    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None, context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
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
        
        # Generate correlation ID for tracking related requests
        correlation_id = str(uuid.uuid4())
        
        # Test user IDs
        test_ids = [1, 2, 3, 'admin', 'root']
        
        try:
            for test_id in test_ids:
                # Try to access user data
                user_url = f"{url}/users/v1/{test_id}"
                request_headers = headers or {}
                if token:
                    request_headers['Authorization'] = f'Bearer {token}'
                
                # Track authentication state for attack chain building
                auth_state = {"token": token, "auth_type": "bearer"} if token else None
                
                user_resp = requests.get(
                    user_url,
                    headers=request_headers,
                    timeout=5
                )
                
                # Capture transaction for evidence
                req_data, res_data = self.capture_transaction(
                    user_resp,
                    auth_state=auth_state,
                    correlation_id=correlation_id
                )
                
                if user_resp.status_code == 200:
                    finding = {
                        "type": "BOLA",
                        "severity": "HIGH",
                        "detail": f"Successfully accessed user data for ID {test_id} without proper authorization",
                        "evidence": {
                            "url": user_url,
                            "method": "GET",
                            "request": req_data,
                            "response": res_data,
                            "auth_state": auth_state,
                            "correlation_id": correlation_id
                        },
                        "dependencies": context.get('finding_ids', []) if context else [],
                        "context_update": {
                            "bola_found": True,
                            "vulnerable_endpoint": user_url,
                            "vulnerable_id": test_id
                        }
                    }
                    vulnerabilities.append(finding)
                    self.logger.warning(f"Found BOLA vulnerability with ID {test_id}")
                    
        except requests.RequestException as e:
            self.logger.error(f"Error in BOLA check: {str(e)}")
            
        return vulnerabilities

scan = BOLAScanner().scan
