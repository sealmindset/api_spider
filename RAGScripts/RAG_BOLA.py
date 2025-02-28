
#!/usr/bin/env python3
"""BOLA (Broken Object Level Authorization) Scanner"""

from typing import Dict, List, Optional, Any
import requests
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class BOLAScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("bola")
        self.target = None

    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        self.target = url
        vulnerabilities = []
        
        # Test user IDs
        test_ids = [1, 2, 3, 'admin', 'root']
        
        try:
            for test_id in test_ids:
                # Try to access user data
                user_url = f"{url}/users/v1/{test_id}"
                request_headers = headers or {}
                if token:
                    request_headers['Authorization'] = f'Bearer {token}'
                
                user_resp = requests.get(
                    user_url,
                    headers=request_headers,
                    timeout=5
                )
                
                if user_resp.status_code == 200:
                    vulnerabilities.append({
                        "type": "BOLA",
                        "severity": "HIGH",
                        "detail": f"Successfully accessed user data for ID {test_id} without proper authorization",
                        "evidence": {
                            "url": user_url,
                            "response": user_resp.json()
                        }
                    })
                    
        except requests.RequestException as e:
            self.logger.error(f"Error in BOLA check: {str(e)}")
            
        return vulnerabilities
        test_ids = ["admin", "user1", "superuser", "root"]
        original_path = path
        
        for test_id in test_ids:
            try:
                test_path = original_path.replace("{id}", test_id)
                test_resp = self.make_request(
                    method="GET",
                    endpoint=test_path
                )
                
                if test_resp.status_code == 200:
                    request_data, response_data = self.capture_transaction(test_resp)
                    
                    self.add_finding(
                        title="Broken Object Level Authorization",
                        description=f"Successfully accessed user data for ID {test_id} without proper authorization",
                        endpoint=test_path,
                        severity_level="tier2",
                        impact="Unauthorized access to user data and potential data breach",
                        request=request_data,
                        response=response_data,
                        remediation="Implement proper authorization checks for all object access"
                    )
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing BOLA with ID {test_id}: {str(e)}")
                
        return self.findings

scan = BOLAScanner().scan
