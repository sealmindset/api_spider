#!/usr/bin/env python3
"""CORS Misconfiguration Scanner"""

from typing import Dict, List, Optional, Any
import requests
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class CORSScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("cors")
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
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
                
                test_resp = self.make_request(
                    method="OPTIONS",
                    endpoint=path,
                    headers=test_headers
                )
                
                acao = test_resp.headers.get("Access-Control-Allow-Origin")
                if acao and (acao == "*" or origin in acao):
                    vulnerabilities.append({
                        "type": "CORS_MISCONFIGURATION",
                        "severity": "HIGH",
                        "detail": f"Endpoint allows CORS from dangerous origin: {origin}",
                        "evidence": {
                            "url": f"{url}{path}",
                            "method": "OPTIONS",
                            "request": {
                                "headers": dict(test_headers),
                                "origin": origin
                            },
                            "response": {
                                "headers": dict(test_resp.headers),
                                "status_code": test_resp.status_code,
                                "body": test_resp.text[:500]
                            }
                        }
                    })
                    
                    self.add_finding(
                        title="CORS Misconfiguration",
                        description=f"Endpoint allows CORS from dangerous origin: {origin}",
                        endpoint=path,
                        severity_level="tier2",
                        impact="Cross-origin resource sharing enables malicious sites to access sensitive data",
                        request=request_data,
                        response=response_data,
                        remediation="Implement strict CORS policy with specific allowed origins"
                    )
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing CORS origin {origin}: {str(e)}")
                
        return self.findings

scan = CORSScanner().scan