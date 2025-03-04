
#!/usr/bin/env python3
"""
Rate Limiting Test Script
Checks if an API endpoint is vulnerable to rate limiting issues
by sending rapid requests and analyzing the responses.
"""

import requests
import time
from typing import Dict, List, Optional, Any
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class RateLimitScanner(BaseScanner):
    @staticmethod
    def scan(url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None, context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        logger = setup_scanner_logger("rate_limit")
        vulnerabilities = []
        
        # Use path from input or context
        if not path and (not context or 'paths' not in context):
            logger.warning("No paths found in context for testing")
            return vulnerabilities
            
        # Test parameters
        request_count = 50
        interval = 0.1  # 100ms between requests
        test_url = f"{url}{path}"  # Use provided path instead of hardcoded endpoint
        
        # Headers setup
        request_headers = headers or {}
        if token:
            request_headers['Authorization'] = f'Bearer {token}'
        
        try:
            # Send rapid requests to test rate limiting
            responses = []
            for i in range(request_count):
                response = requests.get(
                    test_url,
                    headers=request_headers,
                    timeout=5
                )
                responses.append(response.status_code)
                
                if response.status_code == 429:  # Too Many Requests
                    break
                    
                time.sleep(interval)
            
            # Analyze results
            if 429 not in responses:
                vulnerabilities.append({
                    "type": "RATE_LIMIT",
                    "severity": "MEDIUM",
                    "detail": "No rate limiting detected after sending multiple rapid requests",
                    "evidence": {
                        "request_count": len(responses),
                        "status_codes": responses,
                        "request": {
                            "headers": request_headers,
                            "url": test_url,
                            "method": "GET"
                        },
                        "response": {
                            "headers": dict(response.headers),
                            "status_code": response.status_code,
                            "body": response.text
                        }
                    }
                })
                
        except requests.RequestException as e:
            logger.error(f"Error in rate limit check: {str(e)}")
            
        return vulnerabilities

scan = RateLimitScanner.scan
