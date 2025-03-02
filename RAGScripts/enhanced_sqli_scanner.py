#!/usr/bin/env python3
"""
Enhanced SQL Injection Scanner
Specifically designed to detect SQL injection vulnerabilities in URL path parameters
by testing with single quotes and detecting HTML error responses containing SQL errors.

This scanner addresses the specific vulnerability where a URL like:
http://localhost:5002/users/v1/name1'

Returns an error like:
<!doctype html>
<html lang=en>
  <head>
    <title>sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unrecognized token: "'name1''"
[SQL: SELECT * FROM users WHERE username = 'name1'']
"""

import requests
import time
import uuid
import re
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin
from .base_scanner import BaseScanner
from .utils.logger import setup_scanner_logger

class EnhancedSQLiScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("enhanced_sqli")
        self.target = None
        self.context = {}
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, 
             headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None, 
             context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        self.base_url = url
        self.target = url
        vulnerabilities = []
        
        # Store context if provided
        if context:
            self.context = context
            self.logger.info(f"Received context with {len(context)} items")
        
        # Generate correlation ID for tracking related requests
        correlation_id = str(uuid.uuid4())
        
        # Set up headers if not provided
        if headers is None:
            headers = {'Authorization': f'Bearer {token}'} if token else {}
            
        # SQL Error patterns to detect
        sql_errors = [
            "SQL syntax",
            "mysql_fetch_array()",
            "ORA-01756",
            "SQLite3::query",
            "sqlite3.OperationalError",
            "sqlalchemy.exc.OperationalError",
            "pg_query",
            "System.Data.SQLClient",
            "SQLSTATE",
            "Microsoft SQL Native Client error",
            "unrecognized token"
        ]
        
        # HTML error patterns
        html_error_patterns = [
            r'<!doctype html>\s*<html',
            r'<title>[^<]*(?:Error|Exception)[^<]*</title>',
            r'sqlalchemy\.exc\.\w+Error',
            r'\[SQL:.*\]'
        ]
        
        # Test payloads specifically for URL path parameters
        path_payloads = [
            "'",  # Simple single quote
            "''", # Double single quote
            "\"'", # Mixed quotes
            "' OR '1'='1", # Basic SQLi
            "' OR 1=1--", # Comment-based SQLi
            "'; DROP TABLE users--" # Destructive SQLi
        ]
        
        # Test endpoints that are likely to be vulnerable
        test_paths = [
            "/users/v1/",
            "/api/users/",
            "/api/v1/users/",
            "/api/data/",
            "/api/records/"
        ]
        
        self.logger.info(f"Starting enhanced SQL injection tests for URL path parameters")
        
        # First, test the exact case mentioned by the user
        specific_test_url = f"{url}/users/v1/name1'"
        self.logger.info(f"Testing specific URL: {specific_test_url}")
        
        try:
            specific_resp = requests.get(
                specific_test_url,
                headers=headers,
                timeout=5,
                allow_redirects=False
            )
            
            # Capture evidence
            specific_req, specific_res = self.capture_transaction(
                specific_resp,
                auth_state={"auth_type": "none"},
                correlation_id=correlation_id
            )
            
            # Check for SQL errors in HTML response
            is_vulnerable = False
            matched_patterns = []
            
            # Check for HTML error page with SQL error
            if specific_resp.headers.get('Content-Type', '').startswith('text/html'):
                for pattern in html_error_patterns:
                    if re.search(pattern, specific_resp.text, re.IGNORECASE):
                        is_vulnerable = True
                        matched_patterns.append(pattern)
            
            # Check for SQL error strings
            for error in sql_errors:
                if error.lower() in specific_resp.text.lower():
                    is_vulnerable = True
                    matched_patterns.append(error)
            
            if is_vulnerable:
                vulnerabilities.append({
                    "type": "SQL_INJECTION",
                    "severity": "HIGH",
                    "detail": "SQL Injection vulnerability found in URL path parameter",
                    "evidence": {
                        "url": specific_test_url,
                        "method": "GET",
                        "status_code": specific_resp.status_code,
                        "headers": dict(specific_resp.headers),
                        "response_preview": specific_resp.text[:1000],
                        "response_full": specific_resp.text,
                        "matched_patterns": matched_patterns,
                        "request": specific_req,
                        "response": specific_res,
                        "correlation_id": correlation_id
                    },
                    "remediation": {
                        "description": "URL path parameters are vulnerable to SQL injection",
                        "impact": "Attackers can extract sensitive data or modify database content",
                        "steps": [
                            "Use parameterized queries or prepared statements",
                            "Implement proper input validation for URL path parameters",
                            "Apply proper escaping for user inputs",
                            "Use an ORM with proper parameter binding",
                            "Implement least privilege database access"
                        ]
                    }
                })
                self.logger.warning(f"Found SQL_INJECTION vulnerability at {specific_test_url}")
        
        except requests.RequestException as e:
            self.logger.error(f"Error testing specific URL: {str(e)}")
        
        # Now test other endpoints with various payloads
        for base_path in test_paths:
            for payload in path_payloads:
                try:
                    test_url = urljoin(url, f"{base_path}{payload}")
                    self.logger.info(f"Testing URL: {test_url}")
                    
                    test_resp = requests.get(
                        test_url,
                        headers=headers,
                        timeout=5,
                        allow_redirects=False
                    )
                    
                    # Capture evidence
                    test_req, test_res = self.capture_transaction(
                        test_resp,
                        auth_state={"auth_type": "none"},
                        correlation_id=correlation_id
                    )
                    
                    # Check for SQL errors in HTML response
                    is_vulnerable = False
                    matched_patterns = []
                    
                    # Check for HTML error page with SQL error
                    if test_resp.headers.get('Content-Type', '').startswith('text/html'):
                        for pattern in html_error_patterns:
                            if re.search(pattern, test_resp.text, re.IGNORECASE):
                                is_vulnerable = True
                                matched_patterns.append(pattern)
                    
                    # Check for SQL error strings
                    for error in sql_errors:
                        if error.lower() in test_resp.text.lower():
                            is_vulnerable = True
                            matched_patterns.append(error)
                    
                    if is_vulnerable:
                        vulnerabilities.append({
                            "type": "SQL_INJECTION",
                            "severity": "HIGH",
                            "detail": f"SQL Injection vulnerability found in URL path parameter at {base_path}",
                            "evidence": {
                                "url": test_url,
                                "method": "GET",
                                "status_code": test_resp.status_code,
                                "headers": dict(test_resp.headers),
                                "response_preview": test_resp.text[:1000],
                                "response_full": test_resp.text,
                                "matched_patterns": matched_patterns,
                                "request": test_req,
                                "response": test_res,
                                "payload": payload,
                                "correlation_id": correlation_id
                            },
                            "remediation": {
                                "description": "URL path parameters are vulnerable to SQL injection",
                                "impact": "Attackers can extract sensitive data or modify database content",
                                "steps": [
                                    "Use parameterized queries or prepared statements",
                                    "Implement proper input validation for URL path parameters",
                                    "Apply proper escaping for user inputs",
                                    "Use an ORM with proper parameter binding",
                                    "Implement least privilege database access"
                                ]
                            }
                        })
                        self.logger.warning(f"Found SQL_INJECTION vulnerability at {test_url}")
                        
                except requests.RequestException as e:
                    self.logger.error(f"Error testing URL {test_url}: {str(e)}")
        
        return vulnerabilities

# Keep the scan function for backward compatibility
scan = EnhancedSQLiScanner().scan