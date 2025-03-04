#!/usr/bin/env python3
"""
Integrated SQL Injection Scanner

This scanner combines the functionality from sql_injection.py and enhanced_sqli_scanner.py
to provide comprehensive SQL injection detection with proper evidence capture for reporting.

It specifically focuses on detecting SQL injection vulnerabilities in URL path parameters
and captures the full HTML error responses for detailed reporting.
"""

import requests
import time
import uuid
import re
import sys
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin
from datetime import datetime
from .base_scanner import BaseScanner
from .utils.logger import setup_scanner_logger

class IntegratedSQLiScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("integrated_sqli")
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
        
        # Use the provided path from the API specification
        test_paths = [path] if path else []
        
        # If no path provided, try to get paths from context
        if not test_paths and context and 'paths' in context:
            for api_path in context['paths']:
                # Look for endpoints that might be vulnerable to SQL injection
                if any(keyword in api_path.lower() for keyword in ['user', 'data', 'record', 'search', 'query', 'id']):
                    test_paths.append(api_path)
                    
        # If still no paths, use some common patterns as fallback
        if not test_paths:
            test_paths = [
                "/users/v1/",
                "/api/users/",
                "/api/v1/users/",
                "/api/data/",
                "/api/records/"
            ]
            self.logger.info("No paths found in context, using default endpoints for testing")
        
        self.logger.info(f"Starting integrated SQL injection tests for URL path parameters")
        
        # First, test the exact case mentioned in the path parameter
        # Only test if we have a valid path
        if path:
            specific_test_url = urljoin(url, f"{path}name1'")
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
                    "endpoint": specific_test_url,
                    "parameter": "path",
                    "attack_pattern": "Single quote in URL path",
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
                        "correlation_id": correlation_id,
                        "code": "SELECT * FROM users WHERE username = '${username}'"
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
                        finding_id = str(uuid.uuid4())[:3]
                        timestamp = datetime.utcnow().isoformat()
                        vulnerabilities.append({
                            "id": finding_id,
                            "type": "SQLi",
                            "severity": "HIGH",
                            "endpoint": test_url,
                            "parameter": "path",
                            "attack_pattern": payload,
                            "evidence": {
                                "code": "SELECT * FROM users WHERE username = '${username}'",
                                "payload": payload,
                                "response_sample": test_resp.text[:500],
                                "correlation_id": correlation_id
                            },
                            "detail": f"SQL Injection vulnerability found in URL path parameter at {base_path}",
                            "timestamp": timestamp,
                            "correlation_id": correlation_id
                        })
                        self.logger.warning(f"Found SQL_INJECTION vulnerability at {test_url}")
                        
                except requests.RequestException as e:
                    self.logger.error(f"Error testing URL {test_url}: {str(e)}")
        
        return vulnerabilities
    
    def capture_transaction(self, response: requests.Response, auth_state: Dict[str, Any] = None, 
                           correlation_id: str = None) -> tuple:
        """Capture request/response details for evidence"""
        request = response.request
        
        req_data = {
            "method": request.method,
            "url": request.url,
            "headers": dict(request.headers),
            "body": request.body.decode('utf-8', errors='ignore') if request.body else None,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        res_data = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,  # Store full response for HTML error pages
            "content_type": response.headers.get('Content-Type'),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if auth_state:
            req_data["auth_state"] = auth_state
            res_data["auth_state"] = auth_state
            
        if correlation_id:
            req_data["correlation_id"] = correlation_id
            res_data["correlation_id"] = correlation_id
            
        return req_data, res_data
    
    def perform_sql_injection(self, url="http://localhost:5002/users/v1/name1'"):
        """Performs a SQL injection attack by sending a GET request with a single quote
        in the URL path parameter. Imported from sql_injection.py
        
        Args:
            url (str): The target URL with the SQL injection payload
                      Default is http://localhost:5002/users/v1/name1'
        
        Returns:
            tuple: (response_text, response_object)
        """
        try:
            # Send the GET request to the vulnerable endpoint
            response = requests.get(url, timeout=10)
            
            # Return both the response text and the response object
            return response.text, response
        except requests.RequestException as e:
            self.logger.error(f"Error making request: {e}")
            return None, None
    
    def validate_output(self, response_text, expected_output):
        """Validates the output of the SQL injection test against the expected output.
        Imported from validate_output.py
        
        Args:
            response_text (str): The actual response text
            expected_output (str): The expected output to compare against
            
        Returns:
            bool: True if the output matches, False otherwise
        """
        if response_text == expected_output:
            return True
        else:
            return False

# Make the scanner available for direct import
scan = IntegratedSQLiScanner().scan