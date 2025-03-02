#!/usr/bin/env python3
"""
Enhanced Context Scanner

This scanner re-runs all scans while leveraging details discovered from previous scans.
It specifically focuses on:
1. Using cached usernames for parameter injection
2. Constructing appropriate request bodies for endpoints like register/login
3. Dynamically applying discovered details to maximize scan effectiveness
"""

import asyncio
import json
import logging
import re
import uuid
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse

import requests

from .base_scanner import BaseScanner
from .utils.logger import setup_scanner_logger


class EnhancedContextScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("enhanced_context")
        self.context = {}
        self.cached_usernames = []
        self.cached_passwords = []
        self.cached_emails = []
        self.discovered_parameters = {}
        self.endpoint_patterns = {}
        self.auth_tokens = {}
        self.parameter_patterns = {
            "username": r"\{username\}",
            "id": r"\{id\}",
            "email": r"\{email\}",
            "password": r"\{password\}",
            "book_id": r"\{book_id\}"
        }
        # Default values to use when no cached values are available
        self.default_values = {
            "username": ["admin", "user1", "test", "name1"],
            "password": ["pass1", "pass2", "password123"],
            "email": ["admin@example.com", "user1@example.com", "test@example.com"],
            "id": ["1", "2", "3"],
            "book_id": ["1", "2", "3"]
        }
        # Endpoint type patterns
        self.endpoint_type_patterns = {
            "register": r"register|signup|create_account|new_user",
            "login": r"login|signin|auth|token",
            "profile": r"profile|account|me|user_info",
            "admin": r"admin|superuser|management",
            "debug": r"_debug|debug|test|dev"
        }

    async def scan(self, url: str, method: str, path: str, response: requests.Response,
                   token: Optional[str] = None, headers: Optional[Dict[str, str]] = None,
                   tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None,
                   context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        
        vulnerabilities = []
        
        # Load context from previous scans if available
        if context:
            self.context = context
            self.logger.info(f"Received context with {len(context)} items")
            
            # Extract cached data from context
            self._load_cached_data_from_context(context)
        
        # Generate correlation ID for tracking related requests
        correlation_id = str(uuid.uuid4())
        
        # Phase 1: Analyze the endpoint to determine its type and expected parameters
        endpoint_type = self._determine_endpoint_type(path)
        expected_params = self._determine_expected_parameters(path, endpoint_type)
        
        self.logger.info(f"Analyzing endpoint {path} - Type: {endpoint_type}, Expected params: {expected_params}")
        
        # Phase 2: Perform targeted scans based on endpoint type
        if endpoint_type == "register":
            register_findings = await self._scan_registration_endpoint(url, path, expected_params, correlation_id)
            vulnerabilities.extend(register_findings)
            
        elif endpoint_type == "login":
            login_findings = await self._scan_login_endpoint(url, path, expected_params, correlation_id)
            vulnerabilities.extend(login_findings)
            
        elif endpoint_type == "debug":
            debug_findings = await self._scan_debug_endpoint(url, path, token, headers, correlation_id)
            vulnerabilities.extend(debug_findings)
            
        # Phase 3: Parameter injection for endpoints with path parameters
        if any(param in path for param in ["{username}", "{id}", "{email}", "{password}", "{book_id}"]):
            injection_findings = await self._perform_parameter_injection(url, method, path, headers, correlation_id)
            vulnerabilities.extend(injection_findings)
        
        # Phase 4: Try discovered tokens on this endpoint
        if self.auth_tokens:
            token_findings = await self._try_auth_tokens(url, method, path, correlation_id)
            vulnerabilities.extend(token_findings)
            
        return vulnerabilities

    def _load_cached_data_from_context(self, context: Dict[str, Any]) -> None:
        """Extract cached usernames, passwords, emails, and tokens from context"""
        # Extract usernames
        if context.get("enumerated_users"):
            self.cached_usernames = context.get("enumerated_users", [])
            self.logger.info(f"Loaded {len(self.cached_usernames)} cached usernames")
            
        # Extract credentials
        if context.get("credentials"):
            credentials = context.get("credentials", [])
            for cred in credentials:
                if "username" in cred and cred["username"] not in self.cached_usernames:
                    self.cached_usernames.append(cred["username"])
                if "password" in cred and cred["password"] not in self.cached_passwords:
                    self.cached_passwords.append(cred["password"])
                if "email" in cred and cred["email"] not in self.cached_emails:
                    self.cached_emails.append(cred["email"])
            
            self.logger.info(f"Loaded credentials: {len(self.cached_usernames)} usernames, "
                           f"{len(self.cached_passwords)} passwords, {len(self.cached_emails)} emails")
        
        # Extract tokens
        if context.get("discovered_tokens"):
            self.auth_tokens = context.get("discovered_tokens", {})
            self.logger.info(f"Loaded {len(self.auth_tokens)} auth tokens")
            
        # Extract discovered parameters
        if context.get("discovered_parameters"):
            self.discovered_parameters = context.get("discovered_parameters", {})
            self.logger.info(f"Loaded {len(self.discovered_parameters)} discovered parameters")

    def _determine_endpoint_type(self, path: str) -> str:
        """Determine the type of endpoint based on the path"""
        for endpoint_type, pattern in self.endpoint_type_patterns.items():
            if re.search(pattern, path, re.IGNORECASE):
                return endpoint_type
                
        # Default to "unknown" if no match
        return "unknown"

    def _determine_expected_parameters(self, path: str, endpoint_type: str) -> Dict[str, List[str]]:
        """Determine expected parameters based on endpoint type and path"""
        expected_params = {}
        
        # Common parameters based on endpoint type
        if endpoint_type == "register":
            expected_params = {
                "username": self.cached_usernames or self.default_values["username"],
                "password": self.cached_passwords or self.default_values["password"],
                "email": self.cached_emails or self.default_values["email"],
                "admin": ["true", "false", "1", "0"]
            }
        elif endpoint_type == "login":
            expected_params = {
                "username": self.cached_usernames or self.default_values["username"],
                "password": self.cached_passwords or self.default_values["password"]
            }
        
        # Check for path parameters
        for param_name, pattern in self.parameter_patterns.items():
            if re.search(pattern, path):
                if param_name == "username":
                    expected_params[param_name] = self.cached_usernames or self.default_values["username"]
                elif param_name == "id":
                    expected_params[param_name] = self.default_values["id"]
                elif param_name == "email":
                    expected_params[param_name] = self.cached_emails or self.default_values["email"]
                elif param_name == "password":
                    expected_params[param_name] = self.cached_passwords or self.default_values["password"]
                elif param_name == "book_id":
                    expected_params[param_name] = self.default_values["book_id"]
        
        return expected_params

    async def _scan_registration_endpoint(self, url: str, path: str, expected_params: Dict[str, List[str]], 
                                        correlation_id: str) -> List[Dict[str, Any]]:
        """Scan registration endpoint with various payloads"""
        findings = []
        endpoint_url = urljoin(url, path)
        
        # Try to register with admin privileges
        for username in expected_params.get("username", [])[:2]:  # Limit to first 2 usernames
            for password in expected_params.get("password", [])[:2]:  # Limit to first 2 passwords
                # Generate email if not available
                email = f"{username}@example.com"
                if expected_params.get("email") and expected_params["email"]:
                    email = expected_params["email"][0]
                
                # Try with admin flag
                payload = {
                    "username": username,
                    "password": password,
                    "email": email,
                    "admin": "true"  # Attempt privilege escalation
                }
                
                try:
                    headers = {"Content-Type": "application/json"}
                    resp = requests.post(endpoint_url, json=payload, headers=headers, timeout=5)
                    
                    # Check if registration was successful
                    if resp.status_code == 200 or resp.status_code == 201:
                        # Try to login with the registered credentials
                        login_url = urljoin(url, path.replace("register", "login"))
                        login_payload = {"username": username, "password": password}
                        
                        login_resp = requests.post(login_url, json=login_payload, headers=headers, timeout=5)
                        
                        if login_resp.status_code == 200:
                            # Check if we got a token and if admin privileges were granted
                            try:
                                login_data = login_resp.json()
                                token = login_data.get("auth_token") or login_data.get("token")
                                
                                if token:
                                    # Try accessing admin endpoint
                                    admin_headers = {"Authorization": f"Bearer {token}"}
                                    admin_url = urljoin(url, "/admin")
                                    
                                    admin_resp = requests.get(admin_url, headers=admin_headers, timeout=5)
                                    
                                    if admin_resp.status_code == 200:
                                        findings.append({
                                            "type": "PRIVILEGE_ESCALATION",
                                            "severity": "CRITICAL",
                                            "detail": "Successfully registered account with admin privileges",
                                            "evidence": {
                                                "registration_payload": payload,
                                                "login_response": login_data,
                                                "admin_access": True,
                                                "correlation_id": correlation_id
                                            }
                                        })
                            except Exception as e:
                                self.logger.error(f"Error processing login response: {str(e)}")
                
                except requests.RequestException as e:
                    self.logger.error(f"Error in registration scan: {str(e)}")
        
        return findings

    async def _scan_login_endpoint(self, url: str, path: str, expected_params: Dict[str, List[str]], 
                                 correlation_id: str) -> List[Dict[str, Any]]:
        """Scan login endpoint with various credentials"""
        findings = []
        endpoint_url = urljoin(url, path)
        
        # Try username enumeration through timing differences
        timing_differences = {}
        
        for username in expected_params.get("username", []):
            # Test with valid and invalid passwords
            valid_timings = []
            invalid_timings = []
            
            # Try with potentially valid password
            for password in expected_params.get("password", [])[:2]:  # Limit to first 2 passwords
                payload = {"username": username, "password": password}
                
                try:
                    headers = {"Content-Type": "application/json"}
                    start_time = asyncio.get_event_loop().time()
                    resp = requests.post(endpoint_url, json=payload, headers=headers, timeout=5)
                    end_time = asyncio.get_event_loop().time()
                    
                    response_time = end_time - start_time
                    
                    # Check if login was successful
                    if resp.status_code == 200:
                        valid_timings.append(response_time)
                        
                        # Extract token if available
                        try:
                            resp_data = resp.json()
                            token = resp_data.get("auth_token") or resp_data.get("token")
                            
                            if token:
                                # Store the token for later use
                                if "bearer" not in self.auth_tokens:
                                    self.auth_tokens["bearer"] = []
                                    
                                self.auth_tokens["bearer"].append({
                                    "token": token,
                                    "username": username,
                                    "source": "login_scan"
                                })
                                
                                findings.append({
                                    "type": "VALID_CREDENTIALS",
                                    "severity": "MEDIUM",
                                    "detail": f"Valid credentials found for user: {username}",
                                    "evidence": {
                                        "username": username,
                                        "password": password,
                                        "correlation_id": correlation_id,
                                        "token_obtained": True
                                    }
                                })