#!/usr/bin/env python3

import asyncio
import json
import logging
import os
import random
import string
import time
from typing import Dict, List, Any, Optional, Tuple
import requests
from pydantic import BaseModel, Field
from pydantic_ai import Agent
from pydantic_ai.models import KnownModelName
from enum import Enum

from RAGScripts.auth_flow_scanner import AuthFlowScanner, setup_scanner_logger

# Pydantic models for structured data handling
class AuthType(str, Enum):
    BEARER = "bearer"
    BASIC = "basic"
    API_KEY = "apikey"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    CUSTOM = "custom"

class TokenInfo(BaseModel):
    token_type: AuthType
    access_token: str
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    expires_in: Optional[int] = None
    scope: Optional[str] = None
    email: Optional[str] = None

class AuthenticationPattern(BaseModel):
    auth_type: AuthType
    token_location: str = Field(description="Where to place the token (header, query, body)")
    token_prefix: Optional[str] = None
    required_fields: List[str] = Field(default_factory=list)
    optional_fields: List[str] = Field(default_factory=list)
    endpoints: List[str] = Field(default_factory=list)
    login_endpoint: Optional[str] = None
    register_endpoint: Optional[str] = None
    refresh_endpoint: Optional[str] = None

class AuthenticationResult(BaseModel):
    success: bool
    token_info: Optional[TokenInfo] = None
    error: Optional[str] = None
    raw_response: Optional[Dict] = None

class TestCase(BaseModel):
    type: str
    description: str
    endpoint: str
    method: str
    payload: Dict
    expected_status: int = 200
    expected_fields: List[str] = Field(default_factory=list)
    headers: Optional[Dict] = None

class TestResult(BaseModel):
    test_case: TestCase
    success: bool
    status_code: Optional[int] = None
    response_data: Optional[Dict] = None
    error: Optional[str] = None
    execution_time: float = 0.0

# AI Agent for dynamic authentication analysis
class AuthenticationAnalyzer:
    def __init__(self, model_name: str = KnownModelName.LLAMA_3_3):
        self.agent = Agent(model_name=model_name)
        self.logger = setup_scanner_logger("auth_analyzer")

    async def analyze_auth_pattern(self, swagger_spec: Dict) -> AuthenticationPattern:
        """Use LLaMA to analyze and detect authentication patterns from Swagger spec"""
        prompt = f"Analyze this API specification and identify the authentication pattern. Focus on finding login, registration, and token refresh endpoints. Extract the authentication type (bearer, basic, apikey, oauth2, jwt), where tokens are placed (header, query, body), and any required/optional fields for authentication requests.\n\nAPI Spec: {json.dumps(swagger_spec)[:10000]}"
        
        response = await self.agent.analyze(
            prompt,
            context={
                "task": "auth_pattern_detection",
                "supported_auth_types": [auth_type.value for auth_type in AuthType]
            }
        )

        # Parse the AI response into structured pattern
        try:
            pattern_dict = json.loads(response.content)
            return AuthenticationPattern(**pattern_dict)
        except Exception as e:
            self.logger.error(f"Error parsing auth pattern: {str(e)}")
            # Fallback to default pattern
            return AuthenticationPattern(
                auth_type=AuthType.BEARER, 
                token_location="header",
                token_prefix="Bearer"
            )

    async def generate_test_cases(self, auth_pattern: AuthenticationPattern, swagger_spec: Dict) -> List[TestCase]:
        """Generate dynamic test cases based on the detected authentication pattern"""
        prompt = f"Generate test cases for this authentication pattern and API specification. Create test cases for registration, authentication, token refresh, and accessing protected endpoints. For each test case, specify the endpoint, HTTP method, payload, expected status code, and expected response fields.\n\nAuthentication Pattern: {auth_pattern.json()}\n\nAPI Paths: {json.dumps(swagger_spec.get('paths', {}))[:5000]}"
        
        response = await self.agent.analyze(
            prompt,
            context={"task": "test_case_generation"}
        )

        try:
            test_cases_data = json.loads(response.content)
            return [TestCase(**tc) for tc in test_cases_data]
        except Exception as e:
            self.logger.error(f"Error generating test cases: {str(e)}")
            return []
            
    async def analyze_response(self, test_case: TestCase, response: Dict, status_code: int) -> Dict:
        """Analyze API response to extract tokens and determine success"""
        prompt = f"Analyze this API response from an authentication endpoint. Extract any access tokens, refresh tokens, ID tokens, or other authentication credentials. Determine if the authentication was successful.\n\nTest Case: {test_case.json()}\nStatus Code: {status_code}\nResponse: {json.dumps(response)}"
        
        analysis = await self.agent.analyze(
            prompt,
            context={"task": "response_analysis"}
        )
        
        try:
            return json.loads(analysis.content)
        except Exception as e:
            self.logger.error(f"Error analyzing response: {str(e)}")
            return {
                "success": status_code == test_case.expected_status,
                "extracted_tokens": {}
            }

class EnhancedAuthFlowScanner(AuthFlowScanner):
    def __init__(self, base_url: str, swagger_file: str, logger: Optional[logging.Logger] = None, model_name: str = KnownModelName.LLAMA_3_3):
        super().__init__(base_url, swagger_file, logger)
        self.auth_analyzer = AuthenticationAnalyzer(model_name=model_name)
        self.auth_pattern = None
        self.test_cases = []
        self.test_results = []
        self.current_tokens = {}
        self.registered_accounts = []

    async def initialize(self):
        """Initialize the scanner with AI-powered analysis"""
        self.logger.info("Initializing enhanced auth flow scanner with AI analysis")
        self.auth_pattern = await self.auth_analyzer.analyze_auth_pattern(self.swagger_spec)
        self.test_cases = await self.auth_analyzer.generate_test_cases(self.auth_pattern, self.swagger_spec)
        self.logger.info(f"Detected auth pattern: {self.auth_pattern.json()}")
        self.logger.info(f"Generated {len(self.test_cases)} test cases")

    def _generate_random_email(self) -> str:
        """Generate a random email for testing"""
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"test_user_{random_str}@example.com"

    def _generate_random_password(self) -> str:
        """Generate a random password for testing"""
        return f"Password{random.randint(100, 999)}#"

    async def execute_registration_test(self, test_case: TestCase) -> TestResult:
        """Execute a registration test case"""
        start_time = time.time()
        
        # Prepare the registration payload
        payload = test_case.payload.copy()
        
        # Add dynamic values if needed
        if "email" in payload and not payload["email"]:
            payload["email"] = self._generate_random_email()
        if "password" in payload and not payload["password"]:
            payload["password"] = self._generate_random_password()
            
        url = self.base_url + test_case.endpoint
        headers = test_case.headers or {}
        
        try:
            self.logger.info(f"Executing registration test: {test_case.description}")
            response = requests.request(test_case.method, url, json=payload, headers=headers)
            response_data = self._safe_parse_json(response)
            
            # Analyze the response
            analysis = await self.auth_analyzer.analyze_response(test_case, response_data, response.status_code)
            
            # Store the registered account if successful
            if analysis.get("success", False):
                self.registered_accounts.append({
                    "email": payload.get("email"),
                    "password": payload.get("password"),
                    "response": response_data
                })
                
            execution_time = time.time() - start_time
            
            return TestResult(
                test_case=test_case,
                success=analysis.get("success", False),
                status_code=response.status_code,
                response_data=response_data,
                execution_time=execution_time
            )
            
        except Exception as e:
            self.logger.error(f"Error executing registration test: {str(e)}")
            return TestResult(
                test_case=test_case,
                success=False,
                error=str(e),
                execution_time=time.time() - start_time
            )

    async def execute_authentication_test(self, test_case: TestCase) -> TestResult:
        """Execute an authentication test case"""
        start_time = time.time()
        
        # Use credentials from a registered account if available
        payload = test_case.payload.copy()
        if self.registered_accounts and not payload.get("email") and "email" in payload:
            account = self.registered_accounts[0]
            payload["email"] = account["email"]
            payload["password"] = account["password"]
            
        url = self.base_url + test_case.endpoint
        headers = test_case.headers or {}
        
        try:
            self.logger.info(f"Executing authentication test: {test_case.description}")
            response = requests.request(test_case.method, url, json=payload, headers=headers)
            response_data = self._safe_parse_json(response)
            
            # Analyze the response
            analysis = await self.auth_analyzer.analyze_response(test_case, response_data, response.status_code)
            
            # Extract and store tokens
            if analysis.get("success", False) and "extracted_tokens" in analysis:
                extracted_tokens = analysis["extracted_tokens"]
                if "access_token" in extracted_tokens:
                    self.current_tokens["access_token"] = extracted_tokens["access_token"]
                if "refresh_token" in extracted_tokens:
                    self.current_tokens["refresh_token"] = extracted_tokens["refresh_token"]
                if "id_token" in extracted_tokens:
                    self.current_tokens["id_token"] = extracted_tokens["id_token"]
                    
                # Store in the scanner's token format
                email = payload.get("email")
                if email:
                    self.tokens[email] = {
                        "accessToken": self.current_tokens.get("access_token"),
                        "refreshToken": self.current_tokens.get("refresh_token"),
                        "idToken": self.current_tokens.get("id_token"),
                        "email": email
                    }
                    
            execution_time = time.time() - start_time
            
            return TestResult(
                test_case=test_case,
                success=analysis.get("success", False),
                status_code=response.status_code,
                response_data=response_data,
                execution_time=execution_time
            )
            
        except Exception as e:
            self.logger.error(f"Error executing authentication test: {str(e)}")
            return TestResult(
                test_case=test_case,
                success=False,
                error=str(e),
                execution_time=time.time() - start_time
            )

    async def execute_token_refresh_test(self, test_case: TestCase) -> TestResult:
        """Execute a token refresh test case"""
        start_time = time.time()
        
        # Use the stored refresh token
        payload = test_case.payload.copy()
        if "refresh_token" in payload and not payload["refresh_token"] and "refresh_token" in self.current_tokens:
            payload["refresh_token"] = self.current_tokens["refresh_token"]
            
        url = self.base_url + test_case.endpoint
        headers = test_case.headers or {}
        
        try:
            self.logger.info(f"Executing token refresh test: {test_case.description}")
            response = requests.request(test_case.method, url, json=payload, headers=headers)
            response_data = self._safe_parse_json(response)
            
            # Analyze the response
            analysis = await self.auth_analyzer.analyze_response(test_case, response_data, response.status_code)
            
            # Update tokens if successful
            if analysis.get("success", False) and "extracted_tokens" in analysis:
                extracted_tokens = analysis["extracted_tokens"]
                if "access_token" in extracted_tokens:
                    self.current_tokens["access_token"] = extracted_tokens["access_token"]
                if "refresh_token" in extracted_tokens:
                    self.current_tokens["refresh_token"] = extracted_tokens["refresh_token"]
                    
                # Update in the scanner's token format
                if self.registered_accounts:
                    email = self.registered_accounts[0]["email"]
                    if email in self.tokens:
                        self.tokens[email]["accessToken"] = self.current_tokens.get("access_token")
                        if "refresh_token" in extracted_tokens:
                            self.tokens[email]["refreshToken"] = self.current_tokens.get("refresh_token")
                    
            execution_time = time.time() - start_time
            
            return TestResult(
                test_case=test_case,
                success=analysis.get("success", False),
                status_code=response.status_code,
                response_data=response_data,
                execution_time=execution_time
            )
            
        except Exception as e:
            self.logger.error(f"Error